//! DC ZVA in system-mode blocks the engine compiles where it neither traps
//! nor is UNDEFINED (`CompilationPlan::with_zero_block`): Arm
//! `AArch64_MemZero` writes zeroes to the DCZID_EL0.BS block holding Xt,
//! aligned down, through the same direct guest-VA stores as STR, after the
//! guest range check. The block is at most 2 KiB and naturally aligned, so
//! it lies in one host page and either every store completes or the check
//! or the first store faults with nothing written;
//! the engine then completes the instruction itself, which reports Xt as
//! the fault address and checks watchpoints over the whole block. Code
//! clobbers RAX, RCX and RDX.
use crate::aarch64::{
    Register,
    system::registers::{Direction, Encoding},
};
use crate::block::{SystemInstruction, system::SystemOperation};
use alloc::vec::Vec;

/// DC ZVA: SYS #3, C7, C4, #1.
const DC_ZVA: Encoding = Encoding::new(1, 3, 7, 4, 1);
/// The DC ZVA block size bounds of DCZID_EL0.BS (0 to 9).
pub const MIN_BYTES: u16 = 4;
pub const MAX_BYTES: u16 = 2048;
/// Blocks up to this size are unrolled 8-byte stores with 8-bit
/// displacements; larger ones loop.
const UNROLLED_BYTES: u16 = 128;

/// Xt of a DC ZVA, or `None` for any other System instruction.
pub fn operand(instruction: &SystemInstruction) -> Option<u8> {
    match instruction.operation {
        // SYSL with DC ZVA's encoding is not DC ZVA.
        SystemOperation::Maintenance(access)
            if access.encoding() == DC_ZVA && access.direction() == Direction::Write =>
        {
            Some(access.rt())
        }
        _ => None,
    }
}

/// Zero the `bytes` block (a power of two in [`MIN_BYTES`]..=[`MAX_BYTES`])
/// holding Xt.
pub(crate) fn emit(code: &mut Vec<u8>, rt: u8, bytes: u16, range: super::RangeCheck) {
    debug_assert!(bytes.is_power_of_two() && (MIN_BYTES..=MAX_BYTES).contains(&bytes));
    super::load(
        code,
        if rt == 31 {
            Register::Zero
        } else {
            Register::X(rt)
        },
    );
    // Aligning down keeps bits 63:48, so Xt is in range exactly when the
    // block is.
    range.emit(code);
    let mask = -i32::from(bytes);
    if let Ok(mask) = i8::try_from(mask) {
        code.extend([0x48, 0x83, 0xe0, mask as u8]); // and rax,-bytes
    } else {
        code.extend([0x48, 0x25]); // and rax,-bytes
        code.extend(mask.to_le_bytes());
    }
    code.extend([0x31, 0xc9]); // xor ecx,ecx
    if bytes < 8 {
        code.extend([0x89, 0x08]); // mov [rax],ecx
    } else if bytes <= UNROLLED_BYTES {
        for offset in (0..bytes).step_by(8) {
            code.extend([0x48, 0x89, 0x48, offset as u8]); // mov [rax+offset],rcx
        }
    } else {
        code.push(0xba); // mov edx,bytes/8
        code.extend((u32::from(bytes) / 8).to_le_bytes());
        // mov [rax+rdx*8-8],rcx; dec edx; jnz back to the store
        code.extend([0x48, 0x89, 0x4c, 0xd0, 0xf8, 0xff, 0xca, 0x75, 0xf7]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestAddress, block::decode_system_mode_instruction};

    #[test]
    fn only_dc_zva_names_an_operand() {
        let decode = |word| decode_system_mode_instruction(GuestAddress(0x4000), word).unwrap();
        assert_eq!(operand(&decode(0xd50b_7423).unwrap()), Some(3)); // dc zva, x3
        assert_eq!(operand(&decode(0xd50b_743f).unwrap()), Some(31)); // dc zva, xzr
        for word in [
            0xd50b_7a20_u32, // dc cvac, x0
            0xd50b_7463,     // dc gva, x3
            0xd50b_7483,     // dc gzva, x3
            0xd538_d080,     // mrs x0, tpidr_el1
            0xd52b_7423,     // sysl x3, #3, c7, c4, #1
        ] {
            assert_eq!(operand(&decode(word).unwrap()), None, "{word:#x}");
        }
    }

    /// The emitted code runs on the host and zeroes exactly the aligned
    /// block around Xt, for the unrolled, looping and word-sized forms.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn zeroes_exactly_the_aligned_block_holding_xt() {
        use crate::GuestState;
        use core::ffi::c_void;
        unsafe extern "C" {
            fn mmap(
                address: *mut c_void,
                bytes: usize,
                protection: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> *mut c_void;
            fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
            fn munmap(address: *mut c_void, bytes: usize) -> i32;
        }
        #[cfg(target_os = "macos")]
        const MAP_ANONYMOUS: i32 = 0x1000;
        #[cfg(target_os = "linux")]
        const MAP_ANONYMOUS: i32 = 0x20;
        const PAGE: usize = 4096;
        for bytes in [4u16, 8, 64, 128, 256, 2048] {
            let mut memory = alloc::vec![0xa5u8; 3 * usize::from(MAX_BYTES)];
            let base = memory.as_mut_ptr() as u64;
            let block = (base + u64::from(MAX_BYTES)).next_multiple_of(u64::from(bytes));
            let mut state = GuestState::default();
            // Xt points inside the block, past its start.
            state.x[5] = block + u64::from(bytes) - 1;
            let mut code = Vec::new();
            emit(&mut code, 5, bytes, super::super::RangeCheck::FIVE_LEVEL);
            code.push(0xc3); // ret
            // SAFETY: private anonymous memory, RX after the copy, unmapped
            // after the call; the code writes only inside `memory`.
            unsafe {
                let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
                assert_eq!(mprotect(page, PAGE, 5), 0);
                let entry: unsafe extern "sysv64" fn(*mut GuestState) = core::mem::transmute(page);
                entry(&mut state);
                assert_eq!(munmap(page, PAGE), 0);
            }
            let start = (block - base) as usize;
            let end = start + usize::from(bytes);
            assert!(memory[start..end].iter().all(|&byte| byte == 0), "{bytes}");
            assert!(memory[..start].iter().all(|&byte| byte == 0xa5), "{bytes}");
            assert!(memory[end..].iter().all(|&byte| byte == 0xa5), "{bytes}");
            assert_eq!(state.x[5], block + u64::from(bytes) - 1, "Xt is unchanged");
        }
    }
}
