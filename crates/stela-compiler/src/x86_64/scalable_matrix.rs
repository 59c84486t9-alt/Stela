//! ZA storage access for the extended native ABI. R15 holds the
//! ExecutionContext; callers handle slice selection and bounds.
use crate::x86_64::asm::Gpr::{R8, R15};
use crate::x86_64::asm::{Code, Mem, Size};

use super::isa::SimdOpcode as Host;
use crate::{
    TargetCpu,
    context::{EXECUTION_CONTEXT_SCALABLE_OFFSET, SCALABLE_ZA_OFFSET},
};

const XMM_REGISTER_COUNT: u8 = 8;

/// Load the ZA bank base into R8. Every other GPR/XMM and host flag survives.
/// The runtime must have validated a live scalable view and ZA allocation.
pub(crate) fn load_za_pointer_r8(code: &mut Code) {
    // Versioned pointer fields fit a positive signed disp8.
    debug_assert!(EXECUTION_CONTEXT_SCALABLE_OFFSET <= i8::MAX as u32);
    debug_assert!(SCALABLE_ZA_OFFSET <= i8::MAX as u32);
    let mut asm = code.asm();
    asm.mov_load(
        Size::Qword,
        R8,
        Mem::base_disp8(R15, EXECUTION_CONTEXT_SCALABLE_OFFSET as i8),
    );
    asm.mov_load(
        Size::Qword,
        R8,
        Mem::base_disp8(R8, SCALABLE_ZA_OFFSET as i8),
    );
}

fn chunk_memory(code: &mut Code, opcode: Host, register: u8, displacement: u32, target: TargetCpu) {
    assert!(register < XMM_REGISTER_COUNT, "ZA helper requires XMM0..7");
    assert!(
        displacement <= i32::MAX as u32,
        "ZA displacement must be positive disp32"
    );
    code.asm().simd(
        opcode,
        register,
        Mem::base_disp32(R8, displacement as i32),
        target,
    );
}

/// Read exactly 16 unaligned bytes at R8+displacement into the chosen XMM.
/// Preserves R8, every other GPR/XMM and host flags. The caller may first add a
/// validated dynamic row offset to R8; displacement is relative to that base.
pub(crate) fn load_za_chunk_at_r8(
    code: &mut Code,
    destination: u8,
    displacement: u32,
    target: TargetCpu,
) {
    chunk_memory(code, Host::LoadUnaligned, destination, displacement, target);
}

/// Write exactly 16 unaligned bytes from the chosen XMM at R8+displacement.
/// Preserves every GPR/XMM and host flags. The caller stages aliased sources
/// before invoking stores when an instruction requires simultaneous results.
pub(crate) fn store_za_chunk_at_r8(
    code: &mut Code,
    source: u8,
    displacement: u32,
    target: TargetCpu,
) {
    chunk_memory(code, Host::StoreUnaligned, source, displacement, target);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_chase_uses_the_shared_context_contract() {
        let mut code = Code::new();
        load_za_pointer_r8(&mut code);
        assert_eq!(code, [0x4d, 0x8b, 0x47, 16, 0x4d, 0x8b, 0x40, 56]);
    }

    #[test]
    fn rex_base_follows_mandatory_simd_prefix() {
        for register in 0..XMM_REGISTER_COUNT {
            let mut load = Code::new();
            load_za_chunk_at_r8(&mut load, register, 0x1234, TargetCpu::Baseline);
            assert_eq!(load[..5], [0xf3, 0x41, 0x0f, 0x6f, 0x80 | register << 3]);
            assert_eq!(load[5..], 0x1234u32.to_le_bytes());
            let mut store = Code::new();
            store_za_chunk_at_r8(&mut store, register, 0x5678, TargetCpu::Baseline);
            assert_eq!(store[..5], [0xf3, 0x41, 0x0f, 0x7f, 0x80 | register << 3]);
            assert_eq!(store[5..], 0x5678u32.to_le_bytes());
        }
    }
}
