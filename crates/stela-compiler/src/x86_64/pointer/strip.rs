//! Keyless XPACI/XPACD completion with the current regime's address masks.
//!
//! Arm `Strip` selects the lower/upper TnSZ and effective TBI by bit 55.
//! The runtime derives both keep masks through its authoritative PAC layout
//! and closes this cell whenever derived state changes. A closed cell takes
//! the original instruction exit, without changing architectural state.
use super::{JZ, Thunk, jump, land};
use crate::{GuestAddress, block::ExitKind};
use alloc::vec::Vec;

/// Fixed-address state read by a strip thunk. Each keep mask excludes the
/// extension field that is restored from bit 55; tagged bytes remain set.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cell {
    pub enabled: u64,
    pub keep: [u64; 2],
    /// Complement of the upper-range keep mask, used on an independent
    /// dependency chain from the pointer's AND.
    pub upper_extension: u64,
}

const LOWER: u8 = core::mem::offset_of!(Cell, keep) as u8;
const UPPER: u8 = LOWER + 8;
const UPPER_EXTENSION: u8 = core::mem::offset_of!(Cell, upper_extension) as u8;
const REGION_BIT: u8 = 55;

/// Complete XPAC on `register`, with no key access, from `cell` while open.
/// Only RAX, RCX, RDX, R8 and host flags are clobbered, as at a block exit;
/// guest NZCV, SP and every other register remain in their canonical frame.
pub fn thunk(pc: GuestAddress, register: u8, cell: u64) -> Option<Thunk> {
    if register > 31 {
        return None;
    }
    let mut code = Vec::with_capacity(96);
    let mut closed = Vec::new();
    // XZR has no effect and depends on no regime state.
    if register != 31 {
        code.extend([0x48, 0xba]); // movabs rdx,cell
        code.extend(cell.to_le_bytes());
        code.extend([0x48, 0x83, 0x3a, 0]); // cmp qword [rdx],0
        jump(&mut code, &mut closed, JZ);
        code.extend([0x48, 0x8b, 0x87]); // mov rax,[rdi+register]
        code.extend((u32::from(register) * 8).to_le_bytes());
        code.extend([0x48, 0x8b, 0x4a, LOWER]); // mov rcx,[rdx+lower]
        code.extend([0x48, 0x0f, 0xba, 0xe0, REGION_BIT]); // bt rax,55
        code.extend([0x48, 0x0f, 0x42, 0x4a, UPPER]); // cmovc rcx,[rdx+upper]
        code.extend([0x4d, 0x19, 0xc0]); // sbb r8,r8: bit 55 replicated
        code.extend([0x4c, 0x23, 0x42, UPPER_EXTENSION]); // and r8,[rdx+extension]
        code.extend([0x48, 0x21, 0xc8]); // and rax,rcx
        code.extend([0x4c, 0x09, 0xc0]); // or rax,r8
        code.extend([0x48, 0x89, 0x87]); // mov [rdi+register],rax
        code.extend((u32::from(register) * 8).to_le_bytes());
    }
    let next = code.len();
    code.extend(super::super::chain::direct_exit(
        GuestAddress(pc.0.wrapping_add(4)),
        ExitKind::Fallthrough,
    ));
    land(&mut code, &closed);
    code.extend(super::super::chain::direct_exit(
        pc,
        ExitKind::PointerAuthentication,
    ));
    Some(Thunk {
        code,
        next: Some(next),
        dynamic: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_register_refuses_and_xzr_needs_no_cell_access() {
        assert!(thunk(GuestAddress(0x4000), 32, 0).is_none());
        let zero = thunk(GuestAddress(u64::MAX - 3), 31, 0).unwrap();
        assert_eq!(zero.next, Some(0));
        assert_eq!(
            &zero.code[..16],
            &super::super::super::chain::direct_exit(GuestAddress(0), ExitKind::Fallthrough)
        );
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn native_strips_preserve_full_state_and_follow_live_masks_and_closure() {
        use crate::GuestState;
        use core::ffi::c_void;
        unsafe extern "C" {
            fn mmap(
                p: *mut c_void,
                n: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                off: i64,
            ) -> *mut c_void;
            fn mprotect(p: *mut c_void, n: usize, prot: i32) -> i32;
            fn munmap(p: *mut c_void, n: usize) -> i32;
        }
        #[cfg(target_os = "macos")]
        const ANONYMOUS: i32 = 0x1000;
        #[cfg(target_os = "linux")]
        const ANONYMOUS: i32 = 0x20;
        #[repr(C)]
        #[derive(Debug, PartialEq, Eq)]
        struct Exit(u64, u64);
        let pc = GuestAddress(0x4000);
        let mut cell = Cell::default();
        for register in [0, 8, 17, 30, 31] {
            let code = thunk(pc, register, &cell as *const Cell as u64).unwrap();
            // SAFETY: private anonymous page, writable only during copying,
            // then executable; code touches only this live cell and frame.
            unsafe {
                let page = mmap(core::ptr::null_mut(), 4096, 3, 2 | ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(code.code.as_ptr(), page.cast(), code.code.len());
                assert_eq!(mprotect(page, 4096, 5), 0);
                let run: unsafe extern "sysv64" fn(*mut GuestState) -> Exit =
                    core::mem::transmute(page);
                let mut before = GuestState::default();
                for (i, value) in before.x.iter_mut().enumerate() {
                    *value = 0xfeed_0000_0000_0000 | i as u64;
                }
                before.sp = 0x1234_0000;
                before.nzcv = 0xa000_0000;
                before.reserved = 0x9876_5432;
                before.fpcr = 0x0300_0000;
                before.fpsr = 0x0800_009f;
                before
                    .v
                    .fill([0x1234_5678_9abc_def0, 0xffff_5555_0000_aaaa]);
                for lower_bits in [25, 39, 47, 48] {
                    for upper_bits in [25, 39, 47, 48] {
                        for tagged in [false, true] {
                            let top = if tagged { 0xff00_0000_0000_0000 } else { 0 };
                            cell = Cell {
                                enabled: 1,
                                keep: [
                                    top | ((1 << lower_bits) - 1),
                                    top | ((1 << upper_bits) - 1),
                                ],
                                upper_extension: !(top | ((1 << upper_bits) - 1)),
                            };
                            core::hint::black_box(&cell);
                            for pointer in [0, u64::MAX, 1 << 55, 1 << 63, 0xab91_ffee_1234_5678] {
                                let mut input = before.clone();
                                if register != 31 {
                                    input.x[usize::from(register)] = pointer;
                                }
                                let mut expected = input.clone();
                                if register != 31 {
                                    let upper = pointer & (1 << 55) != 0;
                                    let keep = cell.keep[usize::from(upper)];
                                    expected.x[usize::from(register)] =
                                        (pointer & keep) | if upper { !keep } else { 0 };
                                }
                                assert_eq!(
                                    run(&mut input),
                                    Exit(pc.0 + 4, ExitKind::Fallthrough as u64)
                                );
                                assert_eq!(input, expected);
                                cell.enabled = 0;
                                core::hint::black_box(&cell);
                                let mut closed = before.clone();
                                let kind = if register == 31 {
                                    ExitKind::Fallthrough
                                } else {
                                    ExitKind::PointerAuthentication
                                };
                                let at = if register == 31 { pc.0 + 4 } else { pc.0 };
                                assert_eq!(run(&mut closed), Exit(at, kind as u64));
                                assert_eq!(closed, before);
                                cell.enabled = 1;
                            }
                        }
                    }
                }
                assert_eq!(munmap(page, 4096), 0);
            }
        }
    }
}
