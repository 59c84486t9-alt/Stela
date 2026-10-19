//! Native completion of MRS reads of a System register whose value the
//! system-mode engine keeps in a [`Cell`] at a fixed host address.
//!
//! The MRS ends its block with a System exit. A [`thunk`] the engine
//! installs over that exit completes it natively while the cell's
//! `readable` word is nonzero: it writes `value` to Xt (nothing for XZR) and
//! leaves through a direct exit to the next instruction, which the engine
//! may chain like a block's. Otherwise it takes the original exit.
//!
//! The engine sets `readable` only while the read at the current EL is the
//! plain register read of its AARCHMRS accessor, neither UNDEFINED nor
//! trapped nor redirected, with `value` the register's contents, and clears
//! it whenever a System register write, an exception, an exception return
//! or a PE switch may change either. Thunks clobber only RAX and flags.
use super::pointer::Thunk;
use crate::{GuestAddress, block::ExitKind};
use alloc::vec::Vec;

/// What a thunk reads.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cell {
    /// Nonzero while native code may complete the read with `value`.
    pub readable: u64,
    pub value: u64,
}

const VALUE: u8 = core::mem::offset_of!(Cell, value) as u8;
const _: () = assert!(core::mem::offset_of!(Cell, readable) == 0);

/// The thunk completing `MRS Xt, <register>` at `pc` from the cell at
/// `cell`, else exiting at `pc` for the engine.
pub fn thunk(pc: GuestAddress, rt: u8, cell: u64) -> Thunk {
    let mut code = Vec::with_capacity(64);
    code.extend([0x48, 0xb8]); // movabs rax,cell
    code.extend(cell.to_le_bytes());
    code.extend([0x48, 0x83, 0x38, 0x00]); // cmp qword [rax],0
    code.extend([0x0f, 0x84]); // je miss
    let fixup = code.len();
    code.extend([0; 4]);
    if rt != 31 {
        code.extend([0x48, 0x8b, 0x40, VALUE]); // mov rax,[rax+value]
        code.extend([0x48, 0x89, 0x87]); // mov [rdi+x(rt)],rax
        code.extend((u32::from(rt) * 8).to_le_bytes());
    }
    let next = code.len();
    code.extend(super::chain::direct_exit(
        GuestAddress(pc.0.wrapping_add(4)),
        ExitKind::Fallthrough,
    ));
    let relative = (code.len() - fixup - 4) as i32;
    code[fixup..fixup + 4].copy_from_slice(&relative.to_le_bytes());
    code.extend(super::chain::direct_exit(pc, ExitKind::System));
    Thunk {
        code,
        next: Some(next),
        dynamic: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_64::chain::{DIRECT_EXIT_BYTES, direct_exit};

    #[test]
    fn thunks_end_in_the_fallthrough_then_the_original_exit() {
        let pc = GuestAddress(0x4000);
        let thunk = thunk(pc, 8, 0x1000);
        let end = thunk.code.len();
        assert_eq!(
            thunk.code[end - DIRECT_EXIT_BYTES..],
            direct_exit(pc, ExitKind::System)
        );
        let next = thunk.next.unwrap();
        assert_eq!(next + DIRECT_EXIT_BYTES, end - DIRECT_EXIT_BYTES);
        assert_eq!(
            thunk.code[next..next + DIRECT_EXIT_BYTES],
            direct_exit(GuestAddress(0x4004), ExitKind::Fallthrough)
        );
    }

    /// Thunks run on the host: a readable cell completes the read into Xt,
    /// or into nothing for XZR; a cleared one exits with no write.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn thunks_read_the_cell_only_while_it_is_readable() {
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
        #[repr(C)]
        #[derive(Debug, PartialEq, Eq)]
        struct Exit {
            pc: u64,
            kind: u64,
        }
        fn run(code: &[u8], state: &mut GuestState) -> Exit {
            // SAFETY: private anonymous memory, RX after the copy, unmapped
            // after the call; the thunk touches only `state` and the cell,
            // which outlive it.
            unsafe {
                let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
                assert_eq!(mprotect(page, PAGE, 5), 0);
                let entry: unsafe extern "sysv64" fn(*mut GuestState) -> Exit =
                    core::mem::transmute(page);
                let exit = entry(state);
                assert_eq!(munmap(page, PAGE), 0);
                exit
            }
        }
        let pc = GuestAddress(0x4000);
        let mut cell = alloc::boxed::Box::new(Cell::default());
        let address = &mut *cell as *mut Cell;
        let set = |value: Cell| unsafe { address.write(value) };
        let mut state = GuestState::default();
        state.x[19] = 7;
        let read = thunk(pc, 19, address as u64);
        let miss = Exit {
            pc: pc.0,
            kind: ExitKind::System as u64,
        };
        let next = Exit {
            pc: pc.0 + 4,
            kind: ExitKind::Fallthrough as u64,
        };
        set(Cell {
            readable: 0,
            value: 0xffff_fe00_1234_5000,
        });
        assert_eq!(run(&read.code, &mut state), miss);
        assert_eq!(state.x[19], 7);
        set(Cell {
            readable: 1,
            value: 0xffff_fe00_1234_5000,
        });
        assert_eq!(run(&read.code, &mut state), next);
        assert_eq!(state.x[19], 0xffff_fe00_1234_5000);
        let before = state.x;
        assert_eq!(run(&thunk(pc, 31, address as u64).code, &mut state), next);
        assert_eq!(state.x, before);
    }
}
