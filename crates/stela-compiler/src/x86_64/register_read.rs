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
//!
//! A [`count_thunk`] reads a count instead: the system count the engine's
//! clock shows at the host's TSC ([`Count`]), less the cell's `value`.
//! It also clobbers RCX and RDX, which are dead at every block exit (the
//! direct exit returns in RAX and RDX, and chaining uses RCX).
use super::asm::{Alu, Asm, Cond, Gpr, Mem, Patch, ShiftOp, Size, Unary};
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

const VALUE: i8 = core::mem::offset_of!(Cell, value) as i8;
const _: () = assert!(core::mem::offset_of!(Cell, readable) == 0);

/// The engine's system count at a host TSC value `tsc`: the larger of
/// `((tsc - base) * per_tsc >> 64) + offset` and `last`, which becomes the
/// new `last`, so the count never runs backwards.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Count {
    pub base: u64,
    pub per_tsc: u64,
    pub offset: u64,
    pub last: u64,
}

const BASE: i8 = core::mem::offset_of!(Count, base) as i8;
const PER_TSC: i8 = core::mem::offset_of!(Count, per_tsc) as i8;
const OFFSET: i8 = core::mem::offset_of!(Count, offset) as i8;
const LAST: i8 = core::mem::offset_of!(Count, last) as i8;

/// Xt's frame slot.
fn register(rt: u8) -> Mem {
    Mem::base_disp32(Gpr::Rdi, i32::from(rt) * 8)
}

/// The thunk completing `MRS Xt, <register>` at `pc` from the cell at
/// `cell`, else exiting at `pc` for the engine.
pub fn thunk(pc: GuestAddress, rt: u8, cell: u64) -> Thunk {
    let (mut code, miss) = open(cell);
    if rt != 31 {
        let mut asm = Asm::new(&mut code);
        asm.mov_load(Size::Qword, Gpr::Rax, Mem::base_disp8(Gpr::Rax, VALUE));
        asm.mov_store(Size::Qword, register(rt), Gpr::Rax);
    }
    finish(code, miss, pc)
}

/// The thunk completing `MRS Xt, <count>` at `pc` with the count at
/// `count` less the `value` of the cell at `cell`, else exiting at `pc`.
pub fn count_thunk(pc: GuestAddress, rt: u8, cell: u64, count: u64) -> Thunk {
    use Gpr::{Rax, Rcx, Rdx};
    use Size::Qword;
    let (mut code, miss) = open(cell);
    let field = |offset| Mem::base_disp8(Rcx, offset);
    let mut asm = Asm::new(&mut code);
    asm.mov_imm64(Rcx, count);
    asm.rdtsc();
    asm.shift_imm(ShiftOp::Shl, Qword, Rdx, 32);
    asm.alu(Alu::Or, Qword, Rax, Rdx);
    asm.alu_load(Alu::Sub, Qword, Rax, field(BASE));
    asm.unary(Unary::Mul, Qword, field(PER_TSC));
    asm.alu_load(Alu::Add, Qword, Rdx, field(OFFSET));
    asm.mov_load(Qword, Rax, field(LAST));
    asm.alu(Alu::Cmp, Qword, Rdx, Rax);
    asm.cmov(Cond::B, Qword, Rdx, Rax);
    asm.mov_store(Qword, field(LAST), Rdx);
    if rt != 31 {
        asm.mov_imm64(Rax, cell);
        asm.alu_load(Alu::Sub, Qword, Rdx, Mem::base_disp8(Rax, VALUE));
        asm.mov_store(Qword, register(rt), Rdx);
    }
    finish(code, miss, pc)
}

/// Load `cell` and branch to the miss while it is not readable.
fn open(cell: u64) -> (Vec<u8>, Patch) {
    let mut code = Vec::with_capacity(128);
    let mut asm = Asm::new(&mut code);
    asm.mov_imm64(Gpr::Rax, cell);
    asm.alu_imm8(Alu::Cmp, Size::Qword, Mem::base(Gpr::Rax, 0), 0);
    let miss = asm.jcc(Cond::E);
    (code, miss)
}

/// The direct exit to the next instruction, then the `miss` branch's
/// target: the original exit at `pc`.
fn finish(mut code: Vec<u8>, miss: Patch, pc: GuestAddress) -> Thunk {
    let next = code.len();
    let mut asm = Asm::new(&mut code);
    super::block::direct_exit_with(
        &mut asm,
        GuestAddress(pc.0.wrapping_add(4)),
        ExitKind::Fallthrough,
    );
    asm.bind(miss);
    super::block::direct_exit_with(&mut asm, pc, ExitKind::System);
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

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[repr(C)]
    #[derive(Debug, PartialEq, Eq)]
    struct Exit {
        pc: u64,
        kind: u64,
    }

    /// Run a thunk on the host.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    fn run(code: &[u8], state: &mut crate::GuestState) -> Exit {
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
        // SAFETY: private anonymous memory, RX after the copy, unmapped after
        // the call; the thunk touches only `state` and its cells, which
        // outlive it.
        unsafe {
            let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
            assert_ne!(page as usize, usize::MAX);
            core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
            assert_eq!(mprotect(page, PAGE, 5), 0);
            let entry: unsafe extern "sysv64" fn(*mut crate::GuestState) -> Exit =
                core::mem::transmute(page);
            let exit = entry(state);
            assert_eq!(munmap(page, PAGE), 0);
            exit
        }
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    const PC: GuestAddress = GuestAddress(0x4000);
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    const MISS: Exit = Exit {
        pc: PC.0,
        kind: ExitKind::System as u64,
    };
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    const NEXT: Exit = Exit {
        pc: PC.0 + 4,
        kind: ExitKind::Fallthrough as u64,
    };

    /// Thunks run on the host: a readable cell completes the read into Xt,
    /// or into nothing for XZR; a cleared one exits with no write.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn thunks_read_the_cell_only_while_it_is_readable() {
        use crate::GuestState;
        let (pc, miss, next) = (PC, MISS, NEXT);
        let mut cell = alloc::boxed::Box::new(Cell::default());
        let address = &mut *cell as *mut Cell;
        // SAFETY: address points into the live Cell box; the closure runs between thunk calls.
        let set = |value: Cell| unsafe { address.write(value) };
        let mut state = GuestState::default();
        state.x[19] = 7;
        let read = thunk(pc, 19, address as u64);
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

    /// A count read adds the offset to the scaled TSC (zero here, as
    /// `per_tsc` is), never reads below `last` and keeps what it read
    /// there, and subtracts the cell's value; XZR still moves `last`.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn count_thunks_read_a_monotonic_count_less_the_cell_value() {
        use crate::GuestState;
        let mut cell = alloc::boxed::Box::new(Cell::default());
        let mut count = alloc::boxed::Box::new(Count {
            offset: 100,
            last: 50,
            ..Count::default()
        });
        let (cell_at, count_at) = (&mut *cell as *mut Cell, &mut *count as *mut Count);
        let read = count_thunk(PC, 3, cell_at as u64, count_at as u64);
        let mut state = GuestState::default();
        assert_eq!(run(&read.code, &mut state), MISS);
        // SAFETY: the boxes outlive every thunk run.
        unsafe {
            cell_at.write(Cell {
                readable: 1,
                value: 30,
            })
        };
        assert_eq!(run(&read.code, &mut state), NEXT);
        // SAFETY: count_at points into the live Count box and the preceding thunk has returned.
        assert_eq!((state.x[3], unsafe { (*count_at).last }), (70, 100));
        // SAFETY: the box remains live and the native thunk is not running during this write.
        unsafe { (*count_at).offset = 80 };
        assert_eq!(run(&read.code, &mut state), NEXT);
        // SAFETY: count_at points into the live Count box and the preceding thunk has returned.
        assert_eq!((state.x[3], unsafe { (*count_at).last }), (70, 100));
        // SAFETY: the box remains live and the native thunk is not running during this write.
        unsafe { (*count_at).offset = 500 };
        let before = state.x;
        let discard = count_thunk(PC, 31, cell_at as u64, count_at as u64);
        assert_eq!(run(&discard.code, &mut state), NEXT);
        // SAFETY: count_at still names the live Count box after the discard thunk returns.
        assert_eq!((state.x, unsafe { (*count_at).last }), (before, 500));
    }
}
