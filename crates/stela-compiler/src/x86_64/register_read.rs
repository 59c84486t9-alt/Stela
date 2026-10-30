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
//! A [`count_thunk`] reads a count instead: the system count a clock
//! publishes in a [`CountState`] at the host's TSC, through the reader's
//! [`Count`], less the cell's `value`. It also clobbers RCX and RDX, which
//! are dead at every block exit (the direct exit returns in RAX and RDX,
//! and chaining uses RCX).
use super::asm::{Alu, Asm, Cond, Gpr, Mem, Patch, ShiftOp, Size, Unary};
use super::pointer::Thunk;
use crate::{GuestAddress, block::ExitKind};
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;

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

/// A clock's count as every reader computes it: at host count `host`
/// (`((tsc - base) * per_tsc) >> 64`), `min(host + offset, ceiling)`, with
/// wrapping addition. A writer makes `sequence` odd, changes `offset` and
/// `ceiling` and makes it even again; a reader takes both from one even
/// sequence and samples the TSC before that sequence ends, so readers on
/// different cores see one count (a seqlock).
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct CountState {
    pub sequence: AtomicU64,
    pub offset: AtomicU64,
    pub ceiling: AtomicU64,
}

const SEQUENCE: i8 = core::mem::offset_of!(CountState, sequence) as i8;
const STATE_OFFSET: i8 = core::mem::offset_of!(CountState, offset) as i8;
const CEILING: i8 = core::mem::offset_of!(CountState, ceiling) as i8;

/// One reader of a [`CountState`] at `state`: its TSC scale, and `last`,
/// the count it last read, below which it never reads, so its own count
/// never runs backwards. `seen_*` hold the read in progress.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Count {
    pub base: u64,
    pub per_tsc: u64,
    pub last: u64,
    pub state: u64,
    pub seen_sequence: u64,
    pub seen_offset: u64,
    pub seen_ceiling: u64,
}

const BASE: i8 = core::mem::offset_of!(Count, base) as i8;
const PER_TSC: i8 = core::mem::offset_of!(Count, per_tsc) as i8;
const LAST: i8 = core::mem::offset_of!(Count, last) as i8;
const STATE: i8 = core::mem::offset_of!(Count, state) as i8;
const SEEN_SEQUENCE: i8 = core::mem::offset_of!(Count, seen_sequence) as i8;
const SEEN_OFFSET: i8 = core::mem::offset_of!(Count, seen_offset) as i8;
const SEEN_CEILING: i8 = core::mem::offset_of!(Count, seen_ceiling) as i8;

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

/// The thunk completing `MRS Xt, <count>` at `pc` with the count of the
/// reader at `count` less the `value` of the cell at `cell`, else exiting
/// at `pc`. It spins while a writer publishes; `lfence` keeps the TSC
/// sample between the two sequence reads (Intel SDM Vol. 2B, RDTSC).
pub fn count_thunk(pc: GuestAddress, rt: u8, cell: u64, count: u64) -> Thunk {
    use Gpr::{Rax, Rcx, Rdx};
    use Size::Qword;
    let (mut code, miss) = open(cell);
    let field = |offset| Mem::base_disp8(Rcx, offset);
    let state = |offset| Mem::base_disp8(Rax, offset);
    let mut asm = Asm::new(&mut code);
    asm.mov_imm64(Rcx, count);
    let start = asm.jmp8();
    let busy = asm.len();
    asm.pause();
    asm.bind(start);
    asm.mov_load(Qword, Rax, field(STATE));
    asm.mov_load(Qword, Rdx, state(SEQUENCE));
    asm.test_imm(Size::Byte, Rdx, 1);
    let publishing = asm.jcc8(Cond::Ne);
    asm.bind_back(publishing, busy);
    asm.mov_store(Qword, field(SEEN_SEQUENCE), Rdx);
    asm.mov_load(Qword, Rdx, state(STATE_OFFSET));
    asm.mov_store(Qword, field(SEEN_OFFSET), Rdx);
    asm.mov_load(Qword, Rdx, state(CEILING));
    asm.mov_store(Qword, field(SEEN_CEILING), Rdx);
    asm.lfence();
    asm.rdtsc();
    asm.lfence();
    asm.shift_imm(ShiftOp::Shl, Qword, Rdx, 32);
    asm.alu(Alu::Or, Qword, Rax, Rdx);
    asm.alu_load(Alu::Sub, Qword, Rax, field(BASE));
    asm.unary(Unary::Mul, Qword, field(PER_TSC));
    asm.mov_load(Qword, Rax, field(STATE));
    asm.mov_load(Qword, Rax, state(SEQUENCE));
    asm.alu_load(Alu::Cmp, Qword, Rax, field(SEEN_SEQUENCE));
    let changed = asm.jcc8(Cond::Ne);
    asm.bind_back(changed, busy);
    asm.alu_load(Alu::Add, Qword, Rdx, field(SEEN_OFFSET));
    asm.alu_load(Alu::Cmp, Qword, Rdx, field(SEEN_CEILING));
    asm.cmov(Cond::A, Qword, Rdx, field(SEEN_CEILING));
    asm.alu_load(Alu::Cmp, Qword, Rdx, field(LAST));
    asm.cmov(Cond::B, Qword, Rdx, field(LAST));
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

    /// A count read adds the state's offset to the scaled TSC (zero here,
    /// as `per_tsc` is), stays at or below its ceiling, never reads below
    /// `last` and keeps what it read there, and subtracts the cell's value;
    /// XZR still moves `last`.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn count_thunks_read_a_monotonic_bounded_count_less_the_cell_value() {
        use crate::GuestState;
        use core::sync::atomic::Ordering::Relaxed;
        let mut cell = alloc::boxed::Box::new(Cell::default());
        let published = alloc::boxed::Box::new(CountState::default());
        published.offset.store(100, Relaxed);
        published.ceiling.store(u64::MAX, Relaxed);
        let mut count = alloc::boxed::Box::new(Count {
            last: 50,
            state: &*published as *const CountState as u64,
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
        let last = || {
            // SAFETY: the Count box is live and every thunk run has returned.
            unsafe { (*count_at).last }
        };
        assert_eq!(run(&read.code, &mut state), NEXT);
        assert_eq!((state.x[3], last()), (70, 100));
        published.offset.store(80, Relaxed);
        assert_eq!(run(&read.code, &mut state), NEXT);
        assert_eq!((state.x[3], last()), (70, 100));
        published.offset.store(500, Relaxed);
        published.ceiling.store(300, Relaxed);
        assert_eq!(run(&read.code, &mut state), NEXT);
        assert_eq!((state.x[3], last()), (270, 300));
        published.ceiling.store(u64::MAX, Relaxed);
        let before = state.x;
        let discard = count_thunk(PC, 31, cell_at as u64, count_at as u64);
        assert_eq!(run(&discard.code, &mut state), NEXT);
        assert_eq!((state.x, last()), (before, 500));
    }
}
