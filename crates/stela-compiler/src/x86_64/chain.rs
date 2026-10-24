//! Block chaining for the system-mode engine: a block's direct exit to a
//! static successor can be redirected through a thunk straight into the
//! successor's code, so the dispatcher runs once for a chain of blocks.
//!
//! The engine owns one [`ChainControl`] at a fixed host address. Before it
//! enters a block it sets `budget` to the chained transfers it allows,
//! `retired` to 0 and `block` to the entered block's index. Each thunk takes
//! one transfer from `budget` (or, when none is left, exits exactly as the
//! redirected exit would), adds the instructions of the block it leaves to
//! `retired` and names the block it enters in `block`. After the native
//! call returns, `block` is the block whose exit or fault ended the run, in
//! its low 32 bits, and the BTYPE it was entered with in bits 33:32: 0 from
//! every thunk but a lookup thunk of a BR or BLR form.
//! Thunks clobber only RAX, RCX, RDX and flags, which every direct exit
//! already may.
//!
//! A [`lookup_thunk`] serves an exit whose successor is not in the block's
//! page, or not static (a return): it finds the target in the engine's
//! [`LookupEntry`] table, which the engine fills from its own dispatches
//! and tags with the context they were valid in (`ChainControl::contexts`,
//! everything that decides which block a fetch runs: the translation and
//! code generations, the exception level and the block variant), one per
//! half of the address space ([`half`]): a TTBR0 write changes only the
//! lower half's translations, so the upper half's entries outlive it. A hit
//! transfers like a thunk; a miss, another context or no budget exits
//! exactly as the redirected exit would. It also clobbers R8, which no exit
//! keeps live. The thunk of an exit that sets a nonzero BTYPE (BR or BLR)
//! also requires the entry to accept that BTYPE (`LookupEntry::targets`),
//! as a Branch Target check of the entered block's first instruction would.
use crate::{GuestAddress, block::ExitKind};
use alloc::vec::Vec;

/// Bytes in a direct exit: `movabs rax, target; mov edx, kind; ret`.
pub const DIRECT_EXIT_BYTES: usize = 16;
/// Bytes a redirection writes over the start of a direct exit.
pub const JUMP_BYTES: usize = 5;
/// Bytes in a [`thunk`].
pub const THUNK_BYTES: usize = 37 + DIRECT_EXIT_BYTES;
/// Bytes in an exit to a dynamic target in RAX: `mov edx, kind; ret`.
pub const DYNAMIC_EXIT_BYTES: usize = 6;
/// Entries in the engine's lookup table, a power of two.
pub const LOOKUP_ENTRIES: usize = 4096;
/// Bytes in a [`lookup_thunk`], without and with its static target.
pub const LOOKUP_THUNK_BYTES: usize = 91;
pub const STATIC_LOOKUP_THUNK_BYTES: usize = LOOKUP_THUNK_BYTES + 10;

/// A direct exit to a static successor in a block's code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectExit {
    /// Its offset in the block's code.
    pub offset: usize,
    pub target: GuestAddress,
    pub kind: ExitKind,
}

/// The engine's chaining state, which thunks address absolutely.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChainControl {
    /// Chained transfers still allowed; wraps below zero when a thunk
    /// finds none left.
    pub budget: u64,
    /// Instructions of the blocks chained out of.
    pub retired: u64,
    /// The index of the block running, and above it the BTYPE it was
    /// entered with.
    pub block: u64,
    /// The contexts the engine runs in now, for the lower and the upper
    /// half ([`half`]); lookup entries of another miss. The engine never
    /// names a context 0.
    pub contexts: [u64; 2],
    /// The host address of the [`LookupEntry`] table.
    pub table: u64,
    /// Transfers lookup thunks made.
    pub hits: u64,
}

/// One block a fetch at `pc` runs in `context`, or nothing in context 0.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LookupEntry {
    pub pc: u64,
    pub context: u64,
    /// The block's code.
    pub entry: u64,
    /// The block's index.
    pub block: u32,
    /// The BTYPEs a branch to it may set, bit `b` for BTYPE `b`: every one
    /// outside a guarded page, else those its first instruction is
    /// compatible with.
    pub targets: u32,
}

/// The bits of `ChainControl::block` above the block's index that hold the
/// BTYPE it was entered with.
pub const BLOCK_BTYPE_SHIFT: u32 = 32;

/// The half of the address space `pc` is in, by VA bit 55: 0 for TTBR0's,
/// 1 for TTBR1's.
pub const fn half(pc: u64) -> usize {
    (pc >> 55 & 1) as usize
}

/// The table slot of `pc`.
pub const fn lookup_slot(pc: u64) -> usize {
    (pc as usize >> 2) & (LOOKUP_ENTRIES - 1)
}

// `sub qword [rcx],1` addresses the budget at offset 0.
const _: () = assert!(core::mem::offset_of!(ChainControl, budget) == 0);
const RETIRED: u8 = core::mem::offset_of!(ChainControl, retired) as u8;
const BLOCK: u8 = core::mem::offset_of!(ChainControl, block) as u8;
const CONTEXTS: u8 = core::mem::offset_of!(ChainControl, contexts) as u8;
const TABLE: u8 = core::mem::offset_of!(ChainControl, table) as u8;
const HITS: u8 = core::mem::offset_of!(ChainControl, hits) as u8;
const _: () = assert!(core::mem::size_of::<LookupEntry>() == 32);
const _: () = assert!(core::mem::offset_of!(LookupEntry, pc) == 0);
const ENTRY_CONTEXT: u8 = core::mem::offset_of!(LookupEntry, context) as u8;
const ENTRY_CODE: u8 = core::mem::offset_of!(LookupEntry, entry) as u8;
const ENTRY_BLOCK: u8 = core::mem::offset_of!(LookupEntry, block) as u8;
const ENTRY_TARGETS: u8 = core::mem::offset_of!(LookupEntry, targets) as u8;

/// A direct exit to `target` with `kind`, as every block emits it.
pub fn direct_exit(target: GuestAddress, kind: ExitKind) -> [u8; DIRECT_EXIT_BYTES] {
    let mut code = [0; DIRECT_EXIT_BYTES];
    code[..2].copy_from_slice(&[0x48, 0xb8]); // movabs rax,target
    code[2..10].copy_from_slice(&target.0.to_le_bytes());
    code[10] = 0xba; // mov edx,kind: zero-extends to the ABI's u64
    code[11..15].copy_from_slice(&(kind as u32).to_le_bytes());
    code[15] = 0xc3; // ret
    code
}

/// A thunk at host address `at` that chains a block of `retired`
/// instructions into block `block`, whose code is at `entry`, or takes the
/// direct exit to `target` with `kind` when `control` allows no transfer.
/// `None` when `entry` is out of a 32-bit jump's reach or an operand
/// exceeds its 32-bit field.
pub fn thunk(
    at: u64,
    control: u64,
    retired: u32,
    block: u32,
    entry: u64,
    target: GuestAddress,
    kind: ExitKind,
) -> Option<Vec<u8>> {
    let retired = i32::try_from(retired).ok()?;
    let block = i32::try_from(block).ok()?;
    let mut code = Vec::with_capacity(64);
    code.extend([0x48, 0xb9]); // movabs rcx,control
    code.extend(control.to_le_bytes());
    code.extend([0x48, 0x83, 0x29, 0x01]); // sub qword [rcx],1
    code.extend([0x72, 0]); // jb exit
    let skip = code.len();
    code.extend([0x48, 0x81, 0x41, RETIRED]); // add qword [rcx+retired],imm32
    code.extend(retired.to_le_bytes());
    code.extend([0x48, 0xc7, 0x41, BLOCK]); // mov qword [rcx+block],imm32
    code.extend(block.to_le_bytes());
    code.extend(jump(at + code.len() as u64, entry)?);
    code[skip - 1] = (code.len() - skip) as u8;
    code.extend(direct_exit(target, kind));
    debug_assert_eq!(code.len(), THUNK_BYTES);
    Some(code)
}

/// A lookup thunk for an exit of `kind` from a block of `retired`
/// instructions, to `target` or, for `None`, to the target in RAX, by a
/// branch that sets `btype`. `None` when `retired` exceeds its 32-bit field
/// or `btype` is not a BTYPE.
pub fn lookup_thunk(
    control: u64,
    retired: u32,
    target: Option<GuestAddress>,
    kind: ExitKind,
    btype: u8,
) -> Option<Vec<u8>> {
    let retired = i32::try_from(retired).ok()?;
    if btype > 3 {
        return None;
    }
    let mut code = Vec::with_capacity(STATIC_LOOKUP_THUNK_BYTES);
    if let Some(target) = target {
        code.extend([0x48, 0xb8]); // movabs rax,target
        code.extend(target.0.to_le_bytes());
    }
    code.extend([0x48, 0xb9]); // movabs rcx,control
    code.extend(control.to_le_bytes());
    code.extend([0x89, 0xc2]); // mov edx,eax
    code.extend([0xc1, 0xea, 0x02]); // shr edx,2
    code.extend([0x81, 0xe2]); // and edx,LOOKUP_ENTRIES-1
    code.extend((LOOKUP_ENTRIES as u32 - 1).to_le_bytes());
    code.extend([0xc1, 0xe2, 0x05]); // shl edx,5
    code.extend([0x48, 0x03, 0x51, TABLE]); // add rdx,[rcx+table]
    let mut misses = Vec::new();
    code.extend([0x48, 0x3b, 0x02]); // cmp rax,[rdx]
    code.extend([0x75, 0]); // jne miss
    misses.push(code.len());
    code.extend([0x49, 0x89, 0xc0]); // mov r8,rax
    code.extend([0x49, 0xc1, 0xe8, 55]); // shr r8,55
    code.extend([0x41, 0x83, 0xe0, 0x01]); // and r8d,1: the target's half
    code.extend([0x4e, 0x8b, 0x44, 0xc1, CONTEXTS]); // mov r8,[rcx+r8*8+contexts]
    code.extend([0x4c, 0x3b, 0x42, ENTRY_CONTEXT]); // cmp r8,[rdx+context]
    code.extend([0x75, 0]); // jne miss
    misses.push(code.len());
    if btype != 0 {
        code.extend([0xf6, 0x42, ENTRY_TARGETS, 1 << btype]); // test byte [rdx+targets],1<<btype
        code.extend([0x74, 0]); // jz miss
        misses.push(code.len());
    }
    code.extend([0x48, 0x83, 0x29, 0x01]); // sub qword [rcx],1
    code.extend([0x72, 0]); // jb miss
    misses.push(code.len());
    code.extend([0x48, 0x81, 0x41, RETIRED]); // add qword [rcx+retired],imm32
    code.extend(retired.to_le_bytes());
    code.extend([0x48, 0x83, 0x41, HITS, 0x01]); // add qword [rcx+hits],1
    code.extend([0x44, 0x8b, 0x42, ENTRY_BLOCK]); // mov r8d,[rdx+block]
    for bit in 0..2 {
        if btype & 1 << bit != 0 {
            // bts r8,BLOCK_BTYPE_SHIFT+bit
            code.extend([0x49, 0x0f, 0xba, 0xe8, BLOCK_BTYPE_SHIFT as u8 + bit]);
        }
    }
    code.extend([0x4c, 0x89, 0x41, BLOCK]); // mov [rcx+block],r8
    code.extend([0xff, 0x62, ENTRY_CODE]); // jmp qword [rdx+entry]
    for site in misses {
        code[site - 1] = (code.len() - site) as u8;
    }
    code.push(0xba); // miss: mov edx,kind
    code.extend((kind as u32).to_le_bytes());
    code.push(0xc3); // ret
    debug_assert!(
        btype != 0
            || code.len()
                == if target.is_some() {
                    STATIC_LOOKUP_THUNK_BYTES
                } else {
                    LOOKUP_THUNK_BYTES
                }
    );
    Some(code)
}

/// The exit to a dynamic target in RAX that blocks end with.
pub fn dynamic_exit(kind: ExitKind) -> [u8; DYNAMIC_EXIT_BYTES] {
    let mut code = [0xba, 0, 0, 0, 0, 0xc3]; // mov edx,kind; ret
    code[1..5].copy_from_slice(&(kind as u32).to_le_bytes());
    code
}

/// `jmp rel32` at host address `at` to `to`, or `None` out of reach.
pub fn jump(at: u64, to: u64) -> Option<[u8; JUMP_BYTES]> {
    let relative = i32::try_from(to.wrapping_sub(at + JUMP_BYTES as u64) as i64).ok()?;
    let mut code = [0xe9, 0, 0, 0, 0];
    code[1..].copy_from_slice(&relative.to_le_bytes());
    Some(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn direct_exits_match_the_block_emitter() {
        let mut emitted = Vec::new();
        super::super::block::direct_exit(&mut emitted, GuestAddress(0x1234), ExitKind::Direct);
        assert_eq!(emitted, direct_exit(GuestAddress(0x1234), ExitKind::Direct));
    }

    #[test]
    fn thunks_count_name_and_jump_or_exit() {
        let code = thunk(
            0x1000,
            0x8877_6655_4433_2211,
            7,
            3,
            0x2000,
            GuestAddress(0xabc),
            ExitKind::Fallthrough,
        )
        .unwrap();
        let mut expected = vec![0x48, 0xb9, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        expected.extend([0x48, 0x83, 0x29, 0x01, 0x72, 21]);
        expected.extend([0x48, 0x81, 0x41, 0x08, 7, 0, 0, 0]);
        expected.extend([0x48, 0xc7, 0x41, 0x10, 3, 0, 0, 0]);
        // The jump ends 0x25 bytes into the thunk.
        expected.extend([0xe9]);
        expected.extend((0x2000i32 - 0x1025).to_le_bytes());
        expected.extend(direct_exit(GuestAddress(0xabc), ExitKind::Fallthrough));
        assert_eq!(code, expected);
        assert!(thunk(0, 0, 0, 0, 1 << 40, GuestAddress(0), ExitKind::Direct).is_none());
    }

    #[test]
    fn jumps_reach_32_bits_either_way() {
        assert_eq!(jump(0x1000, 0x1005), Some([0xe9, 0, 0, 0, 0]));
        assert_eq!(jump(0x1000, 0x1000), Some([0xe9, 0xfb, 0xff, 0xff, 0xff]));
        assert_eq!(jump(0, 1 << 32), None);
    }

    #[test]
    fn dynamic_exits_match_the_block_emitter() {
        let mut emitted = Vec::new();
        super::super::block::exit_kind(&mut emitted, ExitKind::Return);
        assert_eq!(emitted, dynamic_exit(ExitKind::Return));
        assert_eq!(lookup_slot(0x4004), 1);
        assert_eq!(lookup_slot(0x4000 + 4 * LOOKUP_ENTRIES as u64), 0);
    }

    /// Lookup thunks run on the host: a hit in the current context with
    /// budget left counts and enters the entry's block; a miss, another
    /// context or no budget exits with the target and kind.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn lookup_thunks_enter_current_entries_and_exit_otherwise() {
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
        const BLOCK_AT: usize = 1024;
        const TARGET: u64 = 0xffff_fe00_0123_4568;
        let mut table = vec![LookupEntry::default(); LOOKUP_ENTRIES];
        let mut control = ChainControl {
            table: table.as_ptr() as u64,
            contexts: [5, 7],
            ..ChainControl::default()
        };
        let control_at = &mut control as *mut ChainControl as u64;
        // A target block that returns a marker; the dynamic thunk takes its
        // target from the second argument; the static one names TARGET.
        let block = [
            0xb8, 0x51, 0x51, 0, 0, // mov eax,0x5151
            0xba, 99, 0, 0, 0, // mov edx,99
            0xc3,
        ];
        let dynamic = lookup_thunk(control_at, 9, None, ExitKind::Return, 0).unwrap();
        let fixed =
            lookup_thunk(control_at, 3, Some(GuestAddress(TARGET)), ExitKind::Call, 0).unwrap();
        let branch = lookup_thunk(control_at, 5, None, ExitKind::Indirect, 3).unwrap();
        assert_eq!(dynamic.len(), LOOKUP_THUNK_BYTES);
        assert_eq!(branch.len(), LOOKUP_THUNK_BYTES + 6 + 10);
        assert!(lookup_thunk(control_at, 5, None, ExitKind::Indirect, 4).is_none());
        assert_eq!(fixed.len(), STATIC_LOOKUP_THUNK_BYTES);
        assert_eq!(fixed[fixed.len() - 6..], dynamic_exit(ExitKind::Call));
        // SAFETY: private anonymous memory, RX after the copies, unmapped
        // at the end; the thunks touch only `control` and `table`.
        unsafe {
            let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
            assert_ne!(page as usize, usize::MAX);
            let base = page as *mut u8;
            let mut code = vec![0x48, 0x89, 0xf0]; // mov rax,rsi
            code.extend(&dynamic);
            let fixed_at = code.len();
            code.extend(&fixed);
            let branch_at = code.len();
            code.extend([0x48, 0x89, 0xf0]); // mov rax,rsi
            code.extend(&branch);
            core::ptr::copy_nonoverlapping(code.as_ptr(), base, code.len());
            core::ptr::copy_nonoverlapping(block.as_ptr(), base.add(BLOCK_AT), block.len());
            assert_eq!(mprotect(page, PAGE, 5), 0);
            type Thunk = unsafe extern "sysv64" fn(u64, u64) -> u128;
            let dynamic: Thunk = core::mem::transmute(page);
            let fixed: Thunk = core::mem::transmute(base.add(fixed_at));
            let branch: Thunk = core::mem::transmute(base.add(branch_at));
            let exit = |result: u128| (result as u64, (result >> 64) as u64);
            let entry = LookupEntry {
                pc: TARGET,
                context: 7,
                entry: base.add(BLOCK_AT) as u64,
                block: 42,
                targets: 0b0111,
            };
            table[lookup_slot(TARGET)] = entry;
            control.budget = 2;
            assert_eq!(exit(dynamic(0, TARGET)), (0x5151, 99));
            assert_eq!(
                (control.budget, control.retired, control.hits, control.block),
                (1, 9, 1, 42)
            );
            assert_eq!(exit(fixed(0, 0)), (0x5151, 99));
            assert_eq!((control.budget, control.retired, control.hits), (0, 12, 2));
            // No budget left: the budget wraps and the exit is taken.
            assert_eq!(exit(dynamic(0, TARGET)), (TARGET, ExitKind::Return as u64));
            assert_eq!((control.budget, control.retired), (u64::MAX, 12));
            control.budget = 5;
            // Another PC in the slot, and another context, miss.
            let other = TARGET + 4 * LOOKUP_ENTRIES as u64;
            assert_eq!(exit(dynamic(0, other)), (other, ExitKind::Return as u64));
            table[lookup_slot(TARGET)].context = 6;
            assert_eq!(exit(dynamic(0, TARGET)), (TARGET, ExitKind::Return as u64));
            assert_eq!(exit(fixed(0, 0)), (TARGET, ExitKind::Call as u64));
            assert_eq!((control.budget, control.hits, control.block), (5, 2, 42));
            // The lower half's context names a lower-half target's entries.
            let lower = TARGET & !(1 << 55);
            table[lookup_slot(lower)] = LookupEntry { pc: lower, ..entry };
            assert_eq!(exit(dynamic(0, lower)), (lower, ExitKind::Return as u64));
            table[lookup_slot(lower)].context = 5;
            assert_eq!(exit(dynamic(0, lower)), (0x5151, 99));
            assert_eq!((control.budget, control.hits), (4, 3));
            table[lookup_slot(TARGET)] = entry;
            // A BR with BTYPE 0b11 needs the entry to accept it, and names
            // the BTYPE beside the block.
            table[lookup_slot(TARGET)].context = 7;
            assert_eq!(exit(branch(0, TARGET)), (TARGET, ExitKind::Indirect as u64));
            table[lookup_slot(TARGET)].targets = 0b1001;
            assert_eq!(exit(branch(0, TARGET)), (0x5151, 99));
            assert_eq!(
                (control.budget, control.retired, control.hits, control.block),
                (3, 26, 4, 3 << BLOCK_BTYPE_SHIFT | 42)
            );
            assert_eq!(munmap(page, PAGE), 0);
        }
    }
}
