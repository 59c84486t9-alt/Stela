//! Block chaining for the system-mode engine: a block's direct exit to a
//! static successor can be redirected through a thunk straight into the
//! successor's code, so the dispatcher runs once for a chain of blocks.
//!
//! The engine owns one [`ChainControl`] at a fixed host address. Before it
//! enters a block it sets `budget` to the chained transfers it allows,
//! `retired`, `linked` and `hits` to 0 and `block` to the entered block's
//! index. Each thunk takes one transfer from `budget` (or, when none is
//! left, exits exactly as the redirected exit would), counts it, adds the
//! instructions of the block it leaves to `retired` and names the block it
//! enters in `block`. Notifications publish a monotonic interrupt epoch;
//! every thunk compares it with the owner's acknowledged pre-drain snapshot
//! before spending the local budget. A mismatch takes the original exit. After the native
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
//! lower half's translations, so the upper half's entries outlive it. The
//! context also moves an entry's slot ([`lookup_salt`]), as the processes of
//! a system run one shared library's code at the same addresses in contexts
//! of their own, and would otherwise take each other's entries at every
//! switch. A slot's set holds two entries in one cache line ([`LookupTable`]),
//! as two hot PCs of one set would otherwise take each other's entry at every
//! call. A hit transfers like a thunk; a miss, another context or no budget
//! exits exactly as the redirected exit would. It also clobbers R8, which no exit
//! keeps live. The thunk of an exit that sets a nonzero BTYPE (BR or BLR)
//! also requires the entry to accept that BTYPE (`LookupEntry::targets`),
//! as a Branch Target check of the entered block's first instruction would.
use crate::x86_64::asm::{
    Alu, BitTest, Code, Cond,
    Gpr::{R8, Rax, Rcx, Rdx},
    Mem, ShiftOp,
    Size::{self, Dword, Qword},
};
use crate::{GuestAddress, block::ExitKind};
use alloc::{boxed::Box, vec, vec::Vec};

/// Bytes in a direct exit: `movabs rax, target; mov edx, kind; ret`.
pub const DIRECT_EXIT_BYTES: usize = 16;
/// Bytes a redirection writes over the start of a direct exit.
pub const JUMP_BYTES: usize = 5;
/// Bytes in a [`thunk`].
pub const THUNK_BYTES: usize = 42 + DIRECT_EXIT_BYTES + 10;
/// Bytes in an exit to a dynamic target in RAX: `mov edx, kind; ret`.
pub const DYNAMIC_EXIT_BYTES: usize = 6;
/// Bits of a PC that select a [`LookupEntry`].
const LOOKUP_BITS: u32 = 18;
/// The slots of one PC, one a context takes by the low bits of its number.
pub const LOOKUP_SALT_BITS: u32 = 6;
pub const LOOKUP_SALTS: usize = 1 << LOOKUP_SALT_BITS;
/// Entries in the engine's lookup table, a power of two.
pub const LOOKUP_ENTRIES: usize = 1 << LOOKUP_BITS;
/// Bytes in a [`lookup_thunk`], without and with its static target.
pub const LOOKUP_THUNK_BYTES: usize = 116 + 10;
pub const STATIC_LOOKUP_THUNK_BYTES: usize = LOOKUP_THUNK_BYTES + 10;

/// A direct exit to a static successor in a block's code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectExit {
    /// Its offset in the block's code.
    pub offset: usize,
    pub target: GuestAddress,
    pub kind: ExitKind,
    /// The block's instructions it leaves unrun ([`ExitWord`]).
    pub skipped: u16,
}

impl DirectExit {
    pub fn word(&self) -> ExitWord {
        ExitWord {
            kind: self.kind,
            skipped: self.skipped,
        }
    }
}

/// What a block's exit returns in RDX: its [`ExitKind`] and, for the side
/// exit of a branch the block runs past, how many of the block's instructions
/// that exit left unrun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitWord {
    pub kind: ExitKind,
    pub skipped: u16,
}

impl ExitWord {
    const KIND_BITS: u32 = 8;

    pub const fn encoded(self) -> u32 {
        self.kind as u32 | (self.skipped as u32) << Self::KIND_BITS
    }

    /// The kind and the skipped instructions of a word from RDX.
    pub const fn split(word: u64) -> (u64, u16) {
        (
            word & ((1 << Self::KIND_BITS) - 1),
            (word >> Self::KIND_BITS) as u16,
        )
    }
}

impl From<ExitKind> for ExitWord {
    fn from(kind: ExitKind) -> Self {
        Self { kind, skipped: 0 }
    }
}

/// The engine's chaining state, which thunks address absolutely.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChainControl {
    /// Chained transfers still allowed; only the attached engine/native path
    /// writes it. Wraps below zero when a thunk finds none left.
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
    /// Transfers the other thunks made.
    pub linked: u64,
    /// Sources are published before a Release increment by a notifier.
    /// Saturates at MAX; no owner may acknowledge that exhausted epoch.
    pub interrupt_epoch: u64,
    /// The attached owner's Acquire snapshot taken before draining sources.
    /// A notification after that snapshot remains pending for the next boundary.
    pub observed_interrupt_epoch: u64,
    /// [`lookup_salt`] of each of the `contexts`.
    pub salts: [u32; 2],
}

// Epoch and observed state are naturally aligned atomic-width words. Capture
// and storage owners keep the mapped control alive for every embedded address.
const _: () = assert!(core::mem::offset_of!(ChainControl, interrupt_epoch) == 64);
const _: () = assert!(core::mem::offset_of!(ChainControl, observed_interrupt_epoch) == 72);
const _: () = assert!(core::mem::size_of::<ChainControl>() == 88);

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

/// The entries of one set, a cache line, which a thunk probes from the
/// target's slot to the slot beside it.
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, Default)]
struct LookupSet([LookupEntry; 2]);

const _: () = assert!(core::mem::size_of::<LookupEntry>() == 32);
const _: () = assert!(core::mem::size_of::<LookupSet>() == 64);

/// The other entry of `slot`'s set.
const fn neighbour(slot: usize) -> usize {
    slot ^ 1
}

/// The [`LookupEntry`] table, by [`lookup_slot`].
pub struct LookupTable(Box<[LookupSet]>);

impl LookupTable {
    pub fn new() -> Self {
        let sets = vec![LookupSet::default(); LOOKUP_ENTRIES / 2];
        Self(sets.into_boxed_slice())
    }

    /// The table's host address, for `ChainControl::table`.
    pub fn address(&self) -> u64 {
        self.0.as_ptr() as u64
    }

    pub fn clear(&mut self) {
        self.0.fill(LookupSet::default());
    }

    /// Whether every entry is empty.
    pub fn is_empty(&self) -> bool {
        self.0
            .iter()
            .flat_map(|set| &set.0)
            .all(|entry| *entry == LookupEntry::default())
    }

    /// The entry of `pc` in `context`'s set for `slot`: one in `context` if
    /// there is one, as a thunk would find it, else one in another context.
    pub fn find(&self, slot: usize, pc: u64, context: u64) -> LookupEntry {
        let (first, second) = (self[slot], self[neighbour(slot)]);
        if second.pc == pc && (first.pc != pc || first.context != context) {
            second
        } else {
            first
        }
    }

    /// Put `entry` in the slot its PC and context pick, and what held it
    /// beside it unless that is the entry's own older self.
    pub fn insert(&mut self, slot: usize, entry: LookupEntry) {
        let resident = self[slot];
        if resident.context != 0 && (resident.pc != entry.pc || resident.context != entry.context) {
            self[neighbour(slot)] = resident;
        }
        self[slot] = entry;
    }

    /// Forget what `slot`'s set holds of the PCs in `pcs`.
    pub fn forget(&mut self, slot: usize, pcs: core::ops::RangeInclusive<u64>) {
        for slot in [slot, neighbour(slot)] {
            if pcs.contains(&self[slot].pc) {
                self[slot] = LookupEntry::default();
            }
        }
    }
}

impl Default for LookupTable {
    fn default() -> Self {
        Self::new()
    }
}

impl core::ops::Index<usize> for LookupTable {
    type Output = LookupEntry;

    fn index(&self, slot: usize) -> &LookupEntry {
        &self.0[slot / 2].0[slot % 2]
    }
}

impl core::ops::IndexMut<usize> for LookupTable {
    fn index_mut(&mut self, slot: usize) -> &mut LookupEntry {
        &mut self.0[slot / 2].0[slot % 2]
    }
}

/// The bits of `ChainControl::block` above the block's index that hold the
/// BTYPE it was entered with.
pub const BLOCK_BTYPE_SHIFT: u32 = 32;

/// The half of the address space `pc` is in, by VA bit 55: 0 for TTBR0's,
/// 1 for TTBR1's.
pub const fn half(pc: u64) -> usize {
    (pc >> 55 & 1) as usize
}

/// What `context` flips of the slots of the PCs it looks up.
pub const fn lookup_salt(context: u64) -> u32 {
    (context as u32 & ((1 << LOOKUP_SALT_BITS) - 1)) << (LOOKUP_BITS - LOOKUP_SALT_BITS)
}

/// The table slot of `pc` in `context`: its low bits with the next ones
/// folded in, as code a multiple of the table's span apart is common and
/// would share every slot, and the context's salt.
pub const fn lookup_slot(pc: u64, context: u64) -> usize {
    let pc = pc as u32;
    (pc >> 2 ^ pc >> (2 + LOOKUP_BITS) ^ lookup_salt(context)) as usize & (LOOKUP_ENTRIES - 1)
}

// `sub qword [rcx],1` addresses the budget at offset 0.
const _: () = assert!(core::mem::offset_of!(ChainControl, budget) == 0);
const RETIRED: i32 = core::mem::offset_of!(ChainControl, retired) as i32;
const BLOCK: i32 = core::mem::offset_of!(ChainControl, block) as i32;
const CONTEXTS: i32 = core::mem::offset_of!(ChainControl, contexts) as i32;
const SALTS: i32 = core::mem::offset_of!(ChainControl, salts) as i32;
const TABLE: i32 = core::mem::offset_of!(ChainControl, table) as i32;
const HITS: i32 = core::mem::offset_of!(ChainControl, hits) as i32;
const LINKED: i32 = core::mem::offset_of!(ChainControl, linked) as i32;
const INTERRUPT_EPOCH: i32 = core::mem::offset_of!(ChainControl, interrupt_epoch) as i32;
const OBSERVED_INTERRUPT_EPOCH: i32 =
    core::mem::offset_of!(ChainControl, observed_interrupt_epoch) as i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Interruption {
    Epoch,
    #[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
    LockedBudget,
    #[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
    Flag,
    #[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
    Legacy,
}
impl Interruption {
    fn extra_bytes(self) -> usize {
        match self {
            Self::Epoch => 10,
            #[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
            Self::LockedBudget => 1,
            #[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
            Self::Flag => 7,
            #[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
            Self::Legacy => 0,
        }
    }
}
fn interruption_gate(
    asm: &mut crate::x86_64::asm::Asm,
    policy: Interruption,
) -> Option<crate::x86_64::asm::Patch> {
    match policy {
        Interruption::Epoch => {
            // Aligned MOV is an acquire load on x86. The owner never rewrites
            // this word; a notifier only advances it after publishing sources.
            asm.mov_load(Qword, Rdx, Mem::base(Rcx, INTERRUPT_EPOCH));
            asm.alu_load(
                Alu::Cmp,
                Qword,
                Rdx,
                Mem::base(Rcx, OBSERVED_INTERRUPT_EPOCH),
            );
            Some(asm.jcc8(Cond::Ne))
        }
        #[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
        Interruption::Flag => {
            asm.alu_imm8(Alu::Cmp, Qword, Mem::base(Rcx, INTERRUPT_EPOCH), 0);
            Some(asm.jcc8(Cond::Ne))
        }
        #[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
        Interruption::LockedBudget | Interruption::Legacy => None,
    }
}
fn spend_budget(asm: &mut crate::x86_64::asm::Asm, policy: Interruption) {
    #[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
    if policy == Interruption::LockedBudget {
        asm.lock();
    }
    let _ = policy;
    // This local counter has no foreign writer in the epoch protocol.
    asm.alu_imm8(Alu::Sub, Qword, Mem::base(Rcx, 0), 1);
}
struct ThunkPlan {
    at: u64,
    control: u64,
    retired: u32,
    block: u32,
    entry: u64,
    target: GuestAddress,
    kind: ExitWord,
}

const _: () = assert!(core::mem::size_of::<LookupEntry>() == 32);
const _: () = assert!(core::mem::offset_of!(LookupEntry, pc) == 0);
const ENTRY_CONTEXT: i32 = core::mem::offset_of!(LookupEntry, context) as i32;
const ENTRY_CODE: i32 = core::mem::offset_of!(LookupEntry, entry) as i32;
const ENTRY_BLOCK: i32 = core::mem::offset_of!(LookupEntry, block) as i32;
const ENTRY_TARGETS: i32 = core::mem::offset_of!(LookupEntry, targets) as i32;

/// A direct exit to `target` with `kind`, as every block emits it.
pub fn direct_exit(target: GuestAddress, kind: impl Into<ExitWord>) -> [u8; DIRECT_EXIT_BYTES] {
    let mut code = Code::new();
    super::block::direct_exit_with(&mut code.asm(), target, kind);
    code.try_into().expect("a direct exit's length")
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
    kind: impl Into<ExitWord>,
) -> Option<Vec<u8>> {
    thunk_with_policy(
        ThunkPlan {
            at,
            control,
            retired,
            block,
            entry,
            target,
            kind: kind.into(),
        },
        Interruption::Epoch,
    )
}
fn thunk_with_policy(plan: ThunkPlan, policy: Interruption) -> Option<Vec<u8>> {
    let ThunkPlan {
        at,
        control,
        retired,
        block,
        entry,
        target,
        kind,
    } = plan;
    let retired = i32::try_from(retired).ok()?;
    let block = i32::try_from(block).ok()?;
    let mut code = Code::new();
    let mut asm = code.asm();
    asm.mov_imm64(Rcx, control);
    let interrupted = interruption_gate(&mut asm, policy);
    spend_budget(&mut asm, policy);
    let exhausted = asm.jcc8(Cond::B);
    asm.alu_imm32(Alu::Add, Qword, Mem::base(Rcx, RETIRED), retired);
    asm.alu_imm8(Alu::Add, Qword, Mem::base(Rcx, LINKED), 1);
    asm.mov_rm_imm32(Qword, Mem::base(Rcx, BLOCK), block);
    let transfer = asm.jmp();
    let relative = relative(at + transfer.end() as u64, entry)?;
    asm.bind(exhausted);
    if let Some(interrupted) = interrupted {
        asm.bind(interrupted);
    }
    super::block::direct_exit_with(&mut asm, target, kind);
    code.patch(transfer.offset(), relative.to_le_bytes());
    debug_assert_eq!(code.len(), THUNK_BYTES - 10 + policy.extra_bytes());
    Some(code.into_bytes())
}

/// A lookup thunk for an exit of `kind` from a block of `retired`
/// instructions, to `target` or, for `None`, to the target in RAX, by a
/// branch that sets `btype`. `None` when `retired` exceeds its 32-bit field
/// or `btype` is not a BTYPE.
pub fn lookup_thunk(
    control: u64,
    retired: u32,
    target: Option<GuestAddress>,
    kind: impl Into<ExitWord>,
    btype: u8,
) -> Option<Vec<u8>> {
    lookup_with_policy(control, retired, target, kind, btype, Interruption::Epoch)
}
fn lookup_with_policy(
    control: u64,
    retired: u32,
    target: Option<GuestAddress>,
    kind: impl Into<ExitWord>,
    btype: u8,
    policy: Interruption,
) -> Option<Vec<u8>> {
    let retired = i32::try_from(retired).ok()?;
    if btype > 3 {
        return None;
    }
    let mut code = Code::new();
    let mut asm = code.asm();
    if let Some(target) = target {
        asm.mov_imm64(Rax, target.0);
    }
    asm.mov_imm64(Rcx, control);
    let mut misses = Vec::new();
    if let Some(interrupted) = interruption_gate(&mut asm, policy) {
        misses.push(interrupted);
    }
    // R8 = the target's half; RDX = its entry in the table.
    asm.mov(Qword, R8, Rax);
    asm.shift_imm(ShiftOp::Shr, Qword, R8, 55);
    asm.alu_imm8(Alu::And, Dword, R8, 1);
    asm.mov(Dword, Rdx, Rax);
    asm.shift_imm(ShiftOp::Shr, Dword, Rdx, LOOKUP_BITS as u8);
    asm.alu(Alu::Xor, Dword, Rdx, Rax);
    asm.shift_imm(ShiftOp::Shr, Dword, Rdx, 2);
    asm.alu_load(Alu::Xor, Dword, Rdx, Mem::indexed(Rcx, R8, 4, SALTS));
    asm.alu_imm32(Alu::And, Dword, Rdx, LOOKUP_ENTRIES as i32 - 1);
    asm.shift_imm(ShiftOp::Shl, Dword, Rdx, 5);
    asm.alu_load(Alu::Add, Qword, Rdx, Mem::base(Rcx, TABLE));
    asm.mov_load(Qword, R8, Mem::indexed(Rcx, R8, 8, CONTEXTS));
    asm.alu_load(Alu::Cmp, Qword, Rax, Mem::base(Rdx, 0));
    let other_pc = asm.jcc8(Cond::Ne);
    asm.alu_load(Alu::Cmp, Qword, R8, Mem::base(Rdx, ENTRY_CONTEXT));
    let found = asm.jcc8(Cond::E);
    asm.bind(other_pc);
    asm.alu_imm8(
        Alu::Xor,
        Qword,
        Rdx,
        core::mem::size_of::<LookupEntry>() as i8,
    );
    asm.alu_load(Alu::Cmp, Qword, Rax, Mem::base(Rdx, 0));
    misses.push(asm.jcc8(Cond::Ne));
    asm.alu_load(Alu::Cmp, Qword, R8, Mem::base(Rdx, ENTRY_CONTEXT));
    misses.push(asm.jcc8(Cond::Ne));
    asm.bind(found);
    if btype != 0 {
        asm.test_imm(Size::Byte, Mem::base(Rdx, ENTRY_TARGETS), 1 << btype);
        misses.push(asm.jcc8(Cond::E));
    }
    spend_budget(&mut asm, policy);
    misses.push(asm.jcc8(Cond::B));
    asm.alu_imm32(Alu::Add, Qword, Mem::base(Rcx, RETIRED), retired);
    asm.alu_imm8(Alu::Add, Qword, Mem::base(Rcx, HITS), 1);
    asm.mov_load(Dword, R8, Mem::base(Rdx, ENTRY_BLOCK));
    for bit in 0..2 {
        if btype & 1 << bit != 0 {
            asm.bit_imm(BitTest::Bts, Qword, R8, BLOCK_BTYPE_SHIFT as u8 + bit);
        }
    }
    asm.mov_store(Qword, Mem::base(Rcx, BLOCK), R8);
    asm.jmp_rm(Mem::base(Rdx, ENTRY_CODE));
    for miss in misses {
        asm.bind(miss);
    }
    super::block::exit_kind_with(&mut asm, kind);
    let code = code.into_bytes();
    debug_assert!(
        btype != 0
            || code.len()
                == if target.is_some() {
                    STATIC_LOOKUP_THUNK_BYTES - 10 + policy.extra_bytes()
                } else {
                    LOOKUP_THUNK_BYTES - 10 + policy.extra_bytes()
                }
    );
    Some(code)
}

/// The exit to a dynamic target in RAX that blocks end with.
pub fn dynamic_exit(kind: ExitKind) -> [u8; DYNAMIC_EXIT_BYTES] {
    let mut code = Code::new();
    super::block::exit_kind_with(&mut code.asm(), kind);
    code.try_into().expect("a dynamic exit's length")
}

/// `jmp rel32` at host address `at` to `to`, or `None` out of reach.
pub fn jump(at: u64, to: u64) -> Option<[u8; JUMP_BYTES]> {
    let relative = relative(at + JUMP_BYTES as u64, to)?;
    let mut code = Code::new();
    let field = code.asm().jmp();
    code.patch(field.offset(), relative.to_le_bytes());
    code.try_into().ok()
}

/// The rel32 displacement of a branch ending at host address `end` to
/// `to`, or `None` out of reach.
fn relative(end: u64, to: u64) -> Option<i32> {
    i32::try_from(to.wrapping_sub(end) as i64).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_64::asm::Code;
    use alloc::vec;

    #[test]
    fn direct_exits_match_the_block_emitter() {
        let mut emitted = Code::new();
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
        expected.extend([0x48, 0x8b, 0x51, 0x40, 0x48, 0x3b, 0x51, 0x48, 0x75, 32]);
        expected.extend([0x48, 0x83, 0x29, 0x01, 0x72, 26]);
        expected.extend([0x48, 0x81, 0x41, 0x08, 7, 0, 0, 0]);
        expected.extend([0x48, 0x83, 0x41, 0x38, 0x01]);
        expected.extend([0x48, 0xc7, 0x41, 0x10, 3, 0, 0, 0]);
        // The jump ends 0x34 bytes into the thunk.
        expected.extend([0xe9]);
        expected.extend((0x2000i32 - 0x1034).to_le_bytes());
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
        let mut emitted = Code::new();
        super::super::block::exit_kind(&mut emitted, ExitKind::Return);
        assert_eq!(emitted, dynamic_exit(ExitKind::Return));
        let span = 4 * LOOKUP_ENTRIES as u64;
        assert_eq!(lookup_slot(4, 0), 1);
        assert_eq!(lookup_slot(span, 0), 1);
        assert_ne!(lookup_slot(span + 4, 0), lookup_slot(4, 0));
        assert_ne!(lookup_slot(4, 1), lookup_slot(4, 0));
        assert_eq!(
            lookup_slot(4, 7),
            lookup_slot(4, 7 + LOOKUP_SALTS as u64),
            "only a context's low bits pick its slot"
        );
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
        let mut table = LookupTable::new();
        let mut control = ChainControl {
            table: table.address(),
            contexts: [5, 7],
            salts: [lookup_salt(5), lookup_salt(7)],
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
            table[lookup_slot(TARGET, 7)] = entry;
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
            let other = TARGET ^ (1 << (2 + LOOKUP_BITS) | 1 << 2);
            assert_eq!(lookup_slot(other, 7), lookup_slot(TARGET, 7));
            assert_eq!(exit(dynamic(0, other)), (other, ExitKind::Return as u64));
            // The set's other entry serves too.
            let (hits, retired) = (control.hits, control.retired);
            table.insert(lookup_slot(TARGET, 7), LookupEntry { pc: other, ..entry });
            assert_eq!(table[neighbour(lookup_slot(TARGET, 7))].pc, TARGET);
            assert_eq!(exit(dynamic(0, TARGET)), (0x5151, 99));
            assert_eq!(table.find(lookup_slot(TARGET, 7), TARGET, 7).pc, TARGET);
            assert_eq!(exit(dynamic(0, other)), (0x5151, 99));
            assert_eq!(control.hits, hits + 2);
            control.retired = retired;
            control.hits = hits;
            control.budget = 5;
            table[neighbour(lookup_slot(TARGET, 7))] = LookupEntry::default();
            table[lookup_slot(TARGET, 7)] = entry;
            table[lookup_slot(TARGET, 7)].context = 6;
            assert_eq!(exit(dynamic(0, TARGET)), (TARGET, ExitKind::Return as u64));
            assert_eq!(exit(fixed(0, 0)), (TARGET, ExitKind::Call as u64));
            assert_eq!((control.budget, control.hits, control.block), (5, 2, 42));
            // The lower half's context names a lower-half target's entries.
            let lower = TARGET & !(1 << 55);
            table[lookup_slot(lower, 5)] = LookupEntry { pc: lower, ..entry };
            assert_eq!(exit(dynamic(0, lower)), (lower, ExitKind::Return as u64));
            table[lookup_slot(lower, 5)].context = 5;
            assert_eq!(exit(dynamic(0, lower)), (0x5151, 99));
            assert_eq!((control.budget, control.hits), (4, 3));
            table[lookup_slot(TARGET, 7)] = entry;
            // A BR with BTYPE 0b11 needs the entry to accept it, and names
            // the BTYPE beside the block.
            table[lookup_slot(TARGET, 7)].context = 7;
            assert_eq!(exit(branch(0, TARGET)), (TARGET, ExitKind::Indirect as u64));
            table[lookup_slot(TARGET, 7)].targets = 0b1001;
            assert_eq!(exit(branch(0, TARGET)), (0x5151, 99));
            assert_eq!(
                (control.budget, control.retired, control.hits, control.block),
                (3, 26, 4, 3 << BLOCK_BTYPE_SHIFT | 42)
            );
            control.budget = 5;
            control.interrupt_epoch = 1;
            control.observed_interrupt_epoch = 0;
            let prior = (
                control.budget,
                control.retired,
                control.hits,
                control.linked,
                control.block,
            );
            assert_eq!(exit(dynamic(0, TARGET)), (TARGET, ExitKind::Return as u64));
            assert_eq!(exit(fixed(0, 0)), (TARGET, ExitKind::Call as u64));
            assert_eq!(exit(branch(0, TARGET)), (TARGET, ExitKind::Indirect as u64));
            assert_eq!(
                (
                    control.budget,
                    control.retired,
                    control.hits,
                    control.linked,
                    control.block
                ),
                prior
            );
            control.observed_interrupt_epoch = 1;
            assert_eq!(exit(dynamic(0, TARGET)), (0x5151, 99));
            assert_eq!(control.budget, 4);
            assert_eq!(munmap(page, PAGE), 0);
        }
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    mod budget;
}
