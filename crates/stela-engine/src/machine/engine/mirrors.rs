//! System register reads that native code completes from mirror cells.

use super::*;

/// The System registers whose MRS native code completes from a mirror
/// cell (`x86_64::register_read`): reads without side effects whose result
/// and plainness follow from System registers and PSTATE alone, so a read
/// the engine found plain stays plain, with the same value, until derived
/// state may change ([`Machine::derived_changed`]). They are the thread
/// pointers, Apple's GL2 thread pointer and GXF status, the GL1 exception
/// registers a guarded level saves and restores ([`GUARDED_MIRRORS`]),
/// SPRR_PERM_EL0 ([`SPRR_PERM_MIRROR`]) and DAIF; and the virtual count and
/// Apple's alias of it, whose cells hold the offset they subtract from the
/// clock's count ([`COUNT_MIRRORS`]); CurrentEL, which each state's cell
/// answers for good; and the cycle and instruction counters a kernel reads
/// around each exception to charge threads, which a transition brings up to
/// date ([`COUNTER_MIRRORS`]).
pub(super) const MIRRORED: [Encoding; 16] = {
    use registers::encodings::{
        ASPSR_GL1, CNTVCT_ALIAS_EL0, CURRENT_EL, DAIF, ELR_GL1, GXF_STATUS_EL1, SPRR_PERM_EL0,
        SPSR_GL1, TPIDR_EL0, TPIDR_EL1, TPIDR_EL2, TPIDR_GL2, TPIDRRO_EL0,
    };
    use stela_compiler::aarch64::system::registers::CNTVCT_EL0;
    [
        TPIDR_EL0,
        TPIDRRO_EL0,
        TPIDR_EL1,
        TPIDR_EL2,
        TPIDR_GL2,
        GXF_STATUS_EL1,
        SPSR_GL1,
        ASPSR_GL1,
        ELR_GL1,
        CURRENT_EL,
        super::super::pmu::PMC[0],
        super::super::pmu::PMC[1],
        SPRR_PERM_EL0,
        CNTVCT_EL0,
        CNTVCT_ALIAS_EL0,
        DAIF,
    ]
};

/// Rt 31 in MRS: XZR, which discards the value.
pub(super) const ZERO_REGISTER: u8 = 31;

/// MRS's L bit (21), which makes an MSR (register) word the MRS of the
/// same register and Xt.
pub(super) const MRS_READ: u32 = 1 << 21;

/// The registers read other than [`MIRRORED`] ones that get a cell of their
/// own the first time code naming them is installed
/// ([`Machine::stored_cell`]), which reads the register's live storage: the
/// ones a kernel reads around each exception and thread switch, and FPCR and
/// FPSR. When there are more, the rest take System exits.
pub(super) const STORED_CELLS: usize = 32;

/// The cells of the [`MIRRORED`] registers, in its order, and the
/// [`STORED_CELLS`]: native code reads `cells`, the running PE's at its EL
/// and GXF state. A read's value and plainness follow from System registers
/// and PSTATE, of which an exception entry or return, GENTER or GEXIT changes
/// these and the masks alone: `banks` keeps the cells each state left, which
/// it finds again ([`Mirrors::transition`]). Only SP_EL0 follows SPSel, whose
/// thunks read `selected`, PSTATE.SP while native code runs, which can change
/// it (`x86_64::register_read::stack_select_thunk`).
/// Anything else that changes derived state closes every cell of every bank.
/// The last of them says whether writes of the masks complete natively
/// ([`MASK_WRITES`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Mirrors {
    pub(super) cells: [register_read::Cell; CELLS],
    pub(super) banks: [[register_read::Cell; CELLS]; MIRROR_STATES],
    pub(super) selected: u64,
}

/// The cell of MSR SPSel, open once one completed plainly in the state:
/// its `value` is the address of the stack SPSel 1 selects there.
pub(super) const STACK_SELECT: usize = MASK_WRITES + 1 + WRITTEN.len();

const CELLS: usize = STACK_SELECT + 1;

/// The cell of the mask writes (`x86_64::register_read::mask_thunk`), open
/// once one completed plainly in the state.
pub(super) const MASK_WRITES: usize = MIRRORED.len() + STORED_CELLS;

/// The registers whose MSR native code completes, which a kernel writes
/// around each exception and whose writes change nothing else: a cell each,
/// after [`MASK_WRITES`], that a plain write opens on the storage it reached
/// (FPSR's lives in the frame, so names none). They stay open as reads do.
pub(super) const WRITTEN: [(Encoding, SystemRegister); 4] = [
    (Encoding::new(3, 0, 4, 0, 1), SystemRegister::ELR_EL1),
    (Encoding::new(3, 0, 4, 0, 0), SystemRegister::SPSR_EL1),
    (STACK_ZERO, SystemRegister::SP_EL0),
    (Encoding::new(3, 3, 4, 4, 1), SystemRegister::FPSR),
];

/// SP_EL0, plain only with SP_ELx selected.
pub(super) const STACK_ZERO: Encoding = Encoding::new(3, 0, 4, 1, 0);

impl Default for Mirrors {
    fn default() -> Self {
        let cell = register_read::Cell::default();
        Self {
            cells: [cell; CELLS],
            banks: [[cell; CELLS]; MIRROR_STATES],
            selected: 0,
        }
    }
}

/// The cell of `WRITTEN[index]`.
pub(super) const fn written_cell(index: usize) -> usize {
    MASK_WRITES + 1 + index
}

/// The ELs and GXF states, `Mirrors::banks` per [`mirror_state`].
pub(super) const MIRROR_STATES: usize = 8;

pub(super) fn mirror_state(el: u8, guarded: bool) -> usize {
    usize::from(el) | usize::from(guarded) << 2
}

impl Mirrors {
    /// Keep the cells of state `from` and take those of `to`.
    pub(super) fn transition(&mut self, from: usize, to: usize) {
        self.banks[from] = self.cells;
        self.cells = self.banks[to];
    }

    /// The register of cell `index` now holds `value`, as its open cells
    /// in every state read it.
    pub(super) fn update(&mut self, index: usize, value: u64) {
        for cells in core::iter::once(&mut self.cells).chain(&mut self.banks) {
            if cells[index].readable != 0 {
                cells[index].value = value;
            }
        }
    }

    /// Close the cells of one register in every state.
    pub(super) fn close(&mut self, index: usize) {
        for cells in core::iter::once(&mut self.cells).chain(&mut self.banks) {
            cells[index] = register_read::Cell::default();
        }
    }
}

/// System registers whose writes only store what nothing derived reads:
/// exception entries and returns read the exception registers then, a
/// thread pointer is read as it is, and only translation reads TTBR0,
/// whose change the host's regime follows ([`Machine::table_base_changed`]).
pub(super) fn stored(register: SystemRegister) -> bool {
    use SystemRegister::*;
    matches!(
        register,
        TTBR0_EL1
            | TTBR0_EL2
            | ELR_EL1
            | ELR_EL2
            | SPSR_EL1
            | SPSR_EL2
            | ESR_EL1
            | ESR_EL2
            | FAR_EL1
            | FAR_EL2
            | PAR_EL1
            | TPIDR_EL0
            | TPIDRRO_EL0
            | TPIDR_EL1
            | TPIDR_EL2
    )
}

/// System registers no read of a System register follows: not its value,
/// which only a read of the register itself takes, nor whether it traps. A
/// kernel writes them at each thread switch and timer. What derives from
/// them goes as ever ([`Machine::forget_derived`]).
pub(super) fn keeps_reads(register: SystemRegister) -> bool {
    use SystemRegister::*;
    matches!(
        register,
        CONTEXTIDR_EL1
            | CONTEXTIDR_EL2
            | APIAKeyLo_EL1
            | APIAKeyHi_EL1
            | APIBKeyLo_EL1
            | APIBKeyHi_EL1
            | APDAKeyLo_EL1
            | APDAKeyHi_EL1
            | APDBKeyLo_EL1
            | APDBKeyHi_EL1
            | APGAKeyLo_EL1
            | APGAKeyHi_EL1
            | CNTP_CTL_EL0
            | CNTP_CVAL_EL0
            | CNTV_CTL_EL0
            | CNTV_CVAL_EL0
            | CNTHP_CTL_EL2
            | CNTHP_CVAL_EL2
            | CNTHV_CTL_EL2
            | CNTHV_CVAL_EL2
    )
}

/// Whether a generated read that ends with `register`'s value is the plain
/// read of its storage, which a cell may point at: only state those reads
/// return as stored, never a view composed from it.
pub(super) fn reads_storage(register: SystemRegister) -> bool {
    use SystemRegister::*;
    stored(register)
        || matches!(
            register,
            SP_EL0
                | HCR_EL2
                | SCTLR_EL1
                | SCTLR_EL2
                | TCR_EL1
                | TCR_EL2
                | TTBR1_EL1
                | TTBR1_EL2
                | VBAR_EL1
                | VBAR_EL2
                | CONTEXTIDR_EL1
                | CONTEXTIDR_EL2
                | CPTR_EL2
                | CPACR_EL1
        )
}

/// Whether MRS of `encoding` can have a stored cell: not the ID space, whose
/// reads are few, nor the IMPLEMENTATION DEFINED one, which Apple's state
/// answers.
pub(super) fn storable(encoding: Encoding) -> bool {
    !(encoding.op0() == 3 && matches!(encoding.crn(), 0 | 11 | 15))
}

impl core::ops::Index<usize> for Mirrors {
    type Output = register_read::Cell;
    fn index(&self, index: usize) -> &Self::Output {
        &self.cells[index]
    }
}

impl core::ops::IndexMut<usize> for Mirrors {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.cells[index]
    }
}

/// The [`MIRRORED`] index of DAIF.
pub(super) const DAIF_MIRROR: usize = MIRRORED.len() - 1;
const _: () = assert!(matches!(MIRRORED[DAIF_MIRROR], registers::encodings::DAIF));
/// The [`MIRRORED`] indices of CNTVCT_EL0 and CNTVCT_ALIAS_EL0, count
/// reads completed natively whenever the host's counter is its TSC's
/// ([`Host::tsc_counter`]).
pub(super) const COUNT_MIRRORS: [usize; 2] = [DAIF_MIRROR - 2, DAIF_MIRROR - 1];
const _: () = assert!(matches!(
    MIRRORED[COUNT_MIRRORS[0]],
    stela_compiler::aarch64::system::registers::CNTVCT_EL0
));
const _: () = assert!(matches!(
    MIRRORED[COUNT_MIRRORS[1]],
    registers::encodings::CNTVCT_ALIAS_EL0
));

/// The [`MIRRORED`] indices of SPSR_GL1, ASPSR_GL1 and ELR_GL1, which a
/// guarded level reads when it is entered and writes before it leaves. Their
/// cells open only in a guarded level, where they are plain, on the bank's
/// storage: reads and writes both go there, as GENTER and an exception
/// taken to the level do ([`registers::guarded_storage`]).
pub(super) const GUARDED_MIRRORS: [usize; 3] = [6, 7, 8];
const _: () = assert!(matches!(
    [
        MIRRORED[GUARDED_MIRRORS[0]],
        MIRRORED[GUARDED_MIRRORS[1]],
        MIRRORED[GUARDED_MIRRORS[2]]
    ],
    [
        registers::encodings::SPSR_GL1,
        registers::encodings::ASPSR_GL1,
        registers::encodings::ELR_GL1
    ]
));

/// The [`MIRRORED`] indices of the cycle and instruction counters. They
/// move at every instruction but no read depends on it: between transitions
/// they read the count of the last one, as exceptions are what a kernel
/// charges to threads, and later reads never go back.
pub(super) const COUNTER_MIRRORS: [usize; 2] = [10, 11];
const _: () = assert!(COUNTER_MIRRORS[0] == 10);

/// MRS X0 of `encoding`.
pub(super) fn read_word(encoding: Encoding) -> u32 {
    0xd530_0000
        | u32::from(encoding.op0() & 1) << 19
        | u32::from(encoding.op1()) << 16
        | u32::from(encoding.crn()) << 12
        | u32::from(encoding.crm()) << 8
        | u32::from(encoding.op2()) << 5
}

/// The [`MIRRORED`] index of SPRR_PERM_EL0, which dyld and JIT runtimes
/// write around each write to their protected pages and read back at once.
/// An SPRR_PERM write keeps derived state ([`Machine::permissions_changed`])
/// but closes these cells; a write of SPRR_PERM_EL0 itself reopens the one
/// open before it ([`Machine::permission_write`]).
pub(super) const SPRR_PERM_MIRROR: usize = COUNT_MIRRORS[0] - 1;
const _: () = assert!(matches!(
    MIRRORED[SPRR_PERM_MIRROR],
    registers::encodings::SPRR_PERM_EL0
));

/// MRS DAIF's value for PSTATE's D, A, I and F masks: bits 9:6.
pub(super) fn daif_register(daif: u8) -> u64 {
    u64::from(daif) << DAIF_REGISTER_SHIFT
}

pub(super) const DAIF_REGISTER_SHIFT: u32 = 6;

/// The index in [`WRITTEN`] of a write of `access`.
pub(super) fn written(access: RegisterAccess) -> Option<usize> {
    if access.direction() != Direction::Write {
        return None;
    }
    let encoding = access.encoding();
    WRITTEN.iter().position(|&(written, _)| written == encoding)
}

/// The [`MIRRORED`] index of a read of `access`, other than to XZR.
pub(super) fn mirrored(access: RegisterAccess) -> Option<usize> {
    if access.direction() != Direction::Read || access.rt() == ZERO_REGISTER {
        return None;
    }
    MIRRORED
        .iter()
        .position(|&encoding| encoding == access.encoding())
}

/// The [`GUARDED_MIRRORS`] index of a write of `access`.
pub(super) fn guarded_written(access: RegisterAccess) -> Option<usize> {
    if access.direction() != Direction::Write {
        return None;
    }
    let encoding = access.encoding();
    GUARDED_MIRRORS
        .into_iter()
        .find(|&index| MIRRORED[index] == encoding)
}

/// The MSR `word` at `pc` of a [`GUARDED_MIRRORS`] register: its index and Xt.
pub(super) fn guarded_written_register(pc: u64, word: u32) -> Option<(usize, u8)> {
    let instruction = block::decode_system_mode_instruction(GuestAddress(pc), word).ok()??;
    match instruction.operation {
        SystemOperation::Register(access) => Some((guarded_written(access)?, access.rt())),
        _ => None,
    }
}

/// The MSR `word` at `pc` of a [`WRITTEN`] register: its index and Xt.
pub(super) fn written_register(pc: u64, word: u32) -> Option<(usize, u8)> {
    let instruction = block::decode_system_mode_instruction(GuestAddress(pc), word).ok()??;
    match instruction.operation {
        SystemOperation::Register(access) => Some((written(access)?, access.rt())),
        _ => None,
    }
}

/// The selection the MSR SPSel `word` writes, if it is one.
pub(super) fn stack_select(word: u32) -> Option<bool> {
    match word {
        0xd500_40bf => Some(false),
        0xd500_41bf => Some(true),
        _ => None,
    }
}

/// The MRS `word` at `pc`, if it reads to a register.
pub(super) fn mrs_access(pc: u64, word: u32) -> Option<RegisterAccess> {
    let instruction = block::decode_system_mode_instruction(GuestAddress(pc), word).ok()??;
    match instruction.operation {
        SystemOperation::Register(access)
            if access.direction() == Direction::Read && access.rt() != ZERO_REGISTER =>
        {
            Some(access)
        }
        _ => None,
    }
}

/// The [`MIRRORED`] index and Xt of `word` at `pc` if it is MRS of a
/// mirrored register to Xt, other than XZR.
pub(super) fn mirrored_read(pc: u64, word: u32) -> Option<(usize, u8)> {
    let instruction = block::decode_system_mode_instruction(GuestAddress(pc), word).ok()??;
    match instruction.operation {
        SystemOperation::Register(access) => Some((mirrored(access)?, access.rt())),
        _ => None,
    }
}

/// Whether `word` at `pc` is a System instruction blocks compiled for
/// `system` complete natively: DC ZVA, one of its DC clean operations or an
/// exclusive of one register.
pub(super) fn completes_natively(pc: u64, word: u32, system: NativeSystem) -> bool {
    block::decode_system_mode_instruction(GuestAddress(pc), word)
        .ok()
        .flatten()
        .is_some_and(|instruction| {
            system.zero_block.is_some() && zero_block::operand(&instruction).is_some()
                || cache_clean::operand(&instruction)
                    .is_some_and(|(operation, _)| system.cache_clean.contains(operation))
                || system.exclusive && native_exclusive::operand(&instruction).is_some()
        })
}
