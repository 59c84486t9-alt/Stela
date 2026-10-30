//! System register reads that native code completes from mirror cells.

use super::*;

/// The System registers whose MRS native code completes from a mirror
/// cell (`x86_64::register_read`): reads without side effects whose result
/// and plainness follow from System registers and PSTATE alone, so a read
/// the engine found plain stays plain, with the same value, until derived
/// state may change ([`Machine::derived_changed`]). They are the thread
/// pointers, Apple's GL2 thread pointer and GXF status, the GL1 exception
/// registers a guarded level saves on entry ([`GUARDED_MIRRORS`]),
/// SPRR_PERM_EL0 ([`SPRR_PERM_MIRROR`]) and DAIF; and the virtual count and
/// Apple's alias of it, whose cells hold the offset they subtract from the
/// clock's count ([`COUNT_MIRRORS`]).
pub(super) const MIRRORED: [Encoding; 13] = {
    use registers::encodings::{
        ASPSR_GL1, CNTVCT_ALIAS_EL0, DAIF, ELR_GL1, GXF_STATUS_EL1, SPRR_PERM_EL0, SPSR_GL1,
        TPIDR_EL0, TPIDR_EL1, TPIDR_EL2, TPIDR_GL2, TPIDRRO_EL0,
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

/// The cells of the [`MIRRORED`] registers, in its order: native code reads
/// `cells`, the running PE's at its EL and GXF state. A read's value and
/// plainness follow from System registers and PSTATE, of which an exception
/// entry or return, GENTER or GEXIT changes the EL, the GXF state and the
/// masks alone: `banks` keeps the cells each EL and GXF state left, which
/// it finds again ([`Mirrors::transition`]). Anything else that changes
/// derived state closes every cell of every bank.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Mirrors {
    pub(super) cells: [register_read::Cell; MIRRORED.len()],
    pub(super) banks: [[register_read::Cell; MIRRORED.len()]; MIRROR_STATES],
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
/// guarded level reads when it is entered: GENTER and an exception taken to
/// the level write them, so a transition reads them again into their open
/// cells ([`Machine::transitioned`]), and a write of a GL bank register,
/// through any name, closes them ([`guarded_bank`]). They open only in a
/// guarded level, where they are plain.
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

/// Whether `encoding` names a register of a GL bank: GL1's (`S3_6_C15_C10_*`)
/// or GL1's from EL2 (`S3_6_C15_C9_*`).
pub(super) fn guarded_bank(encoding: Encoding) -> bool {
    (encoding.op0(), encoding.op1(), encoding.crn()) == (3, 6, 15)
        && matches!(encoding.crm(), 9 | 10)
}

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

/// The [`MIRRORED`] index of a read of `access`, other than to XZR.
pub(super) fn mirrored(access: RegisterAccess) -> Option<usize> {
    if access.direction() != Direction::Read || access.rt() == ZERO_REGISTER {
        return None;
    }
    MIRRORED
        .iter()
        .position(|&encoding| encoding == access.encoding())
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
/// `system` complete natively: DC ZVA or one of its DC clean operations.
pub(super) fn completes_natively(pc: u64, word: u32, system: NativeSystem) -> bool {
    block::decode_system_mode_instruction(GuestAddress(pc), word)
        .ok()
        .flatten()
        .is_some_and(|instruction| {
            system.zero_block.is_some() && zero_block::operand(&instruction).is_some()
                || cache_clean::operand(&instruction)
                    .is_some_and(|(operation, _)| system.cache_clean.contains(operation))
        })
}
