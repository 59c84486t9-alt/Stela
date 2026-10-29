//! Optional SCTLR2 and TCR2 storage.

use super::{
    FixedProcessMemoryControls, MemoryStatus, ProcessMemoryError, Register, Snapshot,
    SourceNormalWbDomain,
};
#[cfg(feature = "std")]
use super::{MemoryControls, MemoryExecutionLoan, MemoryThread};
use crate::{
    pauth::features::{LinkRegisterPauthCapability, UnsupportedInstructionProfile},
    system::identification_snapshot::{Origin, Unsupported},
};
use alloc::sync::Arc;

const FIELD_MASK: u64 = 0xf;
const MMFR3_SCTLRX_SHIFT: u32 = 4;
const MMFR3_TCRX_SHIFT: u32 = 0;
const MMFR4_SRMASK_SHIFT: u32 = 44;
const PFR1_MTE_SHIFT: u32 = 8;
const EXTENSION_PRESENT: u8 = 1;
const FEATURE_ABSENT: u8 = 0;
pub(crate) const SCTLR2_ENPACM: u64 = 1 << 7;
pub(crate) const SCTLR2_ENPACM0: u64 = 1 << 8;
pub(crate) const SCTLR2_CPTA: u64 = 1 << 9;
pub(crate) const SCTLR2_CPTA0: u64 = 1 << 10;
pub(crate) const SCTLR2_CPTM: u64 = 1 << 11;
pub(crate) const SCTLR2_CPTM0: u64 = 1 << 12;
const SCTLR2_CPA_FIELDS: u64 = SCTLR2_CPTA | SCTLR2_CPTA0 | SCTLR2_CPTM | SCTLR2_CPTM0;
const SCTLR2_PACM_FIELDS: u64 = SCTLR2_ENPACM | SCTLR2_ENPACM0;
const SCTLR2_REVIEWED: u64 = SCTLR2_PACM_FIELDS | SCTLR2_CPA_FIELDS;
const ISAR3_CPA_SHIFT: u32 = 0;
const CPA_WITH_CHECKING: u8 = 2;

/// Stored once inside FixedProcessMemoryControls; no SCTLR/TCR copies.
/// The constructor rejects nonzero TCR2 and all unimplemented SCTLR2 bits.
/// Future EnFPM or mutation belongs to this same owner.
#[derive(Debug)]
#[cfg_attr(
    not(feature = "std"),
    expect(
        dead_code,
        reason = "only the host checked-memory borrow reads the control bank"
    )
)]
pub(super) struct ExtendedControlBank {
    sctlr2_el1: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Process(ProcessMemoryError),
    Identification(Unsupported),
    PauthProfile(UnsupportedInstructionProfile),
    CapturedSourceRequiresActualTransfer,
    MissingIdentification,
    DifferentSnapshot,
    ExtendedControlsUnavailable,
    MissingAddressSpace,
    SourceDomain(MemoryStatus),
    UnsupportedControl { register: &'static str, value: u64 },
}

fn field(snapshot: &Snapshot, register: Register, shift: u32) -> Result<u8, Error> {
    Ok(((snapshot.read(register).map_err(Error::Identification)? >> shift) & FIELD_MASK) as u8)
}

fn require(
    snapshot: &Snapshot,
    register: Register,
    name: &'static str,
    shift: u32,
    expected: u8,
) -> Result<(), Error> {
    let value = field(snapshot, register, shift)?;
    if value != expected {
        return Err(Error::Identification(Unsupported::Field {
            register,
            field: name,
            value,
        }));
    }
    Ok(())
}

impl FixedProcessMemoryControls {
    /// Build a new software control bank from explicit source facts; not for
    /// upgrading an existing bank. No reset value is guessed.
    pub fn new_source_resolved_with_extended_controls(
        identification: Arc<Snapshot>,
        sctlr_el1: u64,
        tcr_el1: u64,
        lower_address_bits: u8,
        source: SourceNormalWbDomain,
        sctlr2_el1: u64,
        tcr2_el1: u64,
    ) -> Result<Self, Error> {
        if identification.provenance().origin() != Origin::DeclaredGuest {
            return Err(Error::CapturedSourceRequiresActualTransfer);
        }
        require(
            &identification,
            Register::IdAa64Mmfr3El1,
            "SCTLRX",
            MMFR3_SCTLRX_SHIFT,
            EXTENSION_PRESENT,
        )?;
        require(
            &identification,
            Register::IdAa64Mmfr3El1,
            "TCRX",
            MMFR3_TCRX_SHIFT,
            EXTENSION_PRESENT,
        )?;
        require(
            &identification,
            Register::IdAa64Mmfr4El1,
            "SRMASK",
            MMFR4_SRMASK_SHIFT,
            FEATURE_ABSENT,
        )?;
        if sctlr2_el1 & !SCTLR2_REVIEWED != 0 {
            return Err(Error::UnsupportedControl {
                register: "SCTLR2_EL1",
                value: sctlr2_el1,
            });
        }
        // Nonzero feature-dependent fields cannot be stored when FEAT_PAuth_LR
        // is absent, reserved or unsupported.
        if sctlr2_el1 & SCTLR2_PACM_FIELDS != 0 {
            LinkRegisterPauthCapability::from_profile(&identification)
                .map_err(Error::PauthProfile)?;
        }
        if sctlr2_el1 & SCTLR2_CPA_FIELDS != 0 {
            require(
                &identification,
                Register::IdAa64Isar3El1,
                "CPA",
                ISAR3_CPA_SHIFT,
                CPA_WITH_CHECKING,
            )?;
        }
        if tcr2_el1 != 0 {
            return Err(Error::UnsupportedControl {
                register: "TCR2_EL1",
                value: tcr2_el1,
            });
        }
        if !source.is_current().map_err(Error::SourceDomain)? {
            return Err(Error::SourceDomain(MemoryStatus::Domain));
        }
        require(
            &identification,
            Register::IdAa64Pfr1El1,
            "MTE",
            PFR1_MTE_SHIFT,
            FEATURE_ABSENT,
        )?;
        let mut bank = Self::new_with_pointer_identification(
            identification,
            sctlr_el1,
            tcr_el1,
            lower_address_bits,
            source,
        )
        .map_err(Error::Process)?;
        // This new value has not escaped yet; there is no setter on an existing
        // bank.
        bank.extended = Some(ExtendedControlBank { sctlr2_el1 });
        Ok(bank)
    }

    /// Validate the thread with a short borrow, then keep only the bank,
    /// snapshot and outer references; the consumer keeps the mutable thread and
    /// PE through its memory and native stages. The borrow validates the
    /// current source and outer domain; it does not extend MTE support or prove
    /// PE identity.
    #[cfg(feature = "std")]
    pub(crate) fn extended_controls<'run>(
        &'run self,
        expected_snapshot: &Snapshot,
        thread: &MemoryThread<MemoryControls>,
        execution: &'run MemoryExecutionLoan,
    ) -> Result<ExtendedControlLoan<'run>, Error> {
        let snapshot = self
            .identification_snapshot()
            .ok_or(Error::MissingIdentification)?;
        if !snapshot.same_snapshot(expected_snapshot) {
            return Err(Error::DifferentSnapshot);
        }
        let extended = self
            .extended
            .as_ref()
            .ok_or(Error::ExtendedControlsUnavailable)?;
        self.source
            .check_current_execution(thread, execution)
            .map_err(Error::SourceDomain)?;
        let address_space = thread.address_space().ok_or(Error::MissingAddressSpace)?;
        Ok(ExtendedControlLoan {
            _bank: self,
            extended,
            snapshot,
            _execution: execution,
            address_space,
        })
    }
}

/// While borrowed, the bank cannot be renewed or changed and the outer pin
/// cannot be released.
#[cfg(feature = "std")]
pub(crate) struct ExtendedControlLoan<'run> {
    _bank: &'run FixedProcessMemoryControls,
    extended: &'run ExtendedControlBank,
    snapshot: &'run Snapshot,
    _execution: &'run MemoryExecutionLoan,
    address_space: u64,
}

#[cfg(feature = "std")]
impl<'run> ExtendedControlLoan<'run> {
    pub(crate) fn snapshot(&self) -> &'run Snapshot {
        self.snapshot
    }
    pub(crate) fn address_space(&self) -> u64 {
        self.address_space
    }
    pub(crate) fn sctlr2_el1(&self) -> u64 {
        self.extended.sctlr2_el1
    }
}

#[cfg(test)]
mod tests;
