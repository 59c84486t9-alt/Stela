//! FP/AdvSIMD access checks (CPACR) for the low 128 bits of the vector registers.

use super::{
    identification::Register,
    identification_snapshot::{Snapshot, Unsupported},
    scalable_controls::{AccessTrap, Error as ControlError, fp::FpControlOwner},
    state::{PSTATE_IL_MASK, PSTATE_SS_MASK, SystemState},
};
use stela_compiler::{GuestAddress, GuestState};

const SVE_SHIFT: u32 = 32;
const SME_SHIFT: u32 = 24;
const ID_FIELD_MASK: u64 = 0xf;
const SVE_ABSENT: u8 = 0;
const SVE_PRESENT: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    DifferentIdentificationSnapshot,
    DifferentGuestState,
    DifferentSystemState,
    Identification(Unsupported),
    Control(ControlError),
    IllegalExecutionState,
    SingleStepUnavailable,
    SveRequiresScalableWriter,
    ReservedSveField(u8),
    SmeStateRequired,
    ReservedSmeField(u8),
    /// Refused at the source PC before any prefix ran; not an architectural
    /// exception.
    PreflightTrap(AccessTrap),
}

/// SME absence derived from exact PFR1 bits in this immutable Snapshot. This
/// witness needs no ScalableState allocation, dummy vector length or SMCR value.
/// It proves only absence; the CPACR owner separately checks the EL0/EL1 regime.
pub struct NoSme<'id> {
    ids: &'id Snapshot,
}

impl<'id> NoSme<'id> {
    pub fn from_snapshot(ids: &'id Snapshot) -> Result<Self, Error> {
        let sme = ((ids
            .read(Register::IdAa64Pfr1El1)
            .map_err(Error::Identification)?
            >> SME_SHIFT)
            & ID_FIELD_MASK) as u8;
        match sme {
            0 => Ok(Self { ids }),
            1 | 2 => Err(Error::SmeStateRequired),
            other => Err(Error::ReservedSmeField(other)),
        }
    }
}

/// Non-Clone, non-Copy and externally unconstructible. The immutable borrows keep
/// CPACR, EL/PSTATE and SM from changing while the same GuestState is accessed.
/// No independent permission boolean or writable copy of either bank is kept.
pub struct Low128FpContext<'loan, 'id> {
    _controls: &'loan FpControlOwner<'id>,
    _system: &'loan SystemState,
    _streaming: NoSme<'loan>,
    guest_identity: *const GuestState,
}

impl Low128FpContext<'_, '_> {
    /// Check that `system` is the very object this borrow holds.
    pub fn check_system(&self, system: &SystemState) -> Result<(), Error> {
        if core::ptr::eq(self._system, system) {
            Ok(())
        } else {
            Err(Error::DifferentSystemState)
        }
    }

    /// Check that `guest` is the very state this borrow was taken for; the
    /// pointer is compared, never read.
    pub fn check_guest(&self, guest: &GuestState) -> Result<(), Error> {
        if core::ptr::eq(self.guest_identity, guest) {
            Ok(())
        } else {
            Err(Error::DifferentGuestState)
        }
    }
}

/// Holds the context alongside the mutable guest state. Authorization and the
/// memory call happen inside the split callback, so the memory token can share
/// the context while the bank is mutable.
pub struct Low128FpAccess<'loan, 'id> {
    context: Low128FpContext<'loan, 'id>,
    registers: &'loan mut GuestState,
}

impl<'loan, 'id> Low128FpAccess<'loan, 'id> {
    /// Read the same bound state for memory preparation before mutable entry.
    /// Its lifetime is confined to this capability borrow.
    pub fn guest(&self) -> &GuestState {
        self.registers
    }

    /// The memory owner borrows this context during admission and keeps it
    /// through the native call with the same guest state.
    pub fn with_guest<R>(
        &mut self,
        operation: impl FnOnce(&Low128FpContext<'loan, 'id>, &mut GuestState) -> R,
    ) -> R {
        operation(&self.context, self.registers)
    }
}

/// Admit AdvSIMD/FP access to the low 128 bits for one synchronous operation;
/// the higher-ranked callback prevents leaking the borrow. CPUs with SVE are
/// refused, because their V writes also need a non-streaming upper-Z clear that
/// ScalableState does not provide.
pub fn with_nonstreaming_low128<'id, R>(
    ids: &Snapshot,
    controls: &FpControlOwner<'id>,
    system: &SystemState,
    streaming: NoSme<'_>,
    registers: &mut GuestState,
    pc: GuestAddress,
    operation: impl for<'loan> FnOnce(Low128FpAccess<'loan, 'id>) -> R,
) -> Result<R, Error> {
    if !ids.same_snapshot(controls.identification_snapshot()) {
        return Err(Error::DifferentIdentificationSnapshot);
    }
    if system.pstate_misc() & PSTATE_IL_MASK != 0 {
        return Err(Error::IllegalExecutionState);
    }
    if system.pstate_misc() & PSTATE_SS_MASK != 0 {
        return Err(Error::SingleStepUnavailable);
    }
    // Source-independent admission conditions precede the helper decision.
    // Their failure never purports to be a reached architectural exception.
    let sve = ((ids
        .read(Register::IdAa64Pfr0El1)
        .map_err(Error::Identification)?
        >> SVE_SHIFT)
        & ID_FIELD_MASK) as u8;
    match sve {
        SVE_ABSENT => {}
        SVE_PRESENT => return Err(Error::SveRequiresScalableWriter),
        other => return Err(Error::ReservedSveField(other)),
    }
    if !ids.same_snapshot(streaming.ids) {
        return Err(Error::DifferentIdentificationSnapshot);
    }
    controls.check_fp_enabled(system, pc).map_err(|error| {
        if let ControlError::Trap(trap) = error {
            Error::PreflightTrap(trap)
        } else {
            Error::Control(error)
        }
    })?;
    Ok(operation(Low128FpAccess {
        context: Low128FpContext {
            _controls: controls,
            _system: system,
            _streaming: streaming,
            guest_identity: registers,
        },
        registers,
    }))
}
