//! Scoped ordinary FP/AdvSIMD access to the existing GuestState low128 bank.
//!
//! The actual process owner must supply its same Snapshot, CPACR owner, system,
//! scalable and guest state. This leaf cannot authenticate those caller choices.
//! It proves the bounded FP access facts while retaining their borrows. Memory,
//! fetched-source identity, reached traps, PE health and PC settlement remain
//! separate requirements, including ordinary little-endian memory policy.

use super::{
    identification::Register,
    identification_snapshot::{Snapshot, Unsupported},
    scalable_controls::{AccessTrap, Error as ControlError, fp::FpControlOwner},
    state::{PSTATE_IL_MASK, PSTATE_SS_MASK, SystemState},
};
use crate::scalable::ScalableState;
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
    StreamingStateRequiresScalableWriter,
    SveRequiresScalableWriter,
    ReservedSveField(u8),
    SmeStateRequired,
    ReservedSmeField(u8),
    /// Admission decline at the original source PC. No prefix has run here;
    /// this must not be delivered as an already reached architectural exception.
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

/// Select real state when SME exists, or a same-Snapshot absence witness when
/// it does not. This enum contains no caller-selected permission boolean.
pub enum StreamingState<'loan> {
    Actual(&'loan ScalableState),
    Absent(NoSme<'loan>),
}

/// Non-Clone, non-Copy and externally unconstructible. The immutable borrows keep
/// CPACR, EL/PSTATE and SM from changing while the same GuestState is accessed.
/// No independent permission boolean or writable copy of either bank is kept.
pub struct Low128FpContext<'loan, 'id> {
    _controls: &'loan FpControlOwner<'id>,
    _system: &'loan SystemState,
    _streaming: StreamingState<'loan>,
    guest_identity: *const GuestState,
}

impl Low128FpContext<'_, '_> {
    /// Check the actual SystemState retained by this live scoped loan. This
    /// compares object identity, not copied controls or value equality, and
    /// independently grants no PE, source, memory or retirement authority.
    pub fn check_system(&self, system: &SystemState) -> Result<(), Error> {
        if std::ptr::eq(self._system, system) {
            Ok(())
        } else {
            Err(Error::DifferentSystemState)
        }
    }

    /// Check only the identity of the state supplied to memory preparation or
    /// native entry against this live scoped loan. The pointer is never read or
    /// dereferenced and proves no PE/source/memory authority independently of
    /// this context's retained owners. The actual entry token must retain this
    /// context and check the same bound bank through the native call.
    pub fn check_guest(&self, guest: &GuestState) -> Result<(), Error> {
        if std::ptr::eq(self.guest_identity, guest) {
            Ok(())
        } else {
            Err(Error::DifferentGuestState)
        }
    }
}

/// Retains the context alongside the actual mutable GuestState. Authorization
/// and memory preparation/invocation occur inside its split callback, allowing
/// the memory token to retain a shared context while the guest bank is mutable.
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

    /// The memory requirement owner borrows this typed context during admission
    /// and retains it through native invocation using the same actual guest.
    /// Any native invocation still requires its real source and memory loans;
    /// this method alone supplies neither authority.
    pub fn with_guest<R>(
        &mut self,
        operation: impl FnOnce(&Low128FpContext<'loan, 'id>, &mut GuestState) -> R,
    ) -> R {
        operation(&self.context, self.registers)
    }
}

/// Qualify this bounded ordinary FP/AdvSIMD bank for one synchronous operation.
/// The higher-ranked callback prevents returning a capability or GuestState loan.
/// SVE-present CPUs explicitly decline: their low128 writes also require a real
/// nonstreaming scalable upper-Z setter, absent from the current ScalableState.
pub fn with_nonstreaming_low128<'id, R>(
    ids: &Snapshot,
    controls: &FpControlOwner<'id>,
    system: &SystemState,
    streaming: StreamingState<'_>,
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
    match &streaming {
        StreamingState::Actual(scalable) if scalable.mode().streaming() => {
            return Err(Error::StreamingStateRequiresScalableWriter);
        }
        StreamingState::Absent(absent) if !ids.same_snapshot(absent.ids) => {
            return Err(Error::DifferentIdentificationSnapshot);
        }
        _ => {}
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
