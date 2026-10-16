//! The fixed controls of a software EL1 machine. Control writes are not
//! supported.

use super::access::{ExceptionLevel, Profile, SecurityState};
use super::exception::{EntryControls, RequiredEffects, ServiceRequest};
use super::execution::EntrySnapshot;
use super::profile::{BaseSpeAbsence, EntryProfile, EntryProfileError};
use super::pstate::{DAIF_MASK, NZCV_MASK};
use super::state::{PSTATE_EL1H, PSTATE_EL1T, PSTATE_MODE_MASK, SystemState};
use stela_compiler::GuestState;

const SCTLR_MMU_ENABLE: u64 = 1;
const SOURCE_PSTATE_MASK: u64 = NZCV_MASK | DAIF_MASK | PSTATE_MODE_MASK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedControlsError {
    MmuEnabled,
    EntryControls(EntryProfileError),
    DebugState,
    UnsupportedMode(u64),
    UnsupportedPstate(u64),
    MteState,
    ProfileMismatch,
    SourceLevelMismatch,
    ControlsMismatch,
    InterruptEntry,
    UnsupportedReturnMode(u64),
    UnsupportedDestination(ExceptionLevel),
}

/// Sole owner of these actual controls in the declared software machine.
/// Deliberately neither Clone nor Copy; replacing it requires ending run borrows.
#[derive(Debug)]
pub struct FixedEl1Controls {
    features: EntryProfile,
    _base_spe: BaseSpeAbsence,
    sctlr_el1: u64,
    entry: EntryControls,
}

impl FixedEl1Controls {
    pub fn new(
        features: EntryProfile,
        base_spe: BaseSpeAbsence,
        sctlr_el1: u64,
        entry: EntryControls,
    ) -> Result<Self, FixedControlsError> {
        if sctlr_el1 & SCTLR_MMU_ENABLE != 0 {
            return Err(FixedControlsError::MmuEnabled);
        }
        features
            .check_controls(entry.tcr_el1, entry.mdscr_el1)
            .map_err(FixedControlsError::EntryControls)?;
        if entry.debug.halted || entry.debug.halting_allowed {
            return Err(FixedControlsError::DebugState);
        }
        Ok(Self {
            features,
            _base_spe: base_spe,
            sctlr_el1,
            entry,
        })
    }

    pub const fn entry_profile(&self) -> EntryProfile {
        self.features
    }

    pub const fn sctlr_el1(&self) -> u64 {
        self.sctlr_el1
    }

    pub const fn entry_controls(&self) -> EntryControls {
        self.entry
    }

    /// Ephemeral values read from this owner and the actual state. This does not
    /// freeze another bank or cache PSTATE, stack selection or saved registers.
    pub fn entry_snapshot(
        &self,
        system: &SystemState,
        registers: &GuestState,
    ) -> Result<EntrySnapshot, FixedControlsError> {
        check_source_pstate(system.pstate(registers))?;
        if system.mte().is_some() {
            return Err(FixedControlsError::MteState);
        }
        Ok(EntrySnapshot {
            profile: own_el1_profile(),
            features: self.features,
            controls: self.entry,
        })
    }

    /// CodePublicationScope separately checks the exact runtime, source site and
    /// typed operation. The existing exception plan checks actual source state.
    pub fn check_exception_request(
        &self,
        request: &ServiceRequest,
    ) -> Result<(), FixedControlsError> {
        if request.profile != own_el1_profile() {
            return Err(FixedControlsError::ProfileMismatch);
        }
        if request.source_el != ExceptionLevel::El1 {
            return Err(FixedControlsError::SourceLevelMismatch);
        }
        if request.controls != self.entry {
            return Err(FixedControlsError::ControlsMismatch);
        }
        check_source_pstate(request.source_pstate)?;
        if matches!(request.effects, RequiredEffects::Entry { irq: true }) {
            return Err(FixedControlsError::InterruptEntry);
        }
        Ok(())
    }

    /// Restrict destination mode before return mutation. The exception owner
    /// retains saved-bit masking, debug-off SS handling and legal IL restoration;
    /// the next native entry independently rejects illegal execution state.
    pub fn validate_return(&self, system: &SystemState) -> Result<(), FixedControlsError> {
        if system.current_el() != ExceptionLevel::El1 {
            return Err(FixedControlsError::SourceLevelMismatch);
        }
        let mode = system.el1_registers().spsr() & PSTATE_MODE_MASK;
        match mode {
            PSTATE_EL1T | PSTATE_EL1H => Ok(()),
            mode => Err(FixedControlsError::UnsupportedReturnMode(mode)),
        }
    }

    /// TBI is checked off in the actual owner, so BranchAddr preserves all target
    /// bits. Alignment, instruction lookup and fetch faults are subsequent work.
    pub fn branch_address(
        &self,
        target: u64,
        destination_el: ExceptionLevel,
    ) -> Result<u64, FixedControlsError> {
        if destination_el != ExceptionLevel::El1 {
            return Err(FixedControlsError::UnsupportedDestination(destination_el));
        }
        Ok(target)
    }
}

fn own_el1_profile() -> Profile {
    Profile {
        current_el: ExceptionLevel::El1,
        security: SecurityState::NonSecure,
        el2_enabled: false,
        el3_present: false,
    }
}

fn check_source_pstate(pstate: u64) -> Result<(), FixedControlsError> {
    match pstate & PSTATE_MODE_MASK {
        PSTATE_EL1T | PSTATE_EL1H => {}
        mode => return Err(FixedControlsError::UnsupportedMode(mode)),
    }
    let unsupported = pstate & !SOURCE_PSTATE_MASK;
    if unsupported != 0 {
        return Err(FixedControlsError::UnsupportedPstate(unsupported));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
