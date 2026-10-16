//! Resource-specific System effects under the sole canonical retiring consumer.
//! Preparation retains original resource/source loans without a PE/state borrow
//! that could obstruct start_retirement. Only the parent constructs this commit.

use crate::{
    memory::domain::MemoryExecutionLoan,
    system::{
        execution::{
            Boundary,
            authority::{PeExecutionAuthority, PeIdentity},
        },
        state::SystemState,
    },
};
use stela_compiler::GuestState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemEffectCommitError {
    WrongRetiringAttempt,
    ChangedSource,
    ChangedOuter,
    WrongPe,
    ChangedSystemBank,
    ChangedRegisterBank,
}

/// Constructed by the canonical parent only AFTER its actual Retiring transition.
/// These are original retained objects, never copied state or replacement loans.
/// No mutable state getter, phase transition, PC write or authority mint exists.
pub(crate) struct SystemEffectCommit<'commit> {
    pub(in crate::blocks::retirement::checked) authority: &'commit PeExecutionAuthority,
    pub(in crate::blocks::retirement::checked) boundary: &'commit Boundary,
    pub(in crate::blocks::retirement::checked) outer: &'commit MemoryExecutionLoan,
    pub(in crate::blocks::retirement::checked) attempt: u64,
    pub(in crate::blocks::retirement::checked) system: &'commit mut SystemState,
    pub(in crate::blocks::retirement::checked) registers: &'commit mut GuestState,
}

/// Required read-only split of the SAME live retiring commit. Only the concrete
/// family delegators below construct it; raw pointers are identity diagnostics,
/// never dereferenced and never permission without the actual borrowed phase.
pub(crate) struct SystemEffectCommitView<'commit> {
    authority: &'commit PeExecutionAuthority,
    boundary: &'commit Boundary,
    outer: &'commit MemoryExecutionLoan,
    attempt: u64,
    system: *const SystemState,
    registers: *const GuestState,
}

impl SystemEffectCommitView<'_> {
    pub(crate) fn validate(
        &self,
        boundary: &Boundary,
        outer: &MemoryExecutionLoan,
        pe: &PeIdentity,
        system: &SystemState,
        registers: &GuestState,
    ) -> Result<(), SystemEffectCommitError> {
        check_commit_membership(
            self.authority,
            self.boundary,
            self.outer,
            self.attempt,
            boundary,
            outer,
            pe,
        )?;
        if !std::ptr::eq(self.system, system) {
            return Err(SystemEffectCommitError::ChangedSystemBank);
        }
        if !std::ptr::eq(self.registers, registers) {
            return Err(SystemEffectCommitError::ChangedRegisterBank);
        }
        Ok(())
    }
}

fn check_commit_membership(
    authority: &PeExecutionAuthority,
    original_boundary: &Boundary,
    original_outer: &MemoryExecutionLoan,
    attempt: u64,
    boundary: &Boundary,
    outer: &MemoryExecutionLoan,
    pe: &PeIdentity,
) -> Result<(), SystemEffectCommitError> {
    if !authority.retiring_attempt(attempt) {
        return Err(SystemEffectCommitError::WrongRetiringAttempt);
    }
    if !std::ptr::eq(original_boundary, boundary) {
        return Err(SystemEffectCommitError::ChangedSource);
    }
    if !std::ptr::eq(original_outer, outer) {
        return Err(SystemEffectCommitError::ChangedOuter);
    }
    if !authority.identity().same_pe(pe) {
        return Err(SystemEffectCommitError::WrongPe);
    }
    Ok(())
}

impl SystemEffectCommit<'_> {
    pub(crate) fn validate(
        &self,
        boundary: &Boundary,
        outer: &MemoryExecutionLoan,
        pe: &PeIdentity,
    ) -> Result<(), SystemEffectCommitError> {
        check_commit_membership(
            self.authority,
            self.boundary,
            self.outer,
            self.attempt,
            boundary,
            outer,
            pe,
        )
    }

    pub(super) fn apply_dsb(
        &mut self,
        prepared: &mut super::dsb::PreparedRamDsb<'_>,
    ) -> Result<super::dsb::RamDsbApplied, super::dsb::RamDsbFailure> {
        prepared.validate_commit(self)?;
        // Split only original fields; no whole-commit borrow overlaps banks.
        let view = SystemEffectCommitView {
            authority: self.authority,
            boundary: self.boundary,
            outer: self.outer,
            attempt: self.attempt,
            system: std::ptr::from_ref(&*self.system),
            registers: std::ptr::from_ref(&*self.registers),
        };
        prepared.apply_owned(&view, self.system, self.registers)
    }
}
