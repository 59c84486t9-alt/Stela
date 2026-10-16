//! Preparing and committing a system effect without borrowing the PE state.

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

/// Constructed by the parent after the transition to retiring. Every field is
/// the PE's own object.
pub(crate) struct SystemEffectCommit<'commit> {
    pub(in crate::blocks::retirement::checked) authority: &'commit PeExecutionAuthority,
    pub(in crate::blocks::retirement::checked) boundary: &'commit Boundary,
    pub(in crate::blocks::retirement::checked) outer: &'commit MemoryExecutionLoan,
    pub(in crate::blocks::retirement::checked) attempt: u64,
    pub(in crate::blocks::retirement::checked) system: &'commit mut SystemState,
    pub(in crate::blocks::retirement::checked) registers: &'commit mut GuestState,
}

/// A read-only view of the same live commit, built only by the family
/// delegators below. Its raw pointers are identity diagnostics and are never
/// dereferenced.
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
        if !core::ptr::eq(self.system, system) {
            return Err(SystemEffectCommitError::ChangedSystemBank);
        }
        if !core::ptr::eq(self.registers, registers) {
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
    if !core::ptr::eq(original_boundary, boundary) {
        return Err(SystemEffectCommitError::ChangedSource);
    }
    if !core::ptr::eq(original_outer, outer) {
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
        // Split field by field, so no borrow of the whole commit overlaps the
        // banks.
        let view = SystemEffectCommitView {
            authority: self.authority,
            boundary: self.boundary,
            outer: self.outer,
            attempt: self.attempt,
            system: core::ptr::from_ref(&*self.system),
            registers: core::ptr::from_ref(&*self.registers),
        };
        prepared.apply_owned(&view, self.system, self.registers)
    }
}
