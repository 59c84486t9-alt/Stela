//! Completion of the fresh machine's original synchronous RAM participants.
//! The immutable installed-source loan excludes a simultaneous publication;
//! the physical loan serializes the actual staged Device-RAM participants.
//! This is not an arbitrary device, DMA, trace or error completion service.

use super::{SystemEffectCommit, SystemEffectCommitError, SystemEffectCommitView};
use crate::{
    blocks::{
        InstalledEl1SourceScope,
        retirement::checked::{el1_system::El1PlatformControls, provider::M0ExecutionChecks},
    },
    memory::domain::{
        MemoryExecutionLoan,
        physical::completion::{PhysicalRamCompletion, RamCompletionError, RamCompletionProgress},
    },
    system::{
        access::Resolution,
        barriers::{self, DataCompletion, RequestKind},
        execution::{Boundary, authority::PeIdentity},
        state::SystemState,
        translation_controls::TranslationControls,
    },
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString};
use stela_compiler::{GuestAddress, GuestState};

pub(crate) enum RamDsbError {
    Commit(SystemEffectCommitError),
    Source,
    Access(&'static str),
    Owner(String),
    ChangedState,
    Completion(RamCompletionError),
}

pub(crate) struct RamDsbFailure {
    pub(crate) error: RamDsbError,
    pub(crate) progress: RamCompletionProgress,
}

pub(crate) struct RamDsbApplied {
    pub(crate) next_pc: GuestAddress,
    pub(crate) requirement: DataCompletion,
    pub(crate) progress: RamCompletionProgress,
}

/// No authority/state borrow survives preparation. These are original actual
/// source/control/RAM/outer loans, not a profile inferred from the DSB word.
/// The sole fresh platform factory closes its physical participants for the
/// entire executable lifetime; its constructor excludes external memory masters.
pub(super) struct PreparedRamDsb<'loan> {
    boundary: &'loan Boundary,
    outer: &'loan MemoryExecutionLoan,
    pe: PeIdentity,
    scope: &'loan InstalledEl1SourceScope<'loan>,
    controls: &'loan TranslationControls,
    platform: &'loan El1PlatformControls,
    checks: &'loan M0ExecutionChecks<'loan>,
    pstate: u64,
    requirement: DataCompletion,
    ram: PhysicalRamCompletion<'loan>,
}

impl<'loan> PreparedRamDsb<'loan> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        boundary: &'loan Boundary,
        outer: &'loan MemoryExecutionLoan,
        pe: PeIdentity,
        scope: &'loan InstalledEl1SourceScope<'loan>,
        controls: &'loan TranslationControls,
        platform: &'loan El1PlatformControls,
        checks: &'loan M0ExecutionChecks<'loan>,
        system: &SystemState,
        registers: &GuestState,
    ) -> Result<Self, RamDsbError> {
        let instruction = boundary.instruction();
        if boundary.consumed_bytes() != size_of::<u32>()
            || boundary.source().entry() != instruction.instruction_pc
            || boundary.source().word() != instruction.word
            || !instruction.matches_source(instruction.instruction_pc, instruction.word)
        {
            return Err(RamDsbError::Source);
        }
        checks
            .check(outer)
            .map_err(|error| RamDsbError::Owner(error.to_string()))?;
        scope
            .check_installed(controls, system)
            .map_err(RamDsbError::Access)?;
        let profile = platform
            .context(system)
            .map_err(|error| RamDsbError::Owner(error.to_string()))?
            .profile;
        let request = match barriers::resolve_ordinary_el2_disabled(instruction.word, profile) {
            Resolution::BackendRequired(request) => request,
            Resolution::Unsupported(reason) => return Err(RamDsbError::Access(reason)),
            _ => return Err(RamDsbError::Access("no ordinary DSB completion request")),
        };
        let RequestKind::Data(requirement) = request.kind() else {
            return Err(RamDsbError::Access(
                "instruction publication has a separate owner",
            ));
        };
        // Full RAM completion is stronger than a load/store/shareability subset.
        // No nXS support or unavailable XS readback is inferred here: this pure
        // EL2-disabled route admits ordinary DSB only, whose FnXS is inapplicable.
        let ram = scope
            .physical_space()
            .prepare_ram_completion(outer)
            .map_err(RamDsbError::Completion)?;
        Ok(Self {
            boundary,
            outer,
            pe,
            scope,
            controls,
            platform,
            checks,
            pstate: system.pstate(registers),
            requirement,
            ram,
        })
    }

    pub(super) fn validate_commit(
        &self,
        commit: &SystemEffectCommit<'_>,
    ) -> Result<(), RamDsbFailure> {
        commit
            .validate(self.boundary, self.outer, &self.pe)
            .map_err(|error| RamDsbFailure {
                error: RamDsbError::Commit(error),
                progress: self.ram.progress(),
            })
    }

    /// This mutating entry cannot be called with loose banks: the closed view
    /// checks the original Retiring attempt/source/outer/PE and both actual banks.
    pub(super) fn apply_owned(
        &mut self,
        commit: &SystemEffectCommitView<'_>,
        system: &mut SystemState,
        registers: &mut GuestState,
    ) -> Result<RamDsbApplied, RamDsbFailure> {
        let result = (|| -> Result<(), RamDsbError> {
            commit
                .validate(self.boundary, self.outer, &self.pe, system, registers)
                .map_err(RamDsbError::Commit)?;
            if system.pstate(registers) != self.pstate {
                return Err(RamDsbError::ChangedState);
            }
            self.checks
                .check(self.outer)
                .map_err(|error| RamDsbError::Owner(error.to_string()))?;
            self.scope
                .check_installed(self.controls, system)
                .map_err(RamDsbError::Access)?;
            self.platform
                .context(system)
                .map_err(|error| RamDsbError::Owner(error.to_string()))?;
            self.ram.complete().map_err(RamDsbError::Completion)?;
            // Retain the complete reached receipt even if a later actual owner
            // check fails. Such a failure is terminal, never a replay permit.
            self.ram
                .validate_current()
                .map_err(RamDsbError::Completion)?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(RamDsbApplied {
                next_pc: self.boundary.instruction().next_pc,
                requirement: self.requirement,
                progress: self.ram.progress(),
            }),
            Err(error) => Err(RamDsbFailure {
                error,
                progress: self.ram.progress(),
            }),
        }
    }
}

impl core::fmt::Debug for RamDsbFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RamDsbFailure")
            .field("error", &self.error)
            .field("progress", &self.progress)
            .finish()
    }
}

impl core::fmt::Debug for RamDsbApplied {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RamDsbApplied")
            .field("next_pc", &self.next_pc)
            .field("requirement", &self.requirement)
            .field("progress", &self.progress)
            .finish()
    }
}

impl core::fmt::Debug for RamDsbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Commit(value) => f.debug_tuple("Commit").field(value).finish(),
            Self::Source => f.write_str("Source"),
            Self::Access(value) => f.debug_tuple("Access").field(value).finish(),
            Self::Owner(value) => f.debug_tuple("Owner").field(value).finish(),
            Self::ChangedState => f.write_str("ChangedState"),
            Self::Completion(value) => f.debug_tuple("Completion").field(value).finish(),
        }
    }
}
