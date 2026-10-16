//! Preparation, physical fetch and context publication for one translation.

use super::{BlockRuntime, profile};
use crate::{
    memory::{
        domain::{
            MemorySystem,
            physical::{BoundPhysicalInstruction, ImmutableCodeBacking, PhysicalAddressSpace},
        },
        stage1,
    },
    system::{
        profile::EntryProfile,
        state::SystemState,
        translation_controls::{
            ContextSynchronizationRequest, ControlSnapshot, FetchFailure, PhysicalFetch,
            PreparedPublication, PublicationFailure, PublicationProgress, PublicationRequest,
            TranslationServices,
        },
    },
};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
use alloc::sync::Arc;
use stela_compiler::{aarch64::system::synchronization::Operation, block::system::SystemOperation};

pub(super) struct InstalledContext {
    pub(super) snapshot: ControlSnapshot,
    pub(super) cpu: stage1::CpuProfile,
    pub(super) cache: super::stage1_cache::Stage1Cache,
}

pub(super) enum ContextState {
    Unbound,
    Installed(Box<InstalledContext>),
    Failed,
}

/// A borrow of the code owner, constructed only by it. The runtime borrow
/// excludes translation and native calls until the scope ends.
pub(crate) struct ControlCodeScope<'run> {
    pub(super) runtime: &'run mut BlockRuntime,
    pub(super) physical: &'run PhysicalAddressSpace,
    pub(super) immutable_sources: &'run [ImmutableCodeBacking],
    pub(super) entry_profile: EntryProfile,
    pub(super) context: &'run mut ContextState,
    pub(super) _outer: Option<&'run crate::memory::domain::MemoryExecutionLoan>,
    pub(super) retired_system:
        Option<&'run crate::blocks::retirement::checked::RetiredInstructionSource<'run>>,
}

impl<'run> ControlCodeScope<'run> {
    /// Bind the System instruction that just retired, supplied by Active after
    /// native retirement. This permits no further instruction, fetch or native
    /// attempt.
    pub(in crate::blocks) fn bind_retired_system_source(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        source: &'run crate::blocks::retirement::checked::RetiredInstructionSource<'run>,
    ) -> Result<(), &'static str> {
        if self.retired_system.is_some() {
            return Err("retired System source already bound");
        }
        self.check_retired_system_source(source)?;
        self.retired_system = Some(source);
        Ok(())
    }

    fn check_retired_system_source(
        &self,
        source: &crate::blocks::retirement::checked::RetiredInstructionSource<'run>,
    ) -> Result<(), &'static str> {
        let original = source.entry();
        if self.runtime.profile() != stela_compiler::block::BlockProfile::El1PlatformV1
            || self.runtime.address_space() != original.address_space()
            || !source
                .instruction()
                .matches_source(original.entry(), original.word())
            || source.source_pin().raw_pc() != original.entry().0
            || source.source_pin().word() != original.word()
        {
            return Err("retired System profile/source descriptor changed");
        }
        let outer = self._outer.ok_or("retired source outer absent")?;
        self.physical
            .validate_retired_instruction(outer, source.source_pin())
    }

    /// Reuse the one initial context allocation after a prepared control commit.
    /// An impossible lost context fails through the existing publication prefix.
    fn replace_current(
        &mut self,
        snapshot: ControlSnapshot,
        cpu: stage1::CpuProfile,
        preserve_translations: bool,
    ) -> Result<(), &'static str> {
        let ContextState::Installed(current) = self.context else {
            return Err("prepared publication lost its installed per-PE context");
        };
        let config = stage1::Config::from_controls_for_cpu(
            snapshot.consumer_inputs().stage1_controls(),
            cpu,
        )
        .map_err(|_| "published controls have no canonical configuration")?;
        if preserve_translations {
            if current.cpu != cpu
                || current.snapshot.consumer_inputs() != snapshot.consumer_inputs()
            {
                return Err("synchronization changes cached translation inputs");
            }
            current.snapshot = snapshot;
        } else {
            **current = InstalledContext {
                snapshot,
                cpu,
                cache: super::stage1_cache::Stage1Cache::new(config, self.physical),
            };
        }
        Ok(())
    }

    fn current(&self, snapshot: &ControlSnapshot) -> Result<&InstalledContext, &'static str> {
        match &*self.context {
            ContextState::Installed(current)
                if current.snapshot.same_pe(snapshot)
                    && current.snapshot.generation() == snapshot.generation() =>
            {
                Ok(current)
            }
            ContextState::Installed(_) => Err("foreign or stale per-PE control snapshot"),
            ContextState::Unbound => Err("per-PE context has not been installed"),
            ContextState::Failed => Err("per-PE code publication owner has failed"),
        }
    }

    fn bound_instruction(
        &self,
        snapshot: &ControlSnapshot,
        cpu: &stage1::CpuProfile,
        state: &SystemState,
        pc: u64,
    ) -> Result<BoundPhysicalInstruction, FetchFailure> {
        profile::check_entry(state).map_err(FetchFailure::Unavailable)?;
        profile::check_features(self.entry_profile, snapshot).map_err(FetchFailure::Unavailable)?;
        if self
            .current(snapshot)
            .map_err(FetchFailure::Unavailable)?
            .cpu
            != *cpu
        {
            return Err(FetchFailure::Unavailable(
                "CPU witness differs from installed per-PE context",
            ));
        }
        self.physical.fetch_control_instruction(pc, self, state)
    }

    pub(crate) fn same_physical_owner(&self, physical: &PhysicalAddressSpace) -> bool {
        core::ptr::eq(self.physical, physical)
    }

    pub(crate) fn retained_outer(&self) -> Option<&crate::memory::domain::MemoryExecutionLoan> {
        self._outer
    }

    pub(crate) fn source_cache_controls(&self) -> Result<u64, FetchFailure> {
        match &*self.context {
            ContextState::Installed(current) => Ok(current.snapshot.consumer_inputs().sctlr_el1),
            _ => Err(FetchFailure::Unavailable(
                "source visibility has no original installed controls",
            )),
        }
    }
    pub(crate) fn immutable_sources(&self) -> &[ImmutableCodeBacking] {
        self.immutable_sources
    }

    pub(crate) fn canonical_fetch(
        &self,
        state: &SystemState,
        pc: u64,
    ) -> Result<stage1::Translation, FetchFailure> {
        profile::check_entry(state).map_err(FetchFailure::Unavailable)?;
        let current = match &*self.context {
            ContextState::Installed(current) => current,
            ContextState::Unbound => {
                return Err(FetchFailure::Unavailable("per-PE context is unbound"));
            }
            ContextState::Failed => {
                return Err(FetchFailure::Unavailable("per-PE publication owner failed"));
            }
        };
        profile::check_features(self.entry_profile, &current.snapshot)
            .map_err(FetchFailure::Unavailable)?;
        if !pc.is_multiple_of(size_of::<u32>() as u64) {
            return Err(FetchFailure::InstructionAlignment {
                raw_pc: pc,
                exception_level: state.current_el(),
            });
        }
        let config = stage1::Config::from_controls_for_cpu(
            current.snapshot.consumer_inputs().stage1_controls(),
            current.cpu,
        )
        .map_err(|_| {
            FetchFailure::Unavailable("current controls have no canonical configuration backend")
        })?;
        let access = stage1::Access {
            kind: stage1::AccessKind::Fetch,
            exception_level: stage1::ExceptionLevel::El1,
            raw_virtual_address: pc,
            source_pc: pc,
            // Actual SystemState + base EntryProfile exclude these features.
            pan: false,
            uao: false,
            aligned: true,
        };
        let result = if matches!(config.mode(), stage1::Mode::Enabled { .. }) {
            let outer = self._outer.ok_or(FetchFailure::Unavailable(
                "enabled control fetch requires original retained outer",
            ))?;
            current
                .cache
                .translate(&config, self.physical, outer, access)
        } else {
            stage1::translate(&config, self.physical, access)
        };
        if let Some(outer) = self._outer {
            self.physical.check_execution_loan(outer).map_err(|_| {
                FetchFailure::Platform("control fetch original outer became unavailable")
            })?;
        }
        result.map_err(|error| match error {
            stage1::TranslationError::Fault(fault) => FetchFailure::Architectural(fault),
            stage1::TranslationError::Unsupported(stage1::Unsupported::PhysicalPlatform(
                reason,
            )) => FetchFailure::Platform(reason),
            stage1::TranslationError::Unsupported(_) => {
                FetchFailure::Unavailable("canonical instruction translation is unavailable")
            }
        })
    }

    pub(crate) fn check_source_word(&self, pc: u64, word: u32) -> Result<(), &'static str> {
        if self.retired_system.is_some() {
            Err("retired physical source is not a fresh instruction fetch permit")
        } else if self.runtime.profile() == stela_compiler::block::BlockProfile::El1PlatformV1 {
            profile::check_context_instruction(pc, word).map(|_| ())
        } else {
            profile::check_instruction(pc, word).map(|_| ())
        }
    }

    pub(crate) fn check_fetch_policy(
        &self,
        translation: &stage1::Translation,
        raw_pc: u64,
        state: &SystemState,
    ) -> Result<(), &'static str> {
        profile::check_immutable_fetch(translation, raw_pc, state)
    }

    fn revalidate_source(
        &self,
        snapshot: &ControlSnapshot,
        source: PhysicalFetch,
        state: &SystemState,
    ) -> Result<BoundPhysicalInstruction, &'static str> {
        let cpu = self.current(snapshot)?.cpu;
        let reached = self
            .bound_instruction(snapshot, &cpu, state, source.pc)
            .map_err(|_| "current canonical instruction source cannot be revalidated")?;
        self.runtime
            .check_physical_source(snapshot, source, &reached)?;
        Ok(reached)
    }
}

impl<'run> TranslationServices for ControlCodeScope<'run> {
    type Prepared<'a>
        = PreparedCodePublication<'a, 'run>
    where
        Self: 'a;

    fn prepare_context_synchronization<'a>(
        &'a mut self,
        request: ContextSynchronizationRequest<'_>,
    ) -> Result<Self::Prepared<'a>, &'static str> {
        let ContextSynchronizationRequest {
            before,
            after,
            source,
            cpu,
            state,
            cause,
            retired_source,
        } = request;
        self.physical.check_fetch_execution()?;
        if cause == crate::system::translation_controls::ContextSynchronizationCause::InterruptEntry
        {
            let original = retired_source.ok_or("IRQ CSE lost its retired source")?;
            let bound = self
                .retired_system
                .ok_or("IRQ CSE lacks the retired source pin")?;
            if !core::ptr::eq(bound, original) || source != original.physical_fetch() {
                return Err("IRQ CSE changed the retired physical source");
            }
            self.check_retired_system_source(original)?;
        } else if retired_source.is_some()
            || self.retired_system.is_some()
            || !cause.matches_source(source.word)
        {
            return Err("exception CSE cause differs from source operation");
        }
        if self.current(&before)?.cpu != cpu
            || !before.same_pe(&after)
            || before.generation().checked_add(1) != Some(after.generation())
            || before.readbacks() != after.readbacks()
            || before.consumer_inputs() != after.consumer_inputs()
        {
            return Err("exception CSE changes controls or original PE authority");
        }
        profile::check_features(self.entry_profile, &after)?;
        let retained = if retired_source.is_some() {
            None
        } else {
            Some(self.revalidate_source(&before, source, state)?)
        };
        Ok(PreparedCodePublication {
            scope: self,
            action: PreparedAction::Synchronize {
                snapshot: after,
                cpu,
            },
            _source: retained,
        })
    }

    fn memory_system(&self) -> &Arc<MemorySystem> {
        self.physical.memory_system()
    }

    fn validate_source(
        &mut self,
        snapshot: &ControlSnapshot,
        source: PhysicalFetch,
        state: &SystemState,
    ) -> Result<(), &'static str> {
        match self.revalidate_source(snapshot, source, state) {
            Ok(_) => Ok(()),
            Err(error) => {
                *self.context = ContextState::Failed;
                Err(error)
            }
        }
    }

    fn fetch(
        &mut self,
        snapshot: &ControlSnapshot,
        cpu: &stage1::CpuProfile,
        state: &SystemState,
        pc: u64,
    ) -> Result<PhysicalFetch, FetchFailure> {
        let reached = self.bound_instruction(snapshot, cpu, state, pc)?;
        self.runtime
            .bind_physical_instruction(snapshot, reached)
            .map_err(|_| FetchFailure::Platform("physical source registration failed"))
    }

    fn prepare<'a>(
        &'a mut self,
        request: PublicationRequest<'a>,
    ) -> Result<Self::Prepared<'a>, &'static str> {
        self.physical.check_fetch_execution()?;
        let (action, retained_source) = match request {
            PublicationRequest::Initial {
                snapshot,
                cpu,
                state,
            } => {
                if !matches!(self.context, ContextState::Unbound) {
                    return Err("per-PE source owner cannot be initialized twice");
                }
                profile::check_entry(state)?;
                profile::check_features(self.entry_profile, &snapshot)?;
                // Config construction checks supported effective behavior only.
                // Future root/leaf faults are not walked or raised during prepare.
                let config = stage1::Config::from_controls_for_cpu(
                    snapshot.consumer_inputs().stage1_controls(),
                    cpu,
                )
                .map_err(|_| "initial controls have no canonical configuration backend")?;
                // Reserve the single context slot during initial preparation;
                // later commits reuse it.
                (
                    PreparedAction::Install(Box::new(InstalledContext {
                        snapshot,
                        cpu,
                        cache: super::stage1_cache::Stage1Cache::new(config, self.physical),
                    })),
                    None,
                )
            }
            PublicationRequest::Read {
                snapshot,
                source,
                cpu,
                state,
            } => {
                profile::check_features(self.entry_profile, &snapshot)?;
                if self.current(&snapshot)?.cpu != cpu {
                    return Err("read CPU witness differs from installed context");
                }
                let retained = self.revalidate_source(&snapshot, source, state)?;
                (PreparedAction::Read, Some(retained))
            }
            PublicationRequest::Write {
                change,
                cpu,
                state,
                registers: _,
            } => {
                self.current(&change.before)?;
                if self.current(&change.before)?.cpu != cpu {
                    return Err("write CPU witness differs from installed context");
                }
                if !change.before.same_pe(&change.after)
                    || change.before.generation().checked_add(1) != Some(change.after.generation())
                {
                    return Err("control write changes per-PE authority");
                }
                profile::check_features(self.entry_profile, &change.after)?;
                let retained = self.revalidate_source(&change.before, change.source, state)?;
                stage1::Config::from_controls_for_cpu(
                    change.after.consumer_inputs().stage1_controls(),
                    cpu,
                )
                .map_err(|_| "written controls require an unavailable canonical backend")?;
                (
                    PreparedAction::Switch {
                        snapshot: change.after,
                        cpu,
                    },
                    Some(retained),
                )
            }
            PublicationRequest::Isb {
                before,
                after,
                source,
                operation,
                cpu,
                state,
                registers: _,
            } => {
                self.current(&before)?;
                if self.current(&before)?.cpu != cpu {
                    return Err("ISB CPU witness differs from installed context");
                }
                if !before.same_pe(&after)
                    || before.generation().checked_add(1) != Some(after.generation())
                    || before.readbacks() != after.readbacks()
                    || before.consumer_inputs() != after.consumer_inputs()
                {
                    return Err("ISB changes architectural control values or PE authority");
                }
                profile::check_features(self.entry_profile, &after)?;
                let retained = self.revalidate_source(&before, source, state)?;
                // Check the current System decoder, not the legacy control entry.
                // The source, profile and PE borrows were re-checked above and are
                // held through the cache, context and serialization commit.
                let instruction = profile::check_context_instruction(source.pc, source.word)?;
                match (instruction.operation, operation) {
                    (
                        SystemOperation::InstructionSynchronization { option: actual },
                        Operation::InstructionSynchronization { option: expected },
                    ) if actual == expected => {}
                    _ => return Err("ISB operation differs from source"),
                }
                (
                    PreparedAction::Synchronize {
                        snapshot: after,
                        cpu,
                    },
                    Some(retained),
                )
            }
        };
        Ok(PreparedCodePublication {
            scope: self,
            action,
            _source: retained_source,
        })
    }
}

enum PreparedAction {
    Install(Box<InstalledContext>),
    Read,
    Switch {
        snapshot: ControlSnapshot,
        cpu: stage1::CpuProfile,
    },
    Synchronize {
        snapshot: ControlSnapshot,
        cpu: stage1::CpuProfile,
    },
}

pub(crate) struct PreparedCodePublication<'loan, 'run> {
    scope: &'loan mut ControlCodeScope<'run>,
    action: PreparedAction,
    _source: Option<BoundPhysicalInstruction>,
}

impl PreparedPublication for PreparedCodePublication<'_, '_> {
    fn commit(self) -> Result<(), PublicationFailure> {
        let Self {
            scope,
            action,
            _source,
        } = self;
        let mut progress = PublicationProgress::None;
        let result = (|| {
            scope.physical.check_fetch_execution()?;
            if let Some(retired) = scope.retired_system {
                scope.check_retired_system_source(retired)?;
            }
            match action {
                PreparedAction::Read => return Ok(()),
                PreparedAction::Install(current) => {
                    *scope.context = ContextState::Installed(current);
                    progress = PublicationProgress::CurrentContextInstalled;
                }
                PreparedAction::Switch { snapshot, cpu } => {
                    scope.runtime.retire_translation_sources();
                    progress = PublicationProgress::CodeDependenciesRetired;
                    scope.physical.check_fetch_execution()?;
                    scope.replace_current(snapshot, cpu, false)?;
                    progress = PublicationProgress::CurrentContextInstalled;
                }
                PreparedAction::Synchronize { snapshot, cpu } => {
                    scope.runtime.retire_translation_sources();
                    progress = PublicationProgress::CodeDependenciesRetired;
                    scope.physical.check_fetch_execution()?;
                    scope.replace_current(snapshot, cpu, true)?;
                    progress = PublicationProgress::CurrentContextInstalled;
                    super::super::serialize_instruction_execution()
                        .map_err(|_| "host instruction serialization failed")?;
                    progress = PublicationProgress::InstructionExecutionSerialized;
                }
            }
            if let Some(retired) = scope.retired_system {
                scope.check_retired_system_source(retired)?;
            }
            scope.physical.check_fetch_execution()
        })();
        if let Err(reason) = result {
            *scope.context = ContextState::Failed;
            return Err(PublicationFailure { progress, reason });
        }
        Ok(())
    }
}
