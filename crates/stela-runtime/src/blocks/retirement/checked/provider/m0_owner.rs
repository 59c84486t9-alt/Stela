//! Concrete fresh M0 backend. Contextual hosted join; freestanding mounting remains unverified.
//! The containing provider module alone seals this implementation.
use super::super::super::software_async::NoAsyncSources;
use super::super::{
    NativeObservation,
    source::{BoundSource, Helper},
};
use super::resources::{El1ExecutionResources, M0ExecutionChecks, M0ExecutionResources};
use super::{HelperOutcome, Owner, ProcessEntryControls, sealed};
use crate::{
    blocks::{InstalledEl1Sources, InstalledM0Sources},
    memory::{
        domain::{MemoryExecutionLoan, MemoryThread},
        policy::MemoryControls,
    },
    system::{
        events::EventEndpoint, state::SystemState, translation_controls::TranslationControls,
    },
};
use stela_compiler::{
    GuestState,
    block::{BlockProfile, CheckedMemoryProfile},
    context::ExecutionContext,
};

/// Sole live TranslationControls is borrowed from the consumed fresh installed
/// machine. No SCTLR/TCR fields are copied into this backend or FixedEl1 owner.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InstalledCohort {
    M0Read64,
    El1DirectBranch,
    El1Integer,
}

pub(crate) struct M0Owner<'pe> {
    cohort: InstalledCohort,
    address_space: u64,
    sources: &'pe InstalledM0Sources,
    controls: &'pe TranslationControls,
    execution: &'pe ProcessEntryControls,
    memory: &'pe mut MemoryThread<MemoryControls>,
    endpoint: &'pe EventEndpoint,
    context: &'pe mut ExecutionContext,
    pending: NoAsyncSources<'pe>,
}

impl<'pe> M0Owner<'pe> {
    /// # Safety
    /// Called once inside InstalledM0Owner's consuming fresh-machine scope.
    /// Every original resource belongs to that one declared PE/System/domain;
    /// the complete producer registry and physical/source mutation ownership
    /// remain closed for the sole SystemExecutionOwner's executable lifetime.
    /// This cannot adopt hardware/caller-provided copied state or reset a PE.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::blocks::retirement) unsafe fn fresh_software(
        address_space: u64,
        sources: &'pe InstalledM0Sources,
        controls: &'pe TranslationControls,
        execution: &'pe ProcessEntryControls,
        memory: &'pe mut MemoryThread<MemoryControls>,
        endpoint: &'pe EventEndpoint,
        context: &'pe mut ExecutionContext,
        pending: NoAsyncSources<'pe>,
    ) -> anyhow::Result<Self> {
        let owner = Self {
            cohort: InstalledCohort::M0Read64,
            address_space,
            sources,
            controls,
            execution,
            memory,
            endpoint,
            context,
            pending,
        };
        owner.check_resources()?;
        Ok(owner)
    }

    /// # Safety
    /// Same once-only ORIGINAL fresh machine contract as fresh_software. Caller
    /// must consume genuine InstalledEl1Owner resources and create its sole
    /// SystemExecutionOwner once. This is the SAME sealed backend/PE contract,
    /// not an M0Read64 relabel or caller-selected mode/authority flag.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::blocks::retirement) unsafe fn fresh_el1_branch(
        address_space: u64,
        sources: &'pe InstalledEl1Sources,
        controls: &'pe TranslationControls,
        execution: &'pe ProcessEntryControls,
        memory: &'pe mut MemoryThread<MemoryControls>,
        endpoint: &'pe EventEndpoint,
        context: &'pe mut ExecutionContext,
        pending: NoAsyncSources<'pe>,
    ) -> anyhow::Result<Self> {
        let owner = Self {
            cohort: InstalledCohort::El1DirectBranch,
            address_space,
            sources,
            controls,
            execution,
            memory,
            endpoint,
            context,
            pending,
        };
        owner.check_resources()?;
        Ok(owner)
    }

    /// # Safety
    /// Same once-only ORIGINAL fresh machine contract as fresh_software. Caller
    /// must consume genuine InstalledEl1Owner resources and create its sole
    /// SystemExecutionOwner once. This is the SAME sealed backend/PE contract,
    /// not an M0Read64 relabel or caller-selected mode/authority flag.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::blocks::retirement) unsafe fn fresh_el1_integer(
        address_space: u64,
        sources: &'pe InstalledEl1Sources,
        controls: &'pe TranslationControls,
        execution: &'pe ProcessEntryControls,
        memory: &'pe mut MemoryThread<MemoryControls>,
        endpoint: &'pe EventEndpoint,
        context: &'pe mut ExecutionContext,
        pending: NoAsyncSources<'pe>,
    ) -> anyhow::Result<Self> {
        let owner = Self {
            cohort: InstalledCohort::El1Integer,
            address_space,
            sources,
            controls,
            execution,
            memory,
            endpoint,
            context,
            pending,
        };
        owner.check_resources()?;
        Ok(owner)
    }

    fn check_resources(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.memory.address_space() == Some(self.address_space),
            "actual M0 namespace differs"
        );
        anyhow::ensure!(
            self.context.has_supported_header(),
            "actual M0 execution context header differs"
        );
        self.execution.check()?;
        self.pending
            .check_registry()
            .map_err(|error| anyhow::anyhow!("actual M0 producer registry: {error:?}"))?;
        self.memory
            .check_event_endpoint(self.endpoint)
            .map_err(|error| anyhow::anyhow!("actual M0 PE monitor: {error:?}"))?;
        match self.cohort {
            InstalledCohort::M0Read64 => self
                .controls
                .validate_installed_m0_source(&self.sources.source_scope()),
            InstalledCohort::El1DirectBranch | InstalledCohort::El1Integer => self
                .controls
                .validate_installed_el1_source(&self.sources.el1_scope()),
        }
        .map_err(anyhow::Error::msg)
    }
}

impl sealed::Concrete for M0Owner<'_> {}
impl Owner for M0Owner<'_> {
    fn execution_loan(&mut self) -> anyhow::Result<MemoryExecutionLoan> {
        self.memory
            .execution_loan()
            .map_err(|error| anyhow::anyhow!("actual M0 exclusion: {error:?}"))
    }

    fn prepare_source(
        &mut self,
        runtime: &mut crate::blocks::BlockRuntime,
        system: &SystemState,
        pc: stela_compiler::GuestAddress,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        if self.cohort != InstalledCohort::El1Integer {
            return Ok(());
        }
        self.check_resources()?;
        anyhow::ensure!(
            runtime.profile() == BlockProfile::El1M0IntegerV1,
            "installed integer runtime differs"
        );
        let scope = self.sources.el1_scope();
        let reached = scope
            .physical_space()
            .fetch_el1_instruction(outer, self.controls, &scope, system, pc.0)
            .map_err(|error| anyhow::anyhow!("installed integer reached source: {error:?}"))?;
        runtime.bind_physical_instruction(scope.installed_snapshot(), reached)?;
        Ok(())
    }

    fn qualify(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        _registers: &mut GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        // This declared base EL1 profile has no LR/PACM lifecycle. Recheck the
        // actual original storage before native entry, including zero PACM.
        self.execution.check_snapshot(None, system)?;
        self.check_resources()?;
        outer
            .check_thread_domain(&*self.memory)
            .map_err(|error| anyhow::anyhow!("actual M0 outer domain: {error:?}"))?;
        bound.recheck()?;
        anyhow::ensure!(
            bound.runtime.profile()
                == match self.cohort {
                    InstalledCohort::M0Read64 =>
                        BlockProfile::CheckedMemory(CheckedMemoryProfile::M0DeviceRamRead64Staged),
                    InstalledCohort::El1DirectBranch => BlockProfile::El1DirectBranchV1,
                    InstalledCohort::El1Integer => BlockProfile::El1M0IntegerV1,
                },
            "M0 backend requires actual staged M0 source profile"
        );
        anyhow::ensure!(
            bound.entry.address_space() == self.address_space,
            "M0 source namespace differs"
        );
        match self.cohort {
            InstalledCohort::M0Read64 => {
                bound.memory_requirements()?;
            }
            InstalledCohort::El1Integer => {
                bound.el1_m0_intent()?;
            }
            InstalledCohort::El1DirectBranch => {
                bound.direct_branch_target()?;
            }
        }
        // Actual installed fetch and current bank translation require the opaque
        // input containing the EXACT outer object. Active mints it after source
        // admission, before any prepared RAM transaction or native call.
        Ok(())
    }

    fn split_m0_resources(&mut self) -> anyhow::Result<M0ExecutionResources<'_>> {
        anyhow::ensure!(
            matches!(
                self.cohort,
                InstalledCohort::M0Read64 | InstalledCohort::El1Integer
            ),
            "branch cohort cannot lend M0 data resources"
        );
        self.check_resources()?;
        Ok(M0ExecutionResources {
            sources: self.sources,
            controls: self.controls,
            memory: &*self.memory,
            context: &mut *self.context,
            checks: M0ExecutionChecks {
                execution: self.execution,
                pending: &self.pending,
                memory: &*self.memory,
                endpoint: self.endpoint,
                address_space: self.address_space,
            },
        })
    }

    fn split_el1_resources(&mut self) -> anyhow::Result<El1ExecutionResources<'_>> {
        anyhow::ensure!(
            matches!(
                self.cohort,
                InstalledCohort::El1DirectBranch | InstalledCohort::El1Integer
            ),
            "M0 data cohort cannot lend branch resources"
        );
        self.check_resources()?;
        Ok(El1ExecutionResources {
            sources: self.sources,
            controls: self.controls,
            memory: &*self.memory,
            context: &mut *self.context,
            checks: M0ExecutionChecks {
                execution: self.execution,
                pending: &self.pending,
                memory: &*self.memory,
                endpoint: self.endpoint,
                address_space: self.address_space,
            },
        })
    }

    fn invoke(
        &mut self,
        _bound: &BoundSource<'_>,
        _system: &mut SystemState,
        _registers: &mut GuestState,
    ) -> anyhow::Result<NativeObservation> {
        anyhow::bail!("M0 backend cannot enter the ordinary checked consumer")
    }
    fn complete_helper(
        &mut self,
        _helper: &Helper,
        _system: &SystemState,
        _registers: &mut GuestState,
        _outer: Option<&MemoryExecutionLoan>,
    ) -> HelperOutcome {
        HelperOutcome::Indeterminate(anyhow::anyhow!(
            "M0 backend has no helper service; actual PE must remain blocked"
        ))
    }
    fn complete_trap(
        &mut self,
        _trap: &stela_compiler::block::SynchronousTrap,
        _system: &SystemState,
        _registers: &mut GuestState,
        _events: &mut super::super::darwin_services::TrapServiceEvents,
    ) -> super::super::darwin_services::Outcome {
        super::super::darwin_services::Outcome::Indeterminate(anyhow::anyhow!(
            "installed EL1 integer owner has no trap service"
        ))
    }

    fn post_retirement(
        &mut self,
        _bound: &BoundSource<'_>,
        _system: &SystemState,
        _registers: &mut GuestState,
        _outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        anyhow::bail!("M0 requires its retained staged commit path")
    }
}
