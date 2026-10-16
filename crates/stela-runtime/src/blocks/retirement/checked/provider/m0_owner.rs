//! The M0 backend.
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
    El1Platform,
}

pub(crate) struct M0Owner<'pe> {
    cohort: InstalledCohort,
    address_space: u64,
    sources: &'pe mut InstalledM0Sources,
    controls: &'pe mut TranslationControls,
    execution: &'pe ProcessEntryControls,
    memory: &'pe mut MemoryThread<MemoryControls>,
    endpoint: &'pe EventEndpoint,
    context: &'pe mut ExecutionContext,
    pending: NoAsyncSources<'pe>,
    platform: Option<&'pe super::super::el1_system::El1PlatformControls>,
}

impl<'pe> M0Owner<'pe> {
    /// # Safety
    /// Called once inside InstalledM0Owner's consuming scope. Every resource
    /// belongs to the one declared PE, system and domain, and the producer
    /// registry and physical and source mutation stay closed for the execution
    /// owner's lifetime.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::blocks::retirement) unsafe fn fresh_software(
        address_space: u64,
        sources: &'pe mut InstalledM0Sources,
        controls: &'pe mut TranslationControls,
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
            platform: None,
        };
        owner.check_resources()?;
        Ok(owner)
    }

    /// # Safety
    /// As for `fresh_software`: the caller consumes InstalledEl1Owner resources
    /// and creates the execution owner once.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::blocks::retirement) unsafe fn fresh_el1_branch(
        address_space: u64,
        sources: &'pe mut InstalledEl1Sources,
        controls: &'pe mut TranslationControls,
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
            platform: None,
        };
        owner.check_resources()?;
        Ok(owner)
    }

    /// # Safety
    /// As for `fresh_software`: the caller consumes InstalledEl1Owner resources
    /// and creates the execution owner once.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::blocks::retirement) unsafe fn fresh_el1_integer(
        address_space: u64,
        sources: &'pe mut InstalledEl1Sources,
        controls: &'pe mut TranslationControls,
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
            platform: None,
        };
        owner.check_resources()?;
        Ok(owner)
    }

    /// # Safety
    /// As for `fresh_software`: the caller consumes InstalledEl1Owner resources
    /// and creates the execution owner once.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::blocks::retirement) unsafe fn fresh_el1_platform(
        address_space: u64,
        sources: &'pe mut InstalledEl1Sources,
        controls: &'pe mut TranslationControls,
        execution: &'pe ProcessEntryControls,
        memory: &'pe mut MemoryThread<MemoryControls>,
        endpoint: &'pe EventEndpoint,
        context: &'pe mut ExecutionContext,
        pending: NoAsyncSources<'pe>,
        platform: &'pe super::super::el1_system::El1PlatformControls,
    ) -> anyhow::Result<Self> {
        let owner = Self {
            cohort: InstalledCohort::El1Platform,
            address_space,
            sources,
            controls,
            execution,
            memory,
            endpoint,
            context,
            pending,
            platform: Some(platform),
        };
        owner.check_resources()?;
        Ok(owner)
    }

    fn check_resources(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.memory.address_space() == Some(self.address_space),
            "M0 namespace differs"
        );
        anyhow::ensure!(
            self.context.has_supported_header(),
            "M0 execution context header differs"
        );
        self.execution.check()?;
        self.pending
            .check_registry()
            .map_err(|error| anyhow::anyhow!("M0 producer registry: {error:?}"))?;
        self.memory
            .check_event_endpoint(self.endpoint)
            .map_err(|error| anyhow::anyhow!("M0 PE monitor: {error:?}"))?;
        if let Some(platform) = self.platform {
            platform.check()?;
        }
        match self.cohort {
            InstalledCohort::M0Read64 => self.controls.validate_installed_m0_source(
                &self.sources.source_scope().map_err(anyhow::Error::msg)?,
            ),
            InstalledCohort::El1DirectBranch
            | InstalledCohort::El1Integer
            | InstalledCohort::El1Platform => self.controls.validate_installed_el1_source(
                &self.sources.el1_scope().map_err(anyhow::Error::msg)?,
            ),
        }
        .map_err(anyhow::Error::msg)
    }
}

impl sealed::Concrete for M0Owner<'_> {}
impl Owner for M0Owner<'_> {
    fn supports_profile(&self, profile: BlockProfile) -> bool {
        profile
            == match self.cohort {
                InstalledCohort::M0Read64 => {
                    BlockProfile::CheckedMemory(CheckedMemoryProfile::M0DeviceRamRead64Staged)
                }
                InstalledCohort::El1DirectBranch => BlockProfile::El1DirectBranchV1,
                InstalledCohort::El1Integer => BlockProfile::El1M0IntegerV1,
                InstalledCohort::El1Platform => BlockProfile::El1PlatformV1,
            }
    }

    fn execution_loan(&mut self) -> anyhow::Result<MemoryExecutionLoan> {
        self.memory
            .execution_loan()
            .map_err(|error| anyhow::anyhow!("M0 exclusion: {error:?}"))
    }

    fn prepare_source(
        &mut self,
        runtime: &mut crate::blocks::BlockRuntime,
        system: &SystemState,
        pc: stela_compiler::GuestAddress,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        system
            .check_lower_el_storage()
            .map_err(|error| anyhow::anyhow!("installed lower-EL source storage: {error:?}"))?;
        if !matches!(
            self.cohort,
            InstalledCohort::El1Integer | InstalledCohort::El1Platform
        ) {
            return Ok(());
        }
        self.check_resources()?;
        anyhow::ensure!(
            runtime.profile()
                == match self.cohort {
                    InstalledCohort::El1Platform => BlockProfile::El1PlatformV1,
                    _ => BlockProfile::El1M0IntegerV1,
                },
            "installed integer runtime differs"
        );
        let scope = self.sources.el1_scope().map_err(anyhow::Error::msg)?;
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
        system
            .check_lower_el_storage()
            .map_err(|error| anyhow::anyhow!("M0 lower-EL storage: {error:?}"))?;
        // This EL1 profile has no LR or PACM lifecycle; re-check the storage
        // before native entry, including a zero PACM.
        self.execution.check_snapshot(None, system)?;
        self.check_resources()?;
        outer
            .check_thread_domain(&*self.memory)
            .map_err(|error| anyhow::anyhow!("M0 outer domain: {error:?}"))?;
        anyhow::ensure!(
            bound.runtime.profile()
                == match self.cohort {
                    InstalledCohort::M0Read64 =>
                        BlockProfile::CheckedMemory(CheckedMemoryProfile::M0DeviceRamRead64Staged),
                    InstalledCohort::El1DirectBranch => BlockProfile::El1DirectBranchV1,
                    InstalledCohort::El1Integer => BlockProfile::El1M0IntegerV1,
                    InstalledCohort::El1Platform => BlockProfile::El1PlatformV1,
                },
            "M0 backend requires staged M0 source profile"
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
            InstalledCohort::El1Platform => {
                bound.el1_platform_intent()?;
            }
        }
        // The installed fetch and the bank translation need the input holding
        // the outer object, which the consumer creates after source admission
        // and before any RAM access or native call.
        Ok(())
    }

    fn split_m0_resources(&mut self) -> anyhow::Result<M0ExecutionResources<'_>> {
        anyhow::ensure!(
            matches!(
                self.cohort,
                InstalledCohort::M0Read64
                    | InstalledCohort::El1Integer
                    | InstalledCohort::El1Platform
            ),
            "branch cohort cannot lend M0 data resources"
        );
        self.check_resources()?;
        Ok(M0ExecutionResources {
            sources: self.sources,
            platform: self.platform,
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
                InstalledCohort::El1DirectBranch
                    | InstalledCohort::El1Integer
                    | InstalledCohort::El1Platform
            ),
            "M0 data cohort cannot lend branch resources"
        );
        self.check_resources()?;
        Ok(El1ExecutionResources {
            sources: self.sources,
            platform: self.platform,
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

    fn split_el1_system_effect_resources(
        &mut self,
    ) -> anyhow::Result<super::El1SystemEffectResources<'_>> {
        anyhow::ensure!(
            self.cohort == InstalledCohort::El1Platform,
            "System completion requires original fixed fresh platform"
        );
        self.check_resources()?;
        Ok(super::El1SystemEffectResources {
            sources: &*self.sources,
            controls: &*self.controls,
            platform: self
                .platform
                .ok_or_else(|| anyhow::anyhow!("System completion original platform absent"))?,
            checks: M0ExecutionChecks {
                execution: self.execution,
                pending: &self.pending,
                memory: &*self.memory,
                endpoint: self.endpoint,
                address_space: self.address_space,
            },
        })
    }

    fn split_el1_context_resources(&mut self) -> anyhow::Result<super::El1ContextResources<'_>> {
        anyhow::ensure!(
            self.cohort == InstalledCohort::El1Platform,
            "context requires original fixed platform cohort"
        );
        self.check_resources()?;
        Ok(super::El1ContextResources {
            sources: &mut *self.sources,
            controls: &mut *self.controls,
            platform: self
                .platform
                .ok_or_else(|| anyhow::anyhow!("context platform absent"))?,
            memory: &mut *self.memory,
            execution: self.execution,
            pending: &self.pending,
            endpoint: self.endpoint,
            address_space: self.address_space,
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
            "M0 backend has no helper service; PE must remain blocked"
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
