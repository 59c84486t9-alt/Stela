//! The M0 backend.
use super::super::super::software_async::NoAsyncSources;
use super::super::{
    NativeObservation,
    source::{BoundSource, Helper},
};
use super::resources::{El1ExecutionResources, M0ExecutionChecks, M0ExecutionResources};
use super::{HelperOutcome, Owner, ProcessEntryControls, sealed};
use super::{
    async_resources::AsyncResources,
    hosted_wait::{HostedWaitResources, WaitReply},
};
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
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
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
    El1HostedWait,
}

pub(crate) struct M0Owner<'pe> {
    cohort: InstalledCohort,
    address_space: u64,
    sources: &'pe mut InstalledM0Sources,
    controls: &'pe mut TranslationControls,
    execution: &'pe ProcessEntryControls,
    memory: &'pe mut MemoryThread<MemoryControls>,
    context: &'pe mut ExecutionContext,
    asynchronous: AsyncResources<'pe>,
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
            context,
            asynchronous: AsyncResources::NoSources { pending, endpoint },
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
            context,
            asynchronous: AsyncResources::NoSources { pending, endpoint },
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
            context,
            asynchronous: AsyncResources::NoSources { pending, endpoint },
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
            context,
            asynchronous: AsyncResources::NoSources { pending, endpoint },
            platform: Some(platform),
        };
        owner.check_resources()?;
        Ok(owner)
    }

    /// # Safety
    /// As for the other constructors; in addition the complete hosted registry,
    /// event endpoint and counter belong to this PE for its whole lifetime.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::blocks::retirement) unsafe fn fresh_el1_hosted_wait(
        address_space: u64,
        sources: &'pe mut InstalledEl1Sources,
        controls: &'pe mut TranslationControls,
        execution: &'pe ProcessEntryControls,
        memory: &'pe mut MemoryThread<MemoryControls>,
        context: &'pe mut ExecutionContext,
        wait: HostedWaitResources<'pe>,
        platform: &'pe super::super::el1_system::El1PlatformControls,
    ) -> anyhow::Result<Self> {
        let owner = Self {
            cohort: InstalledCohort::El1HostedWait,
            address_space,
            sources,
            controls,
            execution,
            memory,
            context,
            // Allocated once; waits, native calls and retirement reuse it.
            asynchronous: AsyncResources::HostedWait {
                wait: Box::new(wait),
                identification: platform.identification(),
            },
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
        self.asynchronous.check_resources()?;
        self.memory
            .check_event_endpoint(self.asynchronous.endpoint())
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
            | InstalledCohort::El1Platform
            | InstalledCohort::El1HostedWait => self.controls.validate_installed_el1_source(
                &self.sources.el1_scope().map_err(anyhow::Error::msg)?,
            ),
        }
        .map_err(anyhow::Error::msg)
    }
}

impl sealed::Concrete for M0Owner<'_> {}
impl Owner for M0Owner<'_> {
    #[cfg(feature = "std")]
    fn reacquire_wait_loan(
        &mut self,
    ) -> anyhow::Result<crate::memory::domain::ExecutionLoanAttempt> {
        self.asynchronous.check_wake_resources()?;
        self.memory
            .try_execution_loan()
            .map_err(|error| anyhow::anyhow!("hosted wake exclusion: {error:?}"))
    }
    fn system_retirement(
        &mut self,
        system: &SystemState,
    ) -> anyhow::Result<super::SystemRetirement> {
        self.asynchronous.system_retirement(system)
    }

    fn supports_profile(&self, profile: BlockProfile) -> bool {
        profile
            == match self.cohort {
                InstalledCohort::M0Read64 => {
                    BlockProfile::CheckedMemory(CheckedMemoryProfile::M0DeviceRamRead64Staged)
                }
                InstalledCohort::El1DirectBranch => BlockProfile::El1DirectBranchV1,
                InstalledCohort::El1Integer => BlockProfile::El1M0IntegerV1,
                InstalledCohort::El1Platform | InstalledCohort::El1HostedWait => {
                    BlockProfile::El1PlatformV1
                }
            }
    }

    fn execution_loan(&mut self) -> anyhow::Result<MemoryExecutionLoan> {
        use crate::memory::domain::ExecutionLoanAttempt;
        loop {
            match self
                .memory
                .try_execution_loan()
                .map_err(|error| anyhow::anyhow!("M0 exclusion: {error:?}"))?
            {
                ExecutionLoanAttempt::Acquired(loan) => return Ok(loan),
                // Only a hosted-wait PE shares its domain with a host service,
                // whose publication is short; wait for it as a wake does.
                #[cfg(feature = "std")]
                ExecutionLoanAttempt::ServiceBusy
                    if self.cohort == InstalledCohort::El1HostedWait =>
                {
                    std::thread::park_timeout(
                        crate::system::events::hosted::HOSTED_MAX_REQUESTED_SLEEP,
                    );
                }
                ExecutionLoanAttempt::ServiceBusy => {
                    anyhow::bail!("M0 exclusion: a host service holds the domain")
                }
            }
        }
    }

    fn prepare_source(
        &mut self,
        runtime: &mut crate::blocks::BlockRuntime,
        system: &SystemState,
        pc: stela_compiler::GuestAddress,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        self.asynchronous.check_native_boundary(system)?;
        system
            .check_lower_el_storage()
            .map_err(|error| anyhow::anyhow!("installed lower-EL source storage: {error:?}"))?;
        if !matches!(
            self.cohort,
            InstalledCohort::El1Integer
                | InstalledCohort::El1Platform
                | InstalledCohort::El1HostedWait
        ) {
            return Ok(());
        }
        self.check_resources()?;
        anyhow::ensure!(
            runtime.profile()
                == match self.cohort {
                    InstalledCohort::El1Platform | InstalledCohort::El1HostedWait =>
                        BlockProfile::El1PlatformV1,
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
        self.execution
            .check_snapshot(self.asynchronous.identification(), system)?;
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
                    InstalledCohort::El1Platform | InstalledCohort::El1HostedWait =>
                        BlockProfile::El1PlatformV1,
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
            InstalledCohort::El1Platform | InstalledCohort::El1HostedWait => {
                let intent = bound.el1_platform_intent()?;
                if self.cohort != InstalledCohort::El1HostedWait
                    && matches!(intent, stela_compiler::block::el1_platform::Intent::System(instruction)
                        if matches!(instruction.operation, stela_compiler::block::system::SystemOperation::Wait { .. }))
                {
                    anyhow::bail!("fixed no-source platform has no hosted wait resources");
                }
            }
        }
        if self.cohort == InstalledCohort::El1HostedWait {
            let scope = self.sources.el1_scope().map_err(anyhow::Error::msg)?;
            let reached = scope
                .physical_space()
                .fetch_el1_instruction(outer, self.controls, &scope, system, bound.entry.entry().0)
                .map_err(|error| anyhow::anyhow!("hosted wake source fetch: {error:?}"))?;
            bound
                .runtime
                .check_physical_source(
                    scope.installed_snapshot(),
                    crate::system::translation_controls::PhysicalFetch {
                        pc: reached.raw_pc(),
                        word: reached.word(),
                        physical_address: reached.physical_address(),
                        source_generation: bound.entry.generation(),
                    },
                    &reached,
                )
                .map_err(anyhow::Error::msg)?;
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
                    | InstalledCohort::El1HostedWait
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
                pending: &self.asynchronous,
                memory: &*self.memory,
                endpoint: self.asynchronous.endpoint(),
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
                    | InstalledCohort::El1HostedWait
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
                pending: &self.asynchronous,
                memory: &*self.memory,
                endpoint: self.asynchronous.endpoint(),
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
                pending: &self.asynchronous,
                memory: &*self.memory,
                endpoint: self.asynchronous.endpoint(),
                address_space: self.address_space,
            },
        })
    }

    fn split_el1_context_resources(&mut self) -> anyhow::Result<super::El1ContextResources<'_>> {
        anyhow::ensure!(
            matches!(
                self.cohort,
                InstalledCohort::El1Platform | InstalledCohort::El1HostedWait
            ),
            "EL1 context cohort unavailable"
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
            pending: &self.asynchronous,
            endpoint: self.asynchronous.endpoint(),
            address_space: self.address_space,
        })
    }

    fn split_el1_irq_resources(&mut self) -> anyhow::Result<super::El1IrqResources<'_>> {
        anyhow::ensure!(
            self.cohort == InstalledCohort::El1HostedWait,
            "IRQ requires hosted cohort"
        );
        self.check_resources()?;
        let platform = self
            .platform
            .ok_or_else(|| anyhow::anyhow!("IRQ platform absent"))?;
        let irq = self.asynchronous.irq_resources()?;
        Ok(super::El1IrqResources {
            sources: &mut *self.sources,
            controls: &mut *self.controls,
            platform,
            memory: &mut *self.memory,
            execution: self.execution,
            irq,
            address_space: self.address_space,
        })
    }
    fn prepare_wait(
        &mut self,
        bound: &BoundSource<'_>,
        instruction: stela_compiler::block::system::SystemInstruction,
        system: &SystemState,
        registers: &GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<WaitReply> {
        anyhow::ensure!(
            self.cohort == InstalledCohort::El1HostedWait,
            "fixed no-source cohort cannot enter hosted waits"
        );
        anyhow::ensure!(
            bound.wait_instruction()? == instruction,
            "wait source differs"
        );
        self.check_resources()?;
        outer
            .check_thread_domain(&*self.memory)
            .map_err(|error| anyhow::anyhow!("wait outer: {error:?}"))?;
        let (wait, identification) = self.asynchronous.hosted()?;
        wait.prepare_typed(
            instruction,
            self.controls,
            identification,
            self.execution,
            system,
            registers,
        )
    }
    #[cfg(feature = "std")]
    fn qualify_wake(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        registers: &mut GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.cohort == InstalledCohort::El1HostedWait,
            "non-hosted wake qualification"
        );
        self.asynchronous.check_wake_resources()?;
        self.qualify(bound, system, registers, outer)?;
        self.asynchronous.check_wake_resources()
    }
    fn abandon_wait(&mut self) {
        self.asynchronous.abandon_wait();
    }
    fn prepare_hosted_counter(
        &mut self,
        bound: &BoundSource<'_>,
        instruction: stela_compiler::block::system::SystemInstruction,
        system: &SystemState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<super::hosted_wait::HostedCounterRead> {
        anyhow::ensure!(
            self.cohort == InstalledCohort::El1HostedWait,
            "no-source cohort has no hosted counter"
        );
        let stela_compiler::block::el1_platform::Intent::System(original) =
            bound.el1_platform_intent()?
        else {
            anyhow::bail!("source is not a hosted counter System request");
        };
        anyhow::ensure!(original == instruction, "hosted counter source differs");
        self.check_resources()?;
        outer
            .check_thread_domain(&*self.memory)
            .map_err(|error| anyhow::anyhow!("counter outer: {error:?}"))?;
        let platform = self
            .platform
            .ok_or_else(|| anyhow::anyhow!("counter platform missing"))?;
        self.asynchronous
            .hosted()?
            .0
            .prepare_counter_read(instruction, platform, system)
    }
    #[cfg(feature = "std")]
    fn poll_wait(&mut self) -> anyhow::Result<WaitReply> {
        self.asynchronous.poll_wait()
    }
    fn wait_outcome(&self) -> anyhow::Result<crate::system::events::Outcome> {
        self.asynchronous.wait_outcome()
    }
    fn settle_wait(&mut self) -> anyhow::Result<()> {
        self.asynchronous.settle_wait()
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
        if self.cohort == InstalledCohort::El1HostedWait {
            self.qualify(_bound, _system, _registers, _outer)?;
            // Active samples the IRQ right after this WFx retires, before the
            // next instruction is fetched.
            self.asynchronous.check_resources()?;
            return Ok(());
        }
        anyhow::bail!("M0 requires its retained staged commit path")
    }
}
