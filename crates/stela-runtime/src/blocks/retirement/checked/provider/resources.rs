//! The disjoint resources a backend lends to one execution.
use super::super::super::software_async::NoAsyncSources;
use super::ProcessEntryControls;
use crate::{
    blocks::InstalledM0Sources,
    memory::{
        domain::{MemoryExecutionLoan, MemoryThread},
        policy::MemoryControls,
    },
    system::{events::EventEndpoint, translation_controls::TranslationControls},
};
use stela_compiler::context::ExecutionContext;

/// Every field is borrowed from the M0 owner.
pub(crate) struct InstalledExecutionResources<'pe> {
    pub(in crate::blocks::retirement::checked) sources: &'pe InstalledM0Sources,
    pub(in crate::blocks::retirement::checked) platform:
        Option<&'pe super::super::el1_system::El1PlatformControls>,
    pub(in crate::blocks::retirement::checked) controls: &'pe TranslationControls,
    pub(in crate::blocks::retirement::checked) memory: &'pe MemoryThread<MemoryControls>,
    pub(in crate::blocks::retirement::checked) context: &'pe mut ExecutionContext,
    pub(in crate::blocks::retirement::checked) checks: M0ExecutionChecks<'pe>,
}

pub(crate) type M0ExecutionResources<'pe> = InstalledExecutionResources<'pe>;
pub(crate) type El1ExecutionResources<'pe> = InstalledExecutionResources<'pe>;

/// Checks shared by every M0 attempt. The context is excluded so the mutable
/// context can stay in the session; the registry stays borrowed.
pub(in crate::blocks::retirement::checked) struct M0ExecutionChecks<'pe> {
    pub(super) execution: &'pe ProcessEntryControls,
    pub(super) pending: &'pe NoAsyncSources<'pe>,
    pub(super) memory: &'pe MemoryThread<MemoryControls>,
    pub(super) endpoint: &'pe EventEndpoint,
    pub(super) address_space: u64,
}

impl M0ExecutionChecks<'_> {
    pub(in crate::blocks::retirement::checked) fn check(
        &self,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.memory.address_space() == Some(self.address_space),
            "M0 memory namespace differs"
        );
        self.execution.check()?;
        self.pending
            .check_registry()
            .map_err(|error| anyhow::anyhow!("M0 producer registry: {error:?}"))?;
        self.memory
            .check_event_endpoint(self.endpoint)
            .map_err(|error| anyhow::anyhow!("M0 PE monitor: {error:?}"))?;
        outer
            .check_thread_domain(self.memory)
            .map_err(|error| anyhow::anyhow!("M0 outer domain: {error:?}"))?;
        // A physical-role domain intentionally refuses the ordinary EL0
        // validate_execution path. Actual M0 source/control/physical producers
        // qualify its access instead; do not call or weaken that generic gate.
        Ok(())
    }
    pub(in crate::blocks::retirement::checked) fn post_retirement_el1(
        &self,
        outer: &MemoryExecutionLoan,
        scope: &crate::blocks::InstalledEl1SourceScope<'_>,
        controls: &TranslationControls,
        platform: &super::super::el1_system::El1PlatformControls,
        system: &crate::system::state::SystemState,
    ) -> anyhow::Result<()> {
        self.check(outer)?;
        scope
            .check_installed(controls, system)
            .map_err(anyhow::Error::msg)?;
        platform.context(system)?;
        Ok(())
    }
}

/// Publication and monitor resources, after native finalization.
pub(crate) struct El1ContextResources<'pe> {
    pub(in crate::blocks::retirement::checked) sources: &'pe mut InstalledM0Sources,
    pub(in crate::blocks::retirement::checked) controls: &'pe mut TranslationControls,
    pub(in crate::blocks::retirement::checked) platform:
        &'pe super::super::el1_system::El1PlatformControls,
    pub(in crate::blocks::retirement::checked) memory: &'pe mut MemoryThread<MemoryControls>,
    pub(in crate::blocks::retirement::checked) execution: &'pe ProcessEntryControls,
    pub(in crate::blocks::retirement::checked) pending: &'pe NoAsyncSources<'pe>,
    pub(in crate::blocks::retirement::checked) endpoint: &'pe EventEndpoint,
    pub(in crate::blocks::retirement::checked) address_space: u64,
}
impl El1ContextResources<'_> {
    pub(in crate::blocks::retirement::checked) fn check(
        &self,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.memory.address_space() == Some(self.address_space),
            "context namespace differs"
        );
        self.execution.check()?;
        self.pending
            .check_registry()
            .map_err(|error| anyhow::anyhow!("context producer registry: {error:?}"))?;
        self.memory
            .check_event_endpoint(self.endpoint)
            .map_err(|error| anyhow::anyhow!("context monitor: {error:?}"))?;
        outer
            .check_thread_domain(&*self.memory)
            .map_err(|error| anyhow::anyhow!("context original outer: {error:?}"))?;
        self.platform.check()?;
        self.controls
            .validate_installed_el1_source(&self.sources.el1_scope().map_err(anyhow::Error::msg)?)
            .map_err(anyhow::Error::msg)
    }
}

/// Borrowed only from the fixed fresh platform backend. The source/physical
/// envelope owns the complete RAM participants and all aliases for its entire
/// executable lifetime. NoAsyncSources below checks IRQ/debug producers only;
/// it is never the memory-participant closure proof.
pub(crate) struct El1SystemEffectResources<'pe> {
    pub(in crate::blocks::retirement::checked) sources: &'pe InstalledM0Sources,
    pub(in crate::blocks::retirement::checked) controls: &'pe TranslationControls,
    pub(in crate::blocks::retirement::checked) platform:
        &'pe super::super::el1_system::El1PlatformControls,
    pub(in crate::blocks::retirement::checked) checks: M0ExecutionChecks<'pe>,
}
