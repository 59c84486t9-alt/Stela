//! Disjoint ORIGINAL backend loans. Contextual hosted join; freestanding mounting remains unverified.
//!
//! This type supplies no NativeActive permission. The canonical Active borrows
//! it once from the same sealed backend, then keeps its actual context separate
//! from immutable source/control/thread borrows through session settlement.
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

/// All fields are borrowed directly from the original concrete M0Owner. No
/// resource bundle, raw pointer or caller implementation can construct this.
pub(crate) struct InstalledExecutionResources<'pe> {
    pub(in crate::blocks::retirement::checked) sources: &'pe InstalledM0Sources,
    pub(in crate::blocks::retirement::checked) controls: &'pe TranslationControls,
    pub(in crate::blocks::retirement::checked) memory: &'pe MemoryThread<MemoryControls>,
    pub(in crate::blocks::retirement::checked) context: &'pe mut ExecutionContext,
    pub(in crate::blocks::retirement::checked) checks: M0ExecutionChecks<'pe>,
}

pub(crate) type M0ExecutionResources<'pe> = InstalledExecutionResources<'pe>;
pub(crate) type El1ExecutionResources<'pe> = InstalledExecutionResources<'pe>;

/// Shared requalification excludes context so the original mutable context can
/// remain in the retained session. The original registry lease stays borrowed;
/// an empty queue or a copied register profile cannot replace this owner.
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
            "actual M0 memory namespace differs"
        );
        self.execution.check()?;
        self.pending
            .check_registry()
            .map_err(|error| anyhow::anyhow!("actual M0 producer registry: {error:?}"))?;
        self.memory
            .check_event_endpoint(self.endpoint)
            .map_err(|error| anyhow::anyhow!("actual M0 PE monitor: {error:?}"))?;
        outer
            .check_thread_domain(self.memory)
            .map_err(|error| anyhow::anyhow!("actual M0 outer domain: {error:?}"))?;
        // A physical-role domain intentionally refuses the ordinary EL0
        // validate_execution path. Actual M0 source/control/physical producers
        // qualify its access instead; do not call or weaken that generic gate.
        Ok(())
    }
}
