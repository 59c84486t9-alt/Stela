//! Memory attributes of one domain generation.

#[cfg(feature = "std")]
use crate::memory::domain::MemoryExecutionLoan;
use crate::memory::domain::{DataPolicy, MemoryDomain, MemoryThread};
use alloc::sync::Arc;
use stela_compiler::context::memory::MemoryStatus;

/// Opaque source mapping authority. It retains the exact domain generation;
/// equal ASIDs, host write-back storage or equivalent-looking views cannot mint
/// or match this capability. Any mapping publication requires fresh complete
/// source resolution, even when the domain Arc and unaffected MappingIds persist.
pub struct SourceNormalWbDomain {
    domain: Arc<MemoryDomain>,
    generation: u64,
}

impl core::fmt::Debug for SourceNormalWbDomain {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SourceNormalWbDomain")
            .finish_non_exhaustive()
    }
}

impl SourceNormalWbDomain {
    /// Bind the source mapping owner's resolved architecture contract.
    ///
    /// # Safety
    /// Every domain view must represent the actual effective ARM Normal
    /// Write-Back mapping over the same virtual range and physical backing
    /// offset. Guest permissions, shareability and allocation-tag attributes
    /// must agree with the registered domain attributes. This is a source
    /// translation/creation authority contract, not a host cacheability claim.
    /// Unmapped ranges must remain unmapped. The caller must exclude effective
    /// translation restrictions, optional modes and memory side effects that
    /// the domain cannot represent. Source resolution and this capture must
    /// occur under the actual mapping owner's serialization after a successful
    /// transaction has published all new views and its generation. The source
    /// resolution must cover the entire resulting domain, including unchanged
    /// views. A copied epoch, host attributes or a successful host mprotect do
    /// not establish this contract. Changed generations must be retired before
    /// native rights changes; unchanged MappingIds remain registered unchanged.
    /// Supplied FixedProcessMemoryControls must describe this same fresh
    /// software machine's applicable controls and lower namespace. Source page
    /// walks/AF/dirty updates and higher-level policy are not implemented here.
    /// Existing native backing and invocation safety contracts still apply.
    /// The actual provider's execution loan must exclude mapping transactions
    /// from source validation through body finalization and PC settlement.
    pub unsafe fn from_source_resolved(domain: Arc<MemoryDomain>) -> Result<Self, MemoryStatus> {
        let generation = domain.generation()?;
        Ok(Self { domain, generation })
    }

    pub(super) fn same_domain(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.domain, &other.domain)
    }

    pub(super) fn is_current(&self) -> Result<bool, MemoryStatus> {
        Ok(self.domain.generation()? == self.generation)
    }

    /// Validate this original source generation while its actual counted domain
    /// pin remains borrowed. No new pin or PE/thread identity is created.
    #[cfg(feature = "std")]
    pub(super) fn check_current_execution<P: DataPolicy>(
        &self,
        thread: &MemoryThread<P>,
        execution: &MemoryExecutionLoan,
    ) -> Result<(), MemoryStatus> {
        if !self.matches(thread) || !execution.belongs_to(&self.domain) {
            return Err(MemoryStatus::Domain);
        }
        Ok(())
    }

    pub(super) fn matches<P: DataPolicy>(&self, thread: &MemoryThread<P>) -> bool {
        // The caller holds the actual domain execution loan before this check.
        // Unavailable/poisoned state fails closed, including same-Arc matches.
        thread.has_domain(&self.domain) && self.is_current().unwrap_or(false)
    }
}
