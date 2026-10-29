//! Memory attributes of one domain generation.

#[cfg(feature = "std")]
use crate::memory::domain::MemoryExecutionLoan;
use crate::memory::domain::{DataPolicy, MemoryDomain, MemoryThread};
use alloc::sync::Arc;
use stela_compiler::context::memory::MemoryStatus;

/// The source mapping witness for one domain generation. Equal ASIDs,
/// write-back host storage or similar views cannot create or match it. Any
/// mapping publication requires a fresh, complete source resolution, even when
/// the domain and unaffected mappings persist.
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
    /// Bind the source mapping owner's resolved architectural contract.
    ///
    /// # Safety
    /// Every view in the domain must be the effective ARM Normal write-back
    /// mapping over the same virtual range and backing offset, with guest
    /// permissions, shareability and tag attributes matching the domain's.
    /// Unmapped ranges must stay unmapped, and the caller must exclude
    /// translation restrictions, optional modes and memory side effects the
    /// domain cannot represent. Resolution and this capture happen under the
    /// mapping owner's serialization, after a successful transaction has
    /// published all new views and its generation, and cover the entire domain,
    /// including unchanged views. Changed generations must be retired before
    /// native rights change. The supplied `FixedProcessMemoryControls` must
    /// describe the same software machine. The native backing and invocation
    /// contracts still apply, and the provider's execution borrow must exclude
    /// mapping transactions from source validation through finalization and PC
    /// settlement.
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

    /// Validate this source generation while the domain pin is borrowed.
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
        // The caller holds the domain execution borrow; an unavailable or
        // failed domain fails closed, even for the same Arc.
        thread.has_domain(&self.domain) && self.is_current().unwrap_or(false)
    }
}
