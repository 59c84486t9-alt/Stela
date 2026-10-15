//! Source-resolved ARM memory attributes for one immutable memory domain.
//! Native storage eligibility is validated separately by the existing domain.

use crate::memory::domain::{DataPolicy, MemoryDomain, MemoryThread};
use std::sync::Arc;

/// Opaque source mapping authority. It retains the exact domain generation;
/// equal ASIDs, host write-back storage or equivalent-looking views cannot mint
/// or match this capability. Replacement mappings require a fresh witness.
pub struct SourceNormalWbDomain {
    domain: Arc<MemoryDomain>,
}

impl std::fmt::Debug for SourceNormalWbDomain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    /// the domain cannot represent, and keep the source resolution valid for
    /// the immutable domain lifetime (retiring/replacing it before changes).
    /// Supplied FixedProcessMemoryControls must describe this same fresh
    /// software machine's applicable controls and lower namespace. Source page
    /// walks/AF/dirty updates and higher-level policy are not implemented here.
    /// Existing native backing and invocation safety contracts still apply.
    pub unsafe fn from_source_resolved(domain: Arc<MemoryDomain>) -> Self {
        Self { domain }
    }

    pub(super) fn matches<P: DataPolicy>(&self, thread: &MemoryThread<P>) -> bool {
        thread.has_domain(&self.domain)
    }
}
