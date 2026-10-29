//! A live canonical RAM borrow, not an MCC/DRAM/DMA completion receipt.
use super::*;
use crate::memory::domain::AllWriterService;

/// Keeps this exact registered reservation/view generation and every canonical
/// physical writer gate borrowed. It neither accesses bytes nor changes a
/// monitor. Native execution is excluded until drop. Unregistered DMA/direct
/// access is never admitted by this capability.
#[must_use]
pub struct CanonicalRamService<'a> {
    ram: &'a RegisteredSystemRam,
    service: AllWriterService<'a>,
}
impl CanonicalRamService<'_> {
    pub fn validate_current(&self) -> Result<(), MemoryStatus> {
        self.service.validate_current()
    }
    pub fn generation(&self) -> u64 {
        self.service.generation()
    }
    /// Identity comparison of the actual retained owner, not matching geometry.
    pub fn belongs_to(&self, ram: &RegisteredSystemRam) -> bool {
        core::ptr::eq(self.ram, ram)
    }
    /// Permanently fail this exact retained RAM domain and its physical-writer
    /// gate after an unqualified native fault. Future entry/service acquisition
    /// refuses; this cannot restore authority or manufacture completion.
    pub fn fail(&self) {
        self.service.fail();
    }
}
impl RegisteredSystemRam {
    /// Acquire an all-writer service borrow only when no registered native
    /// execution or physical writer is active. A busy owner returns `None`.
    /// This serializes canonical memory; it performs no controller or DMA
    /// completion and grants no access to unregistered physical writers.
    pub fn try_service(&self) -> Result<Option<CanonicalRamService<'_>>, MemoryStatus> {
        self.domain
            .try_all_writer_service()
            .map(|service| service.map(|service| CanonicalRamService { ram: self, service }))
    }
}
