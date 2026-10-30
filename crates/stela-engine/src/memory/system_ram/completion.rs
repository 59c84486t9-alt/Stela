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
    /// Identity comparison of the owner, not matching geometry.
    pub fn belongs_to(&self, ram: &RegisteredSystemRam) -> bool {
        core::ptr::eq(self.ram, ram)
    }
    /// Permanently fail this exact RAM domain and its physical-writer
    /// gate after an unchecked native fault. Future entry/service acquisition
    /// refuses; this cannot restore permission or manufacture completion.
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

    /// [`Self::try_service`] for an owner that has stopped every PE: it
    /// waits out the holders left, which finish without it (another PE's
    /// monitor or writer gate while it applies its mail, or the native
    /// slice of one that woke from a wait before it parks).
    pub fn service(&self) -> Result<CanonicalRamService<'_>, MemoryStatus> {
        loop {
            if let Some(service) = self.try_service()? {
                return Ok(service);
            }
            core::hint::spin_loop();
        }
    }
}
