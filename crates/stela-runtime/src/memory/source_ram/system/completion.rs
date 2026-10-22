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
    pub(crate) fn fail(&self) {
        self.service.fail();
    }
}
impl RegisteredSystemRam {
    /// Called only by the engine with actual native frames recovered/held and
    /// synchronous device work completed. No data/controller effect occurs.
    pub(crate) fn try_service(&self) -> Result<Option<CanonicalRamService<'_>>, MemoryStatus> {
        self.domain
            .try_all_writer_service()
            .map(|service| service.map(|service| CanonicalRamService { ram: self, service }))
    }
}
