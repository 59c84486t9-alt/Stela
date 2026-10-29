//! Cold input publication through the same registered native RAM writer.
use super::Ram;
use stela_engine::memory::RegisteredSystemRam;

/// Borrowed only before the first guest instruction and native publication.
/// A physical pointer or legacy BareHost is not another permitted writer.
pub struct ColdRam<'a>(&'a RegisteredSystemRam);
impl<'a> ColdRam<'a> {
    /// # Safety
    /// Registration's all-writer contract holds. All raw input copies are
    /// finished; guest execution, DMA, native frame loans and other publishers
    /// are excluded for this borrow. The supplied RAM is the kept
    /// owner which will be installed in the Machine, not a shadow allocation.
    pub unsafe fn new(ram: &'a RegisteredSystemRam) -> Self {
        Self(ram)
    }
}
impl Ram for ColdRam<'_> {
    fn read(&mut self, physical: u64, bytes: &mut [u8]) -> bool {
        // SAFETY: cold exclusive publication and private LiveTree staging.
        unsafe { self.0.read_physical(physical, bytes) }.is_ok()
    }
    fn write(&mut self, physical: u64, bytes: &[u8]) -> bool {
        // SAFETY: private input bytes, closed producer contract, same writer.
        unsafe { self.0.publish_physical(physical, bytes) }.is_ok()
    }
    fn fence(&mut self) {
        // CPU publication ordering only; this is no MCC/cache flush ACK.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}
