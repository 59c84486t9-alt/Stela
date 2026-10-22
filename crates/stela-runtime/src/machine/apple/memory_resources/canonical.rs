//! Live synchronous RAM visibility for the cacheless Stela frontend. This
//! never settles DRAM timing, clock/power or an outstanding controller request.
use super::*;
use crate::memory::{CanonicalRamService, RegisteredSystemRam};
use alloc::sync::Arc;

impl Prepared {
    /// Retain the actual canonical guest reservations before publishing this
    /// resource. Registration's all-writer contract excludes raw/unjoined DMA;
    /// the engine must still recover every native frame and finish synchronous
    /// device work before lending a live CanonicalRamService for a read.
    pub fn with_registered_ram(
        mut self,
        ram: Arc<RegisteredSystemRam>,
    ) -> Result<Self, &'static str> {
        if self.ram.is_some() {
            return Err("prepared memory resource already owns its canonical RAM association");
        }
        if self.router.controller.cache_resource() != mcc::policy::CacheResource::Cacheless {
            return Err("native synchronous RAM frontend requires the actual cacheless resource");
        }
        self.ram = Some(ram);
        Ok(self)
    }

    /// Effect-free classification only. Unknown widths/offsets retain the
    /// ordinary explicit MMIO refusal; this creates no completion authority.
    pub fn requires_ram_read(&self, offset: u64, width: Width) -> bool {
        offset < self.ptd_offset() && mcc::is_drain_word(offset % mcc::APERTURE_BYTES, width)
    }

    /// Observe an empty synchronous Stela RAM frontend while its exact native
    /// owners, mapping generation and all physical writer gates remain held.
    /// No value is saved into the ordinary register bank: after this borrow
    /// ends a fresh drain read needs another actual engine service.
    ///
    /// # Safety
    /// The complete producer set is the actual stopped native workers and
    /// exclusively borrowed synchronous Host/Devices whose transfer completed
    /// before this borrow. No other host publisher, queued job, firmware or
    /// asynchronous DMA producer may exist, even if it uses registered writer
    /// gates. Free gates alone do not establish an empty submission queue.
    pub unsafe fn read_ram_drain(
        &self,
        offset: u64,
        width: Width,
        memory: &CanonicalRamService<'_>,
    ) -> Result<u64, &'static str> {
        if !self.requires_ram_read(offset, width) {
            return Err("canonical RAM read is not an original DCS drain word");
        }
        self.router.target(offset)?;
        let ram = self
            .ram
            .as_ref()
            .ok_or("joint memory resource has no canonical RAM owner")?;
        if !memory.belongs_to(ram) {
            return Err("DCS drain borrowed a different canonical RAM owner");
        }
        memory
            .validate_current()
            .map_err(|_| "DCS drain lost its actual RAM generation/writer hold")?;
        // A request to change channel configuration or gating is not a
        // synchronous RAM copy. Its unknown readback must remain unresolved;
        // memory exclusion cannot stand in for that missing backend effect.
        if self.router.controller.observations().iter().any(|word| {
            !mcc::is_drain_word(word.offset, Width::Word) && word.known != u64::from(u32::MAX)
        }) {
            return Err("DCS drain cannot settle an outstanding MCC/DRAM/power request");
        }
        // Every admitted frontend transfer is synchronous. The engine
        // completed device copyout and fenced the actual CPU owners before
        // obtaining this same mapping/native/all-writer exclusion. No frontend
        // transaction remains in flight, and none can enter while borrowed.
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        memory::{ReservedSystemRamRange, source_ram::system::fixture},
        platform::apple::interrupt::InterruptLatch,
    };
    use core::{cell::UnsafeCell, ptr::NonNull};

    #[repr(C, align(16))]
    struct Storage(UnsafeCell<[u8; 128]>);
    // SAFETY: after registration these bytes have no Rust references and
    // every reached access participates in the actual fixture memory system.
    unsafe impl Sync for Storage {}

    fn ram() -> Arc<RegisteredSystemRam> {
        let storage = Arc::new(Storage(UnsafeCell::new([0; 128])));
        let range = ReservedSystemRamRange {
            source_pa: 0x800000000,
            host_pa: 0x400000,
            host_base: NonNull::new(storage.0.get().cast()).unwrap(),
            bytes: 128,
        };
        // SAFETY: the fixture retains these stable disjoint bytes. This tests
        // identity/exclusion, not production CPL0/native owner admission.
        Arc::new(unsafe { fixture(&[range], storage) })
    }

    fn read(
        owner: &Prepared,
        offset: u64,
        width: Width,
        memory: &CanonicalRamService<'_>,
    ) -> Result<u64, &'static str> {
        // SAFETY: these single-thread fixtures have no native frames, jobs,
        // background publishers or DMA; the borrowed memory is their complete
        // closed producer domain. This does not qualify a production host.
        unsafe { owner.read_ram_drain(offset, width, memory) }
    }

    #[test]
    fn drain_requires_the_same_live_ram_and_never_leaves_a_ready_register() {
        let ram = ram();
        let owner = super::super::tests::prepared()
            .with_registered_ram(Arc::clone(&ram))
            .unwrap();
        let other = self::ram();
        let foreign = other.try_service().unwrap().unwrap();
        assert!(read(&owner, mcc::DCS_BASE + 0xa40, Width::Word, &foreign).is_err());
        drop(foreign);
        let memory = ram.try_service().unwrap().unwrap();
        for aperture in 0..2 {
            for channel in 0..mcc::CHANNELS {
                let offset = aperture * mcc::APERTURE_BYTES
                    + mcc::DCS_BASE
                    + u64::from(channel) * mcc::DCS_STRIDE
                    + 0xa40;
                assert!(owner.requires_ram_read(offset, Width::Word));
                assert_eq!(read(&owner, offset, Width::Word, &memory), Ok(0));
                assert!(read(&owner, offset, Width::Double, &memory).is_err());
            }
        }
        drop(memory);
        let mut owner = owner;
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert!(
            owner
                .read(mcc::DCS_BASE + 0xa40, Width::Word, &mut access)
                .is_err()
        );
        // A live RAM borrow also cannot turn an accepted but unimplemented
        // dynamic-DRAM request into a completed controller transition.
        owner
            .write(mcc::DCS_BASE + 0x13cc, Width::Word, 0xffff0000, &mut access)
            .unwrap();
        let memory = ram.try_service().unwrap().unwrap();
        assert!(read(&owner, mcc::DCS_BASE + 0xa40, Width::Word, &memory).is_err());
    }
}
