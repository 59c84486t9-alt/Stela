//! Live synchronous RAM visibility for the cacheless Stela frontend. This
//! never settles DRAM timing, clock/power or an outstanding controller request.
use super::*;
use crate::memory::{CanonicalRamService, RegisteredSystemRam};
use alloc::sync::Arc;

impl super::super::AppleDevices {
    /// Publish one prepared MCC/AMCC/PTD owner at its complete physical map.
    /// This is placement only: native execution must separately admit the
    /// registered RAM, stopped-worker reads, PMP services and source policy.
    /// A failed placement leaves the bus and its existing lock owner intact.
    pub fn add_memory_resources(&mut self, owner: Prepared) -> Result<(), alloc::string::String> {
        if self.memory_controller.is_some() {
            return Err("memory controller already has an actual owner".into());
        }
        if owner.ram.is_none() {
            return Err("prepared memory placement requires its canonical RAM association".into());
        }
        let bindings = owner.bindings();
        let device = self
            .bus
            .install(alloc::boxed::Box::new(owner), &bindings)
            .map_err(|error| alloc::format!("joint memory resource placement: {error:?}"))?;
        self.memory_controller = Some(device);
        Ok(())
    }
}

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
    /// before this borrow. Retained synchronous device requests may remain
    /// queued only when the actual exclusive Devices borrow prevents their
    /// transfer from advancing or reentering throughout the service. No other
    /// independently advancing host job, firmware or asynchronous DMA producer
    /// may publish, even through registered gates. Free gates or transfer(Ok)
    /// alone do not establish that exclusion or an empty I/O command queue.
    pub unsafe fn read_ram_drain(
        &self,
        offset: u64,
        width: Width,
        memory: &CanonicalRamService<'_>,
    ) -> Result<u64, &'static str> {
        if !self.requires_ram_read(offset, width) {
            return Err("canonical RAM read is not an original DCS drain word");
        }
        let (aperture, within) = self.router.target(offset)?;
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
        self.router.controller.drain_control(aperture as u8, within).map(u64::from)
    }

    /// Consume the original low-byte clear under the exact same live owner as
    /// the drain read. The high bits belong to the initialized control image;
    /// memory quiescence is never used to invent their value.
    ///
    /// # Safety
    /// The complete closed synchronous producer contract of read_ram_drain
    /// holds for this entire operation. The caller retains all actual native
    /// workers and excludes every independently advancing publisher through
    /// consumption; paused synchronous requests retain their actual owner.
    pub unsafe fn write_ram_drain(
        &self,
        offset: u64,
        width: Width,
        value: u64,
        now: u64,
        memory: &CanonicalRamService<'_>,
    ) -> Result<(), &'static str> {
        // SAFETY: caller retains exactly the same closed producer set/guard.
        let expected = unsafe { self.read_ram_drain(offset, width, memory) }?;
        if u64::from(value as u32) != expected {
            return Err("DCS flush must preserve high16 and clear both low bytes");
        }
        let (aperture, within) = self.router.target(offset)?;
        self.router.controller.record_ram_drain(aperture as u8, within, value as u32, now)
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

    #[test]
    fn consuming_drain_write_requires_its_real_owner_and_preserves_later_refusals() {
        let ram = ram();
        let mut owner = super::super::tests::prepared()
            .with_registered_ram(Arc::clone(&ram)).unwrap();
        let foreign = self::ram();
        let other = foreign.try_service().unwrap().unwrap();
        let offset = mcc::DCS_BASE + mcc::DCS_DRAIN;
        // SAFETY: this fixture has no other producers, frames or DMA. Each
        // call retains its exact actual all-writer borrow through completion.
        unsafe {
            assert!(owner.write_ram_drain(offset, Width::Word, 0, 9, &other).is_err());
        }
        drop(other);
        let memory = ram.try_service().unwrap().unwrap();
        unsafe {
            assert!(owner.write_ram_drain(offset, Width::Double, 0, 9, &memory).is_err());
            assert!(owner.write_ram_drain(offset, Width::Word, 1, 9, &memory).is_err());
            assert!(owner.write_ram_drain(offset, Width::Word, 0x10000, 9, &memory).is_err());
            owner.write_ram_drain(offset, Width::Word, 0, 9, &memory).unwrap();
        }
        let requests = owner.controller().requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].kind, mcc::RequestKind::Drain { channel: 0 });
        assert_eq!(read(&owner, offset, Width::Word, &memory), Ok(0));
        drop(memory);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 10, &mut latch);
        assert!(owner.write(offset, Width::Word, 0, &mut access).is_err());
        assert!(owner.read(offset, Width::Word, &mut access).is_err());
        owner.write(mcc::DCS_BASE + 0x13cc, Width::Word, 0xffff0000, &mut access).unwrap();
        let memory = ram.try_service().unwrap().unwrap();
        unsafe {
            assert!(owner.write_ram_drain(offset, Width::Word, 0, 11, &memory).is_err());
        }
        assert_eq!(owner.controller().requests().len(), 2);
    }

    #[test]
    fn placement_requires_registered_ram_and_keeps_one_complete_owner() {
        use crate::machine::{Devices, apple::AppleDevices};
        let mut devices = AppleDevices::new();
        assert!(
            devices
                .add_memory_resources(super::super::tests::prepared())
                .is_err()
        );
        assert!(devices.memory_controller.is_none());
        let owner = super::super::tests::prepared()
            .with_registered_ram(ram())
            .unwrap();
        let bindings = owner.bindings();
        devices.add_memory_resources(owner).unwrap();
        let id = devices.memory_controller.unwrap();
        for (physical, bytes, offset) in bindings {
            assert_eq!(devices.bus.route(physical, Width::Word), Ok((id, offset)));
            assert_eq!(
                devices.bus.route(physical + bytes - 4, Width::Word),
                Ok((id, offset + bytes - 4))
            );
        }
        assert_eq!(devices.memory_lock(), None);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        devices
            .bus
            .write(0x200000688, Width::Word, 1, &mut access)
            .unwrap();
        assert_eq!(devices.memory_lock(), Some((0x800004000, 0x800007fff)));
        let owner = super::super::tests::prepared()
            .with_registered_ram(ram())
            .unwrap();
        assert!(devices.add_memory_resources(owner).is_err());
        assert_eq!(devices.memory_controller, Some(id));
    }

    #[test]
    fn actual_drain_routes_require_a_live_service_before_any_ordinary_read() {
        use crate::machine::{Devices, apple::AppleDevices, engine::DeviceReadShape};
        let mut devices = AppleDevices::new();
        let owner = super::super::tests::prepared()
            .with_registered_ram(ram())
            .unwrap();
        let controller = owner.controller().clone();
        devices.add_memory_resources(owner).unwrap();
        let drain = 0x200000000 + mcc::DCS_BASE + 0xa40;
        assert!(devices.requires_canonical_read(0, drain, DeviceReadShape::Scalar { bytes: 4 }));
        assert!(devices.requires_canonical_read(0, drain - 4, DeviceReadShape::Pair { bytes: 4 }));
        for (physical, bytes) in [(drain, 8), (drain + 4, 4), (0x4000, 4)] {
            assert!(!devices.requires_canonical_read(
                0,
                physical,
                DeviceReadShape::Scalar { bytes }
            ));
        }
        let before = controller.observations();
        assert!(devices.read(0, drain, 4, 0).is_err());
        assert_eq!(controller.observations(), before);
        assert!(devices.pending_service().is_none());
    }

    #[test]
    fn conflicting_publication_bank_does_not_publish_partial_memory_apertures() {
        use crate::machine::apple::AppleDevices;
        let mut devices = AppleDevices::new();
        let owner = super::super::tests::prepared()
            .with_registered_ram(ram())
            .unwrap();
        let bindings = owner.bindings();
        let publication = owner.publication_bank().clone();
        let (physical, bytes, offset) = owner.publication_binding();
        let id = devices
            .bus
            .install(alloc::boxed::Box::new(publication), &[(physical, bytes, 0)])
            .unwrap();
        assert!(devices.add_memory_resources(owner).is_err());
        assert!(devices.memory_controller.is_none());
        assert_eq!(devices.bus.route(physical, Width::Word), Ok((id, 0)));
        for &(physical, _, _) in &bindings[..bindings.len() - 1] {
            assert!(devices.bus.route(physical, Width::Word).is_err());
        }
        assert_ne!(offset, 0);
    }
}
