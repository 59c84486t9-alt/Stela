//! Independent completion peer for the original model requester and route.
use super::*;
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DomainMapping},
    pages::DmaPages,
};
use core::ops::Range;
pub(super) struct Payload(pub(super) Arc<Mutex<Hardware>>);
// SAFETY: synchronous isolated device/root model. It rejects every mapping;
// literal DMA is the separately kept RegionAllocator peer in the parent suite.
// A drain only acknowledges completed RAM effects from that same device model.
unsafe impl DmaDomain for Payload {
    unsafe fn map(
        &self,
        _: &DmaPages,
        _: Direction,
        _: u64,
    ) -> core::result::Result<DomainMapping, DmaError> {
        Err(DmaError::MappingFailed)
    }
    unsafe fn unmap(&self, _: DomainMapping) -> core::result::Result<(), DmaError> {
        Err(DmaError::Unmapped)
    }
    unsafe fn sync_for_device(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> core::result::Result<(), DmaError> {
        Err(DmaError::Unmapped)
    }
    unsafe fn sync_for_cpu(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> core::result::Result<(), DmaError> {
        Err(DmaError::Unmapped)
    }
    unsafe fn drain_posted_writes(&self) -> core::result::Result<(), DmaError> {
        let mut h = self.0.lock().unwrap();
        assert!(!h.bt.armed);
        assert_eq!(h.bt.reg(FUNC) & (ENABLE | MAC_INIT | FUNC_INIT), 0);
        assert_eq!(h.bt.reg(BOOT), 0);
        h.payload_drains += 1;
        if h.fail_payload {
            Err(DmaError::InvalidationFailed)
        } else {
            Ok(())
        }
    }
}
struct DeliveryDomain {
    hardware: Arc<Mutex<Hardware>>,
    thread: std::thread::ThreadId,
}
// SAFETY: same original synchronous device/root peer and actual owner thread;
// this fixture has no physical/remapping authority or native mode transition.
unsafe impl irq::posted_msi::NotificationDomain for DeliveryDomain {
    fn check(&self) -> core::result::Result<(), irq::posted_msi::Error> {
        if self.thread != std::thread::current().id() {
            return Err(irq::posted_msi::Error::Context);
        }
        let hardware = self.hardware.lock().unwrap();
        if hardware.config_drops != 0 || hardware.register_drops != 0 {
            return Err(irq::posted_msi::Error::RootFailed);
        }
        Ok(())
    }
}
struct Delivery {
    hardware: Arc<Mutex<Hardware>>,
    owner: std::thread::ThreadId,
}
// SAFETY: original synchronous isolated route peer, with independent payload
// and root completion controls, no native configuration pin or DMA attachment.
unsafe impl irq::posted_msi::RouteOwner for Delivery {
    fn allocate(
        &mut self,
        target: &irq::CpuTarget<'_>,
    ) -> core::result::Result<irq::MsiMessage, irq::posted_msi::AllocationError> {
        target.check_current().map_err(|_| {
            irq::posted_msi::AllocationError::Unexposed(irq::posted_msi::Error::Context)
        })?;
        let target = target.descriptor();
        let message = irq::MsiMessage {
            address: 0xfee0_0000 | u64::from(target.destination) << 12,
            data: u32::from(target.vector),
        };
        assert_eq!(message.address, 0xfee01000);
        assert_eq!(message.data, u32::from(irq::FIRST_VECTOR));
        let mut h = self.hardware.lock().unwrap();
        assert!(h.msi_message.replace(message).is_none());
        if h.fail_msi_bind {
            Err(irq::posted_msi::AllocationError::Uncertain(
                irq::posted_msi::Error::RootFailed,
            ))
        } else {
            Ok(message)
        }
    }
    fn validate(&self) -> core::result::Result<(), irq::posted_msi::Error> {
        if self.owner != std::thread::current().id() {
            Err(irq::posted_msi::Error::Context)
        } else {
            Ok(())
        }
    }
    fn notification_domain(
        &self,
    ) -> core::result::Result<Arc<dyn irq::posted_msi::NotificationDomain>, irq::posted_msi::Error>
    {
        self.validate()?;
        // Original resource custody is live before route allocation; binding
        // itself is installed before the guard enters a LIVE Slot.
        Ok(Arc::new(DeliveryDomain {
            hardware: self.hardware.clone(),
            thread: self.owner,
        }))
    }
    unsafe fn strong_fence(&mut self) -> core::result::Result<(), irq::posted_msi::Error> {
        self.validate()?;
        let mut h = self.hardware.lock().unwrap();
        assert!(h.payload_drains > 0);
        assert!(!h.bt.armed);
        assert!(h.msi_message.is_some());
        h.msi_drains += 1;
        if h.fail_posted_msi {
            Err(irq::posted_msi::Error::RootFailed)
        } else {
            Ok(())
        }
    }
    unsafe fn release_endpoint(
        &mut self,
        proof: &irq::posted_msi::EndpointRetirement<'_>,
    ) -> core::result::Result<(), irq::posted_msi::Error> {
        self.validate()?;
        assert!(proof.requester().is_none());
        Ok(())
    }
}
pub(super) fn completion(hardware: Arc<Mutex<Hardware>>) -> irq::posted_msi::MsiRoute {
    // SAFETY: bounded no-native-pin test peer above; not NativeServices and
    // cannot supply an Attachment or a shared reset retirement receipt.
    unsafe {
        irq::posted_msi::MsiRoute::bounded_fixture(Box::new(Delivery {
            hardware,
            owner: std::thread::current().id(),
        }))
    }
}

#[test]
fn missing_notification_admission_refuses_before_source_programming() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut inputs, h, _, _) = inputs();
    inputs.msi_route = irq::posted_msi::MsiRoute::unavailable();
    // SAFETY: original bounded device model; no native capability is minted.
    let platform =
        unsafe { native::NativePlatform::new(inputs) }.unwrap_or_else(|(e, _)| panic!("{e:?}"));
    let mut t = Transport::new(platform, &mut dma).unwrap();
    assert!(t.start().is_err());
    assert!(h.lock().unwrap().msi_message.is_none());
    drop(t);
    let h = h.lock().unwrap();
    assert_eq!(h.msi_drains, 0);
    assert_eq!((h.config_drops, h.bar_drops, h.register_drops), (0, 0, 0));
}
#[test]
fn independent_fabric_pending_does_not_substitute_for_action_or_payload_join() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, h, registry, _) = attach(&mut dma);
    t.start().unwrap();
    h.lock().unwrap().fail_posted_msi = true;
    t.close().unwrap();
    assert!(registry.dispatch(irq::FIRST_VECTOR)); // ordinary unbound EOI only
    drop(t);
    let h = h.lock().unwrap();
    assert_eq!((h.payload_drains, h.msi_drains), (1, 0));
    assert_eq!((h.config_drops, h.bar_drops, h.register_drops), (1, 1, 1));
}
#[test]
fn payload_failure_does_not_claim_posted_interrupt_completion() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, h, _, _) = attach(&mut dma);
    t.start().unwrap();
    h.lock().unwrap().fail_payload = true;
    assert!(t.close().is_err());
    drop(t);
    let h = h.lock().unwrap();
    assert_eq!(h.payload_drains, 1);
    assert_eq!(h.msi_drains, 0);
    assert_eq!((h.config_drops, h.bar_drops, h.register_drops), (0, 0, 0));
}
#[test]
fn terminal_endpoint_close_orders_payload_before_action_and_native_resources() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, h, registry, _) = attach(&mut dma);
    t.start().unwrap();
    {
        let h = h.lock().unwrap();
        assert_eq!((h.payload_drains, h.msi_drains), (0, 0));
    }
    t.close().unwrap();
    assert!(registry.dispatch(irq::FIRST_VECTOR));
    drop(t);
    let h = h.lock().unwrap();
    assert_eq!((h.payload_drains, h.msi_drains), (1, 0));
    assert!(h.cpu_after_payload > 0);
    assert_eq!((h.config_drops, h.bar_drops, h.register_drops), (1, 1, 1));
}

#[test]
fn failed_route_binding_keeps_its_attempted_root_without_delivery_receipt() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (inputs, h, _, _) = inputs();
    h.lock().unwrap().fail_msi_bind = true;
    // SAFETY: isolated same-function model with an injected root-bind failure.
    let platform =
        unsafe { native::NativePlatform::new(inputs) }.unwrap_or_else(|(e, _)| panic!("{e:?}"));
    let mut t = Transport::new(platform, &mut dma).unwrap();
    assert!(t.start().is_err());
    assert_eq!(t.state(), State::Failed);
    drop(t);
    let h = h.lock().unwrap();
    assert!(h.msi_message.is_some());
    assert_eq!(h.msi_drains, 0);
    assert_eq!((h.config_drops, h.bar_drops, h.register_drops), (0, 0, 0));
}
