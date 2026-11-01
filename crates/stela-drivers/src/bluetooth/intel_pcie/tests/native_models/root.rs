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
struct Delivery(Arc<Mutex<Hardware>>);
// SAFETY: original synchronous route peer. Binding checks the registry's exact
// model message; posted interrupt completion is independent of payload/CPU IO.
unsafe impl irq::posted_msi::DeliveryOwner for Delivery {
    fn bind_route(
        &mut self,
        message: irq::MsiMessage,
    ) -> core::result::Result<(), irq::posted_msi::Error> {
        assert_eq!(message.address, 0xfee01000);
        assert_eq!(message.data, u32::from(irq::FIRST_VECTOR));
        let mut h = self.0.lock().unwrap();
        assert!(h.msi_message.replace(message).is_none());
        if h.fail_msi_bind {
            Err(irq::posted_msi::Error::RootFailed)
        } else {
            Ok(())
        }
    }
    unsafe fn drain_posted_msi(&self) -> core::result::Result<(), irq::posted_msi::Error> {
        let mut h = self.0.lock().unwrap();
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
}
pub(super) fn completion(h: Arc<Mutex<Hardware>>) -> irq::posted_msi::MsiCompletion {
    irq::posted_msi::MsiCompletion::model(Box::new(Delivery(h)))
}
#[test]
fn missing_or_failed_posted_completion_keeps_armed_route_and_all_owners() {
    for unavailable in [false, true] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut inputs, h, registry, _) = inputs();
        if unavailable {
            inputs.msi_completion = irq::posted_msi::MsiCompletion::unavailable();
        }
        // SAFETY: explicit original synchronous device/root/IRQ fixture.
        let platform =
            unsafe { native::NativePlatform::new(inputs) }.unwrap_or_else(|(e, _)| panic!("{e:?}"));
        let mut t = Transport::new(platform, &mut dma).unwrap();
        t.start().unwrap();
        if !unavailable {
            h.lock().unwrap().fail_posted_msi = true;
        }
        let error = t
            .close()
            .expect_err("independent posted completion required");
        assert_eq!(
            error,
            Error::Native(native::Error::Delivery(if unavailable {
                irq::posted_msi::Error::RootUnavailable
            } else {
                irq::posted_msi::Error::RootFailed
            }))
        );
        assert!(!t.retired);
        assert_eq!(t.state(), State::Failed);
        let writes = h.lock().unwrap().bt.writes.len();
        assert_eq!(t.close(), Err(error));
        assert!(registry.dispatch(irq::FIRST_VECTOR));
        drop(t);
        let h = h.lock().unwrap();
        assert_eq!(h.payload_drains, 1);
        assert_eq!(h.msi_drains, usize::from(!unavailable));
        assert_eq!((h.config_drops, h.bar_drops, h.register_drops), (0, 0, 0));
        assert_eq!(h.bt.writes.len(), writes);
    }
}
#[test]
fn payload_failure_does_not_claim_posted_interrupt_completion() {
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
fn successful_completion_orders_payload_then_posted_delivery_before_cpu_retirement() {
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, h, registry, _) = attach(&mut dma);
    t.start().unwrap();
    {
        let h = h.lock().unwrap();
        assert_eq!((h.payload_drains, h.msi_drains), (0, 0));
    }
    t.close().unwrap();
    assert!(!registry.dispatch(irq::FIRST_VECTOR));
    drop(t);
    let h = h.lock().unwrap();
    assert_eq!((h.payload_drains, h.msi_drains), (1, 1));
    assert!(h.cpu_after_delivery > 0);
    assert_eq!((h.config_drops, h.bar_drops, h.register_drops), (1, 1, 1));
}

#[test]
fn failed_route_binding_keeps_its_attempted_root_without_delivery_receipt() {
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
