//! Bounded entry/source peer: actual config pins and independent action joins.
//! This model neither maps DMA nor qualifies native MSI-X entry authority.
use super::*;
use crate::bus::irq::{self, Handler, Platform, Request, RouteRequest, Source};
pub(super) struct Entry {
    number: u8,
    vector: Option<u8>,
    masked: bool,
    cause: bool,
    fenced: bool,
    joined: bool,
}
struct ActionDomain {
    pin: ConfigRetention,
    domain: Arc<Domain>,
    epoch: u64,
    thread: std::thread::ThreadId,
}
// SAFETY: bounded actual original RAM config/source custody and epoch only.
unsafe impl irq::posted_msi::NotificationDomain for ActionDomain {
    fn check(&self) -> Result<(), irq::posted_msi::Error> {
        if self.thread != std::thread::current().id()
            || self.epoch != self.domain._owner.0.action_epoch.load(Ordering::Acquire)
        {
            return Err(irq::posted_msi::Error::Context);
        }
        self.pin
            .check_live()
            .map_err(|_| irq::posted_msi::Error::Context)
    }
}
struct Action {
    domain: Arc<Domain>,
    pin: Option<ConfigRetention>,
    epoch: u64,
    thread: std::thread::ThreadId,
    vector: Option<u8>,
}
pub(super) fn owner(domain: Arc<Domain>) -> Result<Box<dyn irq::posted_msi::RouteOwner>, DmaError> {
    let pin = domain
        .binding
        .lock()
        .unwrap()
        .as_ref()
        .ok_or(DmaError::Unmapped)?
        .retention
        .retain_epoch()
        .map_err(|_| DmaError::MappingFailed)?;
    Ok(Box::new(Action {
        epoch: domain._owner.0.action_epoch.load(Ordering::Acquire),
        domain,
        pin: Some(pin),
        thread: std::thread::current().id(),
        vector: None,
    }))
}
// SAFETY: original synchronous test source/domain/config custody only. Every
// fence consults its actual masked/pending source record. No native I/O exists.
unsafe impl irq::posted_msi::RouteOwner for Action {
    fn allocate(
        &mut self,
        target: &irq::CpuTarget<'_>,
    ) -> Result<irq::MsiMessage, irq::posted_msi::AllocationError> {
        self.validate()
            .map_err(irq::posted_msi::AllocationError::Unexposed)?;
        target.check_current().map_err(|_| {
            irq::posted_msi::AllocationError::Unexposed(irq::posted_msi::Error::Context)
        })?;
        if self.vector.is_some() {
            return Err(irq::posted_msi::AllocationError::Unexposed(
                irq::posted_msi::Error::AlreadyBound,
            ));
        }
        let target = target.descriptor();
        self.domain
            ._owner
            .0
            .action_records
            .lock()
            .unwrap()
            .push(target.vector);
        self.vector = Some(target.vector);
        Ok(irq::MsiMessage {
            address: 0xfee0_0000 | u64::from(target.destination) << 12,
            data: u32::from(target.vector),
        })
    }
    fn validate(&self) -> Result<(), irq::posted_msi::Error> {
        if self.thread != std::thread::current().id()
            || self.epoch != self.domain._owner.0.action_epoch.load(Ordering::Acquire)
        {
            return Err(irq::posted_msi::Error::Context);
        }
        if let Some(pin) = &self.pin {
            pin.check_live()
                .map_err(|_| irq::posted_msi::Error::Context)?;
        }
        Ok(())
    }
    fn notification_domain(
        &self,
    ) -> Result<Arc<dyn irq::posted_msi::NotificationDomain>, irq::posted_msi::Error> {
        self.validate()?;
        let pin = self
            .pin
            .as_ref()
            .ok_or(irq::posted_msi::Error::Unbound)?
            .retain_epoch()
            .map_err(|_| irq::posted_msi::Error::Context)?;
        Ok(Arc::new(ActionDomain {
            pin,
            domain: self.domain.clone(),
            epoch: self.epoch,
            thread: self.thread,
        }))
    }
    unsafe fn strong_fence(&mut self) -> Result<(), irq::posted_msi::Error> {
        self.validate()?;
        let mut entries = self.domain._owner.0.action_entries.lock().unwrap();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.vector == self.vector && self.vector.is_some())
            .ok_or(irq::posted_msi::Error::Unbound)?;
        if !entry.masked || entry.cause {
            return Err(irq::posted_msi::Error::RootFailed);
        }
        entry.fenced = true;
        Ok(())
    }
    unsafe fn release_endpoint(
        &mut self,
        proof: &irq::posted_msi::EndpointRetirement<'_>,
    ) -> Result<(), irq::posted_msi::Error> {
        self.validate()?;
        assert!(proof.requester().is_some());
        assert!(self.domain.binding.lock().unwrap().is_none());
        self.pin.take();
        self.domain
            ._owner
            .0
            .action_pins_released
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
struct Cpu {
    thread: std::thread::ThreadId,
}
// SAFETY: bounded synchronous source peer, no native interrupt producer.
unsafe impl Platform for Cpu {
    fn check_cpu(&self) -> Result<(), irq::IrqError> {
        if self.thread == std::thread::current().id() {
            Ok(())
        } else {
            Err(irq::IrqError::WrongCpu)
        }
    }
    fn check_process(&self) -> Result<(), irq::IrqError> {
        self.check_cpu()
    }
    fn save_and_disable(&self) -> u64 {
        0
    }
    unsafe fn restore(&self, saved: u64) {
        assert_eq!(saved, 0);
    }
    fn target(&self, vector: u8) -> Result<irq::Target, irq::IrqError> {
        self.check_cpu()?;
        Ok(irq::Target {
            destination: 0,
            vector,
        })
    }
    fn pending(&self, _: u8) -> Result<bool, irq::IrqError> {
        self.check_cpu()?;
        Ok(false)
    }
    fn eoi(&self, _vector: u8) -> Result<crate::bus::irq::Trigger, crate::bus::irq::IrqError> {
        Ok(crate::bus::irq::Trigger::Edge)
    }
    fn ticks(&self) -> u64 {
        0
    }
    fn timeout_ticks(&self) -> u64 {
        1
    }
    unsafe fn interrupt_window(&self) {
        panic!("no asynchronous producer in this bounded source fixture")
    }
}
struct Callback;
impl Handler for Callback {
    fn handle(&self) -> irq::Disposition {
        panic!("no native dispatch in this entry ownership fixture")
    }
}
struct EntrySource {
    state: Arc<State>,
    requester: RequesterId,
    number: u8,
}
impl EntrySource {
    fn new(state: Arc<State>, requester: RequesterId, number: u8) -> Self {
        {
            let mut entries = state.action_entries.lock().unwrap();
            assert!(!entries.iter().any(|entry| entry.number == number));
            entries.push(Entry {
                number,
                vector: None,
                masked: true,
                cause: false,
                fenced: false,
                joined: false,
            });
        }
        Self {
            state,
            requester,
            number,
        }
    }
    fn entry(
        &self,
        body: impl FnOnce(&mut Entry) -> Result<(), irq::IrqError>,
    ) -> Result<(), irq::IrqError> {
        let mut entries = self.state.action_entries.lock().unwrap();
        body(
            entries
                .iter_mut()
                .find(|entry| entry.number == self.number)
                .unwrap(),
        )
    }
}
// SAFETY: owns the actual unique model entry; pending causes are checked and
// source reuse is possible only after original Source return/join and Drop.
unsafe impl Source for EntrySource {
    fn route_kind(&self) -> irq::RouteKind {
        irq::RouteKind::Msi
    }
    fn requester(&self) -> Option<&RequesterId> {
        Some(&self.requester)
    }
    fn mask(&mut self) -> Result<(), irq::IrqError> {
        self.entry(|entry| {
            entry.masked = true;
            Ok(())
        })
    }
    fn quiesce(&mut self) -> Result<(), irq::IrqError> {
        self.entry(|entry| {
            if entry.masked && !entry.cause {
                Ok(())
            } else {
                Err(irq::IrqError::Quiesce)
            }
        })
    }
    unsafe fn program(&mut self, route: &irq::AllocatedRoute<'_>) -> Result<(), irq::IrqError> {
        assert!(route.matches_requester(&self.requester));
        let irq::Route::Msi(message) = route.programming() else {
            return Err(irq::IrqError::Route);
        };
        self.entry(|entry| {
            assert!(entry.masked);
            entry.vector = Some(message.data.try_into().unwrap());
            Ok(())
        })
    }
    unsafe fn unmask(&mut self) -> Result<(), irq::IrqError> {
        self.entry(|entry| {
            assert!(entry.vector.is_some());
            entry.masked = false;
            Ok(())
        })
    }
    unsafe fn synchronize(&mut self) -> Result<(), irq::IrqError> {
        self.entry(|entry| {
            assert!(entry.masked && !entry.cause);
            entry.joined = true;
            Ok(())
        })
    }
}
impl Drop for EntrySource {
    fn drop(&mut self) {
        let mut entries = self.state.action_entries.lock().unwrap();
        let i = entries
            .iter()
            .position(|entry| entry.number == self.number)
            .unwrap();
        assert!(entries[i].joined || entries[i].vector.is_none());
        entries.remove(i);
    }
}
fn adopt(attachment: &mut Attachment, retired: irq::RetiredSource<EntrySource>) {
    // SAFETY: bounded source and original root/CPU/action work join completed.
    let (source, callback, route) =
        unsafe { retired.into_parts() }.unwrap_or_else(|failure| panic!("{:?}", failure.error));
    drop(source);
    drop(callback);
    attachment
        .retain_irq_action(route)
        .unwrap_or_else(|failure| panic!("{:?}", failure.error));
}
#[test]
fn multiple_entries_and_same_epoch_rerequest_retain_old_pins_until_endpoint_detach() {
    let (prepared, state) = preparing(false, false);
    state.action_delivery.store(true, Ordering::Release);
    // SAFETY: original cold source fixture has no prior producer or DMA.
    let mut bound = unsafe { prepared.acknowledge_quiescence() }
        .finalize()
        .unwrap_or_else(|failure| panic!("{:?}", failure.error));
    let key = bound.attachment.requester().clone();
    let registry = Box::leak(Box::new(irq::Registry::new(Cpu {
        thread: std::thread::current().id(),
    })));
    let mut first = registry
        .request_owned(Request {
            source: EntrySource::new(state.clone(), key.clone(), 0),
            handler: Arc::new(Callback),
            routing: RouteRequest::Msi(bound.attachment.irq_route().unwrap()),
        })
        .unwrap();
    let mut other = registry
        .request_owned(Request {
            source: EntrySource::new(state.clone(), key.clone(), 1),
            handler: Arc::new(Callback),
            routing: RouteRequest::Msi(bound.attachment.irq_route().unwrap()),
        })
        .unwrap();
    let vector = first.vector();
    assert_ne!(vector, other.vector());
    adopt(&mut bound.attachment, first.retire().unwrap());
    assert_eq!(state.detachments.load(Ordering::Relaxed), 0);
    assert_eq!(state.action_pins_released.load(Ordering::Relaxed), 0);
    let mut replacement = registry
        .request_owned(Request {
            source: EntrySource::new(state.clone(), key.clone(), 0),
            handler: Arc::new(Callback),
            routing: RouteRequest::Msi(bound.attachment.irq_route().unwrap()),
        })
        .unwrap();
    assert_eq!(replacement.vector(), vector);
    assert!(bound.attachment.requester().same_requester(&key));
    assert!(matches!(
        // SAFETY: deliberately invalid caller only in this synchronous negative
        // model; outstanding actions must refuse before any backend effect.
        unsafe { bound.attachment.detach() },
        Err(DmaError::DrainUnavailable)
    ));
    adopt(&mut bound.attachment, other.retire().unwrap());
    adopt(&mut bound.attachment, replacement.retire().unwrap());
    assert_eq!(state.action_records.lock().unwrap().len(), 3);
    let mut mapping = bound.requester.into_function().into_config().into_mapping();
    // SAFETY: inactive fixture checks that real old-action config pins remain.
    assert_eq!(unsafe { mapping.retire() }, Err(MappingError::Busy));
    // SAFETY: all action joins adopted, original engines absent and no DMA map
    // was ever admitted in this bounded entry ownership fixture.
    let detached = unsafe { bound.attachment.detach() }.unwrap();
    assert_eq!(state.detachments.load(Ordering::Relaxed), 1);
    // SAFETY: acknowledged endpoint detach alone cannot release old route pins.
    assert_eq!(unsafe { mapping.retire() }, Err(MappingError::Busy));
    bound
        .attachment
        .release_irq_pins(detached)
        .unwrap_or_else(|failure| panic!("{:?}", failure.error));
    assert_eq!(state.action_pins_released.load(Ordering::Relaxed), 3);
    // SAFETY: actual endpoint detach and every original action pin released.
    unsafe { mapping.retire() }.unwrap();
}
