// SPDX-License-Identifier: MIT
//! Native config/mapping/Registry models composed with the literal IPC device.
//! These are software ownership/effect tests, not physical platform validation.
use super::*;
use crate::bluetooth::bcm4377::State as TransportState;
#[test]
fn native_clock_rejects_invalid_calibration_and_unrepresentable_attempt_before_attachment() {
    for rate in [0, u64::MAX, u64::MAX / 2 / 120_000_000 + 1] {
        assert!(
            // SAFETY: constructor receives invalid negative metadata; it must refuse
            // before exposing a native time/attachment permission.
            unsafe {
                crate::bluetooth::bcm4377::native::NativeClock::new(crate::Clock {
                    ticks_per_microsecond: rate,
                })
            }
            .is_err()
        );
    }
}
use crate::bluetooth::bcm4377::native::{
    self as host, Configuration, Inputs, MappedRegisters, NativePlatform, Registers, Time,
};
use crate::bus::{
    dma::{memory::PageSource, pages::DmaPages},
    irq::{self, Registry},
    mmio::owned::{
        self, AddressSpace, Authority, InstalledMapping, MapFailure, MapRequest, Mapping,
        MappingPlatform, PhysicalSpan, Protection, Resource as MmioResource, ResourceBacking,
        ResourceKind,
    },
    pci::{
        ConfigSpace, Function,
        msi::MsiConfigSpace,
        native_aspm::{RootBus, Topology},
        owned::{
            ConfigRetention, OwnedConfig,
            test_support::{Counters, fixture as owned_config},
        },
    },
};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Read(u16, u8),
    Write(u16, u8, u32),
    Reset,
    PayloadDrain,
    OriginalDrain,
    Bind,
    Allocate,
    PageSourceDrop,
    MsiBind,
    MsiDrain,
    MsiPinRelease,
    CpuPending,
    Eoi,
    BarUnmap,
    ConfigUnmap,
    DmaUnmap,
    RootDrop,
    Detach,
}
struct State {
    events: Mutex<Vec<Event>>,
    registry: AtomicPtr<Registry<Cpu>>,
    vector: AtomicU8,
    pending: AtomicBool,
    fail_cpu: AtomicBool,
    fail_payload: AtomicBool,
    fail_msi: AtomicBool,
    delivery_available: AtomicBool,
    ownership_epoch: AtomicU64,
    root_generation: AtomicU64,
    owner_thread: std::thread::ThreadId,
    fail_enable_ack: AtomicBool,
    fail_master_ack: AtomicBool,
    panic_master: AtomicBool,
    fail_bar_unmap: AtomicBool,
    fail_detach: AtomicBool,
    fail_config_unmap: AtomicBool,
    fail_allocate: AtomicUsize,
    allocations: AtomicUsize,
    fail_original: AtomicBool,
    panic_original: AtomicBool,
    panic_detach: AtomicBool,
    panic_payload: AtomicBool,
    panic_control: AtomicBool,
    fail_bind: AtomicBool,
    bound: AtomicBool,
    reset_ready: AtomicU64,
    accesses: AtomicUsize,
    fault_access: AtomicUsize,
    dead: AtomicBool,
    stuck_pending: AtomicBool,
    resets: AtomicUsize,
}
impl State {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            registry: AtomicPtr::new(core::ptr::null_mut()),
            vector: AtomicU8::new(0),
            pending: AtomicBool::new(false),
            fail_cpu: AtomicBool::new(false),
            fail_payload: AtomicBool::new(false),
            fail_msi: AtomicBool::new(false),
            delivery_available: AtomicBool::new(false),
            ownership_epoch: AtomicU64::new(1),
            root_generation: AtomicU64::new(1),
            owner_thread: std::thread::current().id(),
            fail_enable_ack: AtomicBool::new(false),
            fail_master_ack: AtomicBool::new(false),
            panic_master: AtomicBool::new(false),
            fail_bar_unmap: AtomicBool::new(false),
            fail_detach: AtomicBool::new(false),
            fail_config_unmap: AtomicBool::new(false),
            fail_allocate: AtomicUsize::new(0),
            allocations: AtomicUsize::new(0),
            fail_original: AtomicBool::new(false),
            panic_original: AtomicBool::new(false),
            panic_detach: AtomicBool::new(false),
            panic_payload: AtomicBool::new(false),
            panic_control: AtomicBool::new(false),
            fail_bind: AtomicBool::new(false),
            bound: AtomicBool::new(false),
            reset_ready: AtomicU64::new(0),
            accesses: AtomicUsize::new(0),
            fault_access: AtomicUsize::new(0),
            dead: AtomicBool::new(false),
            stuck_pending: AtomicBool::new(false),
            resets: AtomicUsize::new(0),
        }
    }
    fn event(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
    fn access(&self, event: Event) -> bool {
        self.event(event);
        let access = self.accesses.fetch_add(1, Ordering::Relaxed) + 1;
        if self.fault_access.load(Ordering::Relaxed) == access {
            self.dead.store(true, Ordering::Relaxed);
        }
        self.dead.load(Ordering::Relaxed)
    }
    fn interrupt(&self) {
        self.pending.store(true, Ordering::Relaxed);
        let registry = self.registry.load(Ordering::Relaxed);
        assert!(!registry.is_null());
        // SAFETY: test Registry is leaked, owns this route, and keeps context.
        assert!(unsafe { &*registry }.dispatch(self.vector.load(Ordering::Relaxed)));
    }
}
struct Root(Arc<State>);
impl Drop for Root {
    fn drop(&mut self) {
        self.0.event(Event::RootDrop);
    }
}
struct Config {
    inner: OwnedConfig,
    counters: Arc<Counters>,
    state: Arc<State>,
    device: Arc<Mutex<Device>>,
}
impl Config {
    fn readable(&self, offset: u16, width: u8) -> bool {
        assert!(
            self.device.lock().unwrap().ticks >= self.state.reset_ready.load(Ordering::Relaxed),
            "config access inside actual modeled FLR quiet period"
        );
        !self.state.access(Event::Read(offset, width))
    }
}
impl ConfigSpace for Config {
    fn read8(&self, offset: u16) -> u8 {
        if self.readable(offset, 1) {
            self.inner.read8(offset)
        } else {
            u8::MAX
        }
    }
    fn read16(&self, offset: u16) -> u16 {
        if !self.readable(offset, 2) {
            return u16::MAX;
        }
        if offset == 0xba && self.state.stuck_pending.load(Ordering::Relaxed) {
            return 1 << 5;
        }
        self.inner.read16(offset)
    }
    fn read32(&self, offset: u16) -> u32 {
        if self.readable(offset, 4) {
            self.inner.read32(offset)
        } else {
            u32::MAX
        }
    }
    fn write8(&mut self, offset: u16, value: u8) {
        if !self.state.access(Event::Write(offset, 1, u32::from(value))) {
            self.inner.write8(offset, value);
        }
    }
    fn write32(&mut self, offset: u16, value: u32) {
        // Even an effect-then-fault keeps the original storage kept.
        self.inner.write32(offset, value);
        self.state.access(Event::Write(offset, 4, value));
    }
    fn write16(&mut self, offset: u16, value: u16) {
        if offset == 0x4c {
            // Independent PME_Status W1C: a zero preserves pending status.
            let pending = self.inner.read16(offset) & 0x8000 & !(value & 0x8000);
            self.inner.write16(offset, value & !0x8000 | pending);
        } else {
            self.inner.write16(offset, value);
        }
        if offset == 0xb8 && value & 0x8000 != 0 {
            self.state.event(Event::Reset);
            self.state.resets.fetch_add(1, Ordering::Relaxed);
            let mut device = self.device.lock().unwrap();
            self.state
                .reset_ready
                .store(device.ticks + 100_000, Ordering::Relaxed);
            device.boot = 0;
            device.rti = 0;
            device.armed = false;
            self.inner.write16(4, 0);
            self.inner.write16(0x5a, 0x80);
            self.inner.write16(0x4c, 0x8000);
            self.inner.write16(0xb8, value & !0x8000);
            for index in 0..6 {
                self.inner.write32(0x10 + index * 4, 0);
            }
        }
        if offset == 0x5a {
            self.device.lock().unwrap().armed = value & 1 != 0;
        }
        if offset == 4 && value & 4 != 0 {
            self.device.lock().unwrap().domain.0.lock().unwrap().stopped = false;
        }
        self.state.access(Event::Write(offset, 2, u32::from(value)));
        if offset == 4 && value & 4 != 0 {
            assert!(
                !self.state.panic_master.load(Ordering::Relaxed),
                "injected BME admission unwind"
            );
            if self.state.fail_master_ack.load(Ordering::Relaxed) {
                self.state.dead.store(true, Ordering::Relaxed);
            }
        }
        if offset == 0x5a && value & 1 != 0 && self.state.fail_enable_ack.load(Ordering::Relaxed) {
            self.state.dead.store(true, Ordering::Relaxed);
        }
    }
}
// SAFETY: exact narrow RAM effects model one original config.
unsafe impl MsiConfigSpace for Config {}
// SAFETY: this wrapper keeps/returns the original owned fixture map.
unsafe impl Configuration for Config {
    fn owned_address(&self) -> Address {
        self.inner.address()
    }
    fn retain_epoch(&self) -> core::result::Result<ConfigRetention, owned::Error> {
        self.inner.retain_epoch()
    }
    fn matches_retention(
        &self,
        seal: &ConfigRetention,
    ) -> core::result::Result<bool, owned::Error> {
        self.inner.matches_retention(seal)
    }
    fn into_mapping(self) -> Mapping {
        self.state.event(Event::ConfigUnmap);
        if self.state.fail_config_unmap.load(Ordering::Relaxed) {
            self.counters.fail_context_at.store(
                self.counters.contexts.load(Ordering::Relaxed) + 1,
                Ordering::Relaxed,
            );
        }
        self.inner.into_mapping()
    }
}
struct ClockModel(Arc<Mutex<Device>>);
// SAFETY: explicitly advancing monotonic device time, including injected delays.
unsafe impl Time for ClockModel {
    fn now_us(&self) -> u64 {
        let mut d = self.0.lock().unwrap();
        d.ticks += 1000;
        let elapsed = d.domain.0.lock().unwrap().elapsed_us;
        d.ticks + elapsed
    }
}
struct NativeDomain {
    domain: Arc<Domain>,
    state: Arc<State>,
    _root: Root,
}
// SAFETY: delegates the page model's mappings; its independently
// modeled stopped flag and completion fault control retirement, not fence tokens.
unsafe impl DmaDomain for NativeDomain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        limit: u64,
    ) -> core::result::Result<DomainMapping, DmaError> {
        if !self.state.bound.load(Ordering::Relaxed) {
            return Err(DmaError::Unmapped);
        }
        // SAFETY: caller keeps exact pins/domain as in delegated model.
        let mapping = unsafe { self.domain.map(pages, direction, limit) }?;
        let pin = pages.as_single().unwrap();
        let cpu = pin
            .cpu_mapping(CacheAttribute::WriteBack)
            .unwrap()
            .address(0, 1)
            .unwrap()
            .as_ptr() as u64;
        assert_ne!(mapping.address, pin.physical_pages()[0]);
        assert_ne!(mapping.address, cpu);
        assert_ne!(pin.physical_pages()[0], cpu);
        Ok(mapping)
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> core::result::Result<(), DmaError> {
        if !self.state.bound.load(Ordering::Relaxed) {
            return Err(DmaError::Unmapped);
        }
        self.state.event(Event::DmaUnmap);
        // SAFETY: same stopped-consumer caller contract and original domain.
        unsafe { self.domain.unmap(mapping) }
    }
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> core::result::Result<(), DmaError> {
        if !self.state.bound.load(Ordering::Relaxed) {
            return Err(DmaError::Unmapped);
        }
        // SAFETY: exact mapping/direction/bounds delegated to the domain.
        unsafe { self.domain.sync_for_device(mapping, range, direction) }
    }
    unsafe fn sync_for_cpu(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> core::result::Result<(), DmaError> {
        if !self.state.bound.load(Ordering::Relaxed) {
            return Err(DmaError::Unmapped);
        }
        // SAFETY: no continuous CPU handoff is invented by this model.
        unsafe { self.domain.sync_for_cpu(mapping, range, direction) }
    }
    unsafe fn drain_posted_writes(&self) -> core::result::Result<(), DmaError> {
        if !self.state.bound.load(Ordering::Relaxed) {
            return Err(DmaError::Unmapped);
        }
        self.state.event(Event::PayloadDrain);
        assert!(
            !self.state.panic_payload.load(Ordering::Relaxed),
            "injected payload unwind"
        );
        assert!(self.state.resets.load(Ordering::Relaxed) != 0);
        if self.state.fail_payload.load(Ordering::Relaxed) {
            return Err(DmaError::DrainUnavailable);
        }
        self.domain.0.lock().unwrap().stopped = true;
        Ok(())
    }
}
struct AttachmentModel {
    domain: Arc<NativeDomain>,
    retention: Option<ConfigRetention>,
}
impl Drop for AttachmentModel {
    fn drop(&mut self) {
        if self.retention.is_some() {
            core::mem::forget(self.domain.clone());
            core::mem::forget(self.retention.take());
        }
    }
}
// SAFETY: one original config seal pins this independent domain generation;
// detach refuses mappings and releases that pin only after modeled blocking.
unsafe impl crate::bus::pci::requester::preparation::AttachmentBackend for AttachmentModel {
    fn domain(&self) -> Arc<dyn DmaDomain> {
        self.domain.clone()
    }
    fn irq_owner(
        &mut self,
        _requester: &crate::bus::pci::requester::RequesterId,
        _config: Option<&crate::bus::pci::owned::ConfigRetention>,
    ) -> core::result::Result<Option<Box<dyn irq::posted_msi::RouteOwner>>, DmaError> {
        if !self.domain.state.delivery_available.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let pin = self
            .retention
            .as_ref()
            .ok_or(DmaError::Unmapped)?
            .retain_epoch()
            .map_err(|_| DmaError::MappingFailed)?;
        Ok(Some(Box::new(Delivery {
            state: self.domain.state.clone(),
            pin: Some(pin),
            epoch: self.domain.state.ownership_epoch.load(Ordering::Relaxed),
            root_generation: self.domain.state.root_generation.load(Ordering::Relaxed),
            allocated: false,
        })))
    }
    unsafe fn detach(
        &mut self,
    ) -> core::result::Result<(), crate::bus::pci::requester::preparation::DetachError> {
        if self.retention.is_none() {
            return Ok(());
        }
        if !self.domain.domain.0.lock().unwrap().leases.is_empty() {
            return Err(
                crate::bus::pci::requester::preparation::DetachError::Unexposed(
                    DmaError::MappingFailed,
                ),
            );
        }
        self.domain.state.event(Event::Detach);
        assert!(
            !self.domain.state.panic_detach.load(Ordering::Relaxed),
            "injected detach unwind"
        );
        // Audited model-only refusal: the event log is observational; no
        // binding, table, pin or device effect has occurred before this flag.
        if self.domain.state.fail_detach.load(Ordering::Relaxed) {
            return Err(
                crate::bus::pci::requester::preparation::DetachError::Unexposed(
                    DmaError::DrainUnavailable,
                ),
            );
        }
        self.domain.state.bound.store(false, Ordering::Relaxed);
        self.retention.take();
        Ok(())
    }
}
struct PreparingModel {
    owner: core::mem::ManuallyDrop<(Function<Config>, Arc<NativeDomain>, ConfigRetention)>,
}
// SAFETY: the explicit original model owns the exact config and root/domain
// epoch. Its one consumed finalize checks BME and pins config until detach.
unsafe impl host::cold::Preparation for PreparingModel {
    type Config = Config;
    fn function_mut(&mut self) -> &mut Function<Config> {
        &mut self.owner.0
    }
    unsafe fn finalize(
        mut self,
    ) -> core::result::Result<host::cold::Finalized<Config>, host::cold::FinalizeFailure> {
        let state = self.owner.1.state.clone();
        let (function, _, retained) = &mut *self.owner;
        assert!(function.config().inner.matches_retention(retained).unwrap());
        assert_eq!(state.resets.load(Ordering::Relaxed), 1);
        assert_eq!(self.owner.0.config().read16(4) & 0x406, 0x400);
        assert!(self.owner.1.domain.0.lock().unwrap().leases.is_empty());
        state.event(Event::OriginalDrain);
        assert!(
            !state.panic_original.load(Ordering::Relaxed),
            "injected original-root unwind"
        );
        if state.fail_original.load(Ordering::Relaxed) {
            return Err(host::cold::FinalizeFailure {
                error: crate::bus::pci::requester::preparation::Error::Dma(
                    DmaError::DrainUnavailable,
                ),
                retained: core::mem::ManuallyDrop::new(Box::new(self)),
            });
        }
        state.event(Event::Bind);
        if state.fail_bind.load(Ordering::Relaxed) {
            return Err(host::cold::FinalizeFailure {
                error: crate::bus::pci::requester::preparation::Error::Dma(
                    DmaError::DrainUnavailable,
                ),
                retained: core::mem::ManuallyDrop::new(Box::new(self)),
            });
        }
        assert!(!state.bound.swap(true, Ordering::Relaxed));
        // SAFETY: original owner is moved exactly once after modeled binding;
        // failure and unwind leave the ManuallyDrop graph retained.
        let retention = self.owner.0.config().inner.retain_epoch().unwrap();
        // SAFETY: the successful one-shot bind transfers every owner exactly
        // once; before this move, unwind retains the ManuallyDrop graph.
        let (function, domain, old_retention) =
            unsafe { core::mem::ManuallyDrop::take(&mut self.owner) };
        drop(old_retention);
        let wrapper_pin = retention.retain_epoch().unwrap();
        Ok(host::cold::Finalized {
            function,
            // SAFETY: same original model configuration/root binding; wrapper
            // checks its own live pin through the actual backend detach.
            attachment: unsafe {
                crate::bus::pci::requester::preparation::Attachment::new(
                    Box::new(AttachmentModel {
                        domain,
                        retention: Some(retention),
                    }),
                    wrapper_pin,
                )
            },
        })
    }
}
struct PageModel(Mutex<u64>, Arc<State>);
impl Drop for PageModel {
    fn drop(&mut self) {
        self.1.event(Event::PageSourceDrop);
    }
}
impl PageSource for PageModel {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> core::result::Result<PinnedPages, MemoryError> {
        self.1.event(Event::Allocate);
        assert!(self.1.bound.load(Ordering::Relaxed));
        let allocation = self.1.allocations.fetch_add(1, Ordering::Relaxed) + 1;
        if self.1.fail_allocate.load(Ordering::Relaxed) == allocation {
            return Err(MemoryError::OutOfMemory);
        }
        assert_eq!(alignment, 4096);
        assert_eq!(attribute, CacheAttribute::WriteBack);
        let reserved = bytes.next_multiple_of(4096);
        let layout = Layout::from_size_align(reserved, alignment).unwrap();
        // SAFETY: exact allocation kept by existing real PageBacking model.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        let mut next = self.0.lock().unwrap();
        let physical = (0..reserved / 4096)
            .map(|index| *next + index as u64 * 4096)
            .collect();
        *next += reserved as u64;
        PinnedPages::new(
            Box::new(Pages {
                pointer,
                layout,
                physical,
            }),
            bytes,
            alignment,
        )
    }
}
struct DeliveryDomain {
    state: Arc<State>,
    pin: ConfigRetention,
    epoch: u64,
    root_generation: u64,
}
// SAFETY: this exact bounded source holds the actual original config view;
// model root/owner generations are distinct and no native grant is created.
unsafe impl irq::posted_msi::NotificationDomain for DeliveryDomain {
    fn check(&self) -> core::result::Result<(), irq::posted_msi::Error> {
        if self.state.fail_msi.load(Ordering::Acquire) {
            return Err(irq::posted_msi::Error::RootFailed);
        }
        if self.state.owner_thread != std::thread::current().id()
            || self.state.root_generation.load(Ordering::Acquire) != self.root_generation
            || self.state.ownership_epoch.load(Ordering::Acquire) != self.epoch
            || self.state.dead.load(Ordering::Acquire)
        {
            return Err(irq::posted_msi::Error::Context);
        }
        self.pin
            .check_live()
            .map_err(|_| irq::posted_msi::Error::Context)
    }
}
struct Delivery {
    state: Arc<State>,
    pin: Option<ConfigRetention>,
    epoch: u64,
    root_generation: u64,
    allocated: bool,
}
// SAFETY: exact original RAM config/root model and real retained mapping pin.
// Independent payload/MSI/CPU controls remain separate; the same attachment
// must actually detach before this source pin is explicitly released.
unsafe impl irq::posted_msi::RouteOwner for Delivery {
    fn allocate(
        &mut self,
        target: &irq::CpuTarget<'_>,
    ) -> core::result::Result<irq::MsiMessage, irq::posted_msi::AllocationError> {
        target.check_current().map_err(|_| {
            irq::posted_msi::AllocationError::Unexposed(irq::posted_msi::Error::Context)
        })?;
        self.validate()
            .map_err(irq::posted_msi::AllocationError::Unexposed)?;
        assert!(!self.allocated);
        self.allocated = true;
        let target = target.descriptor();
        let message = irq::MsiMessage {
            address: 0xfee0_0000 | u64::from(target.destination) << 12,
            data: u32::from(target.vector),
        };
        assert_eq!(message.address, 0xfee0_0000);
        assert_eq!(
            message.data,
            u32::from(self.state.vector.load(Ordering::Relaxed))
        );
        self.state.event(Event::MsiBind);
        Ok(message)
    }
    fn validate(&self) -> core::result::Result<(), irq::posted_msi::Error> {
        if self.state.owner_thread != std::thread::current().id()
            || self.state.root_generation.load(Ordering::Acquire) != self.root_generation
        {
            return Err(irq::posted_msi::Error::Context);
        }
        if let Some(pin) = &self.pin {
            // Source/config identity is checked while that exact pin exists.
            // Terminal observation never touches a released/reprobed endpoint.
            if self.state.ownership_epoch.load(Ordering::Acquire) != self.epoch
                || self.state.dead.load(Ordering::Acquire)
            {
                return Err(irq::posted_msi::Error::Context);
            }
            pin.check_live()
                .map_err(|_| irq::posted_msi::Error::Context)?;
        }
        Ok(())
    }
    fn notification_domain(
        &self,
    ) -> core::result::Result<Arc<dyn irq::posted_msi::NotificationDomain>, irq::posted_msi::Error>
    {
        self.validate()?;
        let pin = self
            .pin
            .as_ref()
            .ok_or(irq::posted_msi::Error::Unbound)?
            .retain_epoch()
            .map_err(|_| irq::posted_msi::Error::Context)?;
        Ok(Arc::new(DeliveryDomain {
            state: self.state.clone(),
            pin,
            epoch: self.epoch,
            root_generation: self.root_generation,
        }))
    }
    unsafe fn strong_fence(&mut self) -> core::result::Result<(), irq::posted_msi::Error> {
        self.validate()?;
        self.state.event(Event::MsiDrain);
        assert_eq!(
            self.state.events.lock().unwrap().iter().rev().nth(1),
            Some(&Event::PayloadDrain)
        );
        if self.state.fail_msi.load(Ordering::Relaxed) {
            return Err(irq::posted_msi::Error::RootFailed);
        }
        Ok(())
    }
    unsafe fn release_endpoint(
        &mut self,
        proof: &irq::posted_msi::EndpointRetirement<'_>,
    ) -> core::result::Result<(), irq::posted_msi::Error> {
        self.validate()?;
        assert!(proof.requester().is_some());
        assert!(!self.state.bound.load(Ordering::Relaxed));
        self.state.event(Event::MsiPinRelease);
        self.pin.take();
        Ok(())
    }
}

struct Cpu(Arc<State>);
// SAFETY: explicit same-CPU APIC delivery model, Registry controls slots.
unsafe impl irq::Platform for Cpu {
    fn check_cpu(&self) -> core::result::Result<(), irq::IrqError> {
        if self.0.owner_thread != std::thread::current().id() {
            return Err(irq::IrqError::WrongCpu);
        }
        Ok(())
    }
    fn check_process(&self) -> core::result::Result<(), crate::bus::irq::IrqError> {
        self.check_cpu()
    }
    fn save_and_disable(&self) -> u64 {
        0
    }
    unsafe fn restore(&self, _: u64) {}
    fn target(&self, vector: u8) -> core::result::Result<irq::Target, irq::IrqError> {
        self.0.vector.store(vector, Ordering::Relaxed);
        Ok(irq::Target {
            destination: 0,
            vector,
        })
    }
    fn pending(&self, _: u8) -> core::result::Result<bool, irq::IrqError> {
        self.0.event(Event::CpuPending);
        Ok(self.0.fail_cpu.load(Ordering::Relaxed) || self.0.pending.load(Ordering::Relaxed))
    }
    fn eoi(
        &self,
        _vector: u8,
    ) -> core::result::Result<crate::bus::irq::Trigger, crate::bus::irq::IrqError> {
        self.0.event(Event::Eoi);
        self.0.pending.store(false, Ordering::Relaxed);
        Ok(crate::bus::irq::Trigger::Edge)
    }
    fn ticks(&self) -> u64 {
        self.0.accesses.fetch_add(1, Ordering::Relaxed) as u64
    }
    fn timeout_ticks(&self) -> u64 {
        16
    }
    unsafe fn interrupt_window(&self) {
        if self.0.pending.load(Ordering::Relaxed) {
            self.0.interrupt();
        }
    }
}
struct BarResource(PhysicalSpan);
// SAFETY: each test reserves disjoint symbolic native BAR resources.
unsafe impl ResourceBacking for BarResource {
    fn physical_span(&self) -> PhysicalSpan {
        self.0
    }
    fn kind(&self) -> ResourceKind {
        ResourceKind::Registers
    }
}
struct BarPlatform(Arc<State>);
// SAFETY: fresh aligned CPU allocations model full symbolic BARs;
// acknowledged unmap alone returns each exact allocation to the model heap.
unsafe impl MappingPlatform for BarPlatform {
    fn check_context(&self, _: AddressSpace) -> core::result::Result<(), owned::Error> {
        Ok(())
    }
    unsafe fn map(
        &self,
        _: &MmioResource,
        request: MapRequest,
    ) -> core::result::Result<InstalledMapping, MapFailure> {
        let layout = Layout::from_size_align(request.physical.bytes() as usize, 4096).unwrap();
        // SAFETY: valid layout; permission owns this exact allocation/token.
        let cpu_base = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        Ok(InstalledMapping {
            token: request.id,
            cpu_base,
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(
        &self,
        request: MapRequest,
        mapping: InstalledMapping,
    ) -> core::result::Result<(), owned::Error> {
        self.0.event(Event::BarUnmap);
        if self.0.fail_bar_unmap.load(Ordering::Relaxed) {
            return Err(owned::Error::UnmapFailed);
        }
        // SAFETY: original allocation after stopped mapping consumers.
        unsafe {
            dealloc(
                mapping.cpu_base.as_ptr(),
                Layout::from_size_align(request.physical.bytes() as usize, 4096).unwrap(),
            )
        };
        Ok(())
    }
}
struct NativeRegisters {
    registers: MappedRegisters,
    device: RefCell<Model>,
    state: Arc<State>,
}
// SAFETY: explicit composed device model owns original BAR mappings and exact
// source MMIO effects; native mapped retirement keeps original reservations.
unsafe impl Registers for NativeRegisters {
    fn spans(&self) -> [PhysicalSpan; 2] {
        self.registers.spans()
    }
    fn read32(&self, space: Space, offset: u32) -> core::result::Result<u32, host::Error> {
        self.device
            .borrow_mut()
            .read32(space, offset)
            .map_err(|_| host::Error::Requirement("independent MMIO read fault"))
    }
    fn write32(
        &self,
        space: Space,
        offset: u32,
        value: u32,
    ) -> core::result::Result<(), host::Error> {
        let prior = self.device.borrow().0.lock().unwrap().msi;
        let result = self
            .device
            .borrow_mut()
            .write32(space, offset, value)
            .map_err(|_| host::Error::Requirement("independent MMIO write fault"));
        let next = self.device.borrow().0.lock().unwrap().msi;
        if next != prior {
            self.state.interrupt();
        }
        if space == Space::Bar0 && offset == DOORBELL && value & 0xff00 == 0 {
            assert!(
                !self.state.panic_control.load(Ordering::Relaxed),
                "injected protocol-close control doorbell unwind"
            );
        }
        result
    }
    fn read8(&self, space: Space, offset: u32) -> core::result::Result<u8, host::Error> {
        self.device
            .borrow_mut()
            .read8(space, offset)
            .map_err(|_| host::Error::Requirement("independent OTP read fault"))
    }
    unsafe fn retire(&mut self) -> core::result::Result<(), host::Error> {
        // SAFETY: enclosing native stop/posting/Registry drain completed.
        unsafe { self.registers.retire() }
    }
}
struct Fixture {
    inputs: Inputs<Config, NativeRegisters, ClockModel>,
    device: Arc<Mutex<Device>>,
    state: Arc<State>,
    counters: Arc<Counters>,
}
fn fixture_native(device_id: u16, completion: bool) -> Fixture {
    fixture_native_setup(device_id, completion, |_| {})
        .unwrap_or_else(|_| panic!("valid cold model"))
}
type ColdInputs = host::cold::Inputs<PreparingModel, NativeRegisters, ClockModel>;
type ColdFailure = (host::Error, Arc<State>, Arc<Counters>, Arc<Mutex<Device>>);
fn fixture_native_setup(
    device_id: u16,
    completion: bool,
    setup: impl FnOnce(&mut ColdInputs),
) -> core::result::Result<Fixture, ColdFailure> {
    let (mut cold_inputs, state, counters, device) = original_inputs(device_id);
    setup(&mut cold_inputs);
    // SAFETY: model owns original config, BARs, topology and root, with no
    // private mapping or IRQ admission until the shared cold sequence returns.
    let cold = match unsafe { host::cold::Cold::new(cold_inputs) } {
        Ok(cold) => cold,
        Err((error, inputs)) => {
            core::mem::forget(inputs);
            return Err((error, state, counters, device));
        }
    };
    let bound = match cold.quiesce_and_bind() {
        Ok(bound) => bound,
        Err(failure) => return Err((failure.error.clone(), state, counters, device)),
    };
    state
        .delivery_available
        .store(completion, Ordering::Relaxed);
    let inputs = Inputs {
        function: bound.function,
        retained: Arc::new(Root(state.clone())),
        topology: bound.topology,
        registers: bound.registers,
        attachment: bound.attachment,
        pages: Box::new(PageModel(Mutex::new(0x1_0000_0000), state.clone())),
        board: Board::from_property(b"apple,formosa\0").unwrap(),
        properties: vec![],
        clock: bound.clock,
        // SAFETY: original_inputs leaked this same model Registry.
        interrupts: unsafe { &*state.registry.load(Ordering::Relaxed) },
    };
    Ok(Fixture {
        inputs,
        device,
        state,
        counters,
    })
}
fn original_inputs(device_id: u16) -> (ColdInputs, Arc<State>, Arc<Counters>, Arc<Mutex<Device>>) {
    let (model, _, device) = fixture(device_id);
    let state = Arc::new(State::new());
    let registry = Box::leak(Box::new(Registry::new(Cpu(state.clone()))));
    state.registry.store(registry, Ordering::Relaxed);
    let identity = device.lock().unwrap().pci;
    let (mut config, counters) = owned_config(identity.address);
    for (offset, value) in [
        (0, u32::from(device_id) << 16 | 0x14e4),
        (4, 0x0010_0400),
        (8, 0x0280_0003),
        (0x2c, 0x0100_106b),
        (0x10, 0x1000_0000),
        (0x18, 0x2000_0000),
        (0x34, 0x48),
        (0x48, 0x0003_5801),
        (0x4c, 0x8003),
        (0x58, 0x0080_b005),
        (0x88, 1 << 19),
        (0xb0, 0x0002_0010),
        (0xb4, 1 << 28),
        (0xc0, 0xa5c3_5a03),
    ] {
        config.write32(offset, value);
    }
    let config = Config {
        inner: config,
        counters: counters.clone(),
        state: state.clone(),
        device: device.clone(),
    };
    let function = Function::new(identity.address, config).unwrap();
    let bars = [
        PhysicalSpan::new(0x1000_0000, 0x10000).unwrap(),
        PhysicalSpan::new(0x2000_0000, 0x500000).unwrap(),
    ];
    let space = AddressSpace {
        identity: 27,
        physical_bits: 48,
        virtual_bits: 48,
    };
    // SAFETY: isolated symbolic MMIO resources and private CPU storage.
    let authority =
        unsafe { Authority::isolated_model(Arc::new(BarPlatform(state.clone())), space, vec![]) }
            .unwrap();
    let maps = bars.map(|span| {
        authority
            .map(
                MmioResource::new(Box::new(BarResource(span))),
                0,
                span.bytes() as usize,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .unwrap()
    });
    // SAFETY: same explicit symbolic resource/reset epoch, no escaped map view.
    let registers = match unsafe { MappedRegisters::new(bars, maps) } {
        Ok(registers) => registers,
        Err((error, _)) => panic!("valid BARs {error:?}"),
    };
    // SAFETY: complete inventory for this explicit direct-root model.
    let topology = unsafe { Topology::new(vec![], vec![RootBus { segment: 0, bus: 1 }]) };
    let domain = Arc::new(NativeDomain {
        domain: device.lock().unwrap().domain.clone(),
        state: state.clone(),
        _root: Root(state.clone()),
    });
    let mut function = function;
    let retention = function.config().inner.retain_epoch().unwrap();
    let cold_inputs = host::cold::Inputs {
        requester: PreparingModel {
            owner: core::mem::ManuallyDrop::new((function, domain, retention)),
        },
        topology,
        registers: NativeRegisters {
            registers,
            device: RefCell::new(model),
            state: state.clone(),
        },
        clock: ClockModel(device.clone()),
    };
    (cold_inputs, state, counters, device)
}
type NativeTransport = Transport<NativePlatform<Config, NativeRegisters, ClockModel>>;
fn transport(
    f: Fixture,
) -> (
    NativeTransport,
    Arc<Mutex<Device>>,
    Arc<State>,
    Arc<Counters>,
) {
    // SAFETY: complete independent device/config/route/domain/mapping fixture.
    let platform = match unsafe { NativePlatform::new(f.inputs) } {
        Ok(platform) => platform,
        Err((error, _)) => panic!("valid native fixture {error:?}"),
    };
    (
        platform.into_transport().unwrap(),
        f.device,
        f.state,
        f.counters,
    )
}
fn position(events: &[Event], event: Event) -> usize {
    events.iter().position(|e| *e == event).unwrap()
}

#[test]
fn all_four_native_ids_use_real_registry_msi_dma_hci_and_ordered_retirement() {
    for id in [0x5fa0, 0x5f69, 0x5f71, 0x5f72] {
        let (mut t, device, state, counters) = transport(fixture_native(id, true));
        t.start(&catalog(&device, false)).unwrap();
        state.interrupt();
        assert!(t.service_pending());
        let submission = t.send(Kind::Command, &[0x03, 0x0c, 0]).unwrap();
        let observations = t.poll().unwrap();
        assert!(
            observations
                .completions
                .iter()
                .any(|receipt| receipt.submission == submission)
        );
        assert!(
            observations.packets.is_empty(),
            "TX ACK never invents HCI completion"
        );
        device
            .lock()
            .unwrap()
            .completion(2, 2, 0xffff, 0x82, &[0x0e, 4, 1, 3, 0x0c, 0], false);
        state.interrupt();
        assert!(t.service_pending());
        let observations = t.poll().unwrap();
        assert_eq!(observations.packets[0].bytes, [0x0e, 4, 1, 3, 0x0c, 0]);
        assert!(!t.service_pending());
        state.events.lock().unwrap().clear();
        t.close().unwrap();
        let events = state.events.lock().unwrap().clone();
        assert!(position(&events, Event::Reset) < position(&events, Event::PayloadDrain));
        assert!(
            !events.contains(&Event::MsiDrain),
            "action join does not claim fabric completion"
        );
        assert!(position(&events, Event::PayloadDrain) < position(&events, Event::CpuPending));
        assert!(position(&events, Event::CpuPending) < position(&events, Event::BarUnmap));
        assert!(position(&events, Event::CpuPending) < position(&events, Event::DmaUnmap));
        assert!(position(&events, Event::DmaUnmap) < position(&events, Event::Detach));
        assert!(position(&events, Event::Detach) < position(&events, Event::BarUnmap));
        assert!(position(&events, Event::Detach) < position(&events, Event::ConfigUnmap));
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
        assert_eq!(state.resets.load(Ordering::Relaxed), 2);
        assert!(
            device
                .lock()
                .unwrap()
                .domain
                .0
                .lock()
                .unwrap()
                .leases
                .is_empty()
        );
        drop(t);
        assert!(state.events.lock().unwrap().contains(&Event::RootDrop));
    }
}
#[test]
fn native_unpublished_close_stops_the_prepared_bus_master_and_releases_without_route() {
    let (mut t, _, state, counters) = transport(fixture_native(0x5fa0, false));
    state.events.lock().unwrap().clear();
    t.close().unwrap();
    let events = state.events.lock().unwrap();
    assert!(events.contains(&Event::Reset));
    assert!(events.contains(&Event::PayloadDrain));
    assert!(!events.contains(&Event::MsiDrain));
    assert!(!events.contains(&Event::CpuPending));
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
}
#[test]
fn every_distinct_retirement_failure_keeps_original_route_pins_root_and_first_error() {
    for failure in [0, 1, 2, 4, 5, 6] {
        let (mut t, device, state, counters) = transport(fixture_native(0x5f69, true));
        t.start(&catalog(&device, false)).unwrap();
        match failure {
            0 => state.stuck_pending.store(true, Ordering::Relaxed),
            1 => state.fail_payload.store(true, Ordering::Relaxed),
            2 => state.fail_msi.store(true, Ordering::Relaxed),
            4 => state.fail_cpu.store(true, Ordering::Relaxed),
            5 => state.fail_bar_unmap.store(true, Ordering::Relaxed),
            6 => state.fail_detach.store(true, Ordering::Relaxed),
            _ => unreachable!(),
        }
        state.events.lock().unwrap().clear();
        let first = t.close().unwrap_err();
        let events = state.events.lock().unwrap().clone();
        assert_eq!(t.close(), Err(first));
        assert_eq!(
            state.events.lock().unwrap().as_slice(),
            events.as_slice(),
            "terminal close cannot retry any native effect"
        );
        if failure <= 3 {
            assert!(!events.contains(&Event::CpuPending));
        }
        assert_eq!(events.contains(&Event::DmaUnmap), failure >= 5);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        drop(t);
        assert!(!device.lock().unwrap().dropped);
        assert!(!state.events.lock().unwrap().contains(&Event::RootDrop));
        assert_eq!(
            device
                .lock()
                .unwrap()
                .domain
                .0
                .lock()
                .unwrap()
                .leases
                .is_empty(),
            failure >= 5,
        );
    }
}
#[test]
fn native_d0_preserves_pme_status_and_all_pci_control_writes_are_narrow() {
    let (mut t, _, state, _) = transport(fixture_native(0x5fa0, false));
    let events = state.events.lock().unwrap().clone();
    assert!(events.contains(&Event::Write(0x4c, 2, 0)));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Write(4 | 0x4c | 0xb8 | 0xc0, 4, _)))
    );
    t.close().unwrap();
}
#[test]
fn late_effect_then_config_failure_has_one_uncertain_reset_and_no_release() {
    let (mut t, device, state, counters) = transport(fixture_native(0x5f69, true));
    t.start(&catalog(&device, false)).unwrap();
    // Find admission-time access count; the next command read fails.
    state.fault_access.store(
        state.accesses.load(Ordering::Relaxed) + 1,
        Ordering::Relaxed,
    );
    let error = t.close().unwrap_err();
    let accesses = state.accesses.load(Ordering::Relaxed);
    assert_eq!(t.close(), Err(error));
    assert_eq!(state.accesses.load(Ordering::Relaxed), accesses);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    drop(t);
    assert!(!device.lock().unwrap().dropped);
}

fn release_unpublished(mut inputs: Inputs<Config, NativeRegisters, ClockModel>) {
    // SAFETY: constructor rejection left this test attachment unpublished;
    // its independent model has no leases and excludes every prior user.
    unsafe { inputs.attachment.detach() }.unwrap();
    // SAFETY: constructor refusal had no device effects; this isolated model
    // has no DMA/IRQ work or raw views, and its attachment is now detached.
    unsafe { inputs.registers.retire() }.unwrap();
    let mut mapping = inputs.function.into_config().into_mapping();
    // SAFETY: same unpublished original isolated config owner.
    unsafe { mapping.retire() }.unwrap();
    for function in inputs.topology.into_functions() {
        let mut mapping = function.into_config().into_mapping();
        // SAFETY: original bridge model has no concurrent user or device.
        unsafe { mapping.retire() }.unwrap();
    }
}
#[test]
fn native_constructor_rejects_malformed_original_owners_before_any_write() {
    for failure in 0..7 {
        let mut f = fixture_native(0x5fa0, true);
        match failure {
            0 => f.inputs.function.config().inner.write32(0xb4, 0),
            1 => f.inputs.function.config().inner.write32(0x18, 0x3000_0000),
            2 => f.inputs.function.config().inner.write16(0x5a, 0x81),
            3 => f.inputs.function.address.device = 1,
            4 => f.inputs.function.config().inner.write8(0xb1, 0x5c),
            5 => {
                f.inputs.function.config().inner.write8(0x59, 0x80);
                f.inputs.function.config().inner.write32(0x80, 0x0002_0010);
                f.inputs.function.config().inner.write32(0x84, 1 << 28);
            }
            6 => {
                // SAFETY: wrong explicit model root declaration.
                f.inputs.topology =
                    unsafe { Topology::new(vec![], vec![RootBus { segment: 0, bus: 2 }]) };
            }
            _ => unreachable!(),
        }
        f.state.events.lock().unwrap().clear();
        // SAFETY: fixture owns the real symbolic maps; corrupt metadata tests
        // read-only rejection rather than granting another physical requester.
        let mut returned = match unsafe { NativePlatform::new(f.inputs) } {
            Err((_, inputs)) => inputs,
            Ok(_) => panic!("malformed original native input {failure} admitted"),
        };
        assert!(
            !f.state
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|event| matches!(event, Event::Write(..)))
        );
        assert_eq!(f.counters.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(
            returned.function.config().owned_address(),
            f.device.lock().unwrap().pci.address
        );
        release_unpublished(returned);
        assert_eq!(f.counters.unmaps.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn every_constructor_config_read_fault_returns_the_same_original_unmodified_owners() {
    let f = fixture_native(0x5f69, true);
    f.state.accesses.store(0, Ordering::Relaxed);
    // SAFETY: valid isolated native ownership model; reads only in construction.
    let platform = match unsafe { NativePlatform::new(f.inputs) } {
        Ok(platform) => platform,
        Err((error, _)) => panic!("valid preflight {error:?}"),
    };
    let reads = f.state.accesses.load(Ordering::Relaxed);
    let mut t = platform.into_transport().unwrap();
    t.close().unwrap();
    for access in 1..=reads {
        let f = fixture_native(0x5f69, true);
        f.state.accesses.store(0, Ordering::Relaxed);
        f.state.fault_access.store(access, Ordering::Relaxed);
        f.state.events.lock().unwrap().clear();
        // SAFETY: same original fixture; each failed read is injected once.
        let returned = match unsafe { NativePlatform::new(f.inputs) } {
            Err((_, inputs)) => inputs,
            Ok(_) => panic!("preflight read {access} fault ignored"),
        };
        assert!(
            !f.state
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|event| matches!(event, Event::Write(..)))
        );
        assert_eq!(f.counters.unmaps.load(Ordering::Relaxed), 0);
        release_unpublished(returned);
    }
}
#[test]
fn effect_then_failed_msi_enable_admission_keeps_registry_and_original_epoch() {
    let (mut t, device, state, counters) = transport(fixture_native(0x5f69, true));
    state.fail_enable_ack.store(true, Ordering::Relaxed);
    let first = t.start(&catalog(&device, false)).unwrap_err();
    assert_eq!(t.close(), Err(first));
    assert_eq!(
        state.resets.load(Ordering::Relaxed),
        1,
        "uncertain admission cannot run another stop/reset"
    );
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    // SAFETY: fixture registry is leaked and remains valid with its tombstone.
    let registry = unsafe { &*state.registry.load(Ordering::Relaxed) };
    assert_eq!(registry.quarantine_count(), 1);
    drop(t);
    assert!(!device.lock().unwrap().dropped);
    assert!(!state.events.lock().unwrap().contains(&Event::RootDrop));
}

#[test]
fn cold_reset_original_root_drain_and_bind_precede_every_new_dma_allocation() {
    for id in [0x5fa0, 0x5f69, 0x5f71, 0x5f72] {
        let (mut t, _, state, _) = transport(fixture_native(id, false));
        let events = state.events.lock().unwrap().clone();
        assert!(position(&events, Event::Reset) < position(&events, Event::OriginalDrain));
        assert!(position(&events, Event::OriginalDrain) < position(&events, Event::Bind));
        assert!(position(&events, Event::Bind) < position(&events, Event::Allocate));
        assert_eq!(state.resets.load(Ordering::Relaxed), 1);
        assert_eq!(state.allocations.load(Ordering::Relaxed), 14);
        assert!(!events.contains(&Event::PayloadDrain));
        t.close().unwrap();
    }
}
#[test]
fn failed_original_drain_or_bind_retains_original_cold_graph_without_allocation() {
    for failed_bind in [false, true] {
        let result = fixture_native_setup(0x5f69, false, |inputs| {
            let state = &inputs.requester.owner.1.state;
            if failed_bind {
                state.fail_bind.store(true, Ordering::Relaxed);
            } else {
                state.fail_original.store(true, Ordering::Relaxed);
            }
        });
        let (_, state, counters, device) = match result {
            Err(failure) => failure,
            Ok(_) => panic!("original-root failure admitted a private attachment"),
        };
        let events = state.events.lock().unwrap();
        assert!(events.contains(&Event::OriginalDrain));
        assert_eq!(events.contains(&Event::Bind), failed_bind);
        assert!(!events.contains(&Event::Allocate));
        assert!(!events.contains(&Event::BarUnmap));
        assert!(!events.contains(&Event::RootDrop));
        assert!(!state.bound.load(Ordering::Relaxed));
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        assert!(!device.lock().unwrap().dropped);
    }
}
#[test]
fn abandoned_cold_owner_retains_original_configuration_bars_and_root_without_effects() {
    let (inputs, state, counters, device) = original_inputs(0x5f69);
    // SAFETY: original isolated model, with no DMA/IRQ/work admission.
    let cold = match unsafe { host::cold::Cold::new(inputs) } {
        Ok(cold) => cold,
        Err(_) => panic!("valid cold model"),
    };
    state.events.lock().unwrap().clear();
    drop(cold);
    assert!(state.events.lock().unwrap().is_empty());
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert!(!device.lock().unwrap().dropped);
}
#[test]
fn every_cold_config_effect_or_read_failure_retains_before_private_binding() {
    let (inputs, state, _, _) = original_inputs(0x5f69);
    state.accesses.store(0, Ordering::Relaxed);
    // SAFETY: original isolated model owner and advancing clock.
    let cold = match unsafe { host::cold::Cold::new(inputs) } {
        Ok(cold) => cold,
        Err(_) => panic!("valid cold model"),
    };
    let bound = cold
        .quiesce_and_bind()
        .unwrap_or_else(|_| panic!("valid cold bind"));
    // The model finalize's own read is a peer check after the source sequence;
    // fault injection here covers only accesses from Cold and Layout.
    let accesses = state.accesses.load(Ordering::Relaxed) - 1;
    core::mem::forget(bound);
    for access in 1..=accesses {
        let (inputs, state, counters, device) = original_inputs(0x5f69);
        state.accesses.store(0, Ordering::Relaxed);
        state.fault_access.store(access, Ordering::Relaxed);
        state.events.lock().unwrap().clear();
        // SAFETY: same original model; injected effects/read failures never
        // certify quiescence or authorize a private binding.
        match unsafe { host::cold::Cold::new(inputs) } {
            Err((_, inputs)) => core::mem::forget(inputs),
            Ok(cold) => assert!(cold.quiesce_and_bind().is_err(), "cold access {access}"),
        }
        let events = state.events.lock().unwrap();
        assert!(!events.contains(&Event::Bind), "cold access {access}");
        assert!(!events.contains(&Event::Allocate));
        assert!(!events.contains(&Event::BarUnmap));
        assert!(!events.contains(&Event::RootDrop));
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        assert!(!device.lock().unwrap().dropped);
    }
}
#[test]
fn every_partial_native_allocation_failure_keeps_allocator_attachment_and_original_owners() {
    for allocation in 1..=14 {
        let f = fixture_native(0x5f69, false);
        f.state.fail_allocate.store(allocation, Ordering::Relaxed);
        // SAFETY: cold receipt and original-root binding already completed.
        let platform = match unsafe { NativePlatform::new(f.inputs) } {
            Ok(platform) => platform,
            Err(_) => panic!("valid native model"),
        };
        assert!(platform.into_transport().is_err());
        let events = f.state.events.lock().unwrap();
        assert_eq!(f.state.resets.load(Ordering::Relaxed), 1);
        assert!(!events.contains(&Event::DmaUnmap));
        assert!(!events.contains(&Event::Detach));
        assert!(!events.contains(&Event::BarUnmap));
        assert!(!events.contains(&Event::RootDrop));
        assert!(!events.contains(&Event::PageSourceDrop));
        assert_eq!(f.counters.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(
            f.device
                .lock()
                .unwrap()
                .domain
                .0
                .lock()
                .unwrap()
                .leases
                .len(),
            allocation - 1
        );
        assert!(!f.device.lock().unwrap().dropped);
    }
}
#[test]
fn active_native_drop_has_no_hidden_reset_drain_or_release() {
    let (mut t, device, state, counters) = transport(fixture_native(0x5f69, true));
    t.start(&catalog(&device, false)).unwrap();
    state.events.lock().unwrap().clear();
    drop(t);
    assert!(state.events.lock().unwrap().is_empty());
    assert_eq!(state.resets.load(Ordering::Relaxed), 1);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert!(!device.lock().unwrap().dropped);
}
#[test]
fn native_dma_unmap_failure_is_sticky_and_prevents_detach_and_pci_retirement() {
    let (mut t, device, state, counters) = transport(fixture_native(0x5f69, true));
    t.start(&catalog(&device, false)).unwrap();
    device.lock().unwrap().domain.0.lock().unwrap().fail_unmap = true;
    state.events.lock().unwrap().clear();
    let first = t.close().unwrap_err();
    let events = state.events.lock().unwrap().clone();
    assert!(events.contains(&Event::DmaUnmap));
    assert!(!events.contains(&Event::Detach));
    assert!(!events.contains(&Event::BarUnmap));
    assert_eq!(t.close(), Err(first));
    drop(t);
    assert_eq!(*state.events.lock().unwrap(), events);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert!(!device.lock().unwrap().dropped);
}
#[test]
fn native_config_mapping_failure_is_sticky_after_dma_and_requester_retirement() {
    let (mut t, device, state, counters) = transport(fixture_native(0x5f69, true));
    t.start(&catalog(&device, false)).unwrap();
    state.fail_config_unmap.store(true, Ordering::Relaxed);
    state.events.lock().unwrap().clear();
    let first = t.close().unwrap_err();
    let events = state.events.lock().unwrap().clone();
    assert!(position(&events, Event::DmaUnmap) < position(&events, Event::Detach));
    assert!(position(&events, Event::Detach) < position(&events, Event::BarUnmap));
    assert_eq!(t.close(), Err(first));
    drop(t);
    assert_eq!(*state.events.lock().unwrap(), events);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert!(!device.lock().unwrap().dropped);
}
#[test]
fn actual_attachment_pin_blocks_config_mapping_retirement_until_detach_acknowledges() {
    let mut f = fixture_native(0x5f69, false);
    let stale = f.inputs.attachment.domain();
    let mut mapping = f.inputs.function.into_config().into_mapping();
    // SAFETY: original isolated model has no private leases or live IRQ users;
    // this deliberate premature config retirement must independently refuse.
    assert_eq!(unsafe { mapping.retire() }, Err(owned::Error::Busy));
    assert_eq!(f.counters.unmaps.load(Ordering::Relaxed), 0);
    f.state.fail_detach.store(true, Ordering::Relaxed);
    // SAFETY: model original function remains contained with no live mappings.
    assert!(unsafe { f.inputs.attachment.detach() }.is_err());
    // SAFETY: failed detach must keep its actual config retention pin.
    assert_eq!(unsafe { mapping.retire() }, Err(owned::Error::Busy));
    f.state.fail_detach.store(false, Ordering::Relaxed);
    // SAFETY: only this independent test peer retries; native close is sticky.
    unsafe { f.inputs.attachment.detach() }.unwrap();
    // SAFETY: acknowledged detach released the final config retention pin.
    unsafe { mapping.retire() }.unwrap();
    assert_eq!(
        // SAFETY: retained stale domain must reject access after detach before
        // any requester generation or payload operation can be revived.
        unsafe { stale.drain_posted_writes() },
        Err(DmaError::Unmapped)
    );
    // SAFETY: isolated, unpublished device and configuration users are retired.
    unsafe { f.inputs.registers.retire() }.unwrap();
    assert_eq!(f.counters.unmaps.load(Ordering::Relaxed), 1);
}

#[test]
fn original_root_unwind_keeps_the_consumed_cold_owner_and_all_companions() {
    let (inputs, state, counters, device) = original_inputs(0x5f69);
    state.panic_original.store(true, Ordering::Relaxed);
    // SAFETY: original isolated config/root/BAR model with no private users.
    let cold = match unsafe { host::cold::Cold::new(inputs) } {
        Ok(cold) => cold,
        Err(_) => panic!("valid cold model"),
    };
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cold.quiesce_and_bind())).is_err()
    );
    let events = state.events.lock().unwrap();
    assert!(events.contains(&Event::OriginalDrain));
    assert!(!events.contains(&Event::Bind));
    assert!(!events.contains(&Event::BarUnmap));
    assert!(!events.contains(&Event::RootDrop));
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert!(!device.lock().unwrap().dropped);
}
#[test]
fn bound_payload_or_detach_unwind_is_terminal_without_a_hidden_retry_or_success() {
    for detach in [false, true] {
        let (mut t, device, state, counters) = transport(fixture_native(0x5f69, true));
        t.start(&catalog(&device, false)).unwrap();
        if detach {
            state.panic_detach.store(true, Ordering::Relaxed);
        } else {
            state.panic_payload.store(true, Ordering::Relaxed);
        }
        state.events.lock().unwrap().clear();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| t.close())).is_err());
        let events = state.events.lock().unwrap().clone();
        if detach {
            assert!(events.contains(&Event::Detach));
            assert!(Platform::retire_resources(t.platform.as_mut().unwrap()).is_err());
        } else {
            assert!(!events.contains(&Event::Detach));
            assert!(Platform::retire(t.platform.as_mut().unwrap()).is_err());
        }
        assert!(!events.contains(&Event::BarUnmap));
        let first = t.close().unwrap_err();
        assert_eq!(t.close(), Err(first));
        drop(t);
        assert_eq!(*state.events.lock().unwrap(), events);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        assert!(!device.lock().unwrap().dropped);
    }
}

#[test]
fn direct_native_resource_retirement_refuses_live_leases_before_any_pci_release() {
    let (mut t, device, state, counters) = transport(fixture_native(0x5f69, true));
    t.start(&catalog(&device, false)).unwrap();
    t.retire_platform().unwrap();
    assert_eq!(
        device.lock().unwrap().domain.0.lock().unwrap().leases.len(),
        14
    );
    state.events.lock().unwrap().clear();
    let first = Platform::retire_resources(t.platform.as_mut().unwrap()).unwrap_err();
    assert_eq!(
        first,
        Error::Native(host::Error::Dma(DmaError::MappingFailed))
    );
    assert_eq!(
        Platform::retire_resources(t.platform.as_mut().unwrap()),
        Err(first.clone())
    );
    assert_eq!(t.close(), Err(first));
    drop(t);
    assert!(state.events.lock().unwrap().is_empty());
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert!(!device.lock().unwrap().dropped);
    assert_eq!(
        device.lock().unwrap().domain.0.lock().unwrap().leases.len(),
        14
    );
}
#[test]
fn native_prepare_effect_failure_or_unwind_is_terminal_for_every_safe_entry() {
    for unwind in [false, true] {
        let f = fixture_native(0x5f69, false);
        // SAFETY: original cold receipt and binding have completed; no new
        // allocations or route exist before explicit platform preparation.
        let mut platform = match unsafe { NativePlatform::new(f.inputs) } {
            Ok(platform) => platform,
            Err(_) => panic!("valid native model"),
        };
        if unwind {
            f.state.panic_master.store(true, Ordering::Relaxed);
        } else {
            f.state.fail_master_ack.store(true, Ordering::Relaxed);
        }
        if unwind {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Platform::prepare(
                    &mut platform,
                    Chip::Bcm4378
                )))
                .is_err()
            );
        } else {
            assert!(Platform::prepare(&mut platform, Chip::Bcm4378).is_err());
        }
        let events = f.state.events.lock().unwrap().clone();
        let first = Platform::service_begin(&mut platform).unwrap_err();
        assert_eq!(
            Platform::prepare(&mut platform, Chip::Bcm4378),
            Err(first.clone())
        );
        assert_eq!(Platform::retire(&mut platform), Err(first.clone()));
        assert_eq!(Platform::retire_resources(&mut platform), Err(first));
        drop(platform);
        assert_eq!(*f.state.events.lock().unwrap(), events);
        assert_eq!(f.state.resets.load(Ordering::Relaxed), 1);
        assert_eq!(f.counters.unmaps.load(Ordering::Relaxed), 0);
        assert!(!f.device.lock().unwrap().dropped);
        assert!(!events.contains(&Event::Allocate));
        assert!(!events.contains(&Event::PageSourceDrop));
        assert!(!events.contains(&Event::RootDrop));
    }
}

fn native_dma_digest(domain: &Domain) -> Vec<(u64, [u8; 32])> {
    let state = domain.0.lock().unwrap();
    state
        .leases
        .iter()
        .map(|(address, lease)| {
            let pointer = lease.cpu.address(0, lease.token.bytes).unwrap();
            let bytes: Vec<_> = (0..lease.token.bytes)
                .map(|offset| {
                    // SAFETY: this explicit model owns the complete checked CPU
                    // mapping; process/device access is serialized while hashing it.
                    unsafe { pointer.as_ptr().add(offset).read_volatile() }
                })
                .collect();
            (*address, Sha256::digest(bytes).into())
        })
        .collect()
}
#[test]
fn protocol_close_unwind_seals_every_public_admission_before_platform_retirement() {
    let (mut t, device, state, counters) = transport(fixture_native(0x5f69, true));
    let provider = catalog(&device, false);
    t.start(&provider).unwrap();
    let domain = device.lock().unwrap().domain.clone();
    let controls_before = device.lock().unwrap().controls.len();
    state.panic_control.store(true, Ordering::Relaxed);
    state.events.lock().unwrap().clear();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| t.close())).is_err());
    assert_eq!(t.state(), TransportState::Closing);
    let events = state.events.lock().unwrap().clone();
    assert!(!events.contains(&Event::Reset));
    assert!(!events.contains(&Event::PayloadDrain));
    assert!(!events.contains(&Event::MsiDrain));
    assert!(!events.contains(&Event::DmaUnmap));
    assert!(!events.contains(&Event::Detach));
    assert!(!events.contains(&Event::BarUnmap));
    assert!(!events.contains(&Event::ConfigUnmap));
    {
        let model = device.lock().unwrap();
        assert_eq!(model.controls.len(), controls_before + 1);
        assert_eq!(model.controls.last().unwrap()[0], 3);
    }
    let dma = native_dma_digest(&domain);
    let operations = device.lock().unwrap().operations;
    let syncs = domain.0.lock().unwrap().syncs;
    assert_eq!(
        t.send(Kind::Command, &[0x03, 0x0c, 0]),
        Err(Error::State(TransportState::Closing))
    );
    assert_eq!(t.poll(), Err(Error::State(TransportState::Closing)));
    assert_eq!(
        t.start(&provider),
        Err(Error::State(TransportState::Closing))
    );
    assert_eq!(
        t.initialize(&provider),
        Err(Error::State(TransportState::Closing))
    );
    let first = t.close().unwrap_err();
    assert_eq!(t.state(), TransportState::Failed);
    assert_eq!(t.close(), Err(first));
    drop(t);
    assert_eq!(*state.events.lock().unwrap(), events);
    assert_eq!(device.lock().unwrap().operations, operations);
    assert_eq!(device.lock().unwrap().controls.len(), controls_before + 1);
    assert_eq!(domain.0.lock().unwrap().syncs, syncs);
    assert_eq!(native_dma_digest(&domain), dma);
    assert_eq!(domain.0.lock().unwrap().leases.len(), 14);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert!(!device.lock().unwrap().dropped);
}

#[test]
fn containment_flr_preserves_retiring_owner_but_foreign_generation_refuses() {
    let (mut first_transport, device, state, _) = transport(fixture_native(0x5f69, true));
    first_transport.start(&catalog(&device, false)).unwrap();
    let epoch = state.ownership_epoch.load(Ordering::Relaxed);
    first_transport.close().unwrap();
    assert_eq!(state.ownership_epoch.load(Ordering::Relaxed), epoch);
    let events = state.events.lock().unwrap();
    let detached = events.iter().rposition(|e| *e == Event::Detach).unwrap();
    let pin = events
        .iter()
        .rposition(|e| *e == Event::MsiPinRelease)
        .unwrap();
    let config = events
        .iter()
        .rposition(|e| *e == Event::ConfigUnmap)
        .unwrap();
    assert!(detached < pin && pin < config);
    drop(events);

    let (mut transport, device, state, counters) = transport(fixture_native(0x5f69, true));
    transport.start(&catalog(&device, false)).unwrap();
    state.ownership_epoch.fetch_add(1, Ordering::Relaxed);
    assert!(transport.close().is_err());
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert!(!device.lock().unwrap().dropped);
}

#[test]
fn equal_bdf_different_actual_config_attachment_refuses_before_native_admission() {
    let mut source = fixture_native(0x5f69, true);
    let mut foreign = fixture_native(0x5f69, true);
    assert_eq!(
        source.inputs.function.address,
        foreign.inputs.function.address
    );
    // Real independent RAM configuration allocations, not source IDs/numbers.
    let source_pin = source.inputs.function.config().retain_epoch().unwrap();
    assert!(
        source
            .inputs
            .attachment
            .matches_retention(&source_pin)
            .unwrap()
    );
    assert!(
        !foreign
            .inputs
            .attachment
            .matches_retention(&source_pin)
            .unwrap()
    );
    std::mem::swap(
        &mut source.inputs.attachment,
        &mut foreign.inputs.attachment,
    );
    let writes = source
        .state
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| matches!(event, Event::Write(..)))
        .count();
    // SAFETY: bounded read-only adversarial source assembly: all input graphs
    // remain retained, but their claimed association must be rejected.
    let (error, returned) = match unsafe { NativePlatform::new(source.inputs) } {
        Ok(_) => panic!("foreign actual configuration admitted"),
        Err(failure) => failure,
    };
    assert!(matches!(
        error,
        host::Error::Requirement("same actual source/attachment config allocation")
    ));
    let events = source.state.events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::Write(..)))
            .count(),
        writes
    );
    assert!(!events.contains(&Event::MsiBind));
    assert_eq!(source.counters.unmaps.load(Ordering::Relaxed), 0);
    // Default erroneous-input abandonment cannot release uncertain native pins.
    core::mem::forget(returned);
    core::mem::forget(foreign.inputs);
}
