// SPDX-License-Identifier: MIT
//! Native config/mapping/Registry models composed with the literal IPC device.
//! These are software ownership/effect tests, not physical platform validation.
use super::*;
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
    self as host, Configuration, Inputs, MappedRegisters, MsiCompletion, NativePlatform, Registers,
    Time,
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
            OwnedConfig,
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
    MsiBind,
    MsiDrain,
    CpuPending,
    Eoi,
    BarUnmap,
    ConfigUnmap,
    DmaUnmap,
    RootDrop,
}
struct State {
    events: Mutex<Vec<Event>>,
    registry: AtomicPtr<Registry<Cpu>>,
    vector: AtomicU8,
    pending: AtomicBool,
    fail_cpu: AtomicBool,
    fail_payload: AtomicBool,
    fail_msi: AtomicBool,
    fail_enable_ack: AtomicBool,
    fail_bar_unmap: AtomicBool,
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
            fail_enable_ack: AtomicBool::new(false),
            fail_bar_unmap: AtomicBool::new(false),
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
    fn into_mapping(self) -> Mapping {
        self.state.event(Event::ConfigUnmap);
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
        // SAFETY: caller keeps exact pins/domain as in delegated model.
        unsafe { self.domain.map(pages, direction, limit) }
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> core::result::Result<(), DmaError> {
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
        // SAFETY: exact mapping/direction/bounds delegated to the domain.
        unsafe { self.domain.sync_for_device(mapping, range, direction) }
    }
    unsafe fn sync_for_cpu(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> core::result::Result<(), DmaError> {
        // SAFETY: no continuous CPU handoff is invented by this model.
        unsafe { self.domain.sync_for_cpu(mapping, range, direction) }
    }
    unsafe fn drain_posted_writes(&self) -> core::result::Result<(), DmaError> {
        self.state.event(Event::PayloadDrain);
        assert!(self.state.resets.load(Ordering::Relaxed) != 0);
        if self.state.fail_payload.load(Ordering::Relaxed) {
            return Err(DmaError::DrainUnavailable);
        }
        self.domain.0.lock().unwrap().stopped = true;
        Ok(())
    }
}
struct PageModel(Mutex<u64>);
impl PageSource for PageModel {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> core::result::Result<PinnedPages, MemoryError> {
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
struct Delivery(Arc<State>);
// SAFETY: independent route model; payload and MSI completion are
// separate events, with independent injected failures and kept ownership.
unsafe impl host::delivery::DeliveryOwner for Delivery {
    fn bind_route(&mut self, message: irq::MsiMessage) -> core::result::Result<(), host::Error> {
        assert_eq!(message.address, 0xfee0_0000);
        assert_eq!(
            message.data,
            u32::from(self.0.vector.load(Ordering::Relaxed))
        );
        self.0.event(Event::MsiBind);
        Ok(())
    }
    unsafe fn drain_posted_msi(&self) -> core::result::Result<(), host::Error> {
        self.0.event(Event::MsiDrain);
        assert_eq!(
            self.0.events.lock().unwrap().iter().rev().nth(1),
            Some(&Event::PayloadDrain)
        );
        if self.0.fail_msi.load(Ordering::Relaxed) {
            return Err(host::Error::Requirement(
                "independent modeled posted MSI drain failed",
            ));
        }
        Ok(())
    }
}
struct Cpu(Arc<State>);
// SAFETY: explicit same-CPU APIC delivery model, Registry controls slots.
unsafe impl irq::Platform for Cpu {
    fn check_cpu(&self) -> core::result::Result<(), irq::IrqError> {
        Ok(())
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
    fn eoi(&self) {
        self.0.event(Event::Eoi);
        self.0.pending.store(false, Ordering::Relaxed);
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
    });
    let inputs = Inputs {
        function,
        retained: Arc::new(Root(state.clone())),
        topology,
        registers: NativeRegisters {
            registers,
            device: RefCell::new(model),
            state: state.clone(),
        },
        domain,
        pages: Box::new(PageModel(Mutex::new(0x1_0000_0000))),
        board: Board::from_property(b"apple,formosa\0").unwrap(),
        properties: vec![],
        clock: ClockModel(device.clone()),
        interrupts: registry,
        msi_completion: if completion {
            MsiCompletion::model(Box::new(Delivery(state.clone())))
        } else {
            MsiCompletion::unavailable()
        },
    };
    Fixture {
        inputs,
        device,
        state,
        counters,
    }
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
        assert!(position(&events, Event::PayloadDrain) < position(&events, Event::MsiDrain));
        assert!(position(&events, Event::MsiDrain) < position(&events, Event::CpuPending));
        assert!(position(&events, Event::CpuPending) < position(&events, Event::BarUnmap));
        assert!(position(&events, Event::BarUnmap) < position(&events, Event::DmaUnmap));
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
    for failure in 0..6 {
        let (mut t, device, state, counters) = transport(fixture_native(0x5f69, failure != 3));
        t.start(&catalog(&device, false)).unwrap();
        match failure {
            0 => state.stuck_pending.store(true, Ordering::Relaxed),
            1 => state.fail_payload.store(true, Ordering::Relaxed),
            2 => state.fail_msi.store(true, Ordering::Relaxed),
            3 => {}
            4 => state.fail_cpu.store(true, Ordering::Relaxed),
            5 => state.fail_bar_unmap.store(true, Ordering::Relaxed),
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
        assert!(!events.contains(&Event::DmaUnmap));
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        drop(t);
        assert!(!device.lock().unwrap().dropped);
        assert!(!state.events.lock().unwrap().contains(&Event::RootDrop));
        assert!(
            !device
                .lock()
                .unwrap()
                .domain
                .0
                .lock()
                .unwrap()
                .leases
                .is_empty()
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
    // SAFETY: constructor refusal had no device effects; this isolated model
    // has never published DMA/IRQ work or any raw config/BAR mapping alias.
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
