// SPDX-License-Identifier: GPL-2.0-only
//! Independent posted-config and payload-domain models; authored UNRUN.
use super::*;
use crate::bus::{
    dma::{
        mapping::{Direction, DmaError, DmaMapping, DomainMapping},
        memory::{PageBacking, PinnedPages},
        pages::DmaPages,
    },
    mmio::owned::{
        AddressSpace, InstalledMapping, MapFailure, MapRequest, MappingPlatform, PhysicalSpan,
        ResourceBacking, ResourceKind,
    },
};
use alloc::collections::BTreeMap;
use core::{
    cell::UnsafeCell,
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicUsize},
};
use owned::Lifecycle as _;
extern crate std;
use std::sync::Mutex;

const ROOT: usize = 1 << 15;
const BRIDGE: usize = 1 << 20;
const NVME: usize = 2 << 20;
const NVME_BASE: u64 = 0x8000_4000;
const COMMAND_OFFSET: usize = COMMAND as usize;

// The same finite counter scale as the shared independent NVMe peer. This is
// an admitted software-test budget, not a measured physical CPU calibration.
// Composed command timeouts use the explicit cfg(test) 1-ms policy; actual
// public native attachment keeps the shared 30-s controller policy.
fn model_clock() -> Clock {
    Clock {
        ticks_per_microsecond: 1000,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Event {
    Posted(usize, u8, u32),
    Flushed(usize, u8),
    Parent(u16),
    Map(u64),
    Drain,
    Unmap(u64),
    Nvme(&'static str),
    Wait(u64),
}
struct State {
    parent: BTreeMap<u16, u8>,
    child: BTreeMap<usize, u8>,
    pending: Option<(usize, u8, u32)>,
    events: Vec<Event>,
    ack_failure: Option<usize>,
    pm_failure: bool,
    pm_loses_bar: bool,
    release_failure: bool,
    epoch: u64,
    drained: bool,
    mappings: BTreeMap<u64, DomainMapping>,
    next: u64,
}
fn get<K: Ord + Copy>(memory: &BTreeMap<K, u8>, keys: impl Iterator<Item = K>) -> u32 {
    keys.enumerate().fold(0, |value, (i, key)| {
        value | u32::from(*memory.get(&key).unwrap_or(&0xff)) << (i * 8)
    })
}
impl State {
    fn parent(&self, offset: u16, width: u8) -> u32 {
        get(&self.parent, (0..u16::from(width)).map(|i| offset + i))
    }
    fn child(&self, offset: usize, width: u8) -> u32 {
        get(&self.child, (0..usize::from(width)).map(|i| offset + i))
    }
    fn set_parent(&mut self, offset: u16, width: u8, value: u32) {
        for i in 0..u16::from(width) {
            self.parent.insert(offset + i, (value >> (i * 8)) as u8);
        }
    }
    fn set(&mut self, offset: usize, width: u8, value: u32) {
        for i in 0..usize::from(width) {
            self.child.insert(offset + i, (value >> (i * 8)) as u8);
        }
    }
    fn any_master(&self) -> bool {
        self.parent(COMMAND, 2) & u32::from(BUS_MASTER) != 0
            || self
                .child
                .keys()
                .filter(|offset| **offset & 0xfff == COMMAND_OFFSET)
                .any(|offset| self.child(*offset, 2) & u32::from(BUS_MASTER) != 0)
    }
    fn add_function(&mut self, base: usize, class: u32, header: u8, kind: u8) {
        for offset in 0..4096 {
            self.child.insert(base + offset, 0);
        }
        self.set(base, 4, 0x1234_8086);
        self.set(base + 8, 4, class);
        self.set(base + 0xe, 1, u32::from(header));
        self.set(base + COMMAND_OFFSET, 2, u32::from(INTX_DISABLE));
        self.set(base + 6, 2, 0x10);
        self.set(base + 0x34, 1, 0x40);
        self.set(base + 0x40, 2, 0x10);
        self.set(base + 0x42, 2, 2 | u32::from(kind) << 4);
    }
    fn bridge(&mut self, base: usize, primary: u8, secondary: u8, subordinate: u8) {
        self.add_function(base, 0x0604_0000, 1, if primary == 0 { 4 } else { 5 });
        self.set(
            base + 0x18,
            4,
            u32::from(primary) | u32::from(secondary) << 8 | u32::from(subordinate) << 16,
        );
        self.set(base + 0x20, 4, 0x8000_8000);
        self.set(base + 0x24, 4, 0x0000_fff0); // Disabled prefetch window.
    }
}
struct Model {
    state: Arc<Mutex<State>>,
    drops: Arc<AtomicUsize>,
}
impl Model {
    fn new() -> Self {
        let mut state = State {
            parent: BTreeMap::new(),
            child: BTreeMap::new(),
            pending: None,
            events: Vec::new(),
            ack_failure: None,
            pm_failure: false,
            pm_loses_bar: false,
            release_failure: false,
            epoch: 1,
            drained: false,
            mappings: BTreeMap::new(),
            next: 0,
        };
        for offset in 0..256 {
            state.parent.insert(offset, 0);
        }
        state.set_parent(0, 4, 0x28c0_8086);
        state.set_parent(COMMAND, 2, u32::from(INTX_DISABLE));
        for (index, (base, prefetch)) in [
            (0x4000_0000u64, false),
            (0x8000_0000, false),
            (0x9000_0000, true),
        ]
        .into_iter()
        .enumerate()
        {
            state.set_parent(
                0x10 + index as u16 * 8,
                4,
                base as u32 | 4 | if prefetch { 8 } else { 0 },
            );
            state.set_parent(0x14 + index as u16 * 8, 4, (base >> 32) as u32);
        }
        state.bridge(ROOT, 0, 1, 2);
        state.bridge(BRIDGE, 1, 2, 2);
        state.add_function(NVME, 0x0108_0200, 0, 0);
        state.set(NVME + 0x10, 4, NVME_BASE as u32 | 4);
        Self {
            state: Arc::new(Mutex::new(state)),
            drops: Arc::new(AtomicUsize::new(0)),
        }
    }
}
impl Drop for Model {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: isolated independent configuration storage. Child writes are posted
// until an actual equal-width model read flushes them; no production authority.
unsafe impl Registers for Model {
    fn parent_read(&mut self, offset: u16, width: u8) -> Result<u32, Error> {
        let state = self.state.lock().unwrap();
        let value = state.parent(offset, width);
        Ok(if state.release_failure && offset == COMMAND {
            value | u32::from(MEMORY)
        } else {
            value
        })
    }
    fn parent_write(&mut self, offset: u16, width: u8, value: u32) -> Result<(), Error> {
        let mut state = self.state.lock().unwrap();
        let old = state.parent(offset, width);
        state.set_parent(offset, width, value);
        if offset == COMMAND {
            if (old | value) & u32::from(BUS_MASTER) != 0 {
                state.drained = false;
            }
            state.events.push(Event::Parent(value as u16));
        }
        Ok(())
    }
    fn bar(&self, index: u8) -> (u64, u64, bool) {
        match index {
            0 => (0x4000_0000, 4 << 20, false),
            2 => (0x8000_0000, 0x100_0000, false),
            4 => (0x9000_0000, 0x100_0000, true),
            _ => unreachable!(),
        }
    }
    fn shadow_read(&mut self, _: usize) -> Result<u64, Error> {
        Err(Error::Mapping)
    }
    fn child_read(&mut self, offset: usize, width: u8) -> Result<u32, Error> {
        let mut state = self.state.lock().unwrap();
        if let Some((posted, posted_width, value)) = state.pending
            && posted == offset
            && posted_width == width
        {
            state.pending = None;
            if [ROOT, BRIDGE, NVME]
                .into_iter()
                .any(|base| posted == base + COMMAND_OFFSET)
                && (state.child(posted, posted_width) | value) & u32::from(BUS_MASTER) != 0
            {
                state.drained = false;
            }
            let mut value = value;
            if [ROOT, BRIDGE, NVME]
                .into_iter()
                .any(|base| posted == base + 0x84)
            {
                let old = state.child(posted, 2);
                value = value & !0x8000 | if value & 0x8000 == 0 { old & 0x8000 } else { 0 };
                if state.pm_failure {
                    value |= 3;
                }
                if state.pm_loses_bar {
                    state.set(NVME + 0x10, 4, 0);
                }
            }
            state.set(posted, posted_width, value);
            state.events.push(Event::Flushed(posted, posted_width));
        }
        let value = state.child(offset, width);
        Ok(if state.ack_failure == Some(offset) {
            value & !u32::from(BUS_MASTER)
        } else {
            value
        })
    }
    fn child_write(&mut self, offset: usize, width: u8, value: u32) -> Result<(), Error> {
        {
            let mut state = self.state.lock().unwrap();
            assert!(state.pending.is_none());
            state.pending = Some((offset, width, value));
            state.events.push(Event::Posted(offset, width, value));
        }
        // The native Registers contract requires this actual posted-write
        // readback, independently of lifecycle's subsequent equality check.
        let _ = self.child_read(offset, width)?;
        Ok(())
    }
    fn table_read(&mut self, _: u64) -> Result<u32, Error> {
        Err(Error::Mapping)
    }
    fn table_write(&mut self, _: u64, _: u32) -> Result<(), Error> {
        Err(Error::Mapping)
    }
}
struct Backing {
    owner: Arc<()>,
}
// SAFETY: symbolic exclusive aperture in an isolated topology model; never
// passed to a production mapping provider or interpreted as RAM.
unsafe impl ResourceBacking for Backing {
    fn physical_span(&self) -> PhysicalSpan {
        PhysicalSpan::new(0x8000_0000, 0x100_0000).unwrap()
    }
    fn kind(&self) -> ResourceKind {
        ResourceKind::Registers
    }
}
fn fixture(model: Model) -> (Host<Model>, FirmwareBar) {
    let host = match Host::initialize(model) {
        Ok(host) => host,
        Err((error, _)) => panic!("host: {error:?}"),
    };
    let bar = FirmwareBar {
        domain: host.domain,
        child: Address {
            domain: host.domain,
            bus: 2,
            device: 0,
            function: 0,
        },
        low: NVME_BASE as u32 | 4,
        high: 0,
        bus_start: NVME_BASE,
        bytes: 8192,
        window: host.windows[0],
        resource: Resource::new(Box::new(Backing {
            owner: Arc::new(()),
        })),
    };
    (host, bar)
}
fn lifecycle(model: Model) -> (Lifecycle<Model>, Arc<Domain>) {
    let state = Arc::clone(&model.state);
    let (mut host, bar) = fixture(model);
    let hierarchy = Hierarchy::discover(&mut host, &bar).unwrap();
    let domain = Arc::new(Domain { state, epoch: 1 });
    (
        Lifecycle {
            host: Some(host),
            returned: Rc::new(RefCell::new(Returned(None))),
            hierarchy: Some(hierarchy),
            domain: Some(domain.clone()),
            clock: model_clock(),
            phase: Phase::Claimed,
        },
        domain,
    )
}
struct Domain {
    state: Arc<Mutex<State>>,
    epoch: u64,
}
// SAFETY: isolated model tracks its actual retained page pins/IOVA epochs and
// raw config storage. It cannot acknowledge drain while any actual BM is set.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        _: Direction,
        _: u64,
    ) -> Result<DomainMapping, DmaError> {
        let mut state = self.state.lock().unwrap();
        if state.epoch != self.epoch {
            return Err(DmaError::MappingFailed);
        }
        state.next += 1;
        let mapping = DomainMapping {
            id: state.next,
            address: 0x2000_0000 + state.next * 0x10000,
            bytes: pages.bytes(),
        };
        state.mappings.insert(mapping.id, mapping);
        state.events.push(Event::Map(mapping.id));
        Ok(mapping)
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> Result<(), DmaError> {
        let mut state = self.state.lock().unwrap();
        if state.epoch != self.epoch
            || state.any_master()
            || !state.drained
            || !state.mappings.contains_key(&mapping.id)
        {
            return Err(DmaError::InvalidationFailed);
        }
        state.mappings.remove(&mapping.id);
        state.events.push(Event::Unmap(mapping.id));
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        Ok(())
    }
    unsafe fn sync_for_cpu(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        Ok(())
    }
    unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
        let mut state = self.state.lock().unwrap();
        if state.epoch != self.epoch || state.any_master() {
            return Err(DmaError::DrainUnavailable);
        }
        state.drained = true;
        state.events.push(Event::Drain);
        Ok(())
    }
}
#[repr(align(4096))]
struct Buffer([u8; 4096]);
struct Pages {
    buffer: Box<Buffer>,
    drops: Arc<AtomicUsize>,
}
// SAFETY: one owned, aligned, initially zeroed model page with immutable labels.
unsafe impl PageBacking for Pages {
    fn cpu_base(&self) -> NonNull<u8> {
        NonNull::from(&self.buffer.0[0])
    }
    fn physical_pages(&self) -> &[u64] {
        &[0x1000_0000]
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
impl Drop for Pages {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
fn pin(drops: Arc<AtomicUsize>) -> PinnedPages {
    PinnedPages::new(
        Box::new(Pages {
            buffer: Box::new(Buffer([0; 4096])),
            drops,
        }),
        4096,
        4096,
    )
    .unwrap()
}

#[test]
fn real_bridge_path_and_posted_command_order_precede_payload_drain_and_unmap() {
    let model = Model::new();
    let state = model.state.clone();
    let drops = model.drops.clone();
    let (mut life, domain) = lifecycle(model);
    let mut returned = RetiredHierarchy(Rc::clone(&life.returned));
    assert!(!returned.is_ready());
    let page_drops = Arc::new(AtomicUsize::new(0));
    let mut mapping = DmaMapping::map(
        domain.clone(),
        pin(page_drops.clone()),
        Direction::Bidirectional,
        u64::MAX,
    )
    .unwrap();
    life.prepare().unwrap();
    assert!(!state.lock().unwrap().any_master());
    life.enable_dma().unwrap();
    // SAFETY: intentional negative probe against the isolated provider; it
    // refuses because the actual configuration still permits new requests.
    assert_eq!(
        unsafe { domain.drain_posted_writes() },
        Err(DmaError::DrainUnavailable)
    );
    life.disable_dma().unwrap();
    // SAFETY: the model intentionally verifies missing-domain-drain refusal.
    assert_eq!(
        unsafe { mapping.unmap() },
        Err(DmaError::InvalidationFailed)
    );
    // SAFETY: all actual model BM bits have now acknowledged clear.
    unsafe { domain.drain_posted_writes() }.unwrap();
    // SAFETY: this test issues no asynchronous payload accesses; original
    // provider drain completed, while the original host is still retained.
    unsafe { mapping.unmap() }.unwrap();
    assert_eq!(page_drops.load(Ordering::Relaxed), 1);
    assert!(!returned.is_ready());
    life.release().unwrap();
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert!(returned.is_ready());
    // SAFETY: this isolated model has no controller handles, real bindings or
    // native reset/removal actors. All model mappings were explicitly unmapped.
    let original = unsafe { returned.take_after_retirement() }.unwrap();
    assert!(!state.lock().unwrap().any_master());
    drop(original);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    let state = state.lock().unwrap();
    let enabled: Vec<_> = state
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Parent(command) if command & BUS_MASTER != 0 => Some(usize::MAX),
            Event::Posted(offset, 2, value) if value & u32::from(BUS_MASTER) != 0 => Some(*offset),
            _ => None,
        })
        .collect();
    assert_eq!(enabled, [usize::MAX, ROOT + 4, BRIDGE + 4, NVME + 4]);
    for (index, event) in state.events.iter().enumerate() {
        if let Event::Posted(offset, width, _) = event {
            assert_eq!(state.events[index + 1], Event::Flushed(*offset, *width));
        }
    }
    let drain = state
        .events
        .iter()
        .position(|event| *event == Event::Drain)
        .unwrap();
    let unmap = state
        .events
        .iter()
        .position(|event| matches!(event, Event::Unmap(_)))
        .unwrap();
    let release = state
        .events
        .iter()
        .rposition(|event| matches!(event, Event::Parent(command) if command & MEMORY == 0))
        .unwrap();
    assert!(drain < unmap && unmap < release);
}

#[test]
fn abandoned_retired_handle_preserves_the_whole_original_hierarchy() {
    let model = Model::new();
    let drops = model.drops.clone();
    let (mut life, domain) = lifecycle(model);
    let returned = RetiredHierarchy(Rc::clone(&life.returned));
    life.prepare().unwrap();
    life.disable_dma().unwrap();
    // SAFETY: no model engine started; actual hierarchy BM-clear acknowledged.
    unsafe { domain.drain_posted_writes() }.unwrap();
    life.release().unwrap();
    assert!(returned.is_ready());
    drop(life);
    drop(returned);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
}

#[test]
fn every_ancestor_window_and_unique_firmware_bus_route_is_required() {
    for (base, offset, value) in [
        (ROOT, 0x20, 0x8010_8010),
        (BRIDGE, 0x20, 0x8010_8010),
        (ROOT, 0x18, 0x0001_0100),
        (BRIDGE, 0x18, 0x0002_0001),
    ] {
        let model = Model::new();
        model.state.lock().unwrap().set(base + offset, 4, value);
        let (mut host, bar) = fixture(model);
        assert!(Hierarchy::discover(&mut host, &bar).is_err());
    }
    let model = Model::new();
    model
        .state
        .lock()
        .unwrap()
        .bridge(ROOT + (1 << 15), 0, 1, 2);
    let (mut host, bar) = fixture(model);
    assert!(Hierarchy::discover(&mut host, &bar).is_err());
}

#[test]
fn stopped_siblings_remain_contained_and_a_second_nvme_is_explicitly_refused() {
    for extra_class in [0x0200_0000, 0x0108_0200] {
        let model = Model::new();
        let extra = NVME + (1 << 15);
        model
            .state
            .lock()
            .unwrap()
            .add_function(extra, extra_class, 0, 0);
        let state = model.state.clone();
        let (mut host, bar) = fixture(model);
        let result = Hierarchy::discover(&mut host, &bar);
        if extra_class == 0x0108_0200 {
            assert!(matches!(result, Err(Error::UnsupportedDevice)));
        } else {
            let mut hierarchy = result.unwrap();
            hierarchy.prepare(&mut host, model_clock()).unwrap();
            hierarchy.enable(&mut host).unwrap();
            assert_eq!(state.lock().unwrap().child(extra + 4, 2) & 7, 0);
        }
    }
}

#[test]
fn failed_posted_bus_master_ack_retains_original_hierarchy_and_domain() {
    let model = Model::new();
    let state = model.state.clone();
    let drops = model.drops.clone();
    let (mut life, domain) = lifecycle(model);
    life.prepare().unwrap();
    state.lock().unwrap().ack_failure = Some(BRIDGE + 4);
    assert!(life.enable_dma().is_err());
    assert_eq!(life.phase, Phase::Quarantined);
    // The actual posted write occurred despite the failed equality readback.
    assert_ne!(
        state.lock().unwrap().child(BRIDGE + 4, 2) & u32::from(BUS_MASTER),
        0
    );
    // SAFETY: negative model probe; original domain observes actual BM state.
    assert_eq!(
        unsafe { domain.drain_posted_writes() },
        Err(DmaError::DrainUnavailable)
    );
    drop(life);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert!(Arc::strong_count(&domain) > 1);
}

#[test]
fn d3hot_transition_preserves_pme_status_but_refuses_failed_power_or_lost_assignment() {
    for (fail_power, lose_bar) in [(false, false), (true, false), (false, true)] {
        let model = Model::new();
        {
            let mut state = model.state.lock().unwrap();
            state.set(NVME + 0x40, 2, 0x8010);
            state.set(NVME + 0x80, 2, 1);
            state.set(NVME + 0x82, 2, 3);
            state.set(NVME + 0x84, 2, 0x8103);
            state.pm_failure = fail_power;
            state.pm_loses_bar = lose_bar;
        }
        let state = model.state.clone();
        let drops = model.drops.clone();
        let (mut life, _) = lifecycle(model);
        assert_eq!(life.prepare().is_ok(), !(fail_power || lose_bar));
        assert_eq!(state.lock().unwrap().child(NVME + 0x84, 2) & 0x8000, 0x8000);
        assert!(!state.lock().unwrap().any_master());
        drop(life);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn invalid_timing_precedes_hierarchy_and_capability_config_accesses() {
    for rate in [0, u64::MAX, u64::MAX / 2 / 60_000_000 + 1] {
        let model = Model::new();
        let state = model.state.clone();
        let (mut host, bar) = fixture(model);
        let mut hierarchy = Hierarchy::discover(&mut host, &bar).unwrap();
        let before = state.lock().unwrap().events.clone();
        let clock = Clock {
            ticks_per_microsecond: rate,
        };
        assert_eq!(hierarchy.prepare(&mut host, clock), Err(Error::Clock));
        assert_eq!(state.lock().unwrap().events, before);
        let mut config = host.config(2, 0, 0).unwrap();
        let capabilities = capabilities::Capabilities::inspect(&mut config, false).unwrap();
        let before = state.lock().unwrap().events.clone();
        assert_eq!(
            capabilities.power_up_with_timer(&mut config, &clock),
            Err(Error::Clock)
        );
        assert_eq!(state.lock().unwrap().events, before);
    }
}

#[test]
fn exact_pm_wait_requests_follow_actual_word_effect_and_propagate_failure() {
    struct CapturedTime {
        state: Arc<Mutex<State>>,
        fail: bool,
    }
    // SAFETY: explicit same-peer symbolic time. Actual posted config effects
    // must precede the requested interval; no physical timer is represented.
    unsafe impl crate::bus::pci::power::Timer for CapturedTime {
        fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
            Ok(())
        }
        fn wait_us(&self, microseconds: u64) -> Result<(), crate::bus::pci::power::Error> {
            let mut state = self.state.lock().unwrap();
            assert_eq!(state.child(NVME + 0x84, 2) & 0x8103, 0x8000);
            state.events.push(Event::Wait(microseconds));
            if self.fail {
                Err(crate::bus::pci::power::Error::Clock)
            } else {
                Ok(())
            }
        }
    }
    for power in [2, 3] {
        for fail in [false, true] {
            let model = Model::new();
            let state = model.state.clone();
            {
                let mut state = state.lock().unwrap();
                state.set(NVME + 0x40, 2, 0x8010);
                state.set(NVME + 0x80, 2, 1);
                state.set(NVME + 0x82, 2, 3);
                state.set(NVME + 0x84, 2, 0x8100 | power);
            }
            let (mut host, _) = fixture(model);
            let mut config = host.config(2, 0, 0).unwrap();
            let capabilities = capabilities::Capabilities::inspect(&mut config, false).unwrap();
            let result = capabilities.power_up_with_timer(
                &mut config,
                &CapturedTime {
                    state: state.clone(),
                    fail,
                },
            );
            assert_eq!(result, if fail { Err(Error::Clock) } else { Ok(()) });
            let waits: Vec<_> = state
                .lock()
                .unwrap()
                .events
                .iter()
                .filter_map(|event| match event {
                    Event::Wait(us) => Some(*us),
                    _ => None,
                })
                .collect();
            assert_eq!(waits, vec![if power == 3 { 10_000 } else { 200 }]);
        }
    }
}

#[test]
fn reassignment_removal_and_wrong_host_epoch_never_restart_the_controller() {
    for change in 0..7 {
        let model = Model::new();
        let state = model.state.clone();
        let (mut host, mut bar) = fixture(model);
        if change == 0 {
            bar.domain += 1;
            assert!(Hierarchy::discover(&mut host, &bar).is_err());
            continue;
        }
        let mut hierarchy = Hierarchy::discover(&mut host, &bar).unwrap();
        {
            let mut state = state.lock().unwrap();
            match change {
                1 => state.set(NVME + 0x10, 4, 0x8000_8004),
                2 => state.set(NVME, 4, u32::MAX),
                3 => state.set(BRIDGE + 0x20, 4, 0x8010_8010),
                4 => {
                    state.set_parent(VMCAP, 2, 1);
                    state.set_parent(VMCONFIG, 2, 1 << 8);
                }
                5 => {
                    state.set_parent(6, 2, 0x10);
                    state.set_parent(0x34, 1, 0x80);
                    state.set_parent(0x80, 2, 1);
                    state.set_parent(0x82, 2, 3);
                    state.set_parent(0x84, 2, 3);
                }
                _ => state.set_parent(0, 4, 0x28c1_8086),
            }
        }
        assert!(hierarchy.prepare(&mut host, model_clock()).is_err());
        assert!(!state.lock().unwrap().any_master());
    }
}

#[test]
fn provider_epoch_refusal_and_release_failure_keep_original_resources_pinned() {
    let model = Model::new();
    let drops = model.drops.clone();
    let state = model.state.clone();
    let (mut life, domain) = lifecycle(model);
    // This is an actual model provider refusing its own changed root epoch;
    // it does not claim the shared DmaDomain API can identify a wrong domain.
    state.lock().unwrap().epoch = 2;
    let page_drops = Arc::new(AtomicUsize::new(0));
    assert!(
        DmaMapping::map(
            domain.clone(),
            pin(page_drops.clone()),
            Direction::Bidirectional,
            u64::MAX
        )
        .is_err()
    );
    assert_eq!(page_drops.load(Ordering::Relaxed), 1);
    state.lock().unwrap().epoch = 1;
    life.prepare().unwrap();
    life.disable_dma().unwrap();
    // SAFETY: no engine or payload was started, actual BM clears acknowledged.
    unsafe { domain.drain_posted_writes() }.unwrap();
    state.lock().unwrap().release_failure = true;
    assert!(life.release().is_err());
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert!(Arc::strong_count(&domain) > 1);
    assert_eq!(life.phase, Phase::Quarantined);
    assert!(life.returned.borrow().0.is_none());
    drop(life);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
}

#[test]
fn malformed_capabilities_active_translation_and_bar_profiles_are_refused() {
    for case in 0..5 {
        let model = Model::new();
        {
            let mut state = model.state.lock().unwrap();
            match case {
                0 => state.set(NVME + 0x40, 2, 0x4410), // Link into PCIe body.
                1 => state.set(NVME + 0x48, 2, 1 << 11), // NoSnoop enabled.
                2 => {
                    state.set(NVME + 0x100, 4, 0x0001_000f);
                    state.set(NVME + 0x106, 2, 0x8000);
                }
                3 => state.set(NVME + 0x100, 4, 0x0001_0010), // Unqualified SR-IOV.
                _ => state.set(NVME + 4, 2, u32::from(INTX_DISABLE | BUS_MASTER)),
            }
        }
        let (mut host, bar) = fixture(model);
        assert!(Hierarchy::discover(&mut host, &bar).is_err());
    }
    for (low, high, bytes) in [
        (0, 0, 8192),
        (0x8000_4001, 0, 8192),
        (0x8000_4002, 0, 8192),
        (0xffff_e004, u32::MAX, 8192),
        (0x8000_4004, 0, 4096),
        (0x8000_5004, 0, 8192),
    ] {
        assert!(bar_address(low, high, bytes).is_err());
    }
}

#[repr(align(4096))]
struct DeviceMemory(UnsafeCell<[u8; 16384]>);
struct Platform {
    memory: Box<DeviceMemory>,
    original_owner: Arc<()>,
    epoch: AtomicUsize,
    fail_second_once: AtomicBool,
    unmaps: Mutex<Vec<u64>>,
}
// SAFETY: isolated CPU mapping fixture; no concurrent register consumers are
// started, and mutation occurs only through real registry-owned bounded views.
unsafe impl Send for Platform {}
// SAFETY: same fixture exclusion; metadata is immutable, atomic or locked.
unsafe impl Sync for Platform {}
// SAFETY: model allocates its actual aligned CPU storage and validates original
// reservation identity and current provider epoch, not just physical numbers.
unsafe impl MappingPlatform for Platform {
    fn check_context(&self, _: AddressSpace) -> Result<(), crate::bus::mmio::owned::Error> {
        Ok(())
    }
    unsafe fn map(
        &self,
        resource: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        use crate::bus::mmio::owned::Error as MappingError;
        let Some(backing) = resource.backing().downcast_ref::<Backing>() else {
            return Err(MapFailure::Unchanged(MappingError::Unavailable));
        };
        if !Arc::ptr_eq(&backing.owner, &self.original_owner)
            || self.epoch.load(Ordering::Relaxed) != 1
        {
            return Err(MapFailure::Unchanged(MappingError::Unavailable));
        }
        let offset = request
            .physical
            .start()
            .checked_sub(NVME_BASE)
            .ok_or(MapFailure::Unchanged(MappingError::OutsideResource))?;
        if offset
            .checked_add(request.physical.bytes())
            .is_none_or(|end| end > 16384)
        {
            return Err(MapFailure::Unchanged(MappingError::OutsideResource));
        }
        // SAFETY: provider owns this exact bounded model allocation; symbolic
        // physical pages are deliberately unrelated to its actual CPU address.
        let cpu_base = unsafe {
            NonNull::new_unchecked(self.memory.0.get().cast::<u8>().add(offset as usize))
        };
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
        installed: InstalledMapping,
    ) -> Result<(), crate::bus::mmio::owned::Error> {
        use crate::bus::mmio::owned::Error as MappingError;
        assert_eq!(request.id, installed.token);
        self.unmaps.lock().unwrap().push(request.id);
        if request.physical.start() == NVME_BASE + 8192
            && self.fail_second_once.swap(false, Ordering::Relaxed)
        {
            return Err(MappingError::UnmapFailed);
        }
        Ok(())
    }
}
fn mapping_platform(owner: Arc<()>) -> (Authority, Arc<Platform>) {
    let platform = Arc::new(Platform {
        memory: Box::new(DeviceMemory(UnsafeCell::new([0; 16384]))),
        original_owner: owner,
        epoch: AtomicUsize::new(1),
        fail_second_once: AtomicBool::new(false),
        unmaps: Mutex::new(Vec::new()),
    });
    // SAFETY: separate isolated backing and roots; no production latch or
    // aliases are modified, and all mappings retain this actual model owner.
    let authority = unsafe {
        Authority::isolated_model(
            platform.clone(),
            AddressSpace {
                identity: 7,
                physical_bits: 48,
                virtual_bits: 48,
            },
            Vec::new(),
        )
    }
    .unwrap();
    (authority, platform)
}

#[test]
fn original_resource_identity_and_epoch_gate_real_registry_maps_and_platform_retirement() {
    let (_host, bar) = fixture(Model::new());
    let owner = bar
        .resource
        .backing()
        .downcast_ref::<Backing>()
        .unwrap()
        .owner
        .clone();
    let (wrong, _) = mapping_platform(Arc::new(()));
    assert!(map_registers(&bar, &wrong).is_err());
    let (authority, platform) = mapping_platform(owner);
    platform.epoch.store(2, Ordering::Relaxed);
    assert!(map_registers(&bar, &authority).is_err());
    platform.epoch.store(1, Ordering::Relaxed);
    let mut first = map_registers(&bar, &authority).unwrap();
    assert_eq!(
        first.physical_span().unwrap(),
        PhysicalSpan::new(NVME_BASE, 8192).unwrap()
    );
    let offset = (NVME_BASE + 8192 - bar.resource.physical_span().start()) as usize;
    let mut second = authority
        .map(
            bar.resource.clone(),
            offset,
            8192,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    platform.fail_second_once.store(true, Ordering::Relaxed);
    // These are the platform's explicit final mapping acknowledgements, not
    // NVMe Lifecycle.release. No model device/CPU users were ever started.
    // SAFETY: exact isolated tokens with no consumers, callbacks or writes.
    unsafe { first.retire() }.unwrap();
    // SAFETY: same actual model-owner exclusion; failure preserves its token.
    assert_eq!(
        unsafe { second.retire() },
        Err(crate::bus::mmio::owned::Error::UnmapFailed)
    );
    assert!(first.address(0, 4).is_err());
    assert!(second.address(0, 4).is_err());
    // SAFETY: retry the same stopped original token, not a recreated mapping.
    unsafe { second.retire() }.unwrap();
    let unmaps = platform.unmaps.lock().unwrap();
    assert_eq!(unmaps.len(), 3);
    assert_ne!(unmaps[0], unmaps[1]);
    assert_eq!(unmaps[1], unmaps[2]);
}

mod composed;
