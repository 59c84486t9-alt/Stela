//! Modeled NHI DMA, routers and peers shared by the Thunderbolt tests.
extern crate std;
use super::*;
use crate::bus::dma::{
    mapping::DomainMapping,
    memory::{PageBacking, PinnedPages},
};
use alloc::{
    alloc::{alloc_zeroed, dealloc},
    boxed::Box,
    collections::BTreeMap,
};
use core::{
    alloc::Layout,
    ops::Range,
    sync::atomic::{AtomicBool, AtomicUsize},
};
use std::sync::Mutex;

pub(crate) struct Backing {
    pub(crate) pointer: NonNull<u8>,
    pub(crate) layout: Layout,
    pub(crate) pages: Vec<u64>,
    pub(crate) released: Arc<AtomicUsize>,
}

// SAFETY: immutable metadata points at retained exclusive model RAM; all
// modeled hardware operations and CPU operations are serialized by tests.
unsafe impl Send for Backing {}

// SAFETY: as for Send; model RAM has no concurrent hardware writer.
unsafe impl Sync for Backing {}

// SAFETY: owns a real aligned allocation; host pointers serve only as the
// model's physical identifiers, never physical hardware DMA addresses.
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        self.pointer
    }
    fn physical_pages(&self) -> &[u64] {
        &self.pages
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}

impl Drop for Backing {
    fn drop(&mut self) {
        // SAFETY: this is the exact retained allocation and final pin.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        self.released.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct Source {
    pub(crate) allocated: AtomicUsize,
    pub(crate) released: Arc<AtomicUsize>,
    pub(crate) fail_at: AtomicUsize,
}

impl Source {
    pub(crate) fn new() -> Self {
        Self {
            allocated: AtomicUsize::new(0),
            released: Arc::new(AtomicUsize::new(0)),
            fail_at: AtomicUsize::new(usize::MAX),
        }
    }
}

impl PageSource for Source {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(attribute, CacheAttribute::WriteBack);
        let count = self.allocated.fetch_add(1, Ordering::Relaxed) + 1;
        if count == self.fail_at.load(Ordering::Relaxed) {
            return Err(MemoryError::OutOfMemory);
        }
        let length = bytes.next_multiple_of(PAGE);
        let layout = Layout::from_size_align(length, alignment).unwrap();
        // SAFETY: live allocation is owned by Backing until its final Drop.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        let pages = (0..length / PAGE)
            .map(|index| pointer.as_ptr() as u64 + (index * PAGE) as u64)
            .collect();
        PinnedPages::new(
            Box::new(Backing {
                pointer,
                layout,
                pages,
                released: self.released.clone(),
            }),
            bytes,
            alignment,
        )
    }
}

pub(crate) struct Live {
    pub(crate) info: DomainMapping,
    pub(crate) cpu: CpuMapping,
    pub(crate) _pages: PinnedPages,
    pub(crate) direction: DmaDirection,
}

pub(crate) struct DomainState {
    pub(crate) next: u64,
    pub(crate) maps: BTreeMap<u64, Live>,
    pub(crate) sync: Vec<(bool, u64, Range<usize>)>,
    pub(crate) unmaps: usize,
}

pub(crate) struct Domain {
    pub(crate) state: Mutex<DomainState>,
    pub(crate) fail_visibility: AtomicBool,
    pub(crate) fail_unmap_at: AtomicUsize,
}

impl Domain {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(DomainState {
                next: 0x1000,
                maps: BTreeMap::new(),
                sync: Vec::new(),
                unmaps: 0,
            }),
            fail_visibility: AtomicBool::new(false),
            fail_unmap_at: AtomicUsize::new(usize::MAX),
        }
    }
    pub(crate) fn pointer(&self, address: u64, bytes: usize) -> NonNull<u8> {
        let state = self.state.lock().unwrap();
        let (_, live) = state.maps.range(..=address).next_back().unwrap();
        let offset = usize::try_from(address - live.info.address).unwrap();
        live.cpu.address(offset, bytes).unwrap()
    }
    pub(crate) fn read32(&self, address: u64) -> u32 {
        // SAFETY: retained model allocation, aligned bounded access.
        unsafe {
            self.pointer(address, 4)
                .cast::<u32>()
                .as_ptr()
                .read_volatile()
        }
    }
    pub(crate) fn write32(&self, address: u64, value: u32) {
        // SAFETY: serialized modeled device operation within the mapping.
        unsafe {
            self.pointer(address, 4)
                .cast::<u32>()
                .as_ptr()
                .write_volatile(value)
        };
    }
    pub(crate) fn data(&self, address: u64, bytes: usize) -> Vec<u8> {
        let pointer = self.pointer(address, bytes);
        // SAFETY: test runs after publication and before a competing CPU write.
        unsafe { core::slice::from_raw_parts(pointer.as_ptr(), bytes).to_vec() }
    }
    pub(crate) fn write_data(&self, address: u64, bytes: &[u8]) {
        let pointer = self.pointer(address, bytes.len());
        for (index, value) in bytes.iter().enumerate() {
            // SAFETY: serialized modeled DMA within the retained frame.
            unsafe { pointer.as_ptr().add(index).write_volatile(*value) };
        }
    }
}

// SAFETY: this is a serialized synthetic domain with nonidentity IOVAs.
// Every map retains real host RAM; failed unmap retains its reservation.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &crate::bus::dma::pages::DmaPages,
        direction: DmaDirection,
        limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        let pages = pages.as_single().ok_or(DmaError::MappingFailed)?;
        let mut state = self.state.lock().unwrap();
        let address = state.next;
        if address + pages.bytes() as u64 - 1 > limit {
            return Err(DmaError::AddressLimit);
        }
        state.next += pages.bytes() as u64;
        let info = DomainMapping {
            id: address,
            address,
            bytes: pages.bytes(),
        };
        assert_ne!(address, pages.physical_pages()[0]);
        let cpu = pages.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        state.maps.insert(
            address,
            Live {
                info,
                cpu,
                _pages: pages.clone(),
                direction,
            },
        );
        Ok(info)
    }
    unsafe fn unmap(&self, info: DomainMapping) -> Result<(), DmaError> {
        let mut state = self.state.lock().unwrap();
        state.unmaps += 1;
        if state.unmaps == self.fail_unmap_at.load(Ordering::Relaxed) {
            return Err(DmaError::InvalidationFailed);
        }
        assert_eq!(state.maps[&info.address].info, info);
        state.maps.remove(&info.address);
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        info: DomainMapping,
        range: Range<usize>,
        direction: DmaDirection,
    ) -> Result<(), DmaError> {
        if self.fail_visibility.swap(false, Ordering::Relaxed) {
            return Err(DmaError::VisibilityFailed);
        }
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.maps[&info.address].direction, direction);
        assert!(range.start <= range.end && range.end <= info.bytes);
        state.sync.push((true, info.address, range));
        Ok(())
    }
    unsafe fn sync_for_cpu(
        &self,
        info: DomainMapping,
        range: Range<usize>,
        direction: DmaDirection,
    ) -> Result<(), DmaError> {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.maps[&info.address].direction, direction);
        assert!(range.start <= range.end && range.end <= info.bytes);
        state.sync.push((false, info.address, range));
        Ok(())
    }
}

pub(crate) struct RegisterState {
    pub(crate) values: Vec<u32>,
    pub(crate) writes: Vec<(usize, u32)>,
    pub(crate) reject: Option<usize>,
    pub(crate) failed_read: Option<usize>,
}

pub(crate) struct Model {
    pub(crate) state: Mutex<RegisterState>,
    pub(crate) domain: Arc<Domain>,
}

impl Model {
    pub(crate) fn new(domain: Arc<Domain>) -> Self {
        let mut values = vec![0; (CAPABILITIES + PAGE) / 4];
        values[CAPABILITIES / 4] = 8;
        Self {
            state: Mutex::new(RegisterState {
                values,
                writes: Vec::new(),
                reject: None,
                failed_read: None,
            }),
            domain,
        }
    }
    pub(crate) fn descriptor_address(&self, direction: Direction, index: usize) -> u64 {
        let base = match direction {
            Direction::Tx => TX_DESCRIPTOR,
            Direction::Rx => RX_DESCRIPTOR,
        };
        let state = self.state.lock().unwrap();
        (u64::from(state.values[base / 4]) | (u64::from(state.values[base / 4 + 1]) << 32))
            + (index * DESCRIPTOR_BYTES) as u64
    }
    pub(crate) fn frame_address(&self, direction: Direction, index: usize) -> u64 {
        let descriptor = self.descriptor_address(direction, index);
        u64::from(self.domain.read32(descriptor))
            | u64::from(self.domain.read32(descriptor + 4)) << 32
    }
    pub(crate) fn finish(
        &self,
        direction: Direction,
        index: usize,
        data: &[u8],
        word: Option<u32>,
    ) {
        let descriptor = self.descriptor_address(direction, index);
        let old = self.domain.read32(descriptor + 8);
        let value = if let Some(value) = word {
            value
        } else if direction == Direction::Tx {
            old | (u32::from(COMPLETED) << 20)
        } else {
            (data.len() as u32) | (u32::from(COMPLETED) << 20) | (1 << 12)
        };
        if direction == Direction::Rx {
            self.domain
                .write_data(self.frame_address(direction, index), data);
        }
        self.domain.write32(descriptor + 8, value);
    }
}

// SAFETY: all model register access is serialized under its mutex. It
// implements hardware-owned index halves and publication observers.
unsafe impl Registers for Model {
    fn bytes(&self) -> usize {
        self.state.lock().unwrap().values.len() * 4
    }
    fn read32(&self, offset: usize) -> u32 {
        let state = self.state.lock().unwrap();
        if state.failed_read == Some(offset) {
            u32::MAX
        } else {
            state.values[offset / 4]
        }
    }
    fn write32(&self, offset: usize, value: u32) {
        let mut state = self.state.lock().unwrap();
        state.writes.push((offset, value));
        if state.reject == Some(offset) {
            return;
        }
        let old = state.values[offset / 4];
        let direction = if offset == TX_DESCRIPTOR + 8 {
            Some(Direction::Tx)
        } else if offset == RX_DESCRIPTOR + 8 {
            Some(Direction::Rx)
        } else {
            None
        };
        state.values[offset / 4] = match direction {
            Some(Direction::Tx) => old & 0xffff | value & 0xffff_0000,
            Some(Direction::Rx) => old & 0xffff_0000 | value & 0xffff,
            None => value,
        };
        if let Some(direction) = direction {
            let options = match direction {
                Direction::Tx => TX_OPTIONS,
                Direction::Rx => RX_OPTIONS,
            };
            if state.values[options / 4] & ENABLE != 0 {
                let index = match direction {
                    Direction::Tx => old >> 16,
                    Direction::Rx => old & 0xffff,
                } as usize;
                let base = match direction {
                    Direction::Tx => TX_DESCRIPTOR,
                    Direction::Rx => RX_DESCRIPTOR,
                };
                let descriptor_base =
                    u64::from(state.values[base / 4]) | u64::from(state.values[base / 4 + 1]) << 32;
                let descriptor = descriptor_base + (index * DESCRIPTOR_BYTES) as u64;
                drop(state);
                let word = self.domain.read32(descriptor + 8);
                assert_eq!(
                    (word >> 20) as u16,
                    POSTED,
                    "producer published stale completion or interrupt flags"
                );
                assert_eq!(self.domain.read32(descriptor + 12), 0);
                let sync = self.domain.state.lock().unwrap();
                assert_eq!(
                    sync.sync.last(),
                    Some(&(
                        true,
                        descriptor_base,
                        index * DESCRIPTOR_BYTES..(index + 1) * DESCRIPTOR_BYTES
                    )),
                    "doorbell preceded descriptor visibility"
                );
            }
        }
    }
}

pub(crate) fn ring(
    direction: Direction,
    entries: u16,
) -> (Source, Arc<Domain>, Arc<Model>, Ring<Model>) {
    let source = Source::new();
    let domain = Arc::new(Domain::new());
    let model = Arc::new(Model::new(domain.clone()));
    // SAFETY: exact exclusively owned stopped synthetic NHI, coherent host RAM,
    // no other engines or callbacks, modeled requester domain and UC registers.
    let ring = unsafe {
        Ring::new(
            model.clone(),
            &source,
            domain.clone(),
            RingConfig {
                direction,
                hop: 0,
                entries,
                address_limit: u64::MAX,
            },
        )
    }
    .unwrap();
    (source, domain, model, ring)
}

pub(crate) fn frame(seed: u32) -> Encoded {
    super::super::config::Request::write(
        super::super::config::Route::new(0).unwrap(),
        super::super::config::Address {
            port: 0,
            space: super::super::config::Space::Router,
            offset: 1,
            words: 1,
        },
        0,
        &[seed],
    )
    .unwrap()
    .frame()
    .clone()
}

pub(crate) fn release(ring: &mut Ring<Model>) {
    ring.disable().unwrap();
    // SAFETY: the synthetic device is stopped, no pending model operation,
    // posted DMA, interrupt or worker can reference any mapped allocation.
    unsafe { ring.release() }.unwrap();
}

pub(crate) fn channel() -> (
    Source,
    Arc<Domain>,
    Arc<Model>,
    super::super::channel::Channel<Model>,
) {
    let source = Source::new();
    let domain = Arc::new(Domain::new());
    let model = Arc::new(Model::new(domain.clone()));
    // SAFETY: same synthetic ownership and coherent requester-domain contract;
    // neither physical firmware nor another actor owns either hop-zero ring.
    let channel = unsafe {
        super::super::channel::Channel::new(model.clone(), &source, domain.clone(), u64::MAX)
    }
    .unwrap();
    (source, domain, model, channel)
}

pub(crate) fn cfg_address() -> super::super::config::Address {
    super::super::config::Address {
        port: 2,
        space: super::super::config::Space::Router,
        offset: 19,
        words: 1,
    }
}

pub(crate) fn incoming(kind: PacketType, words: &[u32]) -> Encoded {
    let mut bytes = Vec::new();
    for word in words {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    let crc = super::super::config::crc32c(&bytes);
    bytes.extend_from_slice(&crc.to_be_bytes());
    Encoded { kind, bytes }
}

pub(crate) fn finish_rx(model: &Model, index: usize, frame: &Encoded) {
    model.finish(
        Direction::Rx,
        index,
        &frame.bytes,
        Some(
            (u32::from(COMPLETED) << 20) | ((frame.kind as u32) << 12) | (frame.bytes.len() as u32),
        ),
    );
}

pub(crate) fn channel_release(channel: &mut super::super::channel::Channel<Model>) {
    channel.disable().unwrap();
    // SAFETY: actual synthetic device/posted DMA/IRQ/work fully drained.
    unsafe { channel.release() }.unwrap();
}

pub(crate) struct HopOwner {
    pub(crate) target: super::super::hop::Target,
    pub(crate) dropped: Arc<AtomicUsize>,
}

impl Drop for HopOwner {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: the model exclusively reserves this exact synthetic hop/router;
// its Arc is the allocation lifetime, no other model actor reconfigures it.
unsafe impl super::super::hop::Owner for HopOwner {
    fn target(&self) -> super::super::hop::Target {
        self.target
    }
}

pub(crate) fn hop_response(domain: &Domain, model: &Model, index: usize, data: &[u32]) -> Encoded {
    let word = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
    let kind = PacketType::try_from(((word >> 12) & 15) as u8).unwrap();
    let sent = domain.data(
        model.frame_address(Direction::Tx, index),
        (word & 0xfff) as usize,
    );
    let route_hi = u32::from_be_bytes(sent[..4].try_into().unwrap());
    let route_lo = u32::from_be_bytes(sent[4..8].try_into().unwrap());
    let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
    assert_eq!((address >> 25) & 3, 0, "must use actual path config space");
    assert_eq!(address & 0x1fff, 16);
    assert_eq!((address >> 19) & 63, 1);
    assert_eq!((address >> 13) & 63, 2);
    let mut words = vec![route_hi | (1 << 31), route_lo, address & !(63 << 19)];
    words.extend_from_slice(data);
    incoming(kind, &words)
}

pub(crate) struct IcmPci {
    pub(crate) device: u16,
    pub(crate) command: u32,
}

impl crate::bus::pci::ConfigSpace for IcmPci {
    fn read32(&self, offset: u16) -> u32 {
        match offset {
            0 => (u32::from(self.device) << 16) | 0x8086,
            4 => self.command,
            8 => 0x0c034000,
            0x0c => 0,
            _ => u32::MAX,
        }
    }
    fn write32(&mut self, _: u16, _: u32) {
        panic!("ICM must not alter PCI admission");
    }
}

pub(crate) fn icm(
    device: u16,
) -> (
    Source,
    Arc<Domain>,
    Arc<Model>,
    super::super::icm::Host<Model>,
) {
    let source = Source::new();
    let domain = Arc::new(Domain::new());
    let model = Arc::new(Model::new(domain.clone()));
    model.state.lock().unwrap().values[0x39944 / 4] = 0x80000001;
    model.state.lock().unwrap().values[0x3990c / 4] = 3 << 8;
    // SAFETY: exact synthetic requester/epoch owns stopped rings and coherent
    // mappings; firmware is the modeled ICM peer, never a ring programmer.
    let host = unsafe {
        super::super::icm::Host::new(
            &IcmPci { device, command: 6 },
            model.clone(),
            &source,
            domain.clone(),
            u64::MAX,
        )
    }
    .unwrap();
    (source, domain, model, host)
}

pub(crate) fn icm_release(host: &mut super::super::icm::Host<Model>) {
    host.disable().unwrap();
    // SAFETY: modeled physical DMA/IRQ/work is finally drained.
    unsafe { host.release() }.unwrap();
}

pub(crate) struct AdapterOwner {
    pub(crate) target: super::super::adapter::Target,
    pub(crate) operation: super::super::adapter::Operation,
    pub(crate) dropped: Arc<AtomicUsize>,
}

impl Drop for AdapterOwner {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: this fixture owns the actual synthetic adapter, unchanged capability
// metadata and positive credit reservation, with no competing CM/link change.
unsafe impl super::super::adapter::Owner for AdapterOwner {
    fn target(&self) -> super::super::adapter::Target {
        self.target
    }
    fn operation(&self) -> super::super::adapter::Operation {
        self.operation
    }
}

pub(crate) fn adapter_owner(
    operation: super::super::adapter::Operation,
) -> (Arc<AdapterOwner>, Arc<AtomicUsize>) {
    let dropped = Arc::new(AtomicUsize::new(0));
    let owner = Arc::new(AdapterOwner {
        target: super::super::adapter::Target {
            route: super::super::config::Route::new(0).unwrap(),
            port: 1,
            kind: super::super::topology::AdapterKind::Lane,
            usb4: true,
            phy_capability: Some(8),
            usb4_capability: Some(0x30),
        },
        operation,
        dropped: dropped.clone(),
    });
    (owner, dropped)
}

pub(crate) fn adapter_response(
    domain: &Domain,
    model: &Model,
    index: usize,
    offset: u16,
    data: &[u32],
) -> Encoded {
    let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
    let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
    let frame = domain.data(
        model.frame_address(Direction::Tx, index),
        (descriptor & 0xfff) as usize,
    );
    let address = u32::from_be_bytes(frame[8..12].try_into().unwrap());
    assert_eq!(address & 0x1fff, u32::from(offset));
    assert_eq!((address >> 25) & 3, 1);
    assert_eq!((address >> 13) & 63, 1);
    assert_eq!((address >> 19) & 63, 1);
    let mut reply = vec![
        u32::from_be_bytes(frame[..4].try_into().unwrap()) | (1 << 31),
        u32::from_be_bytes(frame[4..8].try_into().unwrap()),
        address & !(63 << 19),
    ];
    reply.extend_from_slice(data);
    incoming(kind, &reply)
}

pub(crate) struct RouterOwner {
    pub(crate) target: super::super::topology::Inventory,
    pub(crate) parent: Option<super::super::topology::Inventory>,
    pub(crate) policy: super::super::router::Policy,
    pub(crate) epoch: u64,
    pub(crate) dropped: Arc<AtomicUsize>,
}

impl Drop for RouterOwner {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: fixtures reserve one exact synthetic NHI/domain/IMR epoch and
// unchanged real model inventories. Policy is an explicit model input,
// not a production platform/_OSC/security provider or Type-C inference.
unsafe impl super::super::router::Owner for RouterOwner {
    fn identity(&self) -> super::super::domain::Identity {
        super::super::domain::Identity {
            nhi: crate::bus::pci::Address {
                segment: 0,
                bus: 1,
                device: 2,
                function: 0,
            },
            epoch: self.epoch,
        }
    }
    fn target(&self) -> &super::super::topology::Inventory {
        &self.target
    }
    fn parent(&self) -> Option<&super::super::topology::Inventory> {
        self.parent.as_ref()
    }
    fn policy(&self) -> super::super::router::Policy {
        self.policy
    }
}

pub(crate) fn router_adapter(
    port: u8,
    kind: u32,
    cap: Option<u16>,
) -> super::super::topology::AdapterObservation {
    use super::super::topology::{AdapterHeader, AdapterObservation, Capability};
    let mut raw = [0; 8];
    raw[2] = kind;
    raw[3] = u32::from(port) << 20;
    AdapterObservation::Present {
        port,
        header: AdapterHeader { raw },
        capabilities: cap
            .map(|offset| {
                vec![Capability {
                    offset,
                    id: 6,
                    vendor_specific: None,
                    length: None,
                    next: 0,
                    raw: vec![6 << 8],
                }]
            })
            .unwrap_or_default(),
    }
}

pub(crate) fn router_owner(route: u64, version: u8, mask: u32) -> RouterOwner {
    use super::super::{
        config::Route,
        router::{Decision, Policy},
        topology::{Inventory, Path, RouterHeader},
    };
    let path = Path::new(Route::new(route).unwrap()).unwrap();
    let header = RouterHeader {
        raw: [
            0x12348086,
            0x43808000 | (9 << 8),
            0xdeadbeef,
            0x10203040,
            (u32::from(version) << 29) | 0x00ab34cd,
        ],
    };
    let target = Inventory {
        path,
        upstream_port: if route == 0 { 0 } else { 1 },
        header,
        capabilities: vec![],
        adapters: vec![
            router_adapter(1, 1, Some(0x30)),
            router_adapter(2, 0x0e0101, Some(0x40)),
        ],
    };
    let parent = if route == 0 {
        None
    } else {
        let depth = path.depth() - 1;
        let shift = depth * 8;
        let raw = route & ((1u64 << shift) - 1);
        let upstream = if depth == 0 { 0 } else { 5 };
        let parent_path = Path::new(Route::new(raw).unwrap()).unwrap();
        let down = (route >> shift) as u8;
        Some(Inventory {
            path: parent_path,
            upstream_port: upstream,
            header: RouterHeader {
                raw: [
                    0x56788086,
                    (5 << 14) | (u32::from(upstream) << 8) | (u32::from(depth) << 20),
                    raw as u32,
                    (raw >> 32) as u32 | (1 << 31),
                    1 << 29,
                ],
            },
            capabilities: vec![],
            adapters: (1..=5)
                .map(|port| {
                    router_adapter(
                        port,
                        match port {
                            1 | 2 | 5 => 1,
                            3 => {
                                if mask & 4 != 0 {
                                    0x200101
                                } else {
                                    0
                                }
                            }
                            4 => {
                                if mask & 8 != 0 {
                                    0x100101
                                } else {
                                    0
                                }
                            }
                            _ => unreachable!(),
                        },
                        if port == down && mask & 64 != 0 {
                            Some(0x30)
                        } else {
                            None
                        },
                    )
                })
                .collect(),
        })
    };
    RouterOwner {
        target,
        parent,
        policy: Policy {
            usb3: if mask & 1 != 0 {
                Decision::Allowed
            } else {
                Decision::Denied
            },
            pcie: if mask & 2 != 0 {
                Decision::Allowed
            } else {
                Decision::Denied
            },
        },
        epoch: 1,
        dropped: Arc::new(AtomicUsize::new(0)),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterWrite {
    pub(crate) port: u8,
    pub(crate) space: u8,
    pub(crate) offset: u16,
    pub(crate) data: Vec<u32>,
}

pub(crate) struct RouterPeer {
    pub(crate) owner: Arc<RouterOwner>,
    pub(crate) regs: [u32; 8],
    pub(crate) hotplug: Vec<u32>,
    pub(crate) mask: u32,
    pub(crate) writes: Vec<RouterWrite>,
    pub(crate) setup_written: bool,
    pub(crate) valid_written: bool,
    pub(crate) ready_reads: u32,
    pub(crate) configured_reads: u32,
    pub(crate) hold_ready: bool,
    pub(crate) hold_configured: bool,
    pub(crate) reject_header: bool,
    pub(crate) override_upstream: Option<u8>,
}

impl RouterPeer {
    pub(crate) fn new(owner: Arc<RouterOwner>, mask: u32) -> Self {
        let mut regs = [0; 8];
        regs[..5].copy_from_slice(&owner.target.header.raw);
        regs[5] = 0x00d5001f;
        regs[6] = 0x1202 | if mask & 32 != 0 { 1 << 18 } else { 0 };
        let hotplug = (0..owner.target.header.max_port())
            .map(|i| match i {
                0 => 0x92345678,
                1 => 0xabcdef01,
                _ => 0x98765430 + u32::from(i),
            })
            .collect();
        Self {
            owner,
            regs,
            hotplug,
            mask,
            writes: vec![],
            setup_written: false,
            valid_written: false,
            ready_reads: 0,
            configured_reads: 0,
            hold_ready: false,
            hold_configured: false,
            reject_header: false,
            override_upstream: None,
        }
    }
    pub(crate) fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
        let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
        let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
        let frame = domain.data(
            model.frame_address(Direction::Tx, index),
            (descriptor & 0xfff) as usize,
        );
        let mut words: Vec<u32> = frame[..frame.len() - 4]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_be_bytes(*word))
            .collect();
        let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
        let address = words[2];
        let offset = (address & 0x1fff) as u16;
        let count = ((address >> 13) & 63) as usize;
        let port = ((address >> 19) & 63) as u8;
        let space = ((address >> 25) & 3) as u8;
        let target = route == self.owner.target.path.route().raw();
        let upstream = if target {
            self.owner.target.upstream_port
        } else {
            self.owner
                .parent
                .as_ref()
                .expect("actual parent")
                .upstream_port
        };
        let data = if kind == PacketType::Write {
            assert!(target, "setup must not program parent");
            let data = words[3..].to_vec();
            assert_eq!(data.len(), count);
            self.writes.push(RouterWrite {
                port,
                space,
                offset,
                data: data.clone(),
            });
            if space == 2 {
                self.regs[usize::from(offset)..usize::from(offset) + count].copy_from_slice(&data);
                if offset == 1 && self.reject_header {
                    self.regs[3] &= !(1 << 31);
                }
                if offset == 5 {
                    self.setup_written = true;
                    if data[0] & (1 << 31) != 0 {
                        self.valid_written = true;
                    }
                }
            } else {
                assert_eq!((space, offset, count), (1, 5, 1));
                self.hotplug[usize::from(port) - 1] = data[0];
            }
            vec![]
        } else {
            assert_eq!(kind, PacketType::Read);
            if !target {
                let parent = self.owner.parent.as_ref().unwrap();
                assert_eq!(route, parent.path.route().raw());
                assert_eq!(space, 1);
                assert_eq!(offset, 0x42);
                assert_eq!(count, 1);
                vec![if self.mask & 16 != 0 { 1 << 9 } else { 0 }]
            } else if space == 2 {
                if offset == 6 {
                    if self.setup_written {
                        self.ready_reads += 1;
                        if self.ready_reads >= 2 && !self.hold_ready {
                            self.regs[6] |= 1 << 24;
                        }
                    }
                    if self.valid_written {
                        self.configured_reads += 1;
                        if self.configured_reads >= 2 && !self.hold_configured {
                            self.regs[6] |= 1 << 25;
                        }
                    }
                }
                self.regs[usize::from(offset)..usize::from(offset) + count].to_vec()
            } else {
                assert_eq!((space, offset, count), (1, 5, 1));
                vec![self.hotplug[usize::from(port) - 1]]
            }
        };
        words.truncate(3);
        words[0] |= 1 << 31;
        words[2] =
            (address & !(63 << 19)) | (u32::from(self.override_upstream.unwrap_or(upstream)) << 19);
        words.extend(data);
        incoming(kind, &words)
    }
}

pub(crate) fn drive_router(
    peer: &mut RouterPeer,
    domain: &Domain,
    model: &Model,
    setup: &mut super::super::router::Setup<Model>,
) -> super::super::router::Configured {
    use super::super::router::Event;
    assert!(setup.poll(0).unwrap().is_none());
    for n in 0..100 {
        let index = n % 10;
        let reply = peer.respond(domain, model, index);
        model.finish(Direction::Tx, index, &[], None);
        finish_rx(model, index, &reply);
        match setup.poll(n as u64 + 1).unwrap() {
            Some(Event::Configured(configured)) => return configured,
            Some(Event::Discarded(error)) => panic!("discarded {error:?}"),
            None => {}
        }
    }
    panic!("bounded router setup did not finish")
}

#[derive(Default)]
pub(crate) struct NativeCursor {
    pub(crate) tx: usize,
    pub(crate) rx: usize,
    pub(crate) now: u64,
}

pub(crate) fn configured_router(
    peer: &mut RouterPeer,
    domain: &Domain,
    model: &Model,
    setup: &mut super::super::router::Setup<Model>,
    cursor: &mut NativeCursor,
) -> super::super::router::Configured {
    use super::super::router::Event;
    assert!(setup.poll(cursor.now).unwrap().is_none());
    for _ in 0..100 {
        let reply = peer.respond(domain, model, cursor.tx % 10);
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
        cursor.now += 1;
        match setup.poll(cursor.now).unwrap() {
            Some(Event::Configured(value)) => return value,
            Some(Event::Discarded(error)) => panic!("{error:?}"),
            None => {}
        }
    }
    panic!("actual source router setup did not finish")
}

pub(crate) struct LinkReservation {
    pub(crate) partners: super::super::link::Partners,
    pub(crate) dropped: Arc<AtomicUsize>,
}

impl Drop for LinkReservation {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: fixture owns actual reciprocal model lanes and both routers in
// this same synthetic NHI reset/topology epoch. No production topology,
// policy, power or attachment provider is fabricated by the driver.
unsafe impl super::super::link::Reservation for LinkReservation {
    fn observed(&self) -> super::super::link::Partners {
        self.partners
    }
}

pub(crate) struct LinkFixture {
    pub(crate) _source: Source,
    pub(crate) domain: Arc<Domain>,
    pub(crate) model: Arc<Model>,
    pub(crate) channel: super::super::channel::Channel<Model>,
    pub(crate) parent: super::super::router::Configured,
    pub(crate) child: super::super::router::Configured,
    pub(crate) reservation: Arc<LinkReservation>,
    pub(crate) cursor: NativeCursor,
    pub(crate) dropped: [Arc<AtomicUsize>; 3],
}

pub(crate) fn link_inventory(owner: &mut RouterOwner, max: u8, primary: u8) {
    use super::super::topology::{AdapterObservation, Capability};
    owner.target.header.raw[1] =
        (owner.target.header.raw[1] & !(63 << 14)) | (u32::from(max) << 14);
    owner.target.adapters = (1..=max)
        .map(|port| {
            let mut adapter =
                router_adapter(port, 1, if port == primary { Some(0x30) } else { None });
            if let AdapterObservation::Present { capabilities, .. } = &mut adapter {
                capabilities.insert(
                    0,
                    Capability {
                        offset: 8,
                        id: 1,
                        vendor_specific: None,
                        length: None,
                        next: if port == primary { 0x30 } else { 0 },
                        raw: vec![1 << 8 | if port == primary { 0x30 } else { 0 }],
                    },
                );
            }
            adapter
        })
        .collect();
}

pub(crate) fn add_path_usb3_adapter(inventory: &mut super::super::topology::Inventory, kind: u32) {
    use super::super::topology::AdapterObservation;
    let port = inventory.header.max_port() + 1;
    inventory.header.raw[1] = (inventory.header.raw[1] & !(63 << 14)) | (u32::from(port) << 14);
    let mut adapter = router_adapter(port, kind, Some(0x50));
    if let AdapterObservation::Present {
        header,
        capabilities,
        ..
    } = &mut adapter
    {
        header.raw[1] = 0x50;
        capabilities[0].id = 4;
        capabilities[0].raw[0] = 4 << 8;
    }
    inventory.adapters.push(adapter);
    for adapter in &mut inventory.adapters {
        if let AdapterObservation::Present { header, .. } = adapter {
            header.raw[5] = 127 | (127 << 11);
        }
    }
}

pub(crate) fn link_fixture(map: u8, mode: bool) -> LinkFixture {
    link_fixture_with_usb3(map, mode, false)
}

pub(crate) fn link_fixture_with_usb3(map: u8, mode: bool, usb3: bool) -> LinkFixture {
    link_fixture_with_protocol(map, mode, if usb3 { 0x200101 } else { 0 })
}
pub(crate) fn link_fixture_with_protocol(map: u8, mode: bool, protocol: u32) -> LinkFixture {
    use super::super::{link::Partners, router::Setup};
    let (source, domain, model, mut channel) = channel();
    channel.start(0).unwrap();
    let mut cursor = NativeCursor::default();
    let mask = 64
        | if mode { 16 } else { 0 }
        | if protocol == 0x100101 {
            2
        } else {
            u32::from(protocol != 0)
        };
    let mut parent_owner = router_owner(0, 1, mask);
    link_inventory(
        &mut parent_owner,
        if map == 0 { 2 } else { 5 },
        if map == 0 { 1 } else { 2 },
    );
    if protocol != 0 {
        add_path_usb3_adapter(&mut parent_owner.target, protocol);
    }
    let parent_owner = Arc::new(parent_owner);
    let parent_drop = parent_owner.dropped.clone();
    let mut peer = RouterPeer::new(parent_owner.clone(), mask);
    // SAFETY: exact same synthetic NHI/domain/IMR epoch and actual current
    // inventories with explicit model native policy; exclusive idle channel.
    let mut setup = unsafe { Setup::new(channel, parent_owner.clone(), cursor.now) }.unwrap();
    let parent = configured_router(&mut peer, &domain, &model, &mut setup, &mut cursor);
    channel = setup.into_channel();
    drop(peer);
    let route = if map == 0 { 1 } else { 2 };
    let mut child_owner = router_owner(route, 1, mask);
    link_inventory(&mut child_owner, if map == 0 { 2 } else { 3 }, 1);
    let mut current_parent = parent_owner.target.clone();
    current_parent.header = parent.header.clone();
    child_owner.parent = Some(current_parent);
    if protocol != 0 {
        add_path_usb3_adapter(&mut child_owner.target, protocol + 1);
    }
    let child_owner = Arc::new(child_owner);
    let child_drop = child_owner.dropped.clone();
    let mut peer = RouterPeer::new(child_owner.clone(), mask);
    // SAFETY: same actual synthetic requester/epoch and already configured
    // retained parent, exact current topology and native model policy.
    let mut setup = unsafe { Setup::new(channel, child_owner.clone(), cursor.now) }.unwrap();
    let child = configured_router(&mut peer, &domain, &model, &mut setup, &mut cursor);
    channel = setup.into_channel();
    drop(peer);
    drop(parent_owner);
    drop(child_owner);
    let reservation_drop = Arc::new(AtomicUsize::new(0));
    let reservation = Arc::new(LinkReservation {
        partners: Partners {
            identity: parent.identity,
            topology_epoch: 2,
            child: [1, if map == 0 { 2 } else { 3 }],
            parent: if map == 0 { [1, 2] } else { [2, 5] },
            observations: core::array::from_fn(|i| {
                let ports = if map == 0 { [1, 2, 1, 2] } else { [1, 3, 2, 5] };
                let routes = [child.route, child.route, parent.route, parent.route];
                super::super::link::ObservedLane {
                    route: routes[i],
                    port: ports[i],
                    lane_index: (i % 2) as u8,
                    dual_port: ports[i ^ 1],
                    remote_route: routes[i ^ 2],
                    remote_port: ports[i ^ 2],
                }
            }),
        },
        dropped: reservation_drop.clone(),
    });
    LinkFixture {
        _source: source,
        domain,
        model,
        channel,
        parent,
        child,
        reservation,
        cursor,
        dropped: [parent_drop, child_drop, reservation_drop],
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LinkWrite {
    pub(crate) index: usize,
    pub(crate) offset: u16,
    pub(crate) value: u32,
}

pub(crate) struct LinkPeer {
    pub(crate) partners: super::super::link::Partners,
    pub(crate) route: u64,
    pub(crate) mode: bool,
    pub(crate) phy: [[u32; 2]; 4],
    pub(crate) credits: [u32; 4],
    pub(crate) pc: [u32; 2],
    pub(crate) writes: Vec<LinkWrite>,
    pub(crate) bonding: bool,
    pub(crate) bond_reads: u32,
    pub(crate) hold_width: bool,
    pub(crate) reject: Option<(usize, u16)>,
    pub(crate) deny_bond: bool,
    pub(crate) port_wait_state: Option<u8>,
    pub(crate) secondary_reads: u32,
}

impl LinkPeer {
    pub(crate) fn new(
        partners: super::super::link::Partners,
        generation: u8,
        dual: bool,
        mode: bool,
        seed: u32,
    ) -> Self {
        let mut phy = [[0; 2]; 4];
        let mut credits = [0; 4];
        for i in 0..4 {
            let mut word = (0x104234ab ^ (seed * 0x01804109) ^ ((i as u32) * 0x01010001))
                & !((15 << 16) | (63 << 20) | (15 << 26) | 0x30 | 0xc000);
            word |= (if generation == 2 { 8 } else { 4 }) << 16;
            word |= (if dual { 2 } else { 1 }) << 20;
            word |= 2 << 26;
            word |= 1 << 4;
            if dual && i == 2 {
                word |= 1 << 15;
            }
            phy[i] = [
                (if i % 2 == 0 { 0x130 } else { 0x100 })
                    | (2 << 20)
                    | ((if generation == 2 { 8 } else { 12 }) << 16)
                    | if mode { 1 << 31 } else { 0 },
                word,
            ];
            credits[i] = ((64 + seed + i as u32) << 20) | (8 + (seed + i as u32) % 4);
        }
        Self {
            partners,
            route: u64::from(partners.parent[0]),
            mode,
            phy,
            credits,
            pc: [0x14050101 ^ (seed * 0x10001); 2],
            writes: vec![],
            bonding: false,
            bond_reads: 0,
            hold_width: false,
            reject: None,
            deny_bond: false,
            port_wait_state: None,
            secondary_reads: 0,
        }
    }
    pub(crate) fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
        let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
        let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
        let bytes = domain.data(
            model.frame_address(Direction::Tx, index),
            (descriptor & 0xfff) as usize,
        );
        let mut words: Vec<u32> = bytes[..bytes.len() - 4]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_be_bytes(*word))
            .collect();
        let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
        let address = words[2];
        assert_eq!((address >> 25) & 3, 1);
        let port = ((address >> 19) & 63) as u8;
        let offset = (address & 0x1fff) as u16;
        let count = ((address >> 13) & 63) as usize;
        let lane = if route == self.route {
            self.partners
                .child
                .iter()
                .position(|number| *number == port)
                .unwrap()
        } else {
            assert_eq!(route, 0);
            2 + self
                .partners
                .parent
                .iter()
                .position(|number| *number == port)
                .unwrap()
        };
        let data = if kind == PacketType::Write {
            assert_eq!(count, 1);
            let value = words[3];
            self.writes.push(LinkWrite {
                index: lane,
                offset,
                value,
            });
            match offset {
                9 => {
                    self.phy[lane][1] = if self.reject == Some((lane, offset)) {
                        value & !((3 << 4) | (1 << 15))
                    } else {
                        value
                    };
                    if lane == 2 && value & (1 << 15) != 0 {
                        self.bonding = true;
                        self.bond_reads = 0;
                    }
                }
                0x43 => {
                    assert!(lane == 0 || lane == 2);
                    self.pc[lane / 2] = if self.reject == Some((lane, offset)) {
                        value & !(1 << 3)
                    } else {
                        value
                    };
                }
                _ => panic!("unsupported actual link write"),
            }
            vec![]
        } else {
            assert_eq!(kind, PacketType::Read);
            if lane == 2 && offset == 9 && self.bonding {
                self.bond_reads += 1;
                if self.bond_reads >= 2 && !self.hold_width {
                    for i in 0..4 {
                        self.phy[i][1] = (self.phy[i][1] & !(63 << 20)) | (2 << 20);
                        self.credits[i] += 32 << 20;
                    }
                    self.bonding = false;
                }
            }
            match (offset, count) {
                (8, 2) => {
                    let mut data = self.phy[lane].to_vec();
                    if lane == 3 {
                        self.secondary_reads += 1;
                        if self.secondary_reads > 1
                            && let Some(state) = self.port_wait_state
                        {
                            data[1] = (data[1] & !(15 << 26)) | (u32::from(state) << 26);
                        }
                    }
                    data
                }
                (8, 1) => vec![self.phy[lane][0]],
                (9, 1) => vec![self.phy[lane][1]],
                (4, 1) => vec![self.credits[lane]],
                (0x42, 1) => vec![
                    if self.deny_bond { 0 } else { 1 << 8 } | if self.mode { 1 << 9 } else { 0 },
                ],
                (0x43, 1) => {
                    assert!(lane == 0 || lane == 2);
                    vec![self.pc[lane / 2]]
                }
                _ => panic!("unsupported actual link read"),
            }
        };
        words.truncate(3);
        words[0] |= 1 << 31;
        words[2] = (address & !(63 << 19))
            | if lane < 2 {
                u32::from(self.partners.child[0]) << 19
            } else {
                0
            };
        words.extend(data);
        incoming(kind, &words)
    }
}

pub(crate) fn drive_link(
    peer: &mut LinkPeer,
    domain: &Domain,
    model: &Model,
    activate: &mut super::super::link::Activate<Model>,
    cursor: &mut NativeCursor,
) -> super::super::link::Linked {
    use super::super::link::Event;
    assert!(activate.poll(cursor.now).unwrap().is_none());
    for _ in 0..150 {
        let reply = peer.respond(domain, model, cursor.tx % 10);
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
        cursor.now += 1;
        match activate.poll(cursor.now).unwrap() {
            Some(Event::Linked(value)) => return *value,
            Some(Event::Discarded(error)) => panic!("{error:?}"),
            None => {}
        }
    }
    panic!("actual native link activation did not finish")
}

pub(crate) struct PathReservation {
    pub(crate) allocation: super::super::path::Allocation,
    pub(crate) dropped: Arc<AtomicUsize>,
}

impl Drop for PathReservation {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: model retains actual protected IDs/credits/permission on the exact
// configured synthetic link. This supplies no production allocator/provider.
unsafe impl super::super::path::Reservation for PathReservation {
    fn allocation(&self) -> super::super::path::Allocation {
        self.allocation
    }
    fn is_current(&self) -> bool {
        // This fixture's actual allocation remains held in its isolated epoch;
        // no independent reset or reassignment actor exists in the model.
        true
    }
}

pub(crate) struct PathFixture {
    pub(crate) domain: Arc<Domain>,
    pub(crate) model: Arc<Model>,
    pub(crate) channel: super::super::channel::Channel<Model>,
    pub(crate) linked: Box<super::super::link::Linked>,
    pub(crate) reservation: Arc<PathReservation>,
    pub(crate) cursor: NativeCursor,
    pub(crate) dropped: [Arc<AtomicUsize>; 4],
}

pub(crate) fn path_fixture(
    direction: super::super::path::Direction,
    credits: super::super::path::LaneCredits,
) -> PathFixture {
    use super::super::{link::Activate, path::Allocation, router::Decision};
    let LinkFixture {
        domain,
        model,
        channel,
        parent,
        child,
        reservation,
        mut cursor,
        dropped,
        ..
    } = link_fixture_with_usb3(1, false, true);
    let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 3);
    // SAFETY: exact model NHI, both actual configured owners, observed lanes.
    let mut activate =
        unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
    let linked = Box::new(drive_link(
        &mut peer,
        &domain,
        &model,
        &mut activate,
        &mut cursor,
    ));
    let channel = activate.into_channel();
    let (parent, child) = linked.retained_routers().unwrap();
    let allocation = Allocation {
        identity: linked.partners.identity,
        topology_epoch: linked.partners.topology_epoch,
        grant_epoch: 3,
        direction,
        usb3_down: parent.header.max_port(),
        usb3_up: child.header.max_port(),
        hops: [(8, 31), (31, 8)],
        lane_credits: credits,
        permission: Decision::Allowed,
    };
    let path_drop = Arc::new(AtomicUsize::new(0));
    let reservation = Arc::new(PathReservation {
        allocation,
        dropped: path_drop.clone(),
    });
    PathFixture {
        domain,
        model,
        channel,
        linked,
        reservation,
        cursor,
        dropped: [
            dropped[0].clone(),
            dropped[1].clone(),
            dropped[2].clone(),
            path_drop,
        ],
    }
}

pub(crate) struct PathPeer {
    pub(crate) routes: [u64; 2],
    pub(crate) ports: [u8; 2],
    pub(crate) upstream: [u8; 2],
    pub(crate) headers: [[u32; 8]; 2],
    pub(crate) raw: [[u32; 2]; 2],
    pub(crate) reads: [usize; 2],
    pub(crate) disabled: [bool; 2],
    pub(crate) writes: Vec<(usize, u8, u16, [u32; 2])>,
    pub(crate) hold_pending: bool,
    pub(crate) hold_hop: [bool; 2],
    pub(crate) reject: Option<usize>,
    pub(crate) changed_header: bool,
    pub(crate) credit: u32,
}

impl PathPeer {
    pub(crate) fn new(
        linked: &super::super::link::Linked,
        allocation: super::super::path::Allocation,
        stale: bool,
        seed: u32,
    ) -> Self {
        use super::super::{path::Direction, topology::AdapterObservation};
        let (parent, child) = linked.retained_routers().unwrap();
        let (source, destination, ports) = match allocation.direction {
            Direction::Downstream => (
                parent,
                child,
                [allocation.usb3_down, linked.partners.child[0]],
            ),
            Direction::Upstream => (
                child,
                parent,
                [allocation.usb3_up, linked.partners.parent[0]],
            ),
        };
        let owners = [source, destination];
        let headers = core::array::from_fn(|i| {
            owners[i]
                .retained_owner()
                .target()
                .adapters
                .iter()
                .find_map(|adapter| match adapter {
                    AdapterObservation::Present { port, header, .. } if *port == ports[i] => {
                        Some(header.raw)
                    }
                    _ => None,
                })
                .unwrap()
        });
        Self {
            routes: [source.route.raw(), destination.route.raw()],
            ports,
            upstream: [
                source.retained_owner().target().upstream_port,
                destination.retained_owner().target().upstream_port,
            ],
            headers,
            raw: core::array::from_fn(|i| {
                [
                    (0x12345678 ^ (seed * 0x104001) ^ (i as u32 * 0x13579)) & !(1 << 31)
                        | if stale { 1 << 31 } else { 0 },
                    (0xabcdef12 ^ (seed * 0x104101) ^ (i as u32 * 0x13579))
                        | if stale { 1 << 28 } else { 0 },
                ]
            }),
            reads: [0; 2],
            disabled: [false; 2],
            writes: vec![],
            hold_pending: false,
            hold_hop: [false; 2],
            reject: None,
            changed_header: false,
            credit: (100 << 20) | 8,
        }
    }
    pub(crate) fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
        let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
        let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
        let bytes = domain.data(
            model.frame_address(Direction::Tx, index),
            (descriptor & 0xfff) as usize,
        );
        let mut words: Vec<u32> = bytes[..bytes.len() - 4]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_be_bytes(*word))
            .collect();
        let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
        let address = words[2];
        let port = ((address >> 19) & 63) as u8;
        let lane = self
            .routes
            .iter()
            .zip(self.ports)
            .position(|(r, p)| *r == route && p == port)
            .unwrap();
        let space = (address >> 25) & 3;
        let offset = address & 8191;
        let count = ((address >> 13) & 63) as usize;
        let data = if kind == PacketType::Write {
            assert_eq!((space, count), (0, 2));
            let value = [words[3], words[4]];
            self.writes.push((lane, port, offset as u16, value));
            if self.reject == Some(self.writes.len()) {
                self.raw[lane] = [value[0] ^ (1 << 31), value[1]];
            } else {
                self.raw[lane] = value;
            }
            self.disabled[lane] = self.raw[lane][0] & (1 << 31) == 0;
            if self.disabled[lane] {
                self.reads[lane] = 0;
            }
            vec![]
        } else {
            assert_eq!(kind, PacketType::Read);
            match (space, offset, count) {
                (1, 0, 8) => {
                    let mut data = self.headers[lane];
                    if self.changed_header {
                        data[2] ^= 1;
                    }
                    data.to_vec()
                }
                (1, 4, 1) => vec![self.credit],
                (0, _, 2) => {
                    self.reads[lane] += 1;
                    if self.disabled[lane]
                        && self.reads[lane] >= 2
                        && !self.hold_pending
                        && !self.hold_hop[lane]
                    {
                        self.raw[lane][1] &= !(1 << 28);
                    }
                    self.raw[lane].to_vec()
                }
                _ => panic!("unexpected actual path read"),
            }
        };
        words.truncate(3);
        words[0] |= 1 << 31;
        words[2] = (address & !(63 << 19)) | (u32::from(self.upstream[lane]) << 19);
        words.extend(data);
        incoming(kind, &words)
    }
}

pub(crate) fn path_step(
    peer: &mut PathPeer,
    domain: &Domain,
    model: &Model,
    activate: &mut super::super::path::Activate<Model>,
    cursor: &mut NativeCursor,
) -> Result<Option<super::super::path::Event>, super::super::path::Error> {
    let producer = model.read32(TX_DESCRIPTOR + 8) >> 16;
    if producer as usize == cursor.tx % 10 {
        cursor.now += 1;
        return activate.poll(cursor.now);
    }
    let reply = peer.respond(domain, model, cursor.tx % 10);
    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
    finish_rx(model, cursor.rx % 10, &reply);
    cursor.tx += 1;
    cursor.rx += 1;
    cursor.now += 1;
    activate.poll(cursor.now)
}

pub(crate) fn drive_path(
    peer: &mut PathPeer,
    domain: &Domain,
    model: &Model,
    activate: &mut super::super::path::Activate<Model>,
    cursor: &mut NativeCursor,
) -> super::super::path::Active {
    use super::super::path::Event;
    activate.poll(cursor.now).unwrap();
    for _ in 0..100 {
        match path_step(peer, domain, model, activate, cursor).unwrap() {
            Some(Event::Active(value)) => return value,
            Some(Event::Discarded(error)) => panic!("{error:?}"),
            None => {}
        }
    }
    panic!("actual path did not activate")
}

pub(crate) struct BandwidthReservation {
    pub(crate) current: Arc<AtomicBool>,
    pub(crate) grant: super::super::usb3::Grant,
    pub(crate) dropped: Arc<AtomicUsize>,
}

impl Drop for BandwidthReservation {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: actual synthetic domain accounting and permission protect this
// exact root/peer link and source floor/quantization throughout the phase.
// When used by tunnel fixtures it also retains actual exclusive synthetic
// CS0 endpoint control on both mapped adapters through final owner lifetime.
// These fixtures implement no production accounting/policy/control service.
unsafe impl super::super::usb3::Reservation for BandwidthReservation {
    fn is_current(&self) -> bool {
        self.current.load(Ordering::Acquire)
    }
    fn grant(&self) -> super::super::usb3::Grant {
        self.grant
    }
}

pub(crate) fn bandwidth_fixture(
    requested: super::super::usb3::Rates,
) -> (PathFixture, Arc<BandwidthReservation>, Arc<AtomicUsize>) {
    use super::super::{
        path::{Direction, LaneCredits},
        usb3::Grant,
    };
    let fixture = path_fixture(Direction::Downstream, LaneCredits::LegacyBonded);
    let allocation = fixture.reservation.allocation;
    let dropped = Arc::new(AtomicUsize::new(0));
    let reservation = Arc::new(BandwidthReservation {
        current: Arc::new(AtomicBool::new(true)),
        grant: Grant {
            identity: allocation.identity,
            topology_epoch: allocation.topology_epoch,
            grant_epoch: allocation.grant_epoch,
            usb3_down: allocation.usb3_down,
            usb3_up: allocation.usb3_up,
            permission: allocation.permission,
            requested,
        },
        dropped: dropped.clone(),
    });
    (fixture, reservation, dropped)
}

pub(crate) struct BandwidthPeer {
    pub(crate) port: u8,
    pub(crate) header: [u32; 8],
    pub(crate) control: u32,
    pub(crate) consumed: u32,
    pub(crate) scale: u32,
    pub(crate) writes: Vec<(u16, u32)>,
    pub(crate) transition: Option<bool>,
    pub(crate) polls: usize,
    pub(crate) hold: [bool; 2],
    pub(crate) reject: Option<usize>,
}

impl BandwidthPeer {
    pub(crate) fn new(
        link: &super::super::link::Linked,
        grant: super::super::usb3::Grant,
        seed: u32,
    ) -> Self {
        use super::super::topology::AdapterObservation;
        let parent = link.retained_routers().unwrap().0;
        let header = parent
            .retained_owner()
            .target()
            .adapters
            .iter()
            .find_map(|a| match a {
                AdapterObservation::Present { port, header, .. } if *port == grant.usb3_down => {
                    Some(header.raw)
                }
                _ => None,
            })
            .unwrap();
        Self {
            port: grant.usb3_down,
            header,
            control: (0x12345678 ^ (seed * 0x10201)) & !(1 << 31),
            consumed: (seed % 256) | (((seed * 3) % 256) << 12),
            scale: (seed % 4) | 0x30000000,
            writes: vec![],
            transition: None,
            polls: 0,
            hold: [false; 2],
            reject: None,
        }
    }
    pub(crate) fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
        let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
        let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
        let bytes = domain.data(
            model.frame_address(Direction::Tx, index),
            (descriptor & 0xfff) as usize,
        );
        let mut words: Vec<u32> = bytes[..bytes.len() - 4]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|v| u32::from_be_bytes(*v))
            .collect();
        let address = words[2];
        assert_eq!((words[0], words[1]), (0, 0));
        assert_eq!((address >> 25) & 3, 1);
        assert_eq!(((address >> 19) & 63) as u8, self.port);
        let offset = (address & 8191) as u16;
        let data = if kind == PacketType::Write {
            assert_eq!((address >> 13) & 63, 1);
            let value = words[3];
            self.writes.push((offset, value));
            let reject = self.reject == Some(self.writes.len());
            match offset {
                0x52 => {
                    let old = self.control;
                    self.control = if reject {
                        value ^ if self.writes.len() == 3 { 1 } else { 1 << 31 }
                    } else {
                        value
                    };
                    if (old ^ value) & (1 << 31) != 0 {
                        self.transition = Some(value & (1 << 31) != 0);
                        self.polls = 0;
                    }
                }
                0x53 => self.scale = if reject { value ^ 1 } else { value },
                _ => panic!("unexpected source bandwidth write"),
            };
            vec![]
        } else {
            assert_eq!(kind, PacketType::Read);
            match offset {
                0 => self.header.to_vec(),
                0x51 => {
                    if let Some(set) = self.transition {
                        self.polls += 1;
                        if self.polls >= 2 && !self.hold[usize::from(!set)] {
                            self.consumed =
                                (self.consumed & !(1 << 31)) | if set { 1 << 31 } else { 0 };
                            self.transition = None;
                        }
                    }
                    vec![self.consumed]
                }
                0x52 => vec![self.control],
                0x53 => vec![self.scale],
                _ => panic!("unexpected bandwidth read"),
            }
        };
        words.truncate(3);
        words[0] |= 1 << 31;
        words[2] &= !(63 << 19);
        words.extend(data);
        incoming(kind, &words)
    }
}

pub(crate) fn bandwidth_step(
    peer: &mut BandwidthPeer,
    domain: &Domain,
    model: &Model,
    allocate: &mut super::super::usb3::Allocate<Model>,
    cursor: &mut NativeCursor,
) -> Result<Option<super::super::usb3::Event>, super::super::usb3::Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
        cursor.now += 1;
        return allocate.poll(cursor.now);
    }
    let reply = peer.respond(domain, model, cursor.tx % 10);
    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
    finish_rx(model, cursor.rx % 10, &reply);
    cursor.tx += 1;
    cursor.rx += 1;
    cursor.now += 1;
    allocate.poll(cursor.now)
}

pub(crate) fn drive_bandwidth(
    peer: &mut BandwidthPeer,
    domain: &Domain,
    model: &Model,
    allocate: &mut super::super::usb3::Allocate<Model>,
    cursor: &mut NativeCursor,
) -> Box<super::super::usb3::Allocated> {
    use super::super::usb3::Event;
    allocate.poll(cursor.now).unwrap();
    for _ in 0..100 {
        match bandwidth_step(peer, domain, model, allocate, cursor).unwrap() {
            Some(Event::Allocated(value)) => return value,
            Some(Event::Discarded(error)) => panic!("{error:?}"),
            None => {}
        }
    }
    panic!("actual HCA transitions did not finish")
}

pub(crate) struct TunnelFixture {
    pub(crate) current: Arc<AtomicBool>,
    pub(crate) domain: Arc<Domain>,
    pub(crate) model: Arc<Model>,
    pub(crate) channel: super::super::channel::Channel<Model>,
    pub(crate) bandwidth: Box<super::super::usb3::Allocated>,
    pub(crate) down: Arc<PathReservation>,
    pub(crate) up: Arc<PathReservation>,
    pub(crate) cursor: NativeCursor,
    pub(crate) dropped: [Arc<AtomicUsize>; 6],
    pub(crate) band_writes: Vec<(u16, u32)>,
}

pub(crate) fn tunnel_fixture(credits: super::super::path::LaneCredits, seed: u32) -> TunnelFixture {
    use super::super::{
        path::Direction,
        usb3::{Allocate, Rates},
    };
    let wanted = [0, 1, 1023, 8191, 10000, 16384, 18000, 20000];
    let (
        PathFixture {
            domain,
            model,
            channel,
            linked,
            reservation,
            mut cursor,
            dropped,
        },
        accounting,
        accounting_drop,
    ) = bandwidth_fixture(Rates {
        upstream: wanted[seed as usize % 8],
        downstream: wanted[(seed as usize / 8) % 8],
    });
    let mut allocation = reservation.allocation;
    allocation.lane_credits = credits;
    let down_drop = Arc::new(AtomicUsize::new(0));
    let up_drop = Arc::new(AtomicUsize::new(0));
    let down = Arc::new(PathReservation {
        allocation,
        dropped: down_drop.clone(),
    });
    allocation.direction = Direction::Upstream;
    let up = Arc::new(PathReservation {
        allocation,
        dropped: up_drop.clone(),
    });
    drop(reservation);
    let current = accounting.current.clone();
    let mut peer = BandwidthPeer::new(&linked, accounting.grant, seed);
    // SAFETY: actual protected native synthetic link/accounting/permission.
    let mut allocate = unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
    let bandwidth = drive_bandwidth(&mut peer, &domain, &model, &mut allocate, &mut cursor);
    let channel = allocate.into_channel();
    TunnelFixture {
        current,
        domain,
        model,
        channel,
        bandwidth,
        down,
        up,
        cursor,
        dropped: [
            dropped[0].clone(),
            dropped[1].clone(),
            dropped[2].clone(),
            accounting_drop,
            down_drop,
            up_drop,
        ],
        band_writes: peer.writes,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TunnelWrite {
    pub(crate) route: u64,
    pub(crate) port: u8,
    pub(crate) space: u8,
    pub(crate) offset: u16,
    pub(crate) data: Vec<u32>,
}

pub(crate) struct TunnelPeer {
    pub(crate) down: PathPeer,
    pub(crate) up: PathPeer,
    pub(crate) endpoints: [u32; 2],
    pub(crate) writes: Vec<TunnelWrite>,
    pub(crate) clear_valid: bool,
    pub(crate) reject: Option<usize>,
    pub(crate) fail_second_header: bool,
}

impl TunnelPeer {
    pub(crate) fn new(fixture: &TunnelFixture, stale: bool, seed: u32) -> Self {
        Self {
            down: PathPeer::new(
                fixture.bandwidth.linked(),
                fixture.down.allocation,
                stale,
                seed,
            ),
            up: PathPeer::new(
                fixture.bandwidth.linked(),
                fixture.up.allocation,
                stale,
                seed + 1,
            ),
            endpoints: [0; 2],
            writes: vec![],
            clear_valid: seed & 1 != 0,
            reject: None,
            fail_second_header: false,
        }
    }
    pub(crate) fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
        let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
        let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
        let bytes = domain.data(
            model.frame_address(Direction::Tx, index),
            (descriptor & 4095) as usize,
        );
        let words: Vec<u32> = bytes[..bytes.len() - 4]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| u32::from_be_bytes(*b))
            .collect();
        let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
        let address = words[2];
        let port = ((address >> 19) & 63) as u8;
        let space = ((address >> 25) & 3) as u8;
        let offset = (address & 8191) as u16;
        if kind == PacketType::Write {
            self.writes.push(TunnelWrite {
                route,
                port,
                space,
                offset,
                data: words[3..].to_vec(),
            });
        }
        let reject = kind == PacketType::Write && self.reject == Some(self.writes.len());
        if space == 1 && offset == 0x50 {
            let endpoint = if route == self.down.routes[0] && port == self.down.ports[0] {
                0
            } else {
                assert_eq!((route, port), (self.up.routes[0], self.up.ports[0]));
                1
            };
            let data = if kind == PacketType::Write {
                assert!(matches!(words[3], 0xc0000000 | 0x40000000));
                let value = if reject {
                    words[3] ^ (1 << 31)
                } else {
                    words[3]
                };
                self.endpoints[endpoint] = if self.clear_valid {
                    value & !(1 << 30)
                } else {
                    value
                };
                vec![]
            } else {
                vec![self.endpoints[endpoint]]
            };
            let upstream = if endpoint == 0 {
                self.down.upstream[0]
            } else {
                self.up.upstream[0]
            };
            let mut reply = words[..3].to_vec();
            reply[0] |= 1 << 31;
            reply[2] = (address & !(63 << 19)) | (u32::from(upstream) << 19);
            reply.extend(data);
            return incoming(kind, &reply);
        }
        let down = self
            .down
            .routes
            .iter()
            .zip(self.down.ports)
            .any(|(r, p)| *r == route && p == port);
        let changed_second = !down && self.fail_second_header && self.down.writes.len() >= 4;
        let peer = if down { &mut self.down } else { &mut self.up };
        if reject {
            peer.reject = Some(peer.writes.len() + 1);
        }
        if changed_second {
            peer.changed_header = true;
        }
        peer.respond(domain, model, index)
    }
}

pub(crate) fn tunnel_step(
    peer: &mut TunnelPeer,
    domain: &Domain,
    model: &Model,
    engine: &mut super::super::usb3::ActivateTunnel<Model>,
    cursor: &mut NativeCursor,
) -> Result<Option<super::super::usb3::TunnelEvent>, super::super::usb3::Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
        cursor.now += 1;
        return engine.poll(cursor.now);
    }
    let reply = peer.respond(domain, model, cursor.tx % 10);
    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
    finish_rx(model, cursor.rx % 10, &reply);
    cursor.tx += 1;
    cursor.rx += 1;
    cursor.now += 1;
    engine.poll(cursor.now)
}

pub(crate) fn drive_tunnel(
    peer: &mut TunnelPeer,
    domain: &Domain,
    model: &Model,
    engine: &mut super::super::usb3::ActivateTunnel<Model>,
    cursor: &mut NativeCursor,
) -> Box<super::super::usb3::ActiveTunnel> {
    use super::super::usb3::TunnelEvent;
    engine.poll(cursor.now).unwrap();
    for _ in 0..200 {
        match tunnel_step(peer, domain, model, engine, cursor).unwrap() {
            Some(TunnelEvent::Active(value)) => return value,
            Some(TunnelEvent::Discarded(error)) => panic!("{error:?}"),
            None => {}
        }
    }
    panic!("actual source USB3 tunnel phase did not finish")
}

pub(crate) struct StopFixture {
    pub(crate) domain: Arc<Domain>,
    pub(crate) model: Arc<Model>,
    pub(crate) channel: super::super::channel::Channel<Model>,
    pub(crate) active: Box<super::super::usb3::ActiveTunnel>,
    pub(crate) peer: TunnelPeer,
    pub(crate) cursor: NativeCursor,
    pub(crate) current: Arc<AtomicBool>,
    pub(crate) dropped: [Arc<AtomicUsize>; 6],
    pub(crate) activation: Vec<TunnelWrite>,
    pub(crate) bandwidth_peer: BandwidthPeer,
}

pub(crate) fn stop_fixture(credits: super::super::path::LaneCredits, seed: u32) -> StopFixture {
    use super::super::usb3::ActivateTunnel;
    let fixture = tunnel_fixture(credits, seed);
    let mut peer = TunnelPeer::new(&fixture, true, seed);
    let control = fixture.band_writes.last().unwrap().1;
    let scale = fixture
        .band_writes
        .iter()
        .find(|(offset, _)| *offset == 0x53)
        .unwrap()
        .1;
    let bandwidth_peer = BandwidthPeer {
        port: 6,
        header: peer.down.headers[0],
        control,
        scale,
        consumed: if seed & 1 == 0 { 0 } else { 1023 }
            | ((if seed.is_multiple_of(3) { 1023 } else { 255 }) << 12),
        writes: vec![],
        transition: None,
        polls: 0,
        hold: [false; 2],
        reject: None,
    };
    let TunnelFixture {
        domain,
        model,
        channel,
        bandwidth,
        down,
        up,
        mut cursor,
        current,
        dropped,
        band_writes,
    } = fixture;
    // SAFETY: complete actual synthetic control/accounting/path authority.
    let mut engine =
        unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }.unwrap();
    let active = drive_tunnel(&mut peer, &domain, &model, &mut engine, &mut cursor);
    let channel = engine.into_channel();
    let mut activation: Vec<_> = band_writes
        .into_iter()
        .map(|(offset, value)| TunnelWrite {
            route: 0,
            port: 6,
            space: 1,
            offset,
            data: vec![value],
        })
        .collect();
    activation.append(&mut peer.writes);
    peer.down.writes.clear();
    peer.up.writes.clear();
    for path in [&mut peer.down, &mut peer.up] {
        for i in 0..2 {
            path.raw[i][1] |= 1 << 28;
            path.disabled[i] = false;
            path.reads[i] = 0;
        }
    }
    StopFixture {
        domain,
        model,
        channel,
        active,
        peer,
        cursor,
        current,
        dropped,
        activation,
        bandwidth_peer,
    }
}

pub(crate) fn stop_step(
    peer: &mut TunnelPeer,
    domain: &Domain,
    model: &Model,
    engine: &mut super::super::usb3::StopTunnel<Model>,
    cursor: &mut NativeCursor,
) -> Result<Option<super::super::usb3::StopEvent>, super::super::usb3::Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
        cursor.now += 1;
        return engine.poll(cursor.now);
    }
    let reply = peer.respond(domain, model, cursor.tx % 10);
    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
    finish_rx(model, cursor.rx % 10, &reply);
    cursor.tx += 1;
    cursor.rx += 1;
    cursor.now += 1;
    engine.poll(cursor.now)
}

pub(crate) fn drive_stop(
    peer: &mut TunnelPeer,
    domain: &Domain,
    model: &Model,
    engine: &mut super::super::usb3::StopTunnel<Model>,
    cursor: &mut NativeCursor,
) -> Box<super::super::usb3::Stopped> {
    use super::super::usb3::StopEvent;
    engine.poll(cursor.now).unwrap();
    for _ in 0..200 {
        match stop_step(peer, domain, model, engine, cursor).unwrap() {
            Some(StopEvent::Stopped(value)) => return value,
            Some(StopEvent::Discarded(e)) => panic!("{e:?}"),
            None => {}
        }
    }
    panic!("normal actual tunnel stop did not finish")
}

pub(crate) fn release_step(
    peer: &mut BandwidthPeer,
    domain: &Domain,
    model: &Model,
    engine: &mut super::super::usb3::ReleaseUnused<Model>,
    cursor: &mut NativeCursor,
) -> Result<Option<super::super::usb3::TunnelEvent>, super::super::usb3::Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
        cursor.now += 1;
        return engine.poll(cursor.now);
    }
    let reply = peer.respond(domain, model, cursor.tx % 10);
    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
    finish_rx(model, cursor.rx % 10, &reply);
    cursor.tx += 1;
    cursor.rx += 1;
    cursor.now += 1;
    engine.poll(cursor.now)
}

pub(crate) fn drive_release(
    peer: &mut BandwidthPeer,
    domain: &Domain,
    model: &Model,
    engine: &mut super::super::usb3::ReleaseUnused<Model>,
    cursor: &mut NativeCursor,
) -> Box<super::super::usb3::ActiveTunnel> {
    use super::super::usb3::TunnelEvent;
    engine.poll(cursor.now).unwrap();
    for _ in 0..100 {
        match release_step(peer, domain, model, engine, cursor).unwrap() {
            Some(TunnelEvent::Active(value)) => return value,
            Some(TunnelEvent::Discarded(e)) => panic!("{e:?}"),
            None => {}
        }
    }
    panic!("source release-unused handshake did not finish")
}

pub(crate) fn controller_error(domain: &Domain, model: &Model, cursor: &NativeCursor) -> Encoded {
    let bytes = domain.data(model.frame_address(Direction::Tx, cursor.tx % 10), 16);
    incoming(
        PacketType::Error,
        &[
            u32::from_be_bytes(bytes[..4].try_into().unwrap()) | (1 << 31),
            u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            2,
        ],
    )
}
