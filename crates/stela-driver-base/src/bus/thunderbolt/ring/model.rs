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

// SAFETY: immutable metadata points at kept exclusive model RAM; all
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
        // SAFETY: this is the exact allocation and final pin.
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
        // SAFETY: model allocation, aligned bounded access.
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
            // SAFETY: serialized modeled DMA within the frame.
            unsafe { pointer.as_ptr().add(index).write_volatile(*value) };
        }
    }
}

// SAFETY: this is a serialized synthetic domain with nonidentity IOVAs.
// Every map keeps real host RAM; failed unmap keeps its reservation.
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
    // SAFETY: synthetic device/posted DMA/IRQ/work fully drained.
    unsafe { channel.release() }.unwrap();
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
    // SAFETY: synthetic requester/epoch owns stopped rings and coherent
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
