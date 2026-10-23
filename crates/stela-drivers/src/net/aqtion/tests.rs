// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Stela contributors
//! Independently authored register/DMA peer derived from Linux atlantic's
//! hardware contract. Tests are source-only until the coordinator runs them.
extern crate std;
use super::*;
use crate::bus::{
    dma::{
        mapping::{Direction, DomainMapping},
        memory::{CacheAttribute, CpuMapping, PageBacking, PinnedPages},
        pages::DmaPages,
    },
    pci::{Address, owned::tests::fixture},
};
use alloc::{
    alloc::{alloc_zeroed, dealloc},
    boxed::Box,
    collections::BTreeMap,
    rc::Rc,
};
use core::{
    alloc::Layout,
    cell::{Cell, RefCell, UnsafeCell},
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::sync::Mutex;

struct Ram {
    pointer: NonNull<u8>,
    physical: Vec<u64>,
    layout: Layout,
    dropped: Arc<AtomicUsize>,
}
// SAFETY: test-only uniquely retained stable allocations; physical labels are
// symbolic and never passed to native hardware or any real remapping provider.
unsafe impl Send for Ram {}
// SAFETY: only raw access, synchronized by the synchronous test model.
unsafe impl Sync for Ram {}
// SAFETY: zeroed page-aligned model storage, immutable labels and retained owner.
unsafe impl PageBacking for Ram {
    fn cpu_base(&self) -> NonNull<u8> {
        self.pointer
    }
    fn physical_pages(&self) -> &[u64] {
        &self.physical
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
impl Drop for Ram {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) }
    }
}
struct Pages {
    dropped: Arc<AtomicUsize>,
    next: Cell<u64>,
}
impl PageSource for Pages {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> core::result::Result<PinnedPages, MemoryError> {
        assert_eq!(attribute, CacheAttribute::WriteBack);
        let bytes = bytes.div_ceil(4096) * 4096;
        let layout = Layout::from_size_align(bytes, alignment).unwrap();
        let p = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
        let base = self.next.get();
        self.next.set(base + bytes as u64);
        PinnedPages::new(
            Box::new(Ram {
                pointer: p,
                physical: (0..bytes / 4096)
                    .map(|i| base + (i * 4096) as u64)
                    .collect(),
                layout,
                dropped: self.dropped.clone(),
            }),
            bytes,
            alignment,
        )
    }
}
#[derive(Default)]
struct Domain {
    maps: Mutex<BTreeMap<u64, CpuMapping>>,
    next: AtomicUsize,
    visibility: Mutex<Vec<(bool, u64, Range<usize>)>>,
    drain_count: AtomicUsize,
    engine_epoch: AtomicUsize,
    drained_epoch: AtomicUsize,
    engines: AtomicUsize,
    pending_dma: AtomicUsize,
    published: Mutex<BTreeMap<u64, u8>>,
    defer_writebacks: AtomicBool,
    posted: Mutex<Vec<(u64, Vec<u8>)>>,
    fail_drain: AtomicBool,
    fail_unmap: AtomicBool,
    fail_sync: AtomicBool,
    incoherent: AtomicBool,
}
impl Domain {
    fn raw(&self, address: u64, bytes: usize) -> NonNull<u8> {
        let maps = self.maps.lock().unwrap();
        for (&base, mapping) in maps.iter() {
            if address >= base && address + bytes as u64 <= base + mapping.bytes() as u64 {
                return mapping.address((address - base) as usize, bytes).unwrap();
            }
        }
        panic!("model DMA outside an actual retained IOVA: {address:x}/{bytes}")
    }
    fn visible(&self, address: u64, bytes: usize) {
        let mut published = self.published.lock().unwrap();
        for n in 0..bytes {
            let at = address + n as u64;
            let actual = unsafe { self.raw(at, 1).as_ptr().read_volatile() };
            assert_eq!(
                published.remove(&at),
                Some(actual),
                "DMA without fresh visibility at {at:x}"
            );
        }
    }
    fn read32(&self, address: u64) -> u32 {
        self.visible(address, 4);
        unsafe { self.raw(address, 4).as_ptr().cast::<u32>().read_volatile() }
    }
    fn read64(&self, address: u64) -> u64 {
        self.visible(address, 8);
        unsafe { self.raw(address, 8).as_ptr().cast::<u64>().read_volatile() }
    }
    fn writeback(&self, address: u64, bytes: &[u8]) {
        if self.defer_writebacks.load(Ordering::Relaxed) {
            self.posted.lock().unwrap().push((address, bytes.to_vec()));
        } else {
            self.store(address, bytes);
        }
    }
    fn store(&self, address: u64, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            unsafe { self.raw(address + i as u64, 1).as_ptr().write_volatile(*b) }
        }
    }
    fn complete_posted(&self) {
        for (address, bytes) in self.posted.lock().unwrap().drain(..) {
            self.store(address, &bytes);
        }
    }
    fn put32(&self, address: u64, value: u32) {
        self.writeback(address, &value.to_le_bytes());
    }
    fn packet(&self, address: u64, length: usize) -> Vec<u8> {
        self.visible(address, length);
        (0..length)
            .map(|n| unsafe { self.raw(address + n as u64, 1).as_ptr().read_volatile() })
            .collect()
    }
    fn put_packet(&self, address: u64, bytes: &[u8]) {
        self.visible(address, memory::BUFFER);
        self.writeback(address, bytes);
    }
}
// SAFETY: explicit independent synchronous model, never native DMA. Each mapping
// retains its exact pins, has a unique symbolic IOVA and checked cache accesses.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        _: Direction,
        limit: u64,
    ) -> core::result::Result<DomainMapping, DmaError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let address = 0x1_0000_0000 + (id as u64) * 0x10_0000;
        assert!(address + pages.bytes() as u64 - 1 <= limit);
        self.maps.lock().unwrap().insert(
            address,
            pages
                .as_single()
                .unwrap()
                .cpu_mapping(CacheAttribute::WriteBack)
                .unwrap(),
        );
        Ok(DomainMapping {
            id: id as u64,
            address,
            bytes: pages.bytes(),
        })
    }
    unsafe fn unmap(&self, m: DomainMapping) -> core::result::Result<(), DmaError> {
        if self.fail_unmap.load(Ordering::Relaxed) {
            return Err(DmaError::InvalidationFailed);
        }
        assert!(self.drain_count.load(Ordering::Relaxed) > 0);
        assert_eq!(self.engines.load(Ordering::Relaxed), 0);
        assert_eq!(self.pending_dma.load(Ordering::Relaxed), 0);
        assert!(self.posted.lock().unwrap().is_empty());
        assert_eq!(
            self.drained_epoch.load(Ordering::Relaxed),
            self.engine_epoch.load(Ordering::Relaxed),
            "historical drain cannot release a newer engine epoch"
        );
        assert!(self.maps.lock().unwrap().remove(&m.address).is_some());
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        m: DomainMapping,
        r: Range<usize>,
        _: Direction,
    ) -> core::result::Result<(), DmaError> {
        if self.fail_sync.load(Ordering::Relaxed) {
            return Err(DmaError::VisibilityFailed);
        }
        assert!(r.end <= m.bytes);
        let mut published = self.published.lock().unwrap();
        for n in r.clone() {
            let address = m.address + n as u64;
            let byte = unsafe { self.raw(address, 1).as_ptr().read_volatile() };
            published.insert(address, byte);
        }
        self.visibility.lock().unwrap().push((false, m.address, r));
        Ok(())
    }
    unsafe fn sync_for_cpu(
        &self,
        m: DomainMapping,
        r: Range<usize>,
        _: Direction,
    ) -> core::result::Result<(), DmaError> {
        assert!(r.end <= m.bytes);
        self.visibility.lock().unwrap().push((true, m.address, r));
        Ok(())
    }
    unsafe fn read_coherent_u32(
        &self,
        m: DomainMapping,
        offset: usize,
        _: Direction,
    ) -> core::result::Result<u32, DmaError> {
        if self.incoherent.load(Ordering::Relaxed) {
            return Err(DmaError::CoherenceUnavailable);
        }
        Ok(unsafe {
            self.raw(m.address + offset as u64, 4)
                .as_ptr()
                .cast::<u32>()
                .read_volatile()
        })
    }
    unsafe fn drain_posted_writes(&self) -> core::result::Result<(), DmaError> {
        if self.fail_drain.load(Ordering::Relaxed) {
            return Err(DmaError::DrainUnavailable);
        }
        assert_eq!(
            self.engines.load(Ordering::Relaxed),
            0,
            "drain while engines can still issue DMA"
        );
        // Pending device writebacks complete at the real modeled drain boundary.
        self.complete_posted();
        self.pending_dma.store(0, Ordering::Relaxed);
        self.drained_epoch
            .store(self.engine_epoch.load(Ordering::Relaxed), Ordering::Relaxed);
        self.drain_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Reset,
    HostBoot,
    BootFailure,
    RamSemaphore,
    RamCompletion,
    FirmwareAck,
    Cache,
    QueueStop,
    Removed,
    Snapshot,
}
struct Peer {
    regs: RefCell<BTreeMap<usize, u32>>,
    ram: RefCell<BTreeMap<u32, u32>>,
    writes: RefCell<Vec<(usize, u32)>>,
    fault: Cell<Fault>,
    profile: Profile,
    elapsed: Cell<u64>,
    domain: Arc<Domain>,
    sent: RefCell<Vec<Vec<u8>>>,
    tx_head: Cell<usize>,
    rx_head: Cell<usize>,
    semaphores: RefCell<BTreeMap<usize, bool>>,
    second_lock_busy: Cell<bool>,
    fail_read: Cell<Option<usize>>,
    fail_write: Cell<Option<usize>>,
    failed_release_reached_device: Cell<bool>,
    failed_acquire_reached_device: Cell<bool>,
    reads: RefCell<Vec<usize>>,
    reset_count: Cell<usize>,
    ack_delay: Cell<u64>,
    pending_ack: RefCell<Vec<(u64, usize, u32)>>,
    tx_delay: Cell<bool>,
    pending_tx: Cell<Option<usize>>,
    native_pm: RefCell<Option<Arc<NativePm>>>,
}
impl Peer {
    fn new(profile: Profile, domain: Arc<Domain>) -> Rc<Self> {
        let peer = Rc::new(Self {
            regs: RefCell::new(BTreeMap::new()),
            ram: RefCell::new(BTreeMap::new()),
            writes: RefCell::new(Vec::new()),
            fault: Cell::new(Fault::None),
            profile,
            elapsed: Cell::new(0),
            domain,
            sent: RefCell::new(Vec::new()),
            tx_head: Cell::new(0),
            rx_head: Cell::new(0),
            semaphores: RefCell::new(BTreeMap::new()),
            second_lock_busy: Cell::new(false),
            fail_read: Cell::new(None),
            fail_write: Cell::new(None),
            failed_release_reached_device: Cell::new(false),
            failed_acquire_reached_device: Cell::new(false),
            reads: RefCell::new(Vec::new()),
            reset_count: Cell::new(0),
            ack_delay: Cell::new(200),
            pending_ack: RefCell::new(Vec::new()),
            tx_delay: Cell::new(false),
            pending_tx: Cell::new(None),
            native_pm: RefCell::new(None),
        });
        peer.set(0x1c, 0xa);
        peer.set(0x18, 0x0301005a);
        peer.set(0x388, 1);
        peer.set(0x364, 0x10000);
        peer.set(0x360, 0x20000);
        peer.set(0x334, 0x30000);
        peer.ram.borrow_mut().insert(0x100a0, 0x02112233);
        peer.ram.borrow_mut().insert(0x100a4, 0x44550000);
        peer.set(0x12008, 0x33221102);
        peer.set(0x1200c, 0x5544);
        peer.set(0x13000, 0x10001);
        peer.set(0x13004, 0x11_0201);
        peer.set(0x13010, 1);
        peer.set(0x13774, 0x1004);
        peer.set(0x13778, 0);
        peer.set(0x1377c, 0x08020000); // ART16..79
        peer.set(0x5a10, 1);
        peer
    }
    fn set(&self, offset: usize, value: u32) {
        self.regs.borrow_mut().insert(offset, value);
    }
    fn get(&self, offset: usize) -> u32 {
        self.regs.borrow().get(&offset).copied().unwrap_or(0)
    }
    fn address(&self, base: usize) -> u64 {
        u64::from(self.get(base)) | (u64::from(self.get(base + 4)) << 32)
    }
    fn acknowledge_later(&self, register: usize, value: u32) {
        self.pending_ack.borrow_mut().push((
            self.elapsed.get() + self.ack_delay.get(),
            register,
            value,
        ));
    }
    fn transmit(&self, tail: usize) {
        let base = self.address(0x7c00);
        assert_ne!(
            self.get(0x7c08) & 0x80000000,
            0,
            "TX before descriptor enable"
        );
        assert_eq!(
            self.get(0x7c08) & 0x1ff8,
            64,
            "ring size must be descriptor count, not byte count"
        );
        assert_ne!(self.domain.engines.load(Ordering::Relaxed) & 1, 0);
        let mut head = self.tx_head.get();
        while head != tail {
            let descriptor = base + (head * 16) as u64;
            let control = self.domain.read32(descriptor + 8);
            let length = ((control >> 4) & 0xffff) as usize;
            assert_eq!(control & 0xffff000f, 0x08200001);
            assert_eq!(self.domain.read32(descriptor + 12), (length as u32) << 14);
            self.sent
                .borrow_mut()
                .push(self.domain.packet(self.domain.read64(descriptor), length));
            self.domain.put32(descriptor + 8, control | (1 << 20));
            self.domain.pending_dma.fetch_add(1, Ordering::Relaxed);
            head = (head + 1) % 64;
        }
        self.tx_head.set(head);
        self.set(0x7c0c, head as u32);
    }
    fn receive(&self, bytes: &[u8], kind: u32, status: u16, length: u16) {
        assert_ne!(self.domain.engines.load(Ordering::Relaxed) & 2, 0);
        let index = self.rx_head.get();
        assert_ne!(
            index,
            self.get(0x5b10) as usize,
            "device ran beyond offered RX tail"
        );
        let desc = self.address(0x5b00) + (index * 16) as u64;
        let address = self.domain.read64(desc);
        assert_eq!(
            self.domain.read64(desc + 8),
            0,
            "receive descriptor must have its stale status cleared"
        );
        self.domain.put_packet(address, bytes);
        self.domain.put32(desc, kind);
        self.domain
            .put32(desc + 8, u32::from(status) | (u32::from(length) << 16));
        self.rx_head.set((index + 1) % 64);
        self.domain.pending_dma.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: stateful, independent symbolic register peer; all operations are
// synchronous and cannot name or access any physical device.
unsafe impl Registers for Rc<Peer> {
    fn read(&self, offset: usize) -> Result<u32> {
        if let Some(pm) = self.native_pm.borrow().as_ref() {
            assert_eq!(
                pm.actual_state.load(Ordering::Relaxed),
                0,
                "powered-off MMIO read"
            );
        }
        if self.fault.get() == Fault::Removed {
            return Ok(u32::MAX);
        }
        self.reads.borrow_mut().push(offset);
        if self.fail_read.get() == Some(offset) {
            if matches!(offset, 0x3ac | 0x3b0) && self.failed_acquire_reached_device.get() {
                self.semaphores.borrow_mut().insert(offset, true);
            }
            return Err(Error::Unsupported("injected native MMIO read failure"));
        }
        if matches!(offset, 0x3a8 | 0x3ac | 0x3b0) {
            if self.fault.get() == Fault::RamSemaphore
                || (offset == 0x3b0 && self.second_lock_busy.get())
            {
                return Ok(0);
            }
            let mut semaphores = self.semaphores.borrow_mut();
            let held = semaphores.entry(offset).or_insert(false);
            if *held {
                return Ok(0);
            }
            *held = true;
            return Ok(1);
        }
        if offset == 0x13000 && self.fault.get() == Fault::Snapshot {
            return Ok(0x20001);
        }
        Ok(self.get(offset))
    }
    fn write(&self, offset: usize, value: u32) -> Result<()> {
        if let Some(pm) = self.native_pm.borrow().as_ref() {
            assert_eq!(
                pm.actual_state.load(Ordering::Relaxed),
                0,
                "powered-off MMIO write"
            );
        }
        self.writes.borrow_mut().push((offset, value));
        if self.fail_write.get() == Some(offset) {
            if matches!(offset, 0x3ac | 0x3b0) && self.failed_release_reached_device.get() {
                self.semaphores.borrow_mut().insert(offset, false);
            }
            return Err(Error::Unsupported("injected native MMIO write failure"));
        }
        if matches!(offset, 0x3a8 | 0x3ac | 0x3b0) && value == 1 {
            assert_eq!(
                self.semaphores.borrow_mut().insert(offset, false),
                Some(true),
                "release must own this read-to-acquire semaphore"
            );
            return Ok(());
        }
        if (offset == 0 && value & 0x8000 != 0) || (offset == 0x3040 && value == 1) {
            self.reset_count.set(self.reset_count.get() + 1);
            assert_eq!(self.domain.engines.load(Ordering::Relaxed), 0);
            self.semaphores.borrow_mut().clear();
            self.pending_ack.borrow_mut().clear();
            self.pending_tx.set(None);
            self.tx_head.set(0);
            self.rx_head.set(0);
            self.set(0x7c0c, 0);
        }
        if offset == 0x3040 && value == 1 {
            self.set(
                offset,
                if self.fault.get() == Fault::Reset {
                    0
                } else if self.fault.get() == Fault::BootFailure {
                    0x11000000
                } else {
                    0x81000000
                },
            );
            if self.fault.get() == Fault::HostBoot {
                self.set(0xf00, 1);
            }
            return Ok(());
        }
        if offset == 0x404 && value == 0x40e0 && self.fault.get() != Fault::Reset {
            self.set(0x388, 1);
        }
        if offset == 0x404 && value == 0x180e0 && self.fault.get() != Fault::Reset {
            self.set(0x704, 0x10);
        }
        if offset == 0x200 && value == 0x8000 && self.fault.get() != Fault::RamCompletion {
            let address = self.get(0x208);
            self.set(0x20c, self.ram.borrow().get(&address).copied().unwrap_or(0));
            self.set(0x208, address + 4);
        }
        if offset == 0x36c && self.fault.get() != Fault::FirmwareAck {
            self.acknowledge_later(0x374, value);
        }
        if offset == 0xe00 {
            self.set(0xe04, 1);
            if self.fault.get() != Fault::FirmwareAck {
                self.acknowledge_later(0xe04, 0);
            }
        }
        if offset == 0x5a00 {
            self.set(
                0x5a10,
                if self.fault.get() == Fault::Cache {
                    0
                } else {
                    1
                },
            );
        }
        if offset == 0x54d0 {
            self.set(offset, value & !(1 << 5));
            return Ok(());
        }
        if matches!(offset, 0x7c08 | 0x5b08)
            && value & (1 << 31) == 0
            && self.fault.get() == Fault::QueueStop
        {
            self.set(offset, value | (1 << 31));
            return Ok(());
        }
        if offset == 0x7c08 && value & (1 << 31) == 0 {
            if let Some(tail) = self.pending_tx.take() {
                self.transmit(tail);
            }
        }
        self.set(offset, value);
        if matches!(offset, 0x7c08 | 0x5b08) {
            let bit = if offset == 0x7c08 { 1 } else { 2 };
            if value & (1 << 31) != 0 {
                let previous = self.domain.engines.fetch_or(bit, Ordering::Relaxed);
                if previous == 0 {
                    self.domain.engine_epoch.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                // Finish any delayed descriptor fetch before acknowledging
                // engine disable. Posted writebacks still require a drain.
                self.domain.engines.fetch_and(!bit, Ordering::Relaxed);
            }
        }
        if offset == 0x7c10 && value as usize != self.tx_head.get() {
            if self.tx_delay.get() {
                self.pending_tx.set(Some(value as usize));
            } else {
                self.transmit(value as usize);
            }
        }
        Ok(())
    }
}
impl Timer for Rc<Peer> {
    fn delay(&self, us: u64) {
        self.elapsed.set(self.elapsed.get() + us);
        self.pending_ack
            .borrow_mut()
            .retain(|&(deadline, register, value)| {
                if self.elapsed.get() >= deadline {
                    self.set(register, value);
                    false
                } else {
                    true
                }
            });
    }
}
fn hardware(peer: &Rc<Peer>) -> Hardware<Rc<Peer>, Rc<Peer>> {
    Hardware {
        registers: peer.clone(),
        timer: peer.clone(),
        reset_ownership: Cell::new(firmware::ResetOwnership::default()),
    }
}
type Fixture = (
    Aqtion<Rc<Peer>, Rc<Peer>>,
    Rc<Peer>,
    Arc<Domain>,
    Arc<AtomicUsize>,
);
fn setup(device: u16) -> Fixture {
    let profile = Profile::identify(0x1d6a, device).unwrap();
    let domain = Arc::new(Domain::default());
    let dropped = Arc::new(AtomicUsize::new(0));
    let pages = Pages {
        dropped: dropped.clone(),
        next: Cell::new(0x40000000),
    };
    let peer = Peer::new(profile, domain.clone());
    let addr = Address {
        segment: 0,
        bus: 1,
        device: 0,
        function: 0,
    };
    let (mut config, _) = fixture(addr);
    config.write32(0, (u32::from(device) << 16) | 0x1d6a);
    config.write32(8, 0x02000000);
    let owner = Aqtion {
        function: Some(Function::new(addr, config).unwrap()),
        hardware: Some(hardware(&peer)),
        domain: Some(domain.clone()),
        memory: Some(Memory::new(&pages, domain.clone()).unwrap()),
        profile,
        firmware: None,
        mac: Mac::default(),
        state: State::Stopped,
        power: PciPower::D0,
        tx_tail: 0,
        tx_head: 0,
        rx_head: 0,
        dropping: false,
    };
    (owner, peer, domain, dropped)
}
#[test]
fn exact_profiles_do_not_admit_usb_fiber_or_unimplemented_silicon_families() {
    for id in [
        0x07b1, 0x87b1, 0x08b1, 0x88b1, 0x11b1, 0x91b1, 0x12b1, 0x92b1, 0x00c0, 0x94c0, 0x93c0,
        0x04c0, 0x14c0, 0x34c0,
    ] {
        assert!(Profile::identify(0x1d6a, id).is_some());
    }
    for (vendor, id) in [
        (0x1d6a, 0x00b1),
        (0x1d6a, 0xd107),
        (0x1d6a, 0x12c0),
        (0x1d6a, 0x11c0),
        (0x2eca, 0xc101),
        (0x8086, 0x07b1),
    ] {
        assert_eq!(Profile::identify(vendor, id), None);
    }
}
#[test]
fn native_b1_and_antigua_initialize_real_rings_transfer_and_wrap() {
    for id in [0x07b1, 0x08b1, 0x11b1, 0x12b1, 0x04c0, 0x93c0] {
        let (mut net, peer, domain, dropped) = setup(id);
        net.start().unwrap();
        assert_eq!(net.mac(), Mac([2, 0x11, 0x22, 0x33, 0x44, 0x55]));
        if peer.profile.generation == Generation::Atlantic {
            peer.set(0x370, 0x100);
        } else {
            peer.set(0x13014, 0x830);
        }
        for n in 0..130 {
            let frame = vec![(n % 251) as u8; 14 + n % 1500];
            net.transmit(&frame).unwrap();
            let sent = peer.sent.borrow().last().unwrap().clone();
            assert_eq!(&sent[..frame.len()], frame);
            assert!(sent[frame.len()..].iter().all(|v| *v == 0));
            peer.receive(&frame, 0, 3, frame.len() as u16);
            assert_eq!(net.receive().unwrap(), Some(frame));
        }
        net.retire().unwrap();
        assert_eq!(net.state(), State::Stopped);
        assert!(domain.maps.lock().unwrap().is_empty());
        assert_eq!(dropped.load(Ordering::Relaxed), 4);
        assert!(domain.drain_count.load(Ordering::Relaxed) > 0);
    }
}
#[test]
fn bad_rx_metadata_and_fragment_chains_are_not_fabricated_as_frames() {
    let (mut net, peer, _, _) = setup(0x07b1);
    net.start().unwrap();
    peer.set(0x370, 0x100);
    for (kind, status, len) in [
        (0, 1, 60),
        (0, 3, 60),
        (0, 7, 60),
        (0x1000, 3, 60),
        (0, 3, 4097),
        (0, 3, 13),
        (0, 0x1003, 60),
    ] {
        peer.receive(&[9; 60], kind, status, len);
    }
    peer.receive(&[7; 60], 0, 3, 60);
    assert_eq!(net.receive().unwrap(), Some(vec![7; 60]));
    assert_eq!(net.receive().unwrap(), None);
    net.retire().unwrap();
}
#[test]
fn genuine_stop_and_dma_drain_failures_retain_all_resources_for_retry() {
    let (mut net, peer, domain, dropped) = setup(0x04c0);
    net.start().unwrap();
    peer.fault.set(Fault::QueueStop);
    assert!(net.stop().is_err());
    assert_eq!(net.state(), State::Faulted);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    peer.fault.set(Fault::None);
    domain.fail_drain.store(true, Ordering::Relaxed);
    assert_eq!(net.stop(), Err(Error::Dma(DmaError::DrainUnavailable)));
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    domain.fail_drain.store(false, Ordering::Relaxed);
    net.stop().unwrap();
    domain.fail_unmap.store(true, Ordering::Relaxed);
    assert_eq!(net.retire(), Err(Error::Dma(DmaError::InvalidationFailed)));
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    domain.fail_unmap.store(false, Ordering::Relaxed);
    net.retire().unwrap();
    assert_eq!(dropped.load(Ordering::Relaxed), 4);
}
#[test]
fn firmware_failures_are_bounded_and_do_not_publish_a_working_link() {
    for (id, fault) in [
        (0x07b1, Fault::RamSemaphore),
        (0x07b1, Fault::RamCompletion),
        (0x04c0, Fault::Reset),
        (0x04c0, Fault::HostBoot),
        (0x04c0, Fault::BootFailure),
        (0x04c0, Fault::Snapshot),
        (0x04c0, Fault::FirmwareAck),
        (0x07b1, Fault::Cache),
    ] {
        let (mut net, peer, domain, dropped) = setup(id);
        peer.fault.set(fault);
        assert!(net.start().is_err());
        assert_eq!(net.state(), State::Faulted);
        assert!(!net.carrier());
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert!(peer.elapsed.get() < 20_000_000);
        peer.fault.set(Fault::None);
        net.retire().unwrap();
        assert_eq!(domain.maps.lock().unwrap().len(), 0);
    }
}
#[test]
fn loss_visibility_and_invalid_hardware_heads_are_terminal_until_recovery() {
    let (mut net, peer, domain, _) = setup(0x07b1);
    net.start().unwrap();
    peer.set(0x370, 0x100);
    peer.set(0x7c0c, 64);
    assert_eq!(net.send(&[1; 60]), Err(Error::RingHead(64)));
    peer.set(0x7c0c, 0);
    domain.fail_sync.store(true, Ordering::Relaxed);
    assert!(net.transmit(&[1; 60]).is_err());
    assert_eq!(net.state(), State::Faulted);
    domain.fail_sync.store(false, Ordering::Relaxed);
    net.restart().unwrap();
    peer.fault.set(Fault::Removed);
    assert!(net.receive().is_err());
    assert_eq!(net.state(), State::Faulted);
    peer.fault.set(Fault::None);
    net.retire().unwrap();
}
#[test]
fn unsupported_coherent_dma_cannot_be_silently_replaced_with_a_fence() {
    let (mut net, _, domain, _) = setup(0x07b1);
    domain.incoherent.store(true, Ordering::Relaxed);
    assert_eq!(net.start(), Err(Error::Dma(DmaError::CoherenceUnavailable)));
    domain.incoherent.store(false, Ordering::Relaxed);
    net.retire().unwrap();
}

#[test]
fn ordinary_suspend_stops_dma_before_d3_and_retains_the_resumable_epoch() {
    let (mut net, peer, domain, dropped) = setup(0x07b1);
    let config = net.function.as_mut().unwrap().config();
    config.write16(6, 1 << 4);
    config.write8(0x34, 0x40);
    config.write16(0x40, 1);
    config.write16(0x44, 0x8100);
    net.start().unwrap();
    net.suspend().unwrap();
    assert_eq!(net.state(), State::Suspended);
    assert!(domain.drain_count.load(Ordering::Relaxed) > 0);
    assert_eq!(net.function.as_mut().unwrap().config().read16(0x44), 3);
    let writes = peer.writes.borrow().len();
    assert!(!net.carrier());
    assert!(net.receive().is_err());
    net.retire().unwrap();
    assert_eq!(
        peer.writes.borrow().len(),
        writes,
        "suspended teardown must not access powered-off MMIO"
    );
    assert_eq!(dropped.load(Ordering::Relaxed), 4);
}

// A native OwnedConfig fixture with a synchronous mapping callback. The callback
// observes actual volatile PMCSR stores before the next native access. It models
// refused D0 and a D3 write whose readback disappears, without changing PCI APIs.
#[repr(align(4096))]
struct ConfigPage([u8; 4096]);
struct NativePm {
    page: Box<UnsafeCell<ConfigPage>>,
    mode: AtomicUsize, // 0 normal, 1 refuse D0, 2 lose D3 readback, 3 refuse D3
    actual_state: AtomicUsize,
}
// SAFETY: test-only stable RAM, serialized native volatile accesses and callback.
unsafe impl Send for NativePm {}
// SAFETY: no references into the UnsafeCell storage are exposed.
unsafe impl Sync for NativePm {}
impl NativePm {
    fn pointer(&self) -> NonNull<u8> {
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.page.get()).0).cast()) }
    }
}
struct ConfigResource(owned::PhysicalSpan);
// SAFETY: symbolic test ECAM span, backed only by the retained fixture RAM.
unsafe impl owned::ResourceBacking for ConfigResource {
    fn physical_span(&self) -> owned::PhysicalSpan {
        self.0
    }
    fn kind(&self) -> owned::ResourceKind {
        owned::ResourceKind::Registers
    }
}
// SAFETY: isolated registry, stable aligned native RAM, no physical device.
// check_context is also the fixture's serialized hardware-response callback.
unsafe impl owned::MappingPlatform for NativePm {
    fn check_context(&self, _: owned::AddressSpace) -> core::result::Result<(), owned::Error> {
        let pm = unsafe { self.pointer().as_ptr().add(0x44).cast::<u16>() };
        let value = unsafe { pm.read_volatile() };
        if value != u16::MAX {
            self.actual_state
                .store(usize::from(value & 3), Ordering::Relaxed);
        }
        match self.mode.load(Ordering::Relaxed) {
            1 if value & 3 == 0 => {
                unsafe { pm.write_volatile(3) };
                self.actual_state.store(3, Ordering::Relaxed);
            }
            2 if value & 3 == 3 => unsafe { pm.write_volatile(u16::MAX) },
            3 if value & 3 == 3 => {
                unsafe { pm.write_volatile(0) };
                self.actual_state.store(0, Ordering::Relaxed);
            }
            _ => {}
        }
        Ok(())
    }
    unsafe fn map(
        &self,
        resource: &owned::Resource,
        request: owned::MapRequest,
    ) -> core::result::Result<owned::InstalledMapping, owned::MapFailure> {
        assert!(resource.backing().is::<ConfigResource>());
        assert_eq!(request.physical, resource.physical_span());
        Ok(owned::InstalledMapping {
            token: request.id,
            cpu_base: self.pointer(),
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(
        &self,
        request: owned::MapRequest,
        mapping: owned::InstalledMapping,
    ) -> core::result::Result<(), owned::Error> {
        assert_eq!(request.id, mapping.token);
        Ok(())
    }
}
fn native_power(net: &mut Aqtion<Rc<Peer>, Rc<Peer>>, peer: &Peer) -> Arc<NativePm> {
    let model = Arc::new(NativePm {
        page: Box::new(UnsafeCell::new(ConfigPage([0; 4096]))),
        mode: AtomicUsize::new(0),
        actual_state: AtomicUsize::new(0),
    });
    let address = net.function.as_ref().unwrap().address;
    let span = owned::PhysicalSpan::new(0x8010_0000, 4096).unwrap();
    let space = owned::AddressSpace {
        identity: 197,
        physical_bits: 48,
        virtual_bits: 48,
    };
    let authority =
        unsafe { owned::Authority::isolated_model(model.clone(), space, Vec::new()) }.unwrap();
    let mapping = authority
        .map(
            owned::Resource::new(Box::new(ConfigResource(span))),
            0,
            4096,
            owned::CacheAttribute::Uncached,
            owned::Protection::ReadWrite,
        )
        .unwrap();
    let window = crate::bus::pci::EcamWindow {
        base: 0x8000_0000,
        segment: 0,
        start_bus: 1,
        end_bus: 1,
    };
    let mut config = match unsafe { OwnedConfig::attach(address, window, mapping) } {
        Ok(config) => config,
        Err((error, _)) => panic!("native PM fixture: {error:?}"),
    };
    config.write32(0, (u32::from(net.profile.device) << 16) | 0x1d6a);
    config.write32(8, 0x02000000);
    config.write16(6, 1 << 4);
    config.write8(0x34, 0x40);
    config.write16(0x40, 1);
    config.write16(0x44, 0);
    net.function = Some(Function::new(address, config).unwrap());
    *peer.native_pm.borrow_mut() = Some(model.clone());
    model
}

#[test]
fn native_failed_d0_resume_is_retryable_and_never_uses_powered_off_mmio() {
    let (mut net, peer, domain, _) = setup(0x07b1);
    let pm = native_power(&mut net, &peer);
    net.start().unwrap();
    net.suspend().unwrap();
    let writes = peer.writes.borrow().len();
    let reads = peer.reads.borrow().len();
    pm.mode.store(1, Ordering::Relaxed);
    let clock = Clock {
        ticks_per_microsecond: 0,
    };
    assert!(net.resume_with_clock(&clock).is_err());
    assert_eq!(net.state(), State::Suspended);
    assert_eq!(net.power, PciPower::Unknown);
    assert_eq!(pm.actual_state.load(Ordering::Relaxed), 3);
    net.stop().unwrap();
    assert!(net.restart().is_err());
    assert_eq!(peer.writes.borrow().len(), writes);
    assert_eq!(peer.reads.borrow().len(), reads);
    pm.mode.store(0, Ordering::Relaxed);
    net.resume_with_clock(&clock).unwrap();
    assert_eq!(net.power, PciPower::D0);
    assert_eq!(net.state(), State::Running);
    assert_eq!(domain.engine_epoch.load(Ordering::Relaxed), 2);
    peer.set(0x370, 0x100);
    net.transmit(&[7; 60]).unwrap();
    net.retire().unwrap();
}

#[test]
fn native_d3_readback_loss_keeps_drained_retirement_and_d0_retry_safe() {
    for retire in [false, true] {
        let (mut net, peer, domain, dropped) = setup(0x04c0);
        let pm = native_power(&mut net, &peer);
        net.start().unwrap();
        pm.mode.store(2, Ordering::Relaxed);
        assert_eq!(net.suspend(), Err(Error::Removed));
        assert_eq!(net.power, PciPower::Unknown);
        assert_eq!(net.state(), State::Stopped);
        assert_eq!(pm.actual_state.load(Ordering::Relaxed), 3);
        let writes = peer.writes.borrow().len();
        let reads = peer.reads.borrow().len();
        net.stop().unwrap();
        assert!(net.restart().is_err());
        if retire {
            net.retire().unwrap();
            assert_eq!(dropped.load(Ordering::Relaxed), 4);
            assert!(domain.maps.lock().unwrap().is_empty());
        }
        assert_eq!(peer.writes.borrow().len(), writes);
        assert_eq!(peer.reads.borrow().len(), reads);
        if !retire {
            pm.mode.store(0, Ordering::Relaxed);
            // The native function answers config again, still actually D3hot.
            net.function.as_mut().unwrap().config().write16(0x44, 3);
            net.resume_with_clock(&Clock {
                ticks_per_microsecond: 0,
            })
            .unwrap();
            net.retire().unwrap();
        }
    }
}

#[test]
fn initial_native_d0_failure_retains_uninitialized_owner_without_mmio() {
    let (mut net, peer, _, dropped) = setup(0x07b1);
    let pm = native_power(&mut net, &peer);
    // Model attach before Memory allocation, using its actual power helper.
    net.memory = None;
    net.state = State::Faulted;
    net.function.as_mut().unwrap().config().write16(0x44, 3);
    pm.mode.store(1, Ordering::Relaxed);
    assert!(
        power_up(
            net.function.as_mut().unwrap(),
            &Clock {
                ticks_per_microsecond: 0
            },
            &mut net.power
        )
        .is_err()
    );
    assert_eq!(net.power, PciPower::Unknown);
    assert!(net.stop().is_err());
    assert!(net.restart().is_err());
    assert!(net.retire().is_err());
    assert!(peer.writes.borrow().is_empty());
    assert!(peer.reads.borrow().is_empty());
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
}

fn firmware4(peer: &Peer, flb: bool) {
    peer.set(0x18, 0x0401005a);
    peer.set(0x348, 1);
    peer.set(0x388, u32::from(!flb));
}
fn reset_releases(peer: &Peer) -> Vec<usize> {
    peer.writes
        .borrow()
        .iter()
        .filter_map(|&(register, value)| {
            (matches!(register, 0x3ac | 0x3b0) && value == 1).then_some(register)
        })
        .collect()
}
#[test]
fn reset_semaphores_are_read_to_acquire_and_write_to_release() {
    let (_, peer, _, _) = setup(0x07b1);
    assert_eq!(peer.read(0x3ac), Ok(1));
    assert_eq!(peer.read(0x3ac), Ok(0));
    peer.write(0x3ac, 1).unwrap();
    assert_eq!(peer.read(0x3ac), Ok(1));
}
#[test]
fn firmware4_second_lock_timeout_releases_only_the_acquired_first_lock_then_retries() {
    for flb in [false, true] {
        let (_, peer, _, _) = setup(0x07b1);
        let hw = hardware(&peer);
        firmware4(&peer, flb);
        peer.second_lock_busy.set(true);
        assert_eq!(
            hw.reset(peer.profile),
            Err(Error::Timeout { register: 0x3b0 })
        );
        assert_eq!(reset_releases(&peer), vec![0x3ac]);
        assert_eq!(peer.reset_count.get(), 0);
        peer.second_lock_busy.set(false);
        hw.reset(peer.profile).unwrap();
        assert_eq!(peer.reset_count.get(), if flb { 2 } else { 1 });
        // Successful reset consumed the locks; a new epoch can acquire again.
        hw.reset(peer.profile).unwrap();
        assert!(peer.semaphores.borrow().values().all(|held| !held));
    }
}
#[test]
fn firmware4_pre_reset_mmio_errors_release_both_locks_in_reverse_order() {
    for flb in [false, true] {
        for failed_read in [0x53c, 0] {
            let (_, peer, _, _) = setup(0x07b1);
            let hw = hardware(&peer);
            firmware4(&peer, flb);
            peer.fail_read.set(Some(failed_read));
            assert!(hw.reset(peer.profile).is_err());
            assert_eq!(peer.reset_count.get(), 0);
            assert_eq!(reset_releases(&peer), vec![0x3b0, 0x3ac]);
            peer.fail_read.set(None);
            hw.reset(peer.profile).unwrap();
        }
        let (_, peer, _, _) = setup(0x07b1);
        let hw = hardware(&peer);
        firmware4(&peer, flb);
        peer.fail_write.set(Some(0x404));
        assert!(hw.reset(peer.profile).is_err());
        assert_eq!(reset_releases(&peer), vec![0x3b0, 0x3ac]);
        peer.fail_write.set(None);
        hw.reset(peer.profile).unwrap();
    }
}
#[test]
fn firmware4_uncertain_semaphore_release_or_acquire_blocks_reacquisition() {
    for (failed_release, reached_device) in
        [(0x3ac, false), (0x3b0, false), (0x3ac, true), (0x3b0, true)]
    {
        let (_, peer, _, _) = setup(0x07b1);
        let hw = hardware(&peer);
        firmware4(&peer, false);
        peer.fail_read.set(Some(0x53c));
        peer.fail_write.set(Some(failed_release));
        peer.failed_release_reached_device.set(reached_device);
        assert!(hw.reset(peer.profile).is_err());
        assert_eq!(reset_releases(&peer), vec![0x3b0, 0x3ac]);
        assert_eq!(
            peer.semaphores.borrow().get(&failed_release),
            Some(&!reached_device)
        );
        // A different owner can acquire after a release whose response failed.
        peer.semaphores.borrow_mut().insert(failed_release, true);
        peer.fail_read.set(None);
        peer.fail_write.set(None);
        let reads = peer.reads.borrow().len();
        let writes = peer.writes.borrow().len();
        assert!(hw.reset(peer.profile).is_err());
        assert_eq!(peer.reads.borrow().len(), reads);
        assert_eq!(peer.writes.borrow().len(), writes);
    }
    for failed_acquire in [0x3ac, 0x3b0] {
        for reached_device in [false, true] {
            let (_, peer, _, _) = setup(0x07b1);
            let hw = hardware(&peer);
            firmware4(&peer, false);
            peer.fail_read.set(Some(failed_acquire));
            peer.failed_acquire_reached_device.set(reached_device);
            assert!(hw.reset(peer.profile).is_err());
            assert_eq!(
                reset_releases(&peer),
                if failed_acquire == 0x3b0 {
                    vec![0x3ac]
                } else {
                    vec![]
                }
            );
            assert_eq!(
                peer.semaphores
                    .borrow()
                    .get(&failed_acquire)
                    .copied()
                    .unwrap_or(false),
                reached_device
            );
            peer.fail_read.set(None);
            let reads = peer.reads.borrow().len();
            let writes = peer.writes.borrow().len();
            assert!(hw.reset(peer.profile).is_err());
            assert_eq!(peer.reads.borrow().len(), reads);
            assert_eq!(peer.writes.borrow().len(), writes);
        }
    }
}
#[test]
fn firmware4_reset_store_uncertainty_and_flb_post_first_reset_abort_keep_ownership() {
    for flb in [false, true] {
        let (_, peer, _, _) = setup(0x07b1);
        let hw = hardware(&peer);
        firmware4(&peer, flb);
        peer.fail_write.set(Some(0));
        assert!(hw.reset(peer.profile).is_err());
        assert!(reset_releases(&peer).is_empty());
        peer.fail_write.set(None);
        assert!(hw.reset(peer.profile).is_err());
    }
    let (_, peer, _, _) = setup(0x07b1);
    let hw = hardware(&peer);
    firmware4(&peer, true);
    peer.fail_write.set(Some(0x520));
    assert!(hw.reset(peer.profile).is_err());
    assert_eq!(peer.reset_count.get(), 1);
    assert!(reset_releases(&peer).is_empty());
    peer.fail_write.set(None);
    assert!(hw.reset(peer.profile).is_err());
    assert_eq!(peer.reset_count.get(), 1);
}
#[test]
fn restart_after_delayed_traffic_drains_each_epoch_and_rebuilds_device_heads() {
    for id in [0x07b1, 0x04c0] {
        let (mut net, peer, domain, dropped) = setup(id);
        net.start().unwrap();
        if peer.profile.generation == Generation::Atlantic {
            peer.set(0x370, 0x100);
        } else {
            peer.set(0x13014, 0x830);
        }
        net.transmit(&[3; 60]).unwrap();
        peer.receive(&[5; 60], 0, 3, 60);
        assert_eq!(net.receive().unwrap(), Some(vec![5; 60]));
        peer.tx_delay.set(true);
        domain.defer_writebacks.store(true, Ordering::Relaxed);
        net.transmit(&[7; 60]).unwrap();
        assert_eq!(peer.pending_tx.get(), Some(2));
        assert!(domain.pending_dma.load(Ordering::Relaxed) > 0);
        net.restart().unwrap();
        assert!(peer.pending_tx.get().is_none());
        assert_eq!(peer.tx_head.get(), 0);
        assert_eq!(peer.rx_head.get(), 0);
        assert_eq!(domain.pending_dma.load(Ordering::Relaxed), 0);
        assert_eq!(domain.engine_epoch.load(Ordering::Relaxed), 2);
        assert_eq!(domain.drained_epoch.load(Ordering::Relaxed), 1);
        peer.tx_delay.set(false);
        domain.defer_writebacks.store(false, Ordering::Relaxed);
        assert!(domain.posted.lock().unwrap().is_empty());
        net.transmit(&[9; 60]).unwrap();
        peer.receive(&[11; 60], 0, 3, 60);
        assert_eq!(net.receive().unwrap(), Some(vec![11; 60]));
        net.retire().unwrap();
        assert_eq!(domain.drained_epoch.load(Ordering::Relaxed), 2);
        assert_eq!(domain.pending_dma.load(Ordering::Relaxed), 0);
        assert_eq!(dropped.load(Ordering::Relaxed), 4);
        assert_eq!(
            peer.sent.borrow().as_slice(),
            &[vec![3; 60], vec![7; 60], vec![9; 60]]
        );
    }
}
#[test]
fn delayed_firmware_ack_is_required_before_link_shutdown_finishes() {
    for id in [0x07b1, 0x04c0] {
        let (mut net, peer, _, _) = setup(id);
        net.start().unwrap();
        peer.ack_delay.set(500);
        let before = peer.elapsed.get();
        net.stop().unwrap();
        assert!(peer.elapsed.get() >= before + 500);
        assert!(peer.pending_ack.borrow().is_empty());
        net.retire().unwrap();
    }
}
#[test]
#[should_panic(expected = "historical drain cannot release a newer engine epoch")]
fn model_rejects_historical_drain_after_a_new_engine_epoch() {
    let (mut net, _, _, _) = setup(0x07b1);
    net.start().unwrap();
    net.stop().unwrap();
    net.start().unwrap();
    net.hw().stop_queues().unwrap();
    // Deliberately omit this epoch's domain drain, bypassing the owner.
    net.memory.as_mut().unwrap().retire().unwrap();
}
fn omit_visibility_before_tx(payload: bool) {
    let (mut net, peer, domain, _) = setup(0x07b1);
    net.start().unwrap();
    net.memory.as_mut().unwrap().transmit(0, &[7; 60]).unwrap();
    let descriptor = peer.address(0x7c00);
    let address = if payload {
        // Inspect native fixture storage without performing a modeled DMA read.
        unsafe {
            domain
                .raw(descriptor, 8)
                .as_ptr()
                .cast::<u64>()
                .read_volatile()
        }
    } else {
        descriptor
    };
    domain.published.lock().unwrap().remove(&address);
    peer.write(0x7c10, 1).unwrap();
}
#[test]
#[should_panic(expected = "DMA without fresh visibility")]
fn model_rejects_tx_descriptor_dma_without_visibility() {
    omit_visibility_before_tx(false);
}
#[test]
#[should_panic(expected = "DMA without fresh visibility")]
fn model_rejects_tx_payload_dma_without_visibility() {
    omit_visibility_before_tx(true);
}

#[test]
fn delayed_rx_writeback_is_invisible_until_completion_and_stop_drains_pending_writes() {
    let (mut net, peer, domain, dropped) = setup(0x07b1);
    net.start().unwrap();
    peer.set(0x370, 0x100);
    domain.defer_writebacks.store(true, Ordering::Relaxed);
    peer.receive(&[13; 60], 0, 3, 60);
    assert_eq!(net.receive().unwrap(), None);
    assert!(!domain.posted.lock().unwrap().is_empty());
    domain.complete_posted();
    assert_eq!(net.receive().unwrap(), Some(vec![13; 60]));
    peer.receive(&[17; 60], 0, 3, 60);
    domain.fail_drain.store(true, Ordering::Relaxed);
    assert_eq!(net.retire(), Err(Error::Dma(DmaError::DrainUnavailable)));
    assert!(!domain.posted.lock().unwrap().is_empty());
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    domain.fail_drain.store(false, Ordering::Relaxed);
    net.retire().unwrap();
    assert!(domain.posted.lock().unwrap().is_empty());
    assert_eq!(dropped.load(Ordering::Relaxed), 4);
}

#[test]
fn firmware4_first_lock_timeout_does_not_release_another_owner() {
    let (_, peer, _, _) = setup(0x07b1);
    let hw = hardware(&peer);
    firmware4(&peer, false);
    peer.semaphores.borrow_mut().insert(0x3ac, true);
    assert_eq!(
        hw.reset(peer.profile),
        Err(Error::Timeout { register: 0x3ac })
    );
    assert!(reset_releases(&peer).is_empty());
    assert_eq!(peer.semaphores.borrow().get(&0x3ac), Some(&true));
    assert_eq!(peer.reset_count.get(), 0);
}

#[test]
fn native_refused_d3_requires_fresh_d0_acknowledgement_before_restart() {
    let (mut net, peer, _, _) = setup(0x07b1);
    let pm = native_power(&mut net, &peer);
    net.start().unwrap();
    pm.mode.store(3, Ordering::Relaxed);
    assert_eq!(
        net.suspend(),
        Err(Error::Readback {
            register: 0x44,
            observed: 0
        })
    );
    assert_eq!(net.state(), State::Stopped);
    assert_eq!(net.power, PciPower::Unknown);
    let writes = peer.writes.borrow().len();
    assert!(net.restart().is_err());
    assert_eq!(peer.writes.borrow().len(), writes);
    pm.mode.store(0, Ordering::Relaxed);
    net.resume_with_clock(&Clock {
        ticks_per_microsecond: 0,
    })
    .unwrap();
    assert_eq!(net.power, PciPower::D0);
    net.retire().unwrap();
}
