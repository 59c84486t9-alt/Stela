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
    cell::{Cell, RefCell},
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
    fn read32(&self, address: u64) -> u32 {
        unsafe { self.raw(address, 4).as_ptr().cast::<u32>().read_volatile() }
    }
    fn read64(&self, address: u64) -> u64 {
        unsafe { self.raw(address, 8).as_ptr().cast::<u64>().read_volatile() }
    }
    fn put32(&self, address: u64, value: u32) {
        unsafe {
            self.raw(address, 4)
                .as_ptr()
                .cast::<u32>()
                .write_volatile(value)
        }
    }
    fn packet(&self, address: u64, length: usize) -> Vec<u8> {
        (0..length)
            .map(|n| unsafe { self.raw(address + n as u64, 1).as_ptr().read_volatile() })
            .collect()
    }
    fn put_packet(&self, address: u64, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            unsafe { self.raw(address + i as u64, 1).as_ptr().write_volatile(*b) }
        }
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
        assert!(
            self.drain_count.load(Ordering::Relaxed) > 0,
            "mapped storage released before real modeled drain"
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
        Ok(self.read32(m.address + offset as u64))
    }
    unsafe fn drain_posted_writes(&self) -> core::result::Result<(), DmaError> {
        if self.fail_drain.load(Ordering::Relaxed) {
            return Err(DmaError::DrainUnavailable);
        }
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
            head = (head + 1) % 64;
        }
        self.tx_head.set(head);
        self.set(0x7c0c, head as u32);
    }
    fn receive(&self, bytes: &[u8], kind: u32, status: u16, length: u16) {
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
    }
}
// SAFETY: stateful, independent symbolic register peer; all operations are
// synchronous and cannot name or access any physical device.
unsafe impl Registers for Rc<Peer> {
    fn read(&self, offset: usize) -> Result<u32> {
        if self.fault.get() == Fault::Removed {
            return Ok(u32::MAX);
        }
        if matches!(offset, 0x3a8 | 0x3ac | 0x3b0) {
            return Ok(if self.fault.get() == Fault::RamSemaphore {
                0
            } else {
                1
            });
        }
        if offset == 0x13000 && self.fault.get() == Fault::Snapshot {
            return Ok(0x20001);
        }
        Ok(self.get(offset))
    }
    fn write(&self, offset: usize, value: u32) -> Result<()> {
        self.writes.borrow_mut().push((offset, value));
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
            self.set(0x374, value);
        }
        if offset == 0xe00 {
            self.set(
                0xe04,
                if self.fault.get() == Fault::FirmwareAck {
                    1
                } else {
                    0
                },
            );
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
        self.set(offset, value);
        if offset == 0x7c10 && value as usize != self.tx_head.get() {
            self.transmit(value as usize);
        }
        Ok(())
    }
}
impl Timer for Rc<Peer> {
    fn delay(&self, us: u64) {
        self.elapsed.set(self.elapsed.get() + us);
    }
}
fn hardware(peer: &Rc<Peer>) -> Hardware<Rc<Peer>, Rc<Peer>> {
    Hardware {
        registers: peer.clone(),
        timer: peer.clone(),
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
