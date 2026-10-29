// SPDX-License-Identifier: MIT
//! Independent literal wire/device model. Device accesses resolve domain IOVAs
//! to kept CPU mappings; model physical pages and CPU pointers are above
//! 4GiB and are never used as the source's 32-bit DMA addresses.
extern crate std;
mod native;
use super::*;
use crate::bus::{
    dma::{
        mapping::{Direction, DmaDomain, DomainMapping},
        memory::{CacheAttribute, CpuMapping, PageBacking, PinnedPages},
    },
    pci::Address,
};
use crate::firmware::{Catalog, Provenance, Resource};
use alloc::{collections::BTreeMap, sync::Arc, vec};
use core::{alloc::Layout, ops::Range, ptr::NonNull};
use sha2::{Digest, Sha256};
use std::{
    alloc::{alloc_zeroed, dealloc},
    sync::Mutex,
};

struct Pages {
    pointer: NonNull<u8>,
    layout: Layout,
    physical: Vec<u64>,
}
// SAFETY: single-threaded coherent model access is serialized through Model's
// mutex. This owner keeps the aligned allocation until its last pin.
unsafe impl Send for Pages {}
// SAFETY: shared references rely on the same argument as `Send` above.
unsafe impl Sync for Pages {}
// SAFETY: `cpu_base` and `physical` describe the one kept, aligned test allocation for its
// whole life.
unsafe impl PageBacking for Pages {
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
impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: original unique allocation, all kept pins ended.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}
struct Lease {
    token: DomainMapping,
    cpu: CpuMapping,
    used: bool,
}
struct DomainState {
    next: u64,
    leases: BTreeMap<u64, Lease>,
    stopped: bool,
    unmaps: usize,
    syncs: usize,
    fail_sync: Option<usize>,
    fail_unmap: bool,
    delay_sync: Option<usize>,
    sync_delay_us: u64,
    elapsed_us: u64,
}
struct Domain(Mutex<DomainState>);
impl Domain {
    fn new() -> Self {
        Self(Mutex::new(DomainState {
            next: 0x10000,
            leases: BTreeMap::new(),
            stopped: false,
            unmaps: 0,
            syncs: 0,
            fail_sync: None,
            fail_unmap: false,
            delay_sync: None,
            sync_delay_us: 121_000_000,
            elapsed_us: 0,
        }))
    }
    fn read(&self, address: u64, bytes: usize) -> Vec<u8> {
        let mut state = self.0.lock().unwrap();
        assert!(!state.stopped, "device DMA after independent root stop");
        let lease = state
            .leases
            .values_mut()
            .find(|lease| {
                address >= lease.token.address
                    && address
                        .checked_add(bytes as u64)
                        .is_some_and(|end| end <= lease.token.address + lease.token.bytes as u64)
            })
            .expect("device resolves actual mapped IOVA");
        lease.used = true;
        let pointer = lease
            .cpu
            .address((address - lease.token.address) as usize, bytes)
            .unwrap();
        (0..bytes)
            .map(|at| {
                // SAFETY: model mapping bounds checked; serialized DMA.
                unsafe { pointer.as_ptr().add(at).read_volatile() }
            })
            .collect()
    }
    fn write(&self, address: u64, bytes: &[u8]) {
        let mut state = self.0.lock().unwrap();
        assert!(!state.stopped);
        let lease = state
            .leases
            .values_mut()
            .find(|lease| {
                address >= lease.token.address
                    && address
                        .checked_add(bytes.len() as u64)
                        .is_some_and(|end| end <= lease.token.address + lease.token.bytes as u64)
            })
            .expect("device write resolves actual mapped IOVA");
        lease.used = true;
        let pointer = lease
            .cpu
            .address((address - lease.token.address) as usize, bytes.len())
            .unwrap();
        for (at, byte) in bytes.iter().enumerate() {
            // SAFETY: checked mapping, serialized device write.
            unsafe { pointer.as_ptr().add(at).write_volatile(*byte) };
        }
    }
    fn word(&self, address: u64) -> u16 {
        u16::from_le_bytes(self.read(address, 2).try_into().unwrap())
    }
    fn set_word(&self, address: u64, value: u16) {
        self.write(address, &value.to_le_bytes());
    }
}
// SAFETY: explicit coherent device model, keeps supplied pins/CPU mapping,
// checks low IOVA extent and never releases used ranges before root stop.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &crate::bus::dma::pages::DmaPages,
        direction: Direction,
        limit: u64,
    ) -> core::result::Result<DomainMapping, DmaError> {
        // This coherent CPU-view model admits one kept
        // allocation; scatter mappings have no invented contiguous view.
        let pages = pages.as_single().ok_or(DmaError::MappingFailed)?;
        assert_eq!(direction, Direction::Bidirectional);
        assert!(pages.physical_pages()[0] >= 0x1_0000_0000);
        assert!(
            (pages
                .cpu_mapping(CacheAttribute::WriteBack)
                .unwrap()
                .address(0, 1)
                .unwrap()
                .as_ptr() as u64)
                > 0xffff_ffff
        );
        let mut state = self.0.lock().unwrap();
        let address = state.next;
        assert!(address + pages.bytes() as u64 - 1 <= limit);
        state.next += pages.bytes() as u64;
        let token = DomainMapping {
            id: address,
            address,
            bytes: pages.bytes(),
        };
        state.leases.insert(
            address,
            Lease {
                token,
                cpu: pages.cpu_mapping(CacheAttribute::WriteBack).unwrap(),
                used: false,
            },
        );
        Ok(token)
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> core::result::Result<(), DmaError> {
        let mut state = self.0.lock().unwrap();
        assert!(
            state.stopped || !state.leases[&mapping.id].used,
            "ring ACK is not root retirement"
        );
        state.unmaps += 1;
        if state.fail_unmap {
            return Err(DmaError::InvalidationFailed);
        }
        assert_eq!(state.leases.remove(&mapping.id).unwrap().token, mapping);
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> core::result::Result<(), DmaError> {
        let mut state = self.0.lock().unwrap();
        assert_eq!(direction, Direction::Bidirectional);
        assert!(range.end <= state.leases[&mapping.id].token.bytes);
        state.syncs += 1;
        if state.delay_sync == Some(state.syncs) {
            let delay = state.sync_delay_us;
            state.elapsed_us += delay;
        }
        if state.fail_sync == Some(state.syncs) {
            return Err(DmaError::VisibilityFailed);
        }
        Ok(())
    }
    unsafe fn sync_for_cpu(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> core::result::Result<(), DmaError> {
        panic!(
            "continuously device-owned coherent producer index cannot use completed-range CPU handoff"
        );
    }
}
struct Allocator {
    domain: Arc<Domain>,
    physical: u64,
}
// SAFETY: independent coherent model uses unique zeroed CPU pages,
// separately modeled high physical pages and low IOVAs in one domain.
unsafe impl CoherentAllocator for Allocator {
    fn allocate(&mut self, bytes: usize) -> Result<CoherentBuffer> {
        let reserved = bytes.next_multiple_of(4096);
        let layout = Layout::from_size_align(reserved, 4096).unwrap();
        // SAFETY: valid layout; PageBacking owns the result until final unpin.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        let physical = (0..reserved / 4096)
            .map(|n| self.physical + n as u64 * 4096)
            .collect();
        self.physical += reserved as u64;
        let pages = PinnedPages::new(
            Box::new(Pages {
                pointer,
                layout,
                physical,
            }),
            bytes,
            4096,
        )
        .unwrap();
        // SAFETY: model coherency and same domain described above.
        unsafe { CoherentBuffer::map(pages, self.domain.clone()) }
    }
}
#[derive(Clone, Copy, Default)]
struct Ring {
    address: u64,
    count: u16,
    footer: usize,
    completion: u16,
    enabled: bool,
}
struct Device {
    domain: Arc<Domain>,
    pci: PciIdentity,
    otp: [u8; 224],
    registers: BTreeMap<(u8, u32), u32>,
    ticks: u64,
    operations: usize,
    fail_operation: Option<usize>,
    writes: usize,
    prepare: usize,
    armed: bool,
    msi: usize,
    retire: usize,
    fail_retire: bool,
    dropped: bool,
    boot: u32,
    rti: u32,
    context: u64,
    heads: u64,
    tails: u64,
    txheads: u64,
    txtails: u64,
    tx: [Ring; 7],
    cr: [Ring; 5],
    controls: Vec<Vec<u8>>,
    sent: Vec<(usize, Vec<u8>, u16)>,
    doorbells: Vec<u32>,
    delay_offset: Option<(u32, u64)>,
    read_delay: Option<(Space, u32, u64)>,
    arm_delay: u64,
    boot_reply: u32,
    rti_reply: Option<u32>,
    consume_tx: bool,
    acknowledge: bool,
    source_image: Vec<u8>,
    properties: BTreeMap<&'static str, Vec<u8>>,
    property_requests: Vec<&'static str>,
    setup: Option<Setup>,
}
fn u16at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn u64at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn field16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn field32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn field64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HciFault {
    None,
    Preexisting,
    LateSleep,
    StatusThenComplete(usize),
    AckOnly(usize),
    StatusOnly(usize),
    Reject(usize, u8),
    WrongOpcode(usize),
    Duplicate(usize),
    MalformedAfter(usize),
    Late(usize),
    SilentCredits(usize),
    ZeroCredits(usize),
    ReadLength,
    IgnoreAddressWrite,
    InvalidReadback,
}
struct Setup {
    expected: Vec<Vec<u8>>,
    index: usize,
    fault: HciFault,
    address: [u8; 6],
    pending_credit_reads: usize,
}
impl Device {
    fn credit_tick(&mut self) {
        let setup = self.setup.as_mut().unwrap();
        if setup.pending_credit_reads != 0 {
            setup.pending_credit_reads -= 1;
            if setup.pending_credit_reads == 0 {
                self.completion(2, 2, 0xfacd, 0x82, &[0x0e, 3, 1, 0, 0], false);
            }
        }
    }
    fn setup_command(&mut self, packet: Vec<u8>) {
        let setup = self.setup.as_mut().unwrap();
        let index = setup.index;
        assert_eq!(
            packet, setup.expected[index],
            "independent native HCI packet{index}"
        );
        setup.index += 1;
        let opcode = u16at(&packet, 0);
        if setup.fault == HciFault::AckOnly(index) {
            return;
        }
        let mut response_opcode = opcode;
        let mut returned = vec![0];
        if let HciFault::Reject(at, status) = setup.fault
            && at == index
        {
            returned[0] = status;
        }
        if setup.fault == HciFault::WrongOpcode(index) {
            response_opcode ^= 1;
        }
        if opcode == 0xfc01 && setup.fault != HciFault::IgnoreAddressWrite {
            setup.address.copy_from_slice(&packet[3..]);
            if setup.fault == HciFault::InvalidReadback {
                setup.address[3] ^= 0x55;
            }
        }
        if opcode == 0x1009 {
            returned.extend_from_slice(&setup.address);
            if setup.fault == HciFault::ReadLength {
                returned.pop();
            }
        }
        let credits = if matches!(setup.fault,HciFault::SilentCredits(at)|HciFault::ZeroCredits(at) if at==index)
        {
            0
        } else {
            1
        };
        if setup.fault == HciFault::ZeroCredits(index) {
            setup.pending_credit_reads = 12;
        }
        let fault = setup.fault;
        let mut event = vec![0x0e, (3 + returned.len()) as u8, credits];
        event.extend_from_slice(&response_opcode.to_le_bytes());
        event.extend_from_slice(&returned);
        if fault == HciFault::StatusOnly(index) {
            event = vec![0x0f, 4, 0, credits, opcode as u8, (opcode >> 8) as u8];
        }
        // Keep unrelated real async traffic and all source footer padding.
        self.completion(2, 2, 0xffff, 0x82, &[0xff, 2, 0xa1, index as u8], false);
        if fault == HciFault::StatusThenComplete(index) {
            self.completion(
                2,
                2,
                0xabcc,
                0x82,
                &[0x0f, 4, 0, credits, opcode as u8, (opcode >> 8) as u8],
                false,
            );
        }
        self.completion(2, 2, 0xabcd, 0x42, &event, false);
        if fault == HciFault::Duplicate(index) {
            self.completion(2, 2, 0xabce, 0x82, &event, false);
        }
        if fault == HciFault::MalformedAfter(index) {
            self.completion(2, 2, 0xabcf, 0x82, &[0xff, 7, 0x99], false);
        }
        if fault == HciFault::Late(index) {
            self.ticks += 10_100_000;
        }
    }
}
impl Device {
    fn register(&self, space: u8, offset: u32) -> u32 {
        self.registers.get(&(space, offset)).copied().unwrap_or(0)
    }
    fn address(&self, low: u32, high: u32) -> u64 {
        u64::from(self.register(2, low)) | u64::from(self.register(2, high)) << 32
    }
    fn completion(
        &mut self,
        ring: usize,
        transfer: u16,
        message: u16,
        flags: u8,
        bytes: &[u8],
        mapped: bool,
    ) -> [u8; 16] {
        let cr = self.cr[ring];
        assert!(cr.enabled);
        let head = self.domain.word(self.heads + ring as u64 * 2);
        let tail = self.domain.word(self.tails + ring as u64 * 2);
        assert_ne!(
            (head + 1) % cr.count,
            tail,
            "model does not overrun a live completion ring"
        );
        let mut entry = [0x6b; 16];
        entry[0] = flags;
        field16(&mut entry, 2, transfer);
        field16(&mut entry, 4, message);
        field32(&mut entry, 6, bytes.len() as u32);
        let address = cr.address + u64::from(head) * (16 + cr.footer) as u64;
        self.domain.write(address, &entry);
        if mapped {
            assert_eq!(transfer, 6);
            let desc = self
                .domain
                .read(self.tx[6].address + u64::from(message & 0xff) * 16, 16);
            assert_eq!(desc[0], 1);
            assert_eq!(u16at(&desc, 1), 1032);
            assert_eq!(u16at(&desc, 12), message);
            self.domain.write(u64at(&desc, 4), bytes);
        } else if !bytes.is_empty() {
            assert!(bytes.len() <= cr.footer);
            let mut footer = vec![0xdd; cr.footer];
            footer[..bytes.len()].copy_from_slice(bytes);
            self.domain.write(address + 16, &footer);
        }
        self.domain
            .set_word(self.heads + ring as u64 * 2, (head + 1) % cr.count);
        self.msi += 1;
        entry
    }
    fn parse_context(&mut self) {
        self.context = self.address(0x20048c, 0x200450);
        let bytes = self.domain.read(self.context, 104);
        let mut expected = [0; 104];
        field16(&mut expected, 0, 1);
        field16(&mut expected, 2, 104);
        field32(&mut expected, 4, 2);
        for at in [8, 16, 24, 32, 40, 52, 60] {
            field64(&mut expected, at, u64at(&bytes, at));
            assert!(u64at(&bytes, at) < 0xffff_fe00);
        }
        field16(&mut expected, 48, 6);
        field16(&mut expected, 50, 9);
        field16(&mut expected, 68, 128);
        field16(&mut expected, 70, 32);
        field16(&mut expected, 74, 0xffff);
        expected[81] = 13;
        assert_eq!(
            bytes, expected,
            "literal source context initializer, including version1 vs prose2"
        );
        self.heads = u64at(&bytes, 16);
        self.txtails = u64at(&bytes, 24);
        self.tails = u64at(&bytes, 32);
        self.txheads = u64at(&bytes, 40);
        for (address, count) in [
            (self.heads, 6),
            (self.tails, 6),
            (self.txheads, 9),
            (self.txtails, 9),
        ] {
            assert_eq!(self.domain.read(address, count * 2), vec![0; count * 2]);
        }
        self.domain.write(u64at(&bytes, 8), &[0x3a; 32]);
        self.cr[0] = Ring {
            address: u64at(&bytes, 52),
            count: 32,
            enabled: true,
            ..Ring::default()
        };
        self.tx[0] = Ring {
            address: u64at(&bytes, 60),
            count: 128,
            footer: 52,
            enabled: true,
            ..Ring::default()
        };
    }
    fn control(&mut self, bytes: Vec<u8>) {
        assert_eq!(bytes.len(), 52);
        let mut expected = vec![0; 52];
        expected[0] = bytes[0];
        let id = usize::from(u16at(&bytes, if bytes[0] <= 2 { 4 } else { 2 }));
        match bytes[0] {
            2 => {
                let (count, footer, delay) = match id {
                    1 => (256, 0, 1000),
                    2 => (256, 264, 1000),
                    3 => (128, 0, 0),
                    4 => (128, 260, 0),
                    _ => panic!("source completion id"),
                };
                expected[2] = (footer / 4) as u8;
                field16(&mut expected, 4, id as u16);
                field16(&mut expected, 6, id as u16);
                field64(&mut expected, 8, u64at(&bytes, 8));
                field16(&mut expected, 16, count);
                field32(&mut expected, 18, u32::MAX);
                field16(&mut expected, 30, delay);
                field32(&mut expected, 32, u32::MAX);
                self.cr[id] = Ring {
                    address: u64at(&bytes, 8),
                    count,
                    footer,
                    enabled: true,
                    ..Ring::default()
                };
            }
            1 => {
                let (footer, completion, db, flags) = match id {
                    1 => (264, 1, 1, 0),
                    2 => (0, 2, 2, 0x80),
                    3 => (260, 3, 6, 0x100),
                    4 => (0, 4, 6, 0x180),
                    5 => (0, 1, 3, 0),
                    6 => (0, 2, 4, 0),
                    _ => panic!("source transfer id"),
                };
                expected[2] = (footer / 4) as u8;
                field16(&mut expected, 4, id as u16);
                field16(&mut expected, 6, id as u16);
                field64(&mut expected, 8, u64at(&bytes, 8));
                field16(&mut expected, 24, 128);
                field16(&mut expected, 26, completion);
                field16(&mut expected, 28, db);
                field16(&mut expected, 30, flags);
                assert_eq!(u64at(&bytes, 8) == 0, matches!(id, 2 | 4));
                self.tx[id] = Ring {
                    address: u64at(&bytes, 8),
                    count: 128,
                    footer,
                    completion,
                    enabled: true,
                };
            }
            3 => {
                field16(&mut expected, 2, id as u16);
                assert!(self.tx[id].enabled);
                self.tx[id].enabled = false;
            }
            4 => {
                field16(&mut expected, 2, id as u16);
                assert!(self.cr[id].enabled);
                self.cr[id].enabled = false;
            }
            _ => panic!("source control message"),
        }
        assert_eq!(
            bytes, expected,
            "all source control fields and reserved bytes"
        );
        if bytes[0] == 1
            && id == 6
            && self
                .setup
                .as_ref()
                .is_some_and(|s| s.fault == HciFault::Preexisting)
        {
            self.completion(2, 2, 0xfacd, 0x82, &[0x0e, 4, 1, 0x97, 0xfd, 0], false);
        }
        self.controls.push(bytes);
    }
    fn consume(&mut self, id: usize) {
        if !self.tx[id].enabled || (!self.consume_tx && id != 0) {
            return;
        }
        let ring = self.tx[id];
        let head = self.domain.word(self.txheads + id as u64 * 2);
        let mut tail = self.domain.word(self.txtails + id as u64 * 2);
        while tail != head {
            let at = ring.address + u64::from(tail) * (16 + ring.footer) as u64;
            let desc = self.domain.read(at, 16);
            let len = usize::from(u16at(&desc, 1));
            assert_eq!(desc[3], 0);
            assert_eq!(&desc[14..], &[0, 0]);
            let bytes = match desc[0] {
                2 => {
                    assert!(len <= ring.footer);
                    assert_eq!(u64at(&desc, 4), 0);
                    self.domain.read(at + 16, len)
                }
                1 => {
                    assert!(matches!(id, 5));
                    assert!(len <= 1032);
                    self.domain.read(u64at(&desc, 4), len)
                }
                _ => panic!("source descriptor flags"),
            };
            let raw = u16at(&desc, 12);
            assert_eq!(raw >> 8, u16::from(id != 0));
            assert!(raw & 0xff < 128);
            if id == 0 {
                self.control(bytes);
            } else {
                self.sent.push((id, bytes.clone(), raw));
                if id == 1 && self.setup.is_some() {
                    self.setup_command(bytes);
                }
            }
            tail = (tail + 1) % ring.count;
            self.domain.set_word(self.txtails + id as u64 * 2, tail);
            if self.acknowledge || id == 0 {
                self.completion(usize::from(ring.completion), id as u16, raw, 0, &[], false);
            }
        }
    }
    fn operation(&mut self, space: Space, offset: u32) -> Result<()> {
        self.operations += 1;
        if self.fail_operation == Some(self.operations) {
            return Err(Error::Io {
                space,
                offset,
                raw: self.operations as u64,
            });
        }
        Ok(())
    }
}
struct Model(Arc<Mutex<Device>>);
impl Drop for Model {
    fn drop(&mut self) {
        self.0.lock().unwrap().dropped = true;
    }
}
// SAFETY: explicitly bounded device model; real native resources are not claimed.
// The independent root-stop flag controls all domain release and late DMA.
unsafe impl Platform for Model {
    fn identity(&self) -> PciIdentity {
        self.0.lock().unwrap().pci
    }
    fn board(&self) -> Board {
        Board::from_property(b"apple,formosa\0").unwrap()
    }
    fn property(&self, name: &'static str) -> Result<Option<Vec<u8>>> {
        let mut d = self.0.lock().unwrap();
        d.property_requests.push(name);
        Ok(d.properties.get(name).cloned())
    }
    fn prepare(&mut self, _: Chip) -> Result<()> {
        let mut d = self.0.lock().unwrap();
        d.prepare += 1;
        d.ticks += 100_000;
        d.operation(Space::Configuration, 0xffff)
    }
    fn read32(&mut self, space: Space, offset: u32) -> Result<u32> {
        let mut d = self.0.lock().unwrap();
        if d.rti == 2 && d.tx[3].enabled && !d.domain.0.lock().unwrap().stopped {
            d.consume(3);
        }
        if d.setup.is_some() {
            d.credit_tick();
        }
        let original = offset;
        let offset = if space == Space::Bar2 && d.pci.device == 0x5f72 {
            offset.checked_sub(0x200000).unwrap()
        } else {
            offset
        };
        let value = match (space, offset) {
            (Space::Bar2, 0x200454) => d.boot,
            (Space::Bar2, 0x20045c) => d.rti,
            _ => d.register(key(space), offset),
        };
        if let Some((at_space, at, delay)) = d.read_delay
            && at_space == space
            && at == original
        {
            d.ticks += delay;
        }
        d.operation(space, original)?;
        Ok(value)
    }
    fn read8(&mut self, space: Space, offset: u32) -> Result<u8> {
        let mut d = self.0.lock().unwrap();
        assert_eq!(space, Space::Bar0);
        let base = match d.pci.device {
            0x5fa0 | 0x5f69 => 0x4120,
            0x5f71 => 0x413c,
            0x5f72 => 0x415c,
            _ => unreachable!(),
        };
        let byte = d.otp[(offset - base) as usize];
        if let Some((at_space, at, delay)) = d.read_delay
            && at_space == space
            && at == offset
        {
            d.ticks += delay;
        }
        d.operation(space, offset)?;
        Ok(byte)
    }
    fn write32(&mut self, space: Space, offset: u32, value: u32) -> Result<()> {
        let mut d = self.0.lock().unwrap();
        assert!(
            !d.domain.0.lock().unwrap().stopped,
            "no writes after retirement"
        );
        d.writes += 1;
        let original = offset;
        let offset = if space == Space::Bar2 && d.pci.device == 0x5f72 {
            offset.checked_sub(0x200000).unwrap()
        } else {
            offset
        };
        d.registers.insert((key(space), offset), value);
        if let Some((at, delay)) = d.delay_offset
            && original == at
        {
            d.ticks += delay;
        }
        match (space, offset) {
            (Space::Bar0, 0x150)
                if d.setup
                    .as_ref()
                    .is_some_and(|s| s.fault == HciFault::LateSleep)
                    && d.tx[1].enabled =>
            {
                // Observe the newly written descriptor. Startup's
                // control-ring wakeups leave the HCI descriptor empty.
                let descriptor = d.domain.read(d.tx[1].address, 3);
                if u16at(&descriptor, 1) != 0 {
                    d.ticks += 11_000_000;
                }
            }
            (Space::Bar0, 0x140) => {
                assert!(d.armed);
                assert_eq!(value, 0);
                assert_eq!(d.register(0, 0x590), 0);
                assert_eq!(d.register(0, 0x594), 0);
                assert_eq!(d.register(0, 0x598), 0xffff_fe00);
                let fw = d.domain.read(
                    d.address(0x200478, 0x20047c),
                    d.register(2, 0x200480) as usize,
                );
                assert_eq!(fw, d.source_image);
                d.boot = d.boot_reply;
                d.msi += 1;
            }
            (Space::Bar0, 0x144) => {
                if value == 1 {
                    assert_eq!(d.boot, 2);
                    d.rti = d.rti_reply.unwrap_or(1);
                } else {
                    assert_eq!(value, 2);
                    assert_eq!(d.rti, 1);
                    for at in [0x200494, 0x200498] {
                        assert_eq!(d.register(2, at), 0);
                    }
                    assert_eq!(d.register(2, 0x20049c), 0xffff_fe00);
                    d.parse_context();
                    d.rti = d.rti_reply.unwrap_or(2);
                }
                d.msi += 1;
            }
            (Space::Bar0, 0x174) => {
                d.doorbells.push(value);
                assert_eq!(value & 0xff, 0x20);
                let db = (value >> 8) & 0xff;
                let head = (value >> 16) as u16;
                let id = match db {
                    0 => 0,
                    1 => 1,
                    2 => 2,
                    3 => 5,
                    4 => 6,
                    6 => 4,
                    _ => panic!("doorbell id"),
                };
                assert_eq!(d.domain.word(d.txheads + id * 2), head);
                if matches!(id, 0 | 1 | 5) {
                    d.consume(id as usize);
                } else if id == 6 {
                    for n in 0..128 {
                        let desc = d.domain.read(d.tx[6].address + n * 16, 16);
                        assert_eq!(desc[0], 1);
                        assert_eq!(u16at(&desc, 1), 1032);
                        assert_eq!(u16at(&desc, 12), 0x100 + n as u16);
                        let _ = d.domain.read(u64at(&desc, 4), 1032);
                    }
                }
            }
            _ => {}
        }
        d.operation(space, original)
    }
    fn now_us(&self) -> u64 {
        let mut d = self.0.lock().unwrap();
        d.ticks += 10_000;
        d.ticks
            .saturating_add(d.domain.0.lock().unwrap().elapsed_us)
    }
    fn arm_msi(&mut self) -> Result<()> {
        let mut d = self.0.lock().unwrap();
        d.armed = true;
        let delay = d.arm_delay;
        d.ticks += delay;
        d.operation(Space::Configuration, 0xeeee)
    }
    fn retire(&mut self) -> Result<()> {
        let mut d = self.0.lock().unwrap();
        d.retire += 1;
        assert_eq!(d.retire, 1, "uncertain retirement never retried");
        if d.fail_retire {
            return Err(Error::Unsupported("independent root drain failed"));
        }
        d.domain.0.lock().unwrap().stopped = true;
        Ok(())
    }
}
fn key(space: Space) -> u8 {
    match space {
        Space::Bar0 => 0,
        Space::Bar2 => 2,
        Space::Configuration => 3,
    }
}
fn otp() -> [u8; 224] {
    let mut bytes = [0; 224];
    let data = b"\x08\0\0\0s=B1 x=7\0V=Murata z=0\0";
    bytes[0] = 0x15;
    bytes[1] = data.len() as u8;
    bytes[2..2 + data.len()].copy_from_slice(data);
    bytes
}
fn fixture(device: u16) -> (Model, Allocator, Arc<Mutex<Device>>) {
    let domain = Arc::new(Domain::new());
    let pci = PciIdentity {
        address: Address {
            segment: 0,
            bus: 1,
            device: 0,
            function: 0,
        },
        vendor: 0x14e4,
        device,
        subsystem_vendor: 0x106b,
        subsystem_device: 0x100,
        revision: 3,
        class: 0x028000,
    };
    let mut registers = BTreeMap::new();
    registers.insert((3, 0), u32::from(device) << 16 | 0x14e4);
    registers.insert((3, 8), 0x02800003);
    registers.insert((3, 0x2c), 0x0100106b);
    registers.insert((3, 0x88), 1 << 19);
    let d = Arc::new(Mutex::new(Device {
        domain: domain.clone(),
        pci,
        otp: otp(),
        registers,
        ticks: 0,
        operations: 0,
        fail_operation: None,
        writes: 0,
        prepare: 0,
        armed: false,
        msi: 0,
        retire: 0,
        fail_retire: false,
        dropped: false,
        boot: 0,
        rti: 0,
        context: 0,
        heads: 0,
        tails: 0,
        txheads: 0,
        txtails: 0,
        tx: [Ring::default(); 7],
        cr: [Ring::default(); 5],
        controls: Vec::new(),
        sent: Vec::new(),
        doorbells: Vec::new(),
        delay_offset: None,
        read_delay: None,
        arm_delay: 0,
        boot_reply: 2,
        rti_reply: None,
        consume_tx: true,
        acknowledge: true,
        source_image: vec![0xa5; 64],
        properties: BTreeMap::new(),
        property_requests: Vec::new(),
        setup: None,
    }));
    (
        Model(d.clone()),
        Allocator {
            domain,
            physical: 0x1_0000_0000,
        },
        d,
    )
}
fn catalog(d: &Arc<Mutex<Device>>, fallback: bool) -> Catalog {
    let d = d.lock().unwrap();
    let identity = Identity::parse(
        d.pci,
        Board::from_property(b"apple,formosa\0").unwrap(),
        d.otp,
    )
    .unwrap();
    let name = identity.names("bin").unwrap();
    let hw = identity.hardware_label();
    let rev = identity.revision_label();
    let bytes = d.source_image.clone();
    Catalog::from_handoff(vec![Resource {
        name: &name[usize::from(fallback)],
        target: identity.target(&hw, &rev),
        provenance: Provenance {
            source: "independent-device-model",
            revision: "literal-source-wire-v1",
            member: &name[usize::from(fallback)],
            license: "test fixture",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(&bytes).into(),
        bytes,
    }])
    .unwrap()
}
fn active(device: u16) -> (Transport<Model>, Arc<Mutex<Device>>) {
    let (p, mut a, d) = fixture(device);
    let provider = catalog(&d, false);
    let mut transport = Transport::new(p, &mut a).unwrap();
    transport.start(&provider).unwrap();
    let observations = transport.take_observations();
    assert_eq!(observations.completions.len(), 10);
    assert!(observations.packets.is_empty());
    (transport, d)
}

#[test]
fn all_source_variants_boot_literal_context_rings_and_reverse_destroy() {
    for device in [0x5fa0, 0x5f69, 0x5f71, 0x5f72] {
        let (mut transport, d) = active(device);
        assert_eq!(transport.state(), State::Active);
        assert_eq!(transport.identity().unwrap().stepping, "b1");
        assert_eq!(transport.identity().unwrap().antenna_vendor, "Murata");
        assert_eq!(transport.snapshot().peripheral_info, [0x3a; 32]);
        {
            let d = d.lock().unwrap();
            assert_eq!(d.prepare, 1);
            assert!(d.msi >= 13);
            let windows = match device {
                0x5fa0 => (0x1800b000, 0x1810c000, None),
                0x5f69 => (0x18002000, 0x1810a000, Some(0x18107000)),
                _ => (0x18002000, 0x18109000, Some(0x18106000)),
            };
            assert_eq!(d.register(3, 0x80), windows.0);
            assert_eq!(d.register(3, 0x70), windows.1);
            assert_eq!(d.register(3, 0x74), 0x18011000);
            assert_eq!(d.registers.get(&(3, 0x78)).copied(), windows.2);
            assert_eq!(d.register(3, 0x84), 0x19000000);
            assert_eq!(
                d.register(3, 0x88),
                (1 << 16) | if device == 0x5f71 { 0 } else { 1 << 19 }
            );
            assert_eq!(
                d.controls
                    .iter()
                    .map(|b| (b[0], u16at(b, 4)))
                    .collect::<Vec<_>>(),
                vec![
                    (2, 1),
                    (2, 2),
                    (2, 3),
                    (2, 4),
                    (1, 1),
                    (1, 2),
                    (1, 3),
                    (1, 4),
                    (1, 5),
                    (1, 6)
                ]
            );
        }
        transport.close().unwrap();
        assert_eq!(transport.state(), State::Closed);
        let d = d.lock().unwrap();
        assert_eq!(d.retire, 1);
        let domain = d.domain.0.lock().unwrap();
        assert!(domain.stopped);
        assert!(domain.leases.is_empty());
        assert_eq!(domain.unmaps, 14);
        assert_eq!(
            d.controls[10..]
                .iter()
                .map(|b| (b[0], u16at(b, 2)))
                .collect::<Vec<_>>(),
            vec![
                (3, 6),
                (3, 5),
                (3, 4),
                (3, 3),
                (3, 2),
                (3, 1),
                (4, 4),
                (4, 3),
                (4, 2),
                (4, 1)
            ]
        );
    }
}
#[test]
fn source_tx_ack_is_distinct_from_real_hci_and_sco_needs_no_tx_doorbell() {
    let (mut transport, d) = active(0x5f69);
    let command = [0x03, 0x0c, 0];
    let sco = [1, 0, 2, 0xaa, 0xbb];
    let acl = [1, 0, 3, 0, 0xcc, 0xdd, 0xee];
    let submitted = transport.send(Kind::Command, &command).unwrap();
    assert_eq!(
        submitted,
        Submission {
            ring: 1,
            message: 0x100
        }
    );
    let observations = transport.poll().unwrap();
    assert_eq!(observations.completions.len(), 1);
    assert!(observations.packets.is_empty());
    let doorbells = d.lock().unwrap().doorbells.len();
    let sco_submission = transport.send(Kind::Sco, &sco).unwrap();
    assert_eq!(d.lock().unwrap().doorbells.len(), doorbells);
    let observations = transport.poll().unwrap();
    assert_eq!(observations.completions[0].submission, sco_submission);
    assert!(observations.packets.is_empty());
    let acl_submission = transport.send(Kind::Acl, &acl).unwrap();
    assert_eq!(
        transport.poll().unwrap().completions[0].submission,
        acl_submission
    );
    let event = [0x0e, 4, 1, 3, 0x0c, 0];
    let completion = d
        .lock()
        .unwrap()
        .completion(2, 2, 0xffff, 0x82, &event, false);
    let observations = transport.poll().unwrap();
    assert_eq!(observations.packets[0].bytes, event);
    assert_eq!(observations.packets[0].completion, completion);
    assert!(
        observations.packets[0].footer[event.len()..]
            .iter()
            .all(|b| *b == 0xdd)
    );
    assert_eq!(
        d.lock().unwrap().sent,
        vec![
            (1, command.to_vec(), 0x100),
            (3, sco.to_vec(), 0x100),
            (5, acl.to_vec(), 0x100)
        ]
    );
}
#[test]
fn source_rx_footer_mapped_sco_credit_and_wrap() {
    let (mut transport, d) = active(0x5f72);
    // More than one complete completion/transfer wrap, including unrecognized
    // footer flags/msgids which donor ignores for short inline ACL/event data.
    for index in 0..270 {
        let event = [0xff, 1, (index & 0xff) as u8];
        let acl = [1, 0, 1, 0, (index & 0xff) as u8];
        let sco = [2, 0, 1, 0xab];
        {
            let mut d = d.lock().unwrap();
            d.completion(2, 2, 0xffff, 0xa2, &event, false);
            d.completion(
                2,
                6,
                if index % 2 == 0 {
                    0x100 + (index % 128) as u16
                } else {
                    0xffff
                },
                if index % 2 == 0 { 1 } else { 0x80 },
                &acl,
                index % 2 == 0,
            );
            d.completion(4, 4, 0xbeef, 0x40, &sco, false);
        }
        let observations = transport.poll().unwrap();
        assert_eq!(
            observations
                .packets
                .iter()
                .map(|p| p.bytes.clone())
                .collect::<Vec<_>>(),
            vec![event.to_vec(), acl.to_vec(), sco.to_vec()]
        );
    }
    let d = d.lock().unwrap();
    assert_eq!(d.domain.word(d.txheads + 4), ((15 + 270) % 128) as u16);
    assert_eq!(d.domain.word(d.txheads + 8), ((15 + 270) % 128) as u16);
    assert_eq!(d.domain.word(d.txheads + 12), ((15 + 270) % 128) as u16);
}
#[test]
fn source_descriptor_wrap_and_message_reuse_wait_for_real_ack() {
    let (mut transport, d) = active(0x5fa0);
    d.lock().unwrap().consume_tx = false;
    for _ in 0..127 {
        transport.send(Kind::Command, &[1, 0, 0]).unwrap();
    }
    assert!(matches!(
        transport.send(Kind::Command, &[1, 0, 0]),
        Err(Error::QueueFull(1))
    ));
    assert_eq!(transport.state(), State::Active);
    {
        let mut d = d.lock().unwrap();
        d.consume_tx = true;
        d.consume(1);
    }
    let first = transport.poll().unwrap();
    assert_eq!(first.completions.len(), 127);
    for _ in 0..140 {
        let submission = transport.send(Kind::Command, &[1, 0, 0]).unwrap();
        assert_eq!(submission.message, 0x100);
        assert_eq!(transport.poll().unwrap().completions.len(), 1);
    }
    assert_eq!(d.lock().unwrap().sent.len(), 267);
}
#[test]
fn firmware_missing_only_fallback_and_target_otp_binding() {
    for fallback in [false, true] {
        let (p, mut a, d) = fixture(0x5f71);
        let provider = catalog(&d, fallback);
        let mut transport = Transport::new(p, &mut a).unwrap();
        transport.start(&provider).unwrap();
        assert_eq!(
            transport.snapshot().firmware_errors.len(),
            usize::from(fallback)
        );
        assert_eq!(
            transport.firmware().unwrap().sha256,
            Sha256::digest([0xa5; 64]).as_slice()
        );
    }
    let (p, mut a, d) = fixture(0x5f71);
    let provider = catalog(&d, false);
    d.lock().unwrap().otp[223] = 1;
    let mut transport = Transport::new(p, &mut a).unwrap();
    assert!(matches!(
        transport.start(&provider),
        Err(Error::Firmware(crate::firmware::Error {
            kind: crate::firmware::ErrorKind::WrongTarget,
            ..
        }))
    ));
    assert!(transport.snapshot().firmware_errors.is_empty());
    assert!(!d.lock().unwrap().armed);
}
#[test]
fn source_identity_refuses_ambiguous_unsafe_or_unsupported_metadata() {
    let (p, _, d) = fixture(0x5fa0);
    drop(p);
    let pci = d.lock().unwrap().pci;
    let board = Board::from_dmi("Apple Inc.", "MacBookPro16,3").unwrap();
    assert_eq!(board.name(), "apple,formosa");
    assert!(Board::from_dmi("Apple Inc.", "MacBookPro16,3suffix").is_err());
    assert!(Board::from_dmi("Apple", "MacBookPro16,3").is_err());
    for bytes in [b"../board".as_slice(), b"board\0other", b"", b"board/path"] {
        assert!(Board::from_property(bytes).is_err());
    }
    let mut invalid = otp();
    invalid[1] = 223;
    assert!(Identity::parse(pci, board.clone(), invalid).is_err());
    let mut invalid = otp();
    invalid[2] = 9;
    assert!(Identity::parse(pci, board.clone(), invalid).is_err());
    let mut invalid = otp();
    invalid[15] = b'/';
    assert!(Identity::parse(pci, board.clone(), invalid).is_err());
    let mut wrong = pci;
    wrong.device = 0xffff;
    assert!(Chip::select(wrong).is_err());
    wrong = pci;
    wrong.class = 0x028100;
    assert!(Chip::select(wrong).is_err());
    let too_long = Board::from_property(&[b'a'; 63]).unwrap();
    let identity = Identity::parse(pci, too_long, otp()).unwrap();
    assert!(identity.names("bin").is_err());
}
#[test]
fn boot_ack_deadline_includes_register_effect_and_wrong_stages_are_terminal() {
    for (offset, delay) in [(0x140, 5_100_000), (0x144, 1_100_000)] {
        let (p, mut a, d) = fixture(0x5f69);
        let provider = catalog(&d, false);
        let mut transport = Transport::new(p, &mut a).unwrap();
        d.lock().unwrap().delay_offset = Some((offset, delay));
        assert!(matches!(transport.start(&provider), Err(Error::Timeout(_))));
        assert_eq!(transport.state(), State::Failed);
        assert_eq!(d.lock().unwrap().retire, 1);
    }
    for (boot, rti, boot_reply, rti_reply) in [
        (2, 0, 2, None),
        (0, 1, 2, None),
        (0, 0, 3, None),
        (0, 0, 2, Some(2)),
    ] {
        let (p, mut a, d) = fixture(0x5f69);
        let provider = catalog(&d, false);
        {
            let mut d = d.lock().unwrap();
            d.boot = boot;
            d.rti = rti;
            d.boot_reply = boot_reply;
            d.rti_reply = rti_reply;
        }
        let mut transport = Transport::new(p, &mut a).unwrap();
        assert!(matches!(
            transport.start(&provider),
            Err(Error::Protocol { .. })
        ));
        assert_eq!(d.lock().unwrap().retire, 1);
    }
}
#[test]
fn complete_raw_packets_before_bad_completion_survive_terminal_fault() {
    for fail_retire in [false, true] {
        let (mut transport, d) = active(0x5f69);
        let event = [0xff, 1, 0x9a];
        let raw;
        {
            let mut d = d.lock().unwrap();
            d.fail_retire = fail_retire;
            raw = d.completion(2, 2, 0xffff, 0x42, &event, false);
            d.completion(2, 1, 0x100, 0, &[], false);
        }
        let fault = transport.poll().unwrap_err();
        assert_eq!(transport.state(), State::Failed);
        let observations = transport.take_observations();
        assert_eq!(observations.packets.len(), 1);
        assert_eq!(observations.packets[0].bytes, event);
        assert_eq!(observations.packets[0].completion, raw);
        assert_eq!(observations.packets[0].footer.len(), 264);
        let writes = d.lock().unwrap().writes;
        assert!(transport.poll().is_err());
        assert!(transport.send(Kind::Command, &[1, 0, 0]).is_err());
        assert_eq!(transport.close().unwrap_err(), fault);
        drop(transport);
        let d = d.lock().unwrap();
        assert_eq!(d.writes, writes);
        assert_eq!(d.retire, 1);
        assert!(!d.dropped);
        assert!(!d.domain.0.lock().unwrap().leases.is_empty());
        if fail_retire {
            let domain = d.domain.clone();
            let address = d.cr[2].address;
            drop(d);
            domain.write(address, &[0x7e; 16]);
            assert_eq!(domain.read(address, 16), vec![0x7e; 16]);
        }
    }
}
#[test]
fn stale_duplicate_out_of_range_cross_ring_and_corrupt_indices_fail_closed() {
    for case in 0..7 {
        let (mut transport, d) = active(0x5fa0);
        let submission = transport.send(Kind::Command, &[1, 0, 0]).unwrap();
        let _ = transport.poll().unwrap();
        {
            let mut d = d.lock().unwrap();
            match case {
                0 => {
                    d.completion(1, 1, submission.message, 0, &[], false);
                }
                1 => {
                    d.completion(1, 1, 0x200, 0, &[], false);
                }
                2 => {
                    d.completion(1, 1, 0x180, 0, &[], false);
                }
                3 => {
                    d.completion(3, 1, submission.message, 0, &[], false);
                }
                4 => {
                    d.domain.set_word(d.heads + 4, 256);
                }
                5 => {
                    d.completion(2, 6, 0x200, 1, &[1, 0, 0, 0], false);
                }
                6 => {
                    d.domain.set_word(d.txheads + 2, 128);
                }
                _ => unreachable!(),
            }
        }
        let result = if case == 6 {
            transport.send(Kind::Command, &[1, 0, 0]).map(|_| ())
        } else {
            transport.poll().map(|_| ())
        };
        assert!(result.is_err(), "case{case}");
        assert_eq!(transport.state(), State::Failed);
        assert_eq!(d.lock().unwrap().retire, 1);
    }
}
#[test]
fn observation_bound_retains_final_packet_and_first_failure() {
    let (mut transport, d) = active(0x5f69);
    transport.observation_bytes = OBSERVATION_BYTES - 1;
    let raw = d.lock().unwrap().completion(2, 2, 0, 2, &[0xff, 0], false);
    assert_eq!(transport.poll(), Err(Error::ObservationLimit));
    let observations = transport.take_observations();
    assert_eq!(observations.packets[0].completion, raw);
    assert_eq!(observations.packets[0].bytes, [0xff, 0]);
    assert_eq!(transport.close(), Err(Error::ObservationLimit));
}
#[test]
fn failed_root_retirement_is_attempted_once_and_all_actual_owners_survive() {
    let (mut transport, d) = active(0x5f71);
    d.lock().unwrap().fail_retire = true;
    let error = transport.close().unwrap_err();
    assert_eq!(error, Error::Unsupported("independent root drain failed"));
    let controls = d.lock().unwrap().controls.len();
    assert_eq!(transport.close().unwrap_err(), error);
    drop(transport);
    let d = d.lock().unwrap();
    assert_eq!(d.retire, 1);
    assert_eq!(d.controls.len(), controls);
    assert!(!d.dropped);
    let domain = d.domain.0.lock().unwrap();
    assert_eq!(domain.unmaps, 0);
    assert_eq!(domain.leases.len(), 14);
    assert!(!domain.stopped);
}
#[test]
fn unmap_failure_preserves_actual_mapping_and_cannot_restart_retirement() {
    let (mut transport, d) = active(0x5fa0);
    d.lock().unwrap().domain.0.lock().unwrap().fail_unmap = true;
    assert_eq!(
        transport.close(),
        Err(Error::Dma(DmaError::InvalidationFailed))
    );
    assert_eq!(d.lock().unwrap().retire, 1);
    drop(transport);
    let d = d.lock().unwrap();
    let domain = d.domain.0.lock().unwrap();
    assert_eq!(domain.unmaps, 1);
    assert_eq!(domain.leases.len(), 14);
    assert!(domain.stopped);
    assert!(!d.dropped);
}
#[test]
fn every_start_mmio_effect_error_is_terminal_with_first_fault_and_no_rewrite() {
    let operations = {
        let (transport, d) = active(0x5f69);
        let operations = d.lock().unwrap().operations;
        drop(transport);
        operations
    };
    for fail in 1..=operations {
        let (p, mut a, d) = fixture(0x5f69);
        let provider = catalog(&d, false);
        d.lock().unwrap().fail_operation = Some(fail);
        match Transport::new(p, &mut a) {
            Err(_) => {
                let d = d.lock().unwrap();
                assert!(d.writes == 0);
                assert_eq!(d.prepare, usize::from(fail > 3));
            }
            Ok(mut transport) => {
                assert!(transport.start(&provider).is_err(), "MMIO op {fail}");
                assert_eq!(transport.state(), State::Failed);
                let fault = transport.fault().unwrap().clone();
                let writes = d.lock().unwrap().writes;
                assert_eq!(transport.close(), Err(fault));
                drop(transport);
                let d = d.lock().unwrap();
                assert_eq!(d.writes, writes);
                assert_eq!(d.retire, 1);
                assert!(!d.dropped);
            }
        }
    }
}
#[test]
fn every_start_visibility_error_preserves_terminal_buffers_and_root_owner() {
    let syncs = {
        let (transport, d) = active(0x5fa0);
        let syncs = d.lock().unwrap().domain.0.lock().unwrap().syncs;
        drop(transport);
        syncs
    };
    for fail in 1..=syncs {
        let (p, mut a, d) = fixture(0x5fa0);
        let provider = catalog(&d, false);
        let mut transport = Transport::new(p, &mut a).unwrap();
        d.lock().unwrap().domain.0.lock().unwrap().fail_sync = Some(fail);
        assert!(transport.start(&provider).is_err(), "sync{fail}");
        assert_eq!(transport.state(), State::Failed);
        let writes = d.lock().unwrap().writes;
        let fault = transport.fault().unwrap().clone();
        assert_eq!(transport.close(), Err(fault));
        drop(transport);
        let d = d.lock().unwrap();
        assert_eq!(d.writes, writes);
        assert_eq!(d.retire, 1);
        assert!(!d.dropped);
    }
}

#[test]
fn tx_capacity_and_rx_malformed_lengths_retain_original_bytes() {
    let (mut transport, d) = active(0x5f69);
    let mut command = vec![0x98, 0xfd, 255];
    command.extend_from_slice(&[0x5a; 255]);
    let mut sco = vec![1, 0, 255];
    sco.extend_from_slice(&[0x5b; 255]);
    let mut acl = vec![1, 0, 4, 4];
    acl.extend_from_slice(&[0x5c; 1028]);
    for (kind, bytes) in [
        (Kind::Command, &command),
        (Kind::Sco, &sco),
        (Kind::Acl, &acl),
    ] {
        transport.send(kind, bytes).unwrap();
        assert_eq!(transport.poll().unwrap().completions.len(), 1);
    }
    assert_eq!(
        d.lock()
            .unwrap()
            .sent
            .iter()
            .map(|(_, b, _)| b.len())
            .collect::<Vec<_>>(),
        vec![258, 258, 1032]
    );
    let mut oversized = vec![1, 0, 5, 4];
    oversized.extend_from_slice(&[0x5c; 1029]);
    assert!(matches!(
        transport.send(Kind::Acl, &oversized),
        Err(Error::Packet { .. })
    ));
    assert_eq!(transport.state(), State::Active);
    let raw = d
        .lock()
        .unwrap()
        .completion(2, 2, 0xffff, 0x82, &[0xff, 5, 0x91], false);
    assert_eq!(
        transport.poll(),
        Err(Error::Packet {
            kind: Kind::Event,
            bytes: vec![0xff, 5, 0x91]
        })
    );
    assert_eq!(transport.snapshot().completion, Some(raw));
    assert_eq!(
        &transport.snapshot().completion_footer[..3],
        &[0xff, 5, 0x91]
    );
}
#[test]
fn source_oversized_footer_and_mapped_lengths_are_rejected_before_reading() {
    for mapped in [false, true] {
        let (mut transport, d) = active(0x5f69);
        {
            let mut d = d.lock().unwrap();
            let ring = d.cr[2];
            let head = d.domain.word(d.heads + 4);
            let mut raw = d.completion(2, 6, 0x100, u8::from(mapped), &[1, 0, 0, 0], mapped);
            field32(&mut raw, 6, if mapped { 1033 } else { 265 });
            d.domain.write(ring.address + u64::from(head) * 280, &raw);
        }
        assert!(matches!(transport.poll(), Err(Error::Protocol { .. })));
        assert_eq!(transport.snapshot().completion_footer.len(), 264);
    }
}
#[test]
fn every_live_send_poll_and_close_mmio_effect_error_stops_once() {
    // Independent RX in the same service turn forces failure coverage for both
    // RX credit doorbells and outbound descriptor doorbells. Closing
    // exercises destroy ACKs plus snapshot reads before root stop.
    for closing in [false, true] {
        let count = {
            let (mut t, d) = active(0x5f69);
            if !closing {
                d.lock()
                    .unwrap()
                    .completion(2, 2, 0xffff, 2, &[0xff, 1, 0x91], false);
            }
            let before = d.lock().unwrap().operations;
            if closing {
                t.close().unwrap();
            } else {
                t.send(Kind::Command, &[1, 0, 0]).unwrap();
                t.poll().unwrap();
            }
            d.lock().unwrap().operations - before
        };
        for fail_at in 1..=count {
            let (mut t, d) = active(0x5f69);
            {
                let mut d = d.lock().unwrap();
                if !closing {
                    d.completion(2, 2, 0xffff, 2, &[0xff, 1, 0x91], false);
                }
                d.fail_operation = Some(d.operations + fail_at);
            }
            let result = if closing {
                t.close()
            } else {
                t.send(Kind::Command, &[1, 0, 0])
                    .and_then(|_| t.poll().map(|_| ()))
            };
            assert!(result.is_err(), "closing={closing}, live effect {fail_at}");
            let fault = t.fault().unwrap().clone();
            let writes = d.lock().unwrap().writes;
            let before = t.snapshot().clone();
            assert_eq!(t.close(), Err(fault));
            assert_eq!(t.snapshot(), &before);
            drop(t);
            let d = d.lock().unwrap();
            assert_eq!(d.writes, writes);
            assert_eq!(d.retire, 1);
            assert!(!d.dropped);
        }
    }
}
#[test]
fn genuine_retirement_cancels_unacknowledged_tx_without_delivery_claim() {
    let (mut transport, d) = active(0x5fa0);
    d.lock().unwrap().acknowledge = false;
    let submission = transport.send(Kind::Acl, &[1, 0, 0, 0]).unwrap();
    assert!(transport.poll().unwrap().completions.is_empty());
    transport.close().unwrap();
    let observed = transport.take_observations();
    assert_eq!(observed.retired_without_ack, vec![submission]);
    assert!(observed.completions.iter().all(|r| r.submission.ring == 0));
    assert!(observed.packets.is_empty());
}

#[test]
fn unpublished_allocations_close_without_device_ring_or_reset_effects() {
    let (p, mut a, d) = fixture(0x5fa0);
    let mut transport = Transport::new(p, &mut a).unwrap();
    transport.close().unwrap();
    let d = d.lock().unwrap();
    assert_eq!(d.writes, 0);
    assert_eq!(d.retire, 0);
    assert!(!d.armed);
    assert!(d.controls.is_empty());
    assert!(d.domain.0.lock().unwrap().leases.is_empty());
}
#[test]
fn original_otp_bytes_survive_rejected_metadata_and_partial_reads() {
    for partial in [false, true] {
        let (p, mut a, d) = fixture(0x5f69);
        let provider = catalog(&d, false);
        d.lock().unwrap().otp[2] = 9;
        let mut transport = Transport::new(p, &mut a).unwrap();
        if partial {
            let mut d = d.lock().unwrap();
            d.fail_operation = Some(d.operations + 40);
        }
        assert!(transport.start(&provider).is_err());
        let d = d.lock().unwrap();
        if partial {
            assert!(!transport.snapshot().otp.is_empty());
            assert!(transport.snapshot().otp.len() < 224);
        } else {
            assert_eq!(transport.snapshot().otp, d.otp);
        }
        assert!(transport.identity().is_none());
        assert!(!d.armed);
    }
}
struct FailedProvider {
    calls: core::cell::Cell<usize>,
    kind: crate::firmware::ErrorKind,
}
impl Provider for FailedProvider {
    fn load(
        &self,
        requirement: crate::firmware::Requirement<'_>,
    ) -> core::result::Result<crate::firmware::Image<'_>, crate::firmware::Error> {
        self.calls.set(self.calls.get() + 1);
        Err(crate::firmware::Error {
            name: requirement.name.into(),
            kind: self.kind.clone(),
        })
    }
}
#[test]
fn resource_integrity_or_target_failure_never_attempts_fallback() {
    for kind in [
        crate::firmware::ErrorKind::WrongTarget,
        crate::firmware::ErrorKind::DigestMismatch {
            expected: [1; 32],
            actual: [2; 32],
        },
        crate::firmware::ErrorKind::LengthMismatch {
            expected: 32,
            actual: 64,
        },
    ] {
        let (p, mut a, d) = fixture(0x5fa0);
        let provider = FailedProvider {
            calls: core::cell::Cell::new(0),
            kind,
        };
        let mut transport = Transport::new(p, &mut a).unwrap();
        assert!(matches!(
            transport.start(&provider),
            Err(Error::Firmware(_))
        ));
        assert_eq!(provider.calls.get(), 1);
        assert!(transport.snapshot().firmware_errors.is_empty());
        assert!(!d.lock().unwrap().armed);
    }
}
fn setup_catalog(d: &Arc<Mutex<Device>>, ptb: &[u8], fallback: bool) -> Catalog {
    let d = d.lock().unwrap();
    let identity = Identity::parse(
        d.pci,
        Board::from_property(b"apple,formosa\0").unwrap(),
        d.otp,
    )
    .unwrap();
    let bin = identity.names("bin").unwrap();
    let ptb_names = identity.names("ptb").unwrap();
    let hardware = identity.hardware_label();
    let revision = identity.revision_label();
    let resources = [
        (&bin[0], d.source_image.as_slice()),
        (&ptb_names[usize::from(fallback)], ptb),
    ]
    .into_iter()
    .map(|(name, bytes)| Resource {
        name,
        target: identity.target(&hardware, &revision),
        provenance: Provenance {
            source: "independent-source-model",
            revision: "calibration-wire-v1",
            member: name,
            license: "test fixture",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(bytes).into(),
        bytes: bytes.to_vec(),
    })
    .collect();
    Catalog::from_handoff(resources).unwrap()
}
fn expected_setup(
    chip: u16,
    calibration: &[u8],
    ptb: &[u8],
    replacement: Option<[u8; 6]>,
) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    if chip != 0x4377 {
        let chunks = calibration.len().div_ceil(230);
        for (index, bytes) in calibration.chunks(230).enumerate() {
            let mut packet = vec![0x97, 0xfd, 233, 3];
            packet.extend_from_slice(&((chunks - index - 1) as u16).to_le_bytes());
            packet.extend_from_slice(bytes);
            packet.resize(236, 0);
            packets.push(packet);
        }
        let chunks = ptb.len().div_ceil(207);
        for (index, bytes) in ptb.chunks(207).enumerate() {
            let mut packet = vec![0x0d, 0xfe, 209];
            packet.extend_from_slice(&((chunks - index - 1) as u16).to_le_bytes());
            packet.extend_from_slice(bytes);
            packet.resize(212, 0);
            packets.push(packet);
        }
    } else {
        let mut packet = vec![0x98, 0xfd, ptb.len() as u8];
        packet.extend_from_slice(ptb);
        packets.push(packet);
    }
    packets.push(vec![9, 0x10, 0]);
    if let Some(address) = replacement {
        let mut packet = vec![1, 0xfc, 6];
        packet.extend_from_slice(&address);
        packets.push(packet);
        packets.push(vec![9, 0x10, 0]);
    }
    packets
}
type SetupFixture = (Transport<Model>, Arc<Mutex<Device>>, Catalog, Vec<Vec<u8>>);
fn setup_fixture(device: u16, stepping: &str, replacement: bool, fault: HciFault) -> SetupFixture {
    let (p, mut a, d) = fixture(device);
    let calibration = (0..461).map(|n| (n % 251) as u8).collect::<Vec<_>>();
    let bf = (0..461).map(|n| 0x80 | (n % 113) as u8).collect::<Vec<_>>();
    let ptb = (0..if device == 0x5fa0 { 233 } else { 415 })
        .map(|n| (n % 239) as u8)
        .collect::<Vec<_>>();
    let selected = [0x52, 0x43, 0x34, 0x25, 0x16, 0x07];
    let chip = match device {
        0x5fa0 => 0x4377,
        0x5f69 => 0x4378,
        0x5f71 => 0x4387,
        0x5f72 => 0x4388,
        _ => unreachable!(),
    };
    let use_bf = match device {
        0x5f69 => matches!(stepping, "b1" | "b3"),
        0x5f71 => stepping == "c2",
        0x5f72 => true,
        _ => false,
    };
    let expected = expected_setup(
        chip,
        if use_bf { &bf } else { &calibration },
        &ptb,
        replacement.then_some(selected),
    );
    {
        let mut d = d.lock().unwrap();
        let mut data = 8u32.to_le_bytes().to_vec();
        data.extend_from_slice(alloc::format!("s={stepping} x=7\0V=Murata z=0\0").as_bytes());
        d.otp = [0; 224];
        d.otp[0] = 0x15;
        d.otp[1] = data.len() as u8;
        d.otp[2..2 + data.len()].copy_from_slice(&data);
        d.properties.insert("brcm,taurus-cal-blob", calibration);
        d.properties.insert("brcm,taurus-bf-cal-blob", bf);
        if replacement {
            d.properties.insert("local-bd-address", selected.to_vec());
        }
        let address = if replacement {
            [0x93, 0x76, 0, 0x88, chip as u8, (chip >> 8) as u8]
        } else {
            [0x62, 0x53, 0x44, 0x35, 0x26, 0x17]
        };
        d.setup = Some(Setup {
            expected: expected.clone(),
            index: 0,
            fault,
            address,
            pending_credit_reads: 0,
        });
    }
    let provider = setup_catalog(&d, &ptb, false);
    (Transport::new(p, &mut a).unwrap(), d, provider, expected)
}
#[test]
fn actual_ipc_initialization_uses_source_variant_calibration_ptb_and_address() {
    for (device, stepping) in [
        (0x5fa0, "a0"),
        (0x5f69, "b1"),
        (0x5f69, "b3"),
        (0x5f69, "b2"),
        (0x5f71, "c2"),
        (0x5f71, "c1"),
        (0x5f72, "z9"),
    ] {
        for replacement in [false, true] {
            let (mut transport, d, provider, expected) =
                setup_fixture(device, stepping, replacement, HciFault::None);
            let report = transport.initialize(&provider).unwrap();
            assert_eq!(report.property_address_applied, replacement);
            assert_eq!(report.ptb, PtbDisposition::Accepted);
            assert_eq!(
                report.address,
                if replacement {
                    [0x52, 0x43, 0x34, 0x25, 0x16, 7]
                } else {
                    [0x62, 0x53, 0x44, 0x35, 0x26, 0x17]
                }
            );
            let attempt = transport.snapshot().initialization.as_ref().unwrap();
            assert_eq!(attempt.stage, InitializationStage::Complete);
            assert_eq!(attempt.report, Some(report));
            assert_eq!(attempt.commands.len(), expected.len());
            for (command, packet) in attempt.commands.iter().zip(&expected) {
                assert_eq!(command.packet_sha256, Sha256::digest(packet).as_slice());
                assert_eq!(command.packet_bytes, packet.len());
                assert!(command.submission.is_some());
                assert_eq!(command.returned.as_ref().unwrap()[0], 0);
            }
            let observed = transport.take_observations();
            assert_eq!(observed.packets.len(), expected.len() * 2);
            assert!(
                observed.packets.iter().all(|p| p.footer.len() == 264
                    && p.footer[p.bytes.len()..].iter().all(|b| *b == 0xdd))
            );
            let d = d.lock().unwrap();
            assert_eq!(
                d.sent
                    .iter()
                    .map(|(_, packet, _)| packet.clone())
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(d.setup.as_ref().unwrap().index, expected.len());
            assert_eq!(
                d.property_requests.len(),
                usize::from(device != 0x5fa0) + usize::from(replacement)
            );
        }
    }
}
#[test]
fn native_ack_or_status_alone_cannot_finish_hci_and_credits_require_actual_grant() {
    for fault in [
        HciFault::AckOnly(0),
        HciFault::StatusOnly(0),
        HciFault::SilentCredits(0),
    ] {
        let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", false, fault);
        assert!(matches!(
            transport.initialize(&provider),
            Err(Error::Timeout(_))
        ));
        assert_eq!(d.lock().unwrap().setup.as_ref().unwrap().index, 1);
        assert!(
            transport
                .snapshot()
                .initialization
                .as_ref()
                .unwrap()
                .report
                .is_none()
        );
        assert_eq!(d.lock().unwrap().retire, 1);
    }
    let (mut transport, d, provider, expected) =
        setup_fixture(0x5f69, "b1", false, HciFault::ZeroCredits(0));
    transport.initialize(&provider).unwrap();
    assert_eq!(
        d.lock().unwrap().setup.as_ref().unwrap().index,
        expected.len()
    );
    let observed = transport.take_observations();
    assert!(
        observed
            .packets
            .iter()
            .any(|p| p.bytes == [0x0e, 3, 1, 0, 0])
    );
}
#[test]
fn actual_controller_rejections_stop_required_upload_but_4377_ptb_is_explicit() {
    for at in 0..7 {
        let (mut transport, d, provider, _) =
            setup_fixture(0x5f69, "b1", false, HciFault::Reject(at, 0x0c));
        assert!(matches!(
            transport.initialize(&provider),
            Err(Error::Controller { status: 0x0c, .. })
        ));
        assert_eq!(d.lock().unwrap().setup.as_ref().unwrap().index, at + 1);
        let attempt = transport.snapshot().initialization.as_ref().unwrap();
        assert_eq!(
            attempt.commands.last().unwrap().returned.as_ref().unwrap()[0],
            0x0c
        );
        assert!(attempt.report.is_none());
    }
    let (mut transport, _, provider, _) =
        setup_fixture(0x5fa0, "a0", false, HciFault::Reject(0, 0x0c));
    let report = transport.initialize(&provider).unwrap();
    assert_eq!(
        report.ptb,
        PtbDisposition::Rejected {
            status: 0x0c,
            returned: vec![0x0c]
        }
    );
    assert_eq!(
        transport
            .snapshot()
            .initialization
            .as_ref()
            .unwrap()
            .ptb_disposition,
        Some(report.ptb)
    );
}
#[test]
fn native_malformed_wrong_duplicate_and_late_hci_are_terminal_with_raw_transcript() {
    for fault in [
        HciFault::WrongOpcode(0),
        HciFault::Duplicate(0),
        HciFault::MalformedAfter(0),
        HciFault::Late(0),
        HciFault::ReadLength,
    ] {
        for fail_retire in [false, true] {
            let (mut transport, d, provider, _) = setup_fixture(0x5f71, "c2", false, fault);
            d.lock().unwrap().fail_retire = fail_retire;
            let error = transport.initialize(&provider).unwrap_err();
            assert_eq!(transport.state(), State::Failed);
            assert!(
                transport
                    .snapshot()
                    .initialization
                    .as_ref()
                    .unwrap()
                    .report
                    .is_none()
            );
            let writes = d.lock().unwrap().writes;
            let observed = transport.take_observations();
            if fault != HciFault::Late(0) {
                assert!(!observed.packets.is_empty());
                assert!(observed.packets.iter().all(|p| p.footer.len() == 264));
            }
            assert_eq!(transport.close(), Err(error));
            drop(transport);
            let d = d.lock().unwrap();
            assert_eq!(d.writes, writes);
            assert_eq!(d.retire, 1);
            assert!(!d.dropped);
            assert_eq!(d.domain.0.lock().unwrap().unmaps, 0);
        }
    }
}
#[test]
fn actual_address_property_requires_real_write_and_matching_readback() {
    for fault in [HciFault::IgnoreAddressWrite, HciFault::InvalidReadback] {
        let (mut transport, _, provider, _) = setup_fixture(0x5f72, "z9", true, fault);
        assert!(matches!(
            transport.initialize(&provider),
            Err(Error::Hci { .. })
        ));
        let attempt = transport.snapshot().initialization.as_ref().unwrap();
        assert_eq!(attempt.stage, InitializationStage::VerifyAddress);
        assert!(attempt.report.is_none());
        assert_eq!(
            attempt.address_property.as_ref().unwrap().bytes,
            [0x52, 0x43, 0x34, 0x25, 0x16, 7]
        );
    }
    for property in [
        None,
        Some(vec![0; 6]),
        Some(vec![0xff; 6]),
        Some(vec![1; 5]),
        Some(vec![0x93, 0x76, 0, 0, 0x88, 0x43]),
    ] {
        let (mut transport, d, provider, _) = setup_fixture(0x5f72, "z9", true, HciFault::None);
        {
            let mut d = d.lock().unwrap();
            d.properties.remove("local-bd-address");
            if let Some(bytes) = property {
                d.properties.insert("local-bd-address", bytes);
            }
        }
        assert!(transport.initialize(&provider).is_err());
        assert!(
            !d.lock()
                .unwrap()
                .sent
                .iter()
                .any(|(_, packet, _)| packet[..2] == [1, 0xfc])
        );
    }
}
#[test]
fn metadata_labels_do_not_supply_actual_board_calibration_or_live_hci_credits() {
    for property in [None, Some(vec![]), Some(vec![0; 4 * 1024 * 1024 + 1])] {
        let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
        let diagnostic = property
            .as_ref()
            .map(|bytes| PropertyDiagnostic::Rejected {
                name: "brcm,taurus-bf-cal-blob",
                bytes: bytes.len(),
                sha256: Sha256::digest(bytes).into(),
            })
            .unwrap_or(PropertyDiagnostic::Missing {
                name: "brcm,taurus-bf-cal-blob",
            });
        {
            let mut d = d.lock().unwrap();
            d.properties.remove("brcm,taurus-bf-cal-blob");
            if let Some(bytes) = property {
                d.properties.insert("brcm,taurus-bf-cal-blob", bytes);
            }
        }
        assert!(transport.initialize(&provider).is_err());
        assert_eq!(
            transport
                .snapshot()
                .initialization
                .as_ref()
                .unwrap()
                .property_diagnostics,
            vec![diagnostic]
        );
        assert!(d.lock().unwrap().sent.is_empty());
        assert_eq!(
            transport.snapshot().initialization.as_ref().unwrap().stage,
            InitializationStage::Calibration
        );
    }
    let (mut transport, d) = active(0x5fa0);
    let provider = catalog(&d, false);
    let writes = d.lock().unwrap().writes;
    assert_eq!(
        transport.initialize(&provider),
        Err(Error::State(State::Active))
    );
    assert_eq!(d.lock().unwrap().writes, writes);
}
struct SetupProvider {
    catalog: Catalog,
    kind: crate::firmware::ErrorKind,
    calls: core::cell::Cell<usize>,
}
impl Provider for SetupProvider {
    fn load(
        &self,
        requirement: crate::firmware::Requirement<'_>,
    ) -> core::result::Result<crate::firmware::Image<'_>, crate::firmware::Error> {
        if requirement.name.ends_with(".ptb") {
            self.calls.set(self.calls.get() + 1);
            Err(crate::firmware::Error {
                name: requirement.name.into(),
                kind: self.kind.clone(),
            })
        } else {
            self.catalog.load(requirement)
        }
    }
}
#[test]
fn actual_ptb_missing_fallback_and_nonmissing_refusal_preserve_completed_calibration() {
    let (mut transport, d, _, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
    let ptb = (0..415).map(|n| (n % 239) as u8).collect::<Vec<_>>();
    let fallback = setup_catalog(&d, &ptb, true);
    transport.initialize(&fallback).unwrap();
    let attempt = transport.snapshot().initialization.as_ref().unwrap();
    assert!(
        attempt
            .ptb
            .as_ref()
            .unwrap()
            .name
            .ends_with("-apple,formosa.ptb")
    );
    assert_eq!(transport.snapshot().firmware_errors.len(), 1);
    for kind in [
        crate::firmware::ErrorKind::Missing,
        crate::firmware::ErrorKind::WrongTarget,
        crate::firmware::ErrorKind::DigestMismatch {
            expected: [1; 32],
            actual: [2; 32],
        },
    ] {
        let (mut transport, d, catalog, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
        let missing = kind == crate::firmware::ErrorKind::Missing;
        let provider = SetupProvider {
            catalog,
            kind,
            calls: core::cell::Cell::new(0),
        };
        assert!(matches!(
            transport.initialize(&provider),
            Err(Error::Firmware(_))
        ));
        assert_eq!(provider.calls.get(), if missing { 2 } else { 1 });
        let attempt = transport.snapshot().initialization.as_ref().unwrap();
        assert_eq!(attempt.stage, InitializationStage::Ptb);
        assert!(attempt.calibration.is_some());
        assert_eq!(attempt.commands.len(), 3);
        assert!(
            attempt
                .commands
                .iter()
                .all(|c| c.returned.as_ref().unwrap() == &[0])
        );
        assert_eq!(d.lock().unwrap().setup.as_ref().unwrap().index, 3);
        assert_eq!(transport.take_observations().packets.len(), 6);
    }
}
#[test]
fn actual_ptb_capacity_refuses_without_truncated_hci_or_fallback() {
    for (device, ptb) in [
        (0x5fa0, vec![0xa1; 256]),
        (0x5f69, vec![0xa2; 4 * 1024 * 1024 + 1]),
    ] {
        let (mut transport, d, _, _) = setup_fixture(device, "b1", false, HciFault::None);
        let provider = setup_catalog(&d, &ptb, false);
        assert!(transport.initialize(&provider).is_err());
        let attempt = transport.snapshot().initialization.as_ref().unwrap();
        assert_eq!(attempt.ptb.as_ref().unwrap().length, ptb.len());
        assert_eq!(
            d.lock().unwrap().setup.as_ref().unwrap().index,
            if device == 0x5fa0 { 0 } else { 3 }
        );
        assert!(attempt.report.is_none());
    }
}
#[test]
fn initialization_transcript_bound_keeps_real_completion_before_terminal_refusal() {
    let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
    // Ten startup control ACKs, then async event+HCI CC fit;
    // its transfer ACK is the observation crossing the bound.
    transport.observation_bytes = OBSERVATION_BYTES - 160 - 585;
    assert_eq!(
        transport.initialize(&provider),
        Err(Error::ObservationLimit)
    );
    let observed = transport.take_observations();
    assert_eq!(observed.packets.len(), 2);
    assert_eq!(observed.packets[1].bytes, [0x0e, 4, 1, 0x97, 0xfd, 0]);
    assert_eq!(observed.packets[1].footer.len(), 264);
    assert!(
        transport
            .snapshot()
            .initialization
            .as_ref()
            .unwrap()
            .report
            .is_none()
    );
    assert_eq!(d.lock().unwrap().retire, 1);
}
#[test]
fn every_native_setup_mmio_effect_error_retains_first_fault_and_actual_domain() {
    let first = {
        let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", true, HciFault::None);
        transport.start(&provider).unwrap();
        d.lock().unwrap().operations + 1
    };
    let last = {
        let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", true, HciFault::None);
        transport.initialize(&provider).unwrap();
        d.lock().unwrap().operations
    };
    // All command-phase accesses, including RX credit/doorbells,
    // are bounded independently of startup OTP/config coverage above.
    for operation in first..=last {
        for fail_retire in [false, true] {
            let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", true, HciFault::None);
            {
                let mut d = d.lock().unwrap();
                d.fail_operation = Some(operation);
                d.fail_retire = fail_retire;
            }
            let error = transport.initialize(&provider).unwrap_err();
            let attempt = transport
                .snapshot()
                .initialization
                .as_ref()
                .unwrap()
                .clone();
            assert!(attempt.report.is_none());
            let observed = transport.take_observations();
            assert!(observed.packets.iter().all(|p| p.footer.len() == 264));
            let writes = d.lock().unwrap().writes;
            assert_eq!(transport.close(), Err(error));
            assert_eq!(
                transport.snapshot().initialization.as_ref().unwrap(),
                &attempt
            );
            drop(transport);
            let d = d.lock().unwrap();
            assert_eq!(d.writes, writes);
            assert_eq!(d.retire, 1);
            assert!(!d.dropped);
            assert_eq!(d.domain.0.lock().unwrap().unmaps, 0);
            if fail_retire && d.context != 0 {
                let domain = d.domain.clone();
                let address = d.context;
                drop(d);
                domain.write(address, &[0x91; 16]);
                assert_eq!(domain.read(address, 16), vec![0x91; 16]);
            }
        }
    }
}
#[test]
fn already_received_same_opcode_cannot_authorize_a_new_hci_command() {
    let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", false, HciFault::Preexisting);
    assert!(matches!(
        transport.initialize(&provider),
        Err(Error::Hci { .. })
    ));
    assert!(d.lock().unwrap().sent.is_empty());
    let observed = transport.take_observations();
    assert_eq!(observed.packets.len(), 1);
    assert_eq!(observed.packets[0].bytes, [0x0e, 4, 1, 0x97, 0xfd, 0]);
}
#[test]
fn actual_status_then_complete_preserves_both_events_and_only_complete_finishes() {
    let (mut transport, _, provider, expected) =
        setup_fixture(0x5f69, "b1", false, HciFault::StatusThenComplete(0));
    transport.initialize(&provider).unwrap();
    let observed = transport.take_observations();
    assert_eq!(observed.packets.len(), expected.len() * 2 + 1);
    assert!(
        observed
            .packets
            .iter()
            .any(|p| p.bytes == [0x0f, 4, 0, 1, 0x97, 0xfd])
    );
    assert_eq!(
        transport
            .snapshot()
            .initialization
            .as_ref()
            .unwrap()
            .commands[0]
            .returned,
        Some(vec![0])
    );
}
#[test]
fn every_native_setup_visibility_error_keeps_command_and_packet_evidence() {
    let first = {
        let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", true, HciFault::None);
        transport.start(&provider).unwrap();
        d.lock().unwrap().domain.0.lock().unwrap().syncs + 1
    };
    let last = {
        let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", true, HciFault::None);
        transport.initialize(&provider).unwrap();
        d.lock().unwrap().domain.0.lock().unwrap().syncs
    };
    for fail in first..=last {
        for fail_retire in [false, true] {
            let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", true, HciFault::None);
            {
                let mut d = d.lock().unwrap();
                d.domain.0.lock().unwrap().fail_sync = Some(fail);
                d.fail_retire = fail_retire;
            }
            let error = transport.initialize(&provider).unwrap_err();
            assert!(
                transport
                    .snapshot()
                    .initialization
                    .as_ref()
                    .unwrap()
                    .report
                    .is_none()
            );
            let evidence = transport
                .snapshot()
                .initialization
                .as_ref()
                .unwrap()
                .clone();
            let observed = transport.take_observations();
            assert!(observed.packets.iter().all(|p| p.footer.len() == 264));
            let writes = d.lock().unwrap().writes;
            assert_eq!(transport.close(), Err(error));
            assert_eq!(
                transport.snapshot().initialization.as_ref(),
                Some(&evidence)
            );
            drop(transport);
            let d = d.lock().unwrap();
            assert_eq!(d.retire, 1);
            assert_eq!(d.writes, writes);
            assert!(!d.dropped);
            assert_eq!(d.domain.0.lock().unwrap().unmaps, 0);
        }
    }
}
#[test]
fn successful_setup_report_and_original_properties_survive_later_unmap_failure() {
    let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", true, HciFault::None);
    let report = transport.initialize(&provider).unwrap();
    let evidence = transport
        .snapshot()
        .initialization
        .as_ref()
        .unwrap()
        .clone();
    d.lock().unwrap().domain.0.lock().unwrap().fail_unmap = true;
    assert_eq!(
        transport.close(),
        Err(Error::Dma(DmaError::InvalidationFailed))
    );
    assert_eq!(
        transport.snapshot().initialization.as_ref(),
        Some(&evidence)
    );
    assert_eq!(evidence.report, Some(report));
    drop(transport);
    let d = d.lock().unwrap();
    assert_eq!(d.retire, 1);
    assert_eq!(d.domain.0.lock().unwrap().unmaps, 1);
    assert!(!d.dropped);
}
struct SlowBin {
    catalog: Catalog,
    device: Arc<Mutex<Device>>,
    missing: bool,
    calls: core::cell::Cell<usize>,
}
impl Provider for SlowBin {
    fn load(
        &self,
        requirement: crate::firmware::Requirement<'_>,
    ) -> core::result::Result<crate::firmware::Image<'_>, crate::firmware::Error> {
        self.calls.set(self.calls.get() + 1);
        if requirement.name.ends_with(".bin") {
            self.device.lock().unwrap().ticks += 121_000_000;
            if self.missing {
                return Err(crate::firmware::Error {
                    name: requirement.name.into(),
                    kind: crate::firmware::ErrorKind::Missing,
                });
            }
        }
        self.catalog.load(requirement)
    }
}
#[test]
fn outer_budget_contains_late_bin_lookup_before_firmware_or_irq_publication() {
    for missing in [false, true] {
        for fail_retire in [false, true] {
            let (mut transport, d, catalog, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
            d.lock().unwrap().fail_retire = fail_retire;
            let provider = SlowBin {
                catalog,
                device: d.clone(),
                missing,
                calls: core::cell::Cell::new(0),
            };
            let error = transport.initialize(&provider).unwrap_err();
            let cause = match &error {
                Error::Cleanup { cause, .. } => cause.as_ref(),
                other => other,
            };
            assert_eq!(
                cause,
                &Error::Timeout("complete Broadcom controller initialization")
            );
            assert_eq!(provider.calls.get(), 1);
            if missing {
                assert!(transport.firmware().is_none());
                assert_eq!(transport.snapshot().firmware_errors.len(), 1);
            } else {
                assert_eq!(transport.firmware().unwrap().length, 64);
                assert_eq!(
                    transport.firmware().unwrap().sha256,
                    Sha256::digest([0xa5; 64]).as_slice()
                );
            }
            assert_eq!(
                transport.firmware.as_ref().unwrap().read(0, 64),
                vec![0; 64]
            );
            assert_eq!(transport.close(), Err(error));
            let d = d.lock().unwrap();
            assert!(!d.armed);
            assert_eq!(d.boot, 0);
            assert_eq!(d.rti, 0);
            assert!(d.controls.is_empty());
            assert!(!d.registers.contains_key(&(2, 0x200478)));
            assert_eq!(d.domain.0.lock().unwrap().syncs, 0);
            assert_eq!(d.retire, 1);
        }
    }
}
#[test]
fn outer_budget_contains_configuration_and_otp_expiry_with_observed_bytes() {
    for otp in [false, true] {
        for fail_retire in [false, true] {
            let (mut transport, d, provider, _) =
                setup_fixture(0x5f69, "b1", false, HciFault::None);
            let (space, offset) = if otp {
                (Space::Bar0, 0x4125)
            } else {
                (Space::Configuration, 0)
            };
            {
                let mut d = d.lock().unwrap();
                d.read_delay = Some((space, offset, 121_000_000));
                d.fail_retire = fail_retire;
            }
            assert!(transport.initialize(&provider).is_err());
            let snapshot = transport.snapshot();
            assert!(
                matches!(snapshot.native_access,Some(RegisterAccess::Read{space:s,offset:o,width,..}) if s==space&&o==offset&&width==if otp{1}else{4})
            );
            assert_eq!(snapshot.otp.len(), if otp { 6 } else { 0 });
            if otp {
                assert_eq!(snapshot.otp, &d.lock().unwrap().otp[..6]);
            }
            assert!(transport.firmware().is_none());
            let writes = d.lock().unwrap().writes;
            let error = transport.fault().unwrap().clone();
            assert_eq!(transport.close(), Err(error));
            let d = d.lock().unwrap();
            assert_eq!(d.writes, writes);
            assert!(!d.armed);
            assert_eq!(d.domain.0.lock().unwrap().syncs, 0);
            assert_eq!(d.retire, 1);
            assert!(d.controls.is_empty());
        }
    }
}
#[test]
fn outer_budget_stops_after_late_firmware_rti_or_control_effect_without_next_publication() {
    for (offset, expected_boot, expected_rti, controls) in
        [(0x140, 2, 0, 0), (0x144, 2, 1, 0), (0x174, 2, 2, 1)]
    {
        for fail_retire in [false, true] {
            let (mut transport, d, provider, _) =
                setup_fixture(0x5f69, "b1", false, HciFault::None);
            {
                let mut d = d.lock().unwrap();
                d.delay_offset = Some((offset, 121_000_000));
                d.fail_retire = fail_retire;
            }
            let error = transport.initialize(&provider).unwrap_err();
            let cause = match &error {
                Error::Cleanup { cause, .. } => cause.as_ref(),
                other => other,
            };
            assert_eq!(
                cause,
                &Error::Timeout("complete Broadcom controller initialization")
            );
            assert!(
                matches!(transport.snapshot().native_access,Some(RegisterAccess::Write{space:Space::Bar0,offset:o,returned:true,..}) if o==offset)
            );
            assert_eq!(transport.firmware().unwrap().length, 64);
            let writes = d.lock().unwrap().writes;
            assert_eq!(transport.close(), Err(error));
            let d = d.lock().unwrap();
            assert_eq!(
                (d.boot, d.rti, d.controls.len()),
                (expected_boot, expected_rti, controls)
            );
            assert_eq!(d.writes, writes);
            assert_eq!(d.retire, 1);
            assert!(d.sent.is_empty());
            if offset == 0x140 {
                assert!(!d.registers.contains_key(&(0, 0x144)));
            }
            if offset == 0x144 {
                assert!(!d.registers.contains_key(&(2, 0x20048c)));
            }
            if offset == 0x174 {
                assert_eq!(d.controls[0][0], 2);
                assert_eq!(u16at(&d.controls[0], 4), 1);
            }
        }
    }
}
#[test]
fn outer_budget_contains_late_dma_visibility_and_msi_admission() {
    for sync in 1..=3 {
        let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
        d.lock().unwrap().domain.0.lock().unwrap().delay_sync = Some(sync);
        assert_eq!(
            transport.initialize(&provider),
            Err(Error::Timeout(
                "complete Broadcom controller initialization"
            ))
        );
        let d = d.lock().unwrap();
        assert_eq!(d.domain.0.lock().unwrap().syncs, sync);
        assert_eq!(
            (d.boot, d.rti),
            match sync {
                1 => (0, 0),
                2 => (2, 1),
                3 => (2, 2),
                _ => unreachable!(),
            }
        );
        assert!(d.controls.is_empty());
        assert_eq!(d.retire, 1);
        if sync == 1 {
            assert!(!d.armed);
            assert!(!d.registers.contains_key(&(0, 0x590)));
        }
        if sync == 2 {
            assert!(!d.registers.contains_key(&(2, 0x20048c)));
        }
    }
    let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
    d.lock().unwrap().arm_delay = 121_000_000;
    assert_eq!(
        transport.initialize(&provider),
        Err(Error::Timeout(
            "complete Broadcom controller initialization"
        ))
    );
    let d = d.lock().unwrap();
    assert!(d.armed);
    assert!(!d.registers.contains_key(&(0, 0x590)));
    assert_eq!(d.boot, 0);
    assert_eq!(d.retire, 1);
}
#[test]
fn original_visibility_failure_has_priority_over_expiry_and_failed_retirement() {
    let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
    {
        let mut d = d.lock().unwrap();
        d.fail_retire = true;
        let mut domain = d.domain.0.lock().unwrap();
        domain.delay_sync = Some(1);
        domain.fail_sync = Some(1);
    }
    let error = transport.initialize(&provider).unwrap_err();
    assert!(
        matches!(&error,Error::Cleanup{cause,cleanup} if **cause==Error::Dma(DmaError::VisibilityFailed)&&**cleanup==Error::Unsupported("independent root drain failed"))
    );
    assert_eq!(transport.close(), Err(error));
    assert_eq!(transport.firmware().unwrap().length, 64);
    let d = d.lock().unwrap();
    assert_eq!(d.retire, 1);
    assert!(!d.armed);
    assert_eq!(d.domain.0.lock().unwrap().unmaps, 0);
}
fn first_hci_visibility() -> usize {
    let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
    transport.start(&provider).unwrap();
    let first = d.lock().unwrap().domain.0.lock().unwrap().syncs + 1;
    transport.close().unwrap();
    first
}
#[test]
fn active_hci_budget_stops_after_11s_visibility_or_sleep_before_head_and_doorbell() {
    let first = first_hci_visibility();
    for sleep in [false, true] {
        for fail_retire in [false, true] {
            let (mut transport, d, provider, _) = setup_fixture(
                0x5f69,
                "b1",
                false,
                if sleep {
                    HciFault::LateSleep
                } else {
                    HciFault::None
                },
            );
            {
                let mut d = d.lock().unwrap();
                d.fail_retire = fail_retire;
                if !sleep {
                    let mut domain = d.domain.0.lock().unwrap();
                    domain.delay_sync = Some(first);
                    domain.sync_delay_us = 11_000_000;
                }
            }
            let error = transport.initialize(&provider).unwrap_err();
            let cause = match &error {
                Error::Cleanup { cause, .. } => cause.as_ref(),
                other => other,
            };
            assert_eq!(
                cause,
                &Error::Timeout("actual Broadcom HCI response or credits")
            );
            assert_eq!(transport.core().read16(128 + 24 + 2), 0);
            let attempt = transport.snapshot().initialization.as_ref().unwrap();
            assert_eq!(attempt.commands.len(), 1);
            assert!(attempt.commands[0].submission.is_none());
            assert!(attempt.commands[0].returned.is_none());
            assert!(attempt.report.is_none());
            assert!(transport.request_deadline.is_none());
            assert!(transport.initialization_deadline.is_none());
            if sleep {
                assert_eq!(
                    transport.snapshot().native_access,
                    Some(RegisterAccess::Write {
                        space: Space::Bar0,
                        offset: 0x150,
                        value: 2,
                        returned: true
                    })
                );
            }
            let writes = d.lock().unwrap().writes;
            assert_eq!(transport.close(), Err(error));
            drop(transport);
            let d = d.lock().unwrap();
            assert!(d.sent.is_empty());
            assert_eq!(d.setup.as_ref().unwrap().index, 0);
            assert!(!d.doorbells.iter().any(|value| (value >> 8) & 0xff == 1));
            assert_eq!(d.writes, writes);
            assert_eq!(d.retire, 1);
            assert!(!d.dropped);
            assert_eq!(d.domain.0.lock().unwrap().unmaps, 0);
        }
    }
}
#[test]
fn active_request_guards_keep_global_priority_and_first_native_visibility_failure() {
    let first = first_hci_visibility();
    let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
    {
        let d = d.lock().unwrap();
        let mut domain = d.domain.0.lock().unwrap();
        domain.delay_sync = Some(first);
        domain.sync_delay_us = 121_000_000;
    }
    assert_eq!(
        transport.initialize(&provider),
        Err(Error::Timeout(
            "complete Broadcom controller initialization"
        ))
    );
    assert_eq!(transport.core().read16(128 + 24 + 2), 0);
    let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
    {
        let mut d = d.lock().unwrap();
        d.fail_retire = true;
        let mut domain = d.domain.0.lock().unwrap();
        domain.delay_sync = Some(first);
        domain.sync_delay_us = 11_000_000;
        domain.fail_sync = Some(first);
    }
    let error = transport.initialize(&provider).unwrap_err();
    assert!(
        matches!(&error,Error::Cleanup{cause,..} if **cause==Error::Dma(DmaError::VisibilityFailed))
    );
    assert_eq!(transport.core().read16(128 + 24 + 2), 0);
    assert_eq!(transport.close(), Err(error));
    assert_eq!(d.lock().unwrap().retire, 1);
}
#[test]
fn ordinary_control_budget_blocks_late_visibility_before_its_head_or_doorbell() {
    let (mut transport, d, provider, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
    {
        let d = d.lock().unwrap();
        let mut domain = d.domain.0.lock().unwrap();
        domain.delay_sync = Some(3);
        domain.sync_delay_us = 2_000_000;
    }
    assert_eq!(
        transport.start(&provider),
        Err(Error::Timeout(
            "actual Broadcom control-ring acknowledgment"
        ))
    );
    assert_eq!(transport.core().read16(128 + 24), 0);
    assert!(transport.snapshot().initialization.is_none());
    let d = d.lock().unwrap();
    assert_eq!((d.boot, d.rti), (2, 2));
    assert!(d.controls.is_empty());
    assert!(d.doorbells.is_empty());
    assert_eq!(d.retire, 1);
}
struct SlowPtb {
    catalog: Catalog,
    device: Arc<Mutex<Device>>,
}
impl Provider for SlowPtb {
    fn load(
        &self,
        requirement: crate::firmware::Requirement<'_>,
    ) -> core::result::Result<crate::firmware::Image<'_>, crate::firmware::Error> {
        if requirement.name.ends_with(".ptb") {
            self.device.lock().unwrap().ticks += 11_000_000;
        }
        self.catalog.load(requirement)
    }
}
#[test]
fn command_deadline_ends_before_intercommand_resource_lookup_and_normal_close() {
    let (mut transport, d, catalog, _) = setup_fixture(0x5f69, "b1", false, HciFault::None);
    let provider = SlowPtb {
        catalog,
        device: d.clone(),
    };
    let report = transport.initialize(&provider).unwrap();
    assert_eq!(report.ptb, PtbDisposition::Accepted);
    assert!(transport.request_deadline.is_none());
    assert!(transport.initialization_deadline.is_none());
    d.lock().unwrap().ticks += 11_000_000;
    transport.close().unwrap();
    let d = d.lock().unwrap();
    assert_eq!(d.retire, 1);
    assert!(d.domain.0.lock().unwrap().leases.is_empty());
}
