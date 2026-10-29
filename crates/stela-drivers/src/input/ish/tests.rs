// SPDX-License-Identifier: GPL-2.0-only
//! Software qualification controls, never physical/native-platform evidence.
//! Original owned config + BAR Mapping + real IRQ Registry surround a separate
//! firmware/register peer. Production MappedRegisters performs every BAR access.
extern crate std;
use super::{native::*, protocol::*, registers::*, *};
use crate::bus::{
    dma::{
        mapping::{Direction, DmaDomain, DmaError, DomainMapping},
        pages::DmaPages,
    },
    irq::{self, Registry},
    mmio::owned::{MappingView, PhysicalSpan},
    pci::{
        Address, ConfigSpace, Function,
        msi::MsiConfigSpace,
        owned::{
            OwnedConfig,
            tests::{Counters, fixture},
        },
    },
};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    ops::Range,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering},
};
use std::sync::Mutex;

fn report_descriptor() -> Vec<u8> {
    let mut d = vec![
        0x05, 0x20, 0x09, 0x73, 0xa1, 0x01, 0x85, 1, 0x75, 8, 0x95, 8, 0x81, 2, 0x95, 3, 0xb1, 2,
    ];
    for _ in 0..80 {
        d.extend_from_slice(&[0x09, 1]);
    }
    d.push(0xc0);
    d
}
fn input_bytes() -> Vec<u8> {
    vec![1, 255, 255, 255, 255, 255, 255, 255, 255]
}
fn hostif(command: u8, id: u8, b: &[u8]) -> Vec<u8> {
    let mut v = vec![command, id, 0, 0];
    v.extend_from_slice(&(b.len() as u16).to_le_bytes());
    v.extend_from_slice(b);
    v
}
fn transport(fw: u8, host: u8, b: &[u8], complete: bool) -> Vec<u8> {
    let word = u32::from(fw)
        | (u32::from(host) << 8)
        | ((b.len() as u32) << 16)
        | (u32::from(complete) << 31);
    let mut v = word.to_le_bytes().to_vec();
    v.extend_from_slice(b);
    v
}
fn wire(protocol: u8, command: u8, b: Vec<u8>) -> (u32, Vec<u8>) {
    (
        BUSY | (u32::from(protocol) << 10) | (u32::from(command) << 16) | b.len() as u32,
        b,
    )
}
struct Data {
    now: u64,
    ready_at: u64,
    ready_written: bool,
    descriptor: Vec<u8>,
    outgoing: VecDeque<(u32, Vec<u8>)>,
    clients: VecDeque<Vec<u8>>,
    rx_credit: bool,
    tx_assembly: Vec<u8>,
    host_credit: bool,
    events: Vec<(bool, u32, u32)>,
    host_messages: Vec<Vec<u8>>,
    wrong_guid: bool,
    wrong_reset: bool,
    duplicate_credit: bool,
    bad_id: bool,
    duplicate_id: bool,
    bad_property: bool,
    no_delivery: bool,
    ignore_pimr: bool,
    ignore_msi: bool,
    stuck_dma: bool,
    fail_drain: bool,
    busy_mailbox: bool,
    removed: Option<u32>,
    access_fault: Option<u32>,
    mix_input: bool,
    first_enable_reset: bool,
    inject_at: Option<usize>,
    injected: bool,
    reset_acks: usize,
    settle_reset_after: Option<u64>,
    hold_ack_us: u64,
    held_ack: Option<(u64, u32, Vec<u8>)>,
    fw_ready_observed_at: u64,
    input_ready_at: u64,
    feature_wire_bytes: usize,
    client_fragment_lengths: Vec<usize>,
    hold_client_us: u64,
    held_client: Option<(u64, u32, Vec<u8>)>,
}
impl Data {
    fn new() -> Self {
        Self {
            now: 0,
            ready_at: 0,
            ready_written: false,
            descriptor: report_descriptor(),
            outgoing: VecDeque::new(),
            clients: VecDeque::new(),
            rx_credit: false,
            tx_assembly: Vec::new(),
            host_credit: false,
            events: Vec::new(),
            host_messages: Vec::new(),
            wrong_guid: false,
            wrong_reset: false,
            duplicate_credit: false,
            bad_id: false,
            duplicate_id: false,
            bad_property: false,
            no_delivery: false,
            ignore_pimr: false,
            ignore_msi: false,
            stuck_dma: false,
            fail_drain: false,
            busy_mailbox: false,
            removed: None,
            access_fault: None,
            mix_input: false,
            first_enable_reset: false,
            inject_at: None,
            injected: false,
            reset_acks: 0,
            settle_reset_after: None,
            hold_ack_us: 0,
            held_ack: None,
            fw_ready_observed_at: 0,
            input_ready_at: 0,
            feature_wire_bytes: 4,
            client_fragment_lengths: Vec::new(),
            hold_client_us: 0,
            held_client: None,
        }
    }
    fn hbm(&mut self, b: &[u8]) {
        self.outgoing
            .push_back(wire(1, 0, transport(0, 0, b, true)));
    }
    fn client(&mut self, b: Vec<u8>) {
        self.clients.push_back(b);
        self.flush_client();
    }
    fn flush_client(&mut self) {
        if self.rx_credit
            && let Some(b) = self.clients.pop_front()
        {
            self.rx_credit = false;
            let count = b.len().div_ceil(MTU);
            for (index, part) in b.chunks(MTU).enumerate() {
                self.outgoing
                    .push_back(wire(1, 0, transport(5, 1, part, index + 1 == count)));
            }
        }
    }
    fn credit(&mut self) {
        self.host_credit = true;
        self.hbm(&[8, 5, 1, 0, 0, 0, 0, 0]);
    }
    fn receive_from_host(&mut self, doorbell: u32, b: &[u8]) {
        if (doorbell >> 10) & 15 == 3 {
            match (doorbell >> 16) & 15 {
                3 => {
                    assert_eq!(b, [1, 0, 0, 0]);
                    self.ready_at = self.now + 20_000;
                    self.ready_written = false;
                    self.outgoing.push_back(wire(
                        3,
                        4,
                        if self.wrong_reset {
                            vec![2, 0, 0, 0]
                        } else {
                            b.to_vec()
                        },
                    ));
                }
                4 => {
                    assert_eq!(b, [0x34, 0x12, 0, 0]);
                    self.reset_acks += 1;
                }
                5 => panic!("no fake UTC clock synchronization may be sent"),
                n => panic!("unexpected management command {n}"),
            }
            return;
        }
        assert_eq!((doorbell >> 10) & 15, 1);
        let h = u32::from_le_bytes(b[..4].try_into().unwrap());
        assert_eq!(((h >> 16) & 511) as usize, b.len() - 4);
        assert_eq!(h & 0x7e00_0000, 0);
        if h & 0xffff == 0 {
            let p = &b[4..];
            match p[0] {
                1 => {
                    assert_eq!(p, [1, 0, 0, 1]);
                    assert!(
                        self.now >= self.fw_ready_observed_at.max(self.input_ready_at) + 300_000,
                        "actual300ms ready settle precedes HBM"
                    );
                    self.hbm(&[0x81, 1, 0, 1]);
                }
                4 => {
                    let mut r = vec![0x84, 0, 0, 0];
                    r.extend_from_slice(&[0; 32]);
                    r[4] |= 1 << 5;
                    r[6] |= 1 << 1;
                    self.hbm(&r);
                }
                5 => {
                    let mut r = vec![0; 32];
                    r[0] = 0x85;
                    r[1] = p[1];
                    if p[1] == 5 {
                        r[4..20].copy_from_slice(&HID_GUID);
                        if self.wrong_guid {
                            r[4] ^= 1;
                        }
                    } else {
                        assert_eq!(p[1], 17);
                        r[4] = 17;
                    }
                    r[20] = 1;
                    r[21] = 1;
                    r[23] = u8::from(self.bad_property);
                    r[24..28].copy_from_slice(&4096u32.to_le_bytes());
                    self.hbm(&r);
                }
                6 => {
                    assert_eq!(p, [6, 5, 1, 0]);
                    self.hbm(&[0x86, 5, 1, 0]);
                    self.credit();
                    if self.duplicate_credit {
                        self.hbm(&[8, 5, 1, 0, 0, 0, 0, 0]);
                    }
                }
                8 => {
                    assert_eq!(p, [8, 5, 1, 0, 0, 0, 0, 0]);
                    assert!(
                        !self.rx_credit,
                        "only one credit with one retained message buffer"
                    );
                    self.rx_credit = true;
                    self.flush_client();
                }
                7 => {
                    assert_eq!(p, [7, 5, 1, 0]);
                    self.hbm(&[0x87, 5, 1, 0]);
                }
                2 => {
                    assert_eq!(p, [2, 0, 0, 0]);
                    self.hbm(&[0x82, 0, 0, 0]);
                }
                n => panic!("unexpected HBM {n}; no DMA buffer negotiation permitted"),
            }
            return;
        }
        assert_eq!(h & 0xffff, 0x105);
        self.client_fragment_lengths.push(b.len() - 4);
        if self.tx_assembly.is_empty() {
            assert!(self.host_credit, "one credit per complete message");
            self.host_credit = false;
        }
        self.tx_assembly.extend_from_slice(&b[4..]);
        if h & BUSY != 0 {
            let msg = core::mem::take(&mut self.tx_assembly);
            assert_eq!(
                &msg[2..6],
                &[0, 0, 0, 0],
                "source request fields remain zero"
            );
            self.host_messages.push(msg.clone());
            let id = msg[1];
            let response = match msg[0] {
                33 => {
                    let mut r = vec![if self.duplicate_id { 2 } else { 1 }];
                    let dev = if self.bad_id { 256u32 } else { 7u32 };
                    r.extend_from_slice(&dev.to_le_bytes());
                    r.push(0);
                    r.extend_from_slice(&0x1234u16.to_le_bytes());
                    r.extend_from_slice(&0x8086u16.to_le_bytes());
                    if self.duplicate_id {
                        let old = r[1..].to_vec();
                        r.extend_from_slice(&old);
                    }
                    hostif(0xa1, 0, &r)
                }
                0 => {
                    assert_eq!(id, 7);
                    let n = self.descriptor.len() as u16;
                    hostif(
                        0x80,
                        id,
                        &[9, 0x21, 0x11, 1, 0, 1, 0x22, n as u8, (n >> 8) as u8],
                    )
                }
                1 => {
                    assert_eq!(id, 7);
                    hostif(0x81, id, &self.descriptor)
                }
                2 => {
                    assert_eq!(&msg[6..], &[1]);
                    hostif(0x82, id, &[1, 9, 8, 7])
                }
                3 => {
                    assert_eq!(msg.len(), 6 + self.feature_wire_bytes);
                    assert_eq!(msg[6], 1);
                    hostif(0x83, id, &[0xaa, 0xbb])
                }
                4 => {
                    assert_eq!(&msg[6..], &[1]);
                    hostif(0x84, id, &input_bytes())
                }
                n => panic!("unexpected HostIF request {n}"),
            };
            if self.mix_input && matches!(msg[0], 2..=4) {
                self.client(hostif(0x85, 7, &input_bytes()));
            }
            self.client(response);
            self.credit();
        }
    }
}
struct Peer {
    view: MappingView,
    state: Mutex<Data>,
    registry: AtomicPtr<Registry<Cpu>>,
    vector: AtomicU8,
    command: AtomicUsize,
    msi: AtomicBool,
    eois: AtomicUsize,
    callbacks: AtomicUsize,
    in_callback: AtomicBool,
    masks: AtomicUsize,
    drains: AtomicUsize,
    root_drops: AtomicUsize,
    domain_drops: AtomicUsize,
}
impl Peer {
    fn raw_read(&self, at: u32) -> u32 {
        let p = self.view.address(at as usize, 4).unwrap();
        unsafe { p.as_ptr().cast::<u32>().read_volatile() }
    }
    fn raw_write(&self, at: u32, v: u32) {
        let p = self.view.address(at as usize, 4).unwrap();
        unsafe { p.as_ptr().cast::<u32>().write_volatile(v) }
    }
    fn deliver(&self) {
        if self.raw_read(PIMR) & 1 == 0
            || self.raw_read(PISR) & 1 == 0
            || !self.msi.load(Ordering::Acquire)
            || self.state.lock().unwrap().no_delivery
        {
            return;
        }
        let r = self.registry.load(Ordering::Acquire);
        assert!(!r.is_null());
        if self.in_callback.swap(true, Ordering::AcqRel) {
            return;
        }
        self.callbacks.fetch_add(1, Ordering::Relaxed);
        assert!(unsafe { &*r }.dispatch(self.vector.load(Ordering::Acquire)));
        self.in_callback.store(false, Ordering::Release);
        if !self.state.lock().unwrap().ignore_pimr {
            assert_eq!(
                self.raw_read(PIMR) & 1,
                0,
                "actual callback masks source before EOI/return"
            );
            self.masks.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn publish(&self) {
        if self.raw_read(I2H) & BUSY == 0 {
            let next = self.state.lock().unwrap().outgoing.pop_front();
            if let Some((doorbell, b)) = next {
                for (i, part) in b.chunks(4).enumerate() {
                    let mut word = [0; 4];
                    word[..part.len()].copy_from_slice(part);
                    self.raw_write(RX + 4 * i as u32, u32::from_le_bytes(word));
                }
                self.raw_write(I2H, doorbell);
                self.raw_write(PISR, self.raw_read(PISR) | 1);
            }
        }
        self.deliver();
    }
    fn event(&self, write: bool, at: u32, value: u32) -> bool {
        let mut s = self.state.lock().unwrap();
        s.events.push((write, at, value));
        if s.inject_at == Some(s.events.len()) {
            s.inject_at = None;
            s.injected = true;
            s.client(hostif(0x85, 7, &input_bytes()));
            true
        } else {
            false
        }
    }
    fn push_client(&self, b: Vec<u8>) {
        self.state.lock().unwrap().client(b);
        self.publish();
    }
}
struct ModelRegisters {
    native: MappedRegisters,
    peer: Arc<Peer>,
}
// SAFETY: explicit software register peer owns the actual isolated mapped CPU
// storage; production native accesses use that same Mapping. Firmware effects
// below are independent bounded device semantics, not native platform grants.
unsafe impl Registers for ModelRegisters {
    fn span(&self) -> PhysicalSpan {
        self.native.span()
    }
    fn read32(&self, at: u32) -> Result<u32> {
        let s = self.peer.state.lock().unwrap();
        if s.access_fault == Some(at) {
            return Err(Error::Access(at));
        }
        if s.removed == Some(at) {
            return Ok(u32::MAX);
        }
        drop(s);
        let v = self.native.read32(at)?;
        if self.peer.event(false, at, v) {
            self.peer.publish();
        }
        Ok(v)
    }
    fn write32(&self, at: u32, value: u32) -> Result<()> {
        self.peer.event(true, at, value);
        let mut s = self.peer.state.lock().unwrap();
        if s.access_fault == Some(at) {
            return Err(Error::Access(at));
        }
        if at == PIMR && s.ignore_pimr {
            return Ok(());
        }
        if (TX..TX + 128).contains(&at) {
            assert_eq!(
                self.peer.raw_read(H2I) & BUSY,
                0,
                "no TXregister overwrite while firmware owns mailbox"
            );
        }
        let old = self.peer.raw_read(at);
        self.native.write32(at, value)?;
        match at {
            PIMR => {
                if s.first_enable_reset && value & 1 != 0 {
                    s.first_enable_reset = false;
                    s.outgoing.push_front(wire(3, 3, vec![0x34, 0x12, 0, 0]));
                }
            }
            // Model-only busy-clear status bit; no production PISRbit8 claim.
            PISR => self.peer.raw_write(PISR, old & !(value & 0x100)),
            I2H if value == 0 => self.peer.raw_write(PISR, self.peer.raw_read(PISR) & !1),
            H2I => {
                assert_eq!(self.peer.command.load(Ordering::Acquire) & 6, 6);
                assert_eq!(self.peer.raw_read(RMP2), 1);
                assert_eq!(self.peer.raw_read(HOST_COMM) & 0x80, 0x80);
                if !s.busy_mailbox {
                    let n = (value & 0x3ff) as usize;
                    assert!(n <= 128);
                    let mut b = Vec::new();
                    for i in 0..n.div_ceil(4) {
                        b.extend_from_slice(&self.peer.raw_read(TX + 4 * i as u32).to_le_bytes());
                    }
                    b.truncate(n);
                    if (value >> 10) & 15 == 3 && (value >> 16) & 15 == 4 && s.hold_ack_us != 0 {
                        let deadline = s.now + s.hold_ack_us;
                        s.held_ack = Some((deadline, value, b));
                    } else if (value >> 10) & 15 == 1
                        && b.len() >= 4
                        && b[1] != 0
                        && s.hold_client_us != 0
                    {
                        let deadline = s.now + s.hold_client_us;
                        s.held_client = Some((deadline, value, b));
                    } else {
                        s.receive_from_host(value, &b);
                        s.input_ready_at = s.now;
                        self.peer.raw_write(H2I, 0);
                        self.peer.raw_write(PISR, self.peer.raw_read(PISR) | 0x100);
                    }
                }
            }
            RMP2 if value == 0 && s.stuck_dma => self
                .peer
                .raw_write(FWSTS, self.peer.raw_read(FWSTS) | IN_DMA),
            _ => {}
        }
        drop(s);
        self.peer.publish();
        Ok(())
    }
}
struct Config {
    native: OwnedConfig,
    peer: Arc<Peer>,
}
impl ConfigSpace for Config {
    fn read32(&self, at: u16) -> u32 {
        self.native.read32(at)
    }
    fn read16(&self, at: u16) -> u16 {
        self.native.read16(at)
    }
    fn read8(&self, at: u16) -> u8 {
        self.native.read8(at)
    }
    fn write32(&mut self, at: u16, v: u32) {
        self.native.write32(at, v);
    }
    fn write8(&mut self, at: u16, v: u8) {
        self.native.write8(at, v);
    }
    fn write16(&mut self, at: u16, v: u16) {
        if at == 0x52 && self.peer.state.lock().unwrap().ignore_msi {
            return;
        }
        self.native.write16(at, v);
        if at == 4 {
            self.peer.command.store(usize::from(v), Ordering::Release);
        }
        if at == 0x52 {
            self.peer.msi.store(v & 1 != 0, Ordering::Release);
        }
    }
}
// SAFETY: forwards actual exact-width native stores through the owned fixture.
unsafe impl MsiConfigSpace for Config {}
// SAFETY: same actual original fixture config owner, no duplicated access path.
unsafe impl Configuration for Config {
    fn owned_address(&self) -> Address {
        self.native.address()
    }
}
struct ClockModel(Arc<Peer>);
// SAFETY: this explicit fixture advances monotonically on every observation.
unsafe impl Time for ClockModel {
    fn now_us(&self) -> u64 {
        let mut s = self.0.state.lock().unwrap();
        s.now += 1000;
        if s.ready_at != 0 && s.now >= s.ready_at && !s.ready_written {
            self.0.raw_write(FWSTS, 0xf003);
            s.ready_written = true;
            s.fw_ready_observed_at = s.now;
        }
        let mut publish = s
            .settle_reset_after
            .is_some_and(|delay| s.ready_at != 0 && s.now >= s.ready_at + delay);
        if publish {
            s.settle_reset_after = None;
            s.outgoing.push_back(wire(3, 3, vec![0x34, 0x12, 0, 0]));
            self.0.raw_write(FWSTS, 0x4000);
            s.ready_written = false;
            s.ready_at = s.now + 20_000;
        }
        if s.held_ack.as_ref().is_some_and(|(due, _, _)| s.now >= *due) {
            let (_, doorbell, bytes) = s.held_ack.take().unwrap();
            s.receive_from_host(doorbell, &bytes);
            s.input_ready_at = s.now;
            self.0.raw_write(H2I, 0);
            self.0.raw_write(PISR, self.0.raw_read(PISR) | 0x100);
        }
        if s.held_client
            .as_ref()
            .is_some_and(|(due, _, _)| s.now >= *due)
        {
            let (_, doorbell, bytes) = s.held_client.take().unwrap();
            s.receive_from_host(doorbell, &bytes);
            s.input_ready_at = s.now;
            self.0.raw_write(H2I, 0);
            self.0.raw_write(PISR, self.0.raw_read(PISR) | 0x100);
            publish = true;
        }
        let now = s.now;
        drop(s);
        if publish {
            self.0.publish();
        }
        now
    }
}
struct Root(Arc<Peer>);
impl Drop for Root {
    fn drop(&mut self) {
        self.0.root_drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct Domain(Arc<Peer>);
impl Drop for Domain {
    fn drop(&mut self) {
        self.0.domain_drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: explicit requester domain peer never advertises/makes any host DMA
// mapping; it observes native stop ordering and actual retained fixture owners.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        _: &DmaPages,
        _: Direction,
        _: u64,
    ) -> core::result::Result<DomainMapping, DmaError> {
        panic!("mailbox profile publishes no host DMA address")
    }
    unsafe fn unmap(&self, _: DomainMapping) -> core::result::Result<(), DmaError> {
        panic!("no host DMA mapping")
    }
    unsafe fn sync_for_device(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> core::result::Result<(), DmaError> {
        panic!("no host DMA mapping")
    }
    unsafe fn sync_for_cpu(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> core::result::Result<(), DmaError> {
        panic!("no host DMA mapping")
    }
    unsafe fn drain_posted_writes(&self) -> core::result::Result<(), DmaError> {
        assert_eq!(self.0.raw_read(RMP2), 0);
        assert_eq!(self.0.raw_read(FWSTS) & IN_DMA, 0);
        assert_eq!(self.0.command.load(Ordering::Acquire) & 4, 0);
        assert!(!self.0.msi.load(Ordering::Acquire));
        self.0.drains.fetch_add(1, Ordering::Relaxed);
        if self.0.state.lock().unwrap().fail_drain {
            Err(DmaError::DrainUnavailable)
        } else {
            Ok(())
        }
    }
}
struct Cpu(Arc<Peer>);
// SAFETY: serial software CPU/real Registry fixture, not a native IRQ adapter.
unsafe impl irq::Platform for Cpu {
    fn check_cpu(&self) -> core::result::Result<(), irq::IrqError> {
        Ok(())
    }
    fn save_and_disable(&self) -> u64 {
        0
    }
    unsafe fn restore(&self, _: u64) {}
    fn target(&self, vector: u8) -> core::result::Result<irq::Target, irq::IrqError> {
        self.0.vector.store(vector, Ordering::Release);
        Ok(irq::Target {
            destination: 0,
            vector,
        })
    }
    fn pending(&self, _: u8) -> core::result::Result<bool, irq::IrqError> {
        Ok(false)
    }
    fn eoi(&self) {
        self.0.eois.fetch_add(1, Ordering::Relaxed);
    }
    fn ticks(&self) -> u64 {
        self.0.state.lock().unwrap().now
    }
    fn timeout_ticks(&self) -> u64 {
        100_000
    }
    unsafe fn interrupt_window(&self) {}
}
type Driver = Native<Config, ModelRegisters, ClockModel>;
struct Fixture {
    driver: Driver,
    peer: Arc<Peer>,
    config_counts: Arc<Counters>,
    bar_counts: Arc<Counters>,
}
/// Native inputs, the firmware peer, and config-space and BAR access counts.
type Parts = (
    Inputs<Config, ModelRegisters, ClockModel>,
    Arc<Peer>,
    Arc<Counters>,
    Arc<Counters>,
);

fn inputs() -> Parts {
    let address = Address {
        segment: 0,
        bus: 0,
        device: 0,
        function: 0,
    };
    let (mut config, config_counts) = fixture(address);
    let (bar, bar_counts) = fixture(Address {
        device: 1,
        ..address
    });
    let mapping = bar.into_mapping();
    let span = mapping.physical_span().unwrap();
    let view = mapping.view(0..4096).unwrap();
    let peer = Arc::new(Peer {
        view,
        state: Mutex::new(Data::new()),
        registry: AtomicPtr::new(core::ptr::null_mut()),
        vector: AtomicU8::new(0),
        command: AtomicUsize::new(0x402),
        msi: AtomicBool::new(false),
        eois: AtomicUsize::new(0),
        callbacks: AtomicUsize::new(0),
        in_callback: AtomicBool::new(false),
        masks: AtomicUsize::new(0),
        drains: AtomicUsize::new(0),
        root_drops: AtomicUsize::new(0),
        domain_drops: AtomicUsize::new(0),
    });
    peer.raw_write(FWSTS, 0x4000);
    peer.raw_write(PIMR, 0x40); // Unrelated bit must survive every mask/rearm.
    config.write32(0, 0x9d35_8086);
    config.write32(4, 0x0010_0402);
    config.write32(8, 0x1180_0002);
    config.write32(0x10, span.start() as u32);
    config.write32(0x2c, 0x1234_8086);
    config.write8(0x34, 0x40);
    config.write16(0x40, 0x5001);
    config.write16(0x44, 0);
    config.write16(0x50, 5);
    config.write16(0x52, 0x80);
    let config = Config {
        native: config,
        peer: peer.clone(),
    };
    let function = Function::new(address, config).unwrap();
    let registers = unsafe { MappedRegisters::new(mapping) }
        .map_err(|(e, _)| e)
        .unwrap();
    let registry = Box::leak(Box::new(Registry::new(Cpu(peer.clone()))));
    peer.registry.store(registry, Ordering::Release);
    (
        Inputs {
            function,
            retained: Arc::new(Root(peer.clone())),
            registers: ModelRegisters {
                native: registers,
                peer: peer.clone(),
            },
            domain: Arc::new(Domain(peer.clone())),
            interrupts: registry,
            clock: ClockModel(peer.clone()),
        },
        peer,
        config_counts,
        bar_counts,
    )
}
fn prepared() -> Fixture {
    let (i, peer, config_counts, bar_counts) = inputs();
    let driver = unsafe { Native::new(i) }.map_err(|(e, _)| e).unwrap();
    Fixture {
        driver,
        peer,
        config_counts,
        bar_counts,
    }
}
fn running() -> Fixture {
    let mut f = prepared();
    f.driver.start().unwrap();
    f
}
fn retained(f: &Fixture) {
    assert_eq!(f.config_counts.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(f.bar_counts.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(f.peer.root_drops.load(Ordering::Relaxed), 0);
    assert_eq!(f.peer.domain_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn actual_owned_native_irq_firmware_discovery_fragmented_descriptors_tx_controls_and_input() {
    let mut f = running();
    assert!(f.driver.irq_handled().unwrap() > 0);
    assert!(f.peer.callbacks.load(Ordering::Relaxed) > 0);
    assert_eq!(
        f.peer.callbacks.load(Ordering::Relaxed),
        f.peer.masks.load(Ordering::Relaxed)
    );
    assert!(f.peer.eois.load(Ordering::Relaxed) > 0);
    assert_eq!(f.driver.firmware().unwrap().hid_client.address, 5);
    assert_eq!(f.driver.devices()[0].report_descriptor, report_descriptor());
    assert!(report_descriptor().len() > MTU);
    assert!(f.driver.get_report(7, ReportKind::Output, 1).is_err());
    assert!(f.driver.get_report(7, ReportKind::Feature, 2).is_err());
    assert_eq!(f.driver.failure(), None);
    assert_eq!(
        f.driver.get_report(7, ReportKind::Feature, 1).unwrap(),
        [1, 9, 8, 7]
    );
    assert_eq!(
        f.driver.set_feature(7, &[1, 3, 4, 5]).unwrap(),
        [0xaa, 0xbb]
    );
    assert_eq!(
        f.driver.get_report(7, ReportKind::Input, 1).unwrap(),
        input_bytes()
    );
    f.peer.push_client(hostif(0x85, 7, &input_bytes()));
    let packet = f.driver.next_input().unwrap().unwrap();
    assert_eq!(packet.bytes, input_bytes());
    assert_eq!(packet.hostif_command, 0x85);
    assert_eq!(
        packet.timestamps,
        TimestampSupport::FirmwareClockSynchronizationUnsupported
    );
    let events = &f.peer.state.lock().unwrap().events;
    assert!(
        events
            .iter()
            .any(|(w, a, v)| !w && *a >= RX && *a < RX + 128 && *v == u32::MAX)
    );
    assert!(
        events
            .iter()
            .filter(|(w, a, _)| *w && *a == PIMR)
            .all(|(_, _, v)| *v == 0x40 || *v == 0x41)
    );
    retained(&f);
    large_feature_transfer();
}
#[test]
fn native_mixed_unsolicited_input_before_feature_response_keeps_receive_credit_available() {
    let mut f = running();
    f.peer.state.lock().unwrap().mix_input = true;
    assert_eq!(
        f.driver.get_report(7, ReportKind::Feature, 1).unwrap(),
        [1, 9, 8, 7]
    );
    assert_eq!(f.driver.next_input().unwrap().unwrap().bytes, input_bytes());
    retained(&f);
}
#[test]
fn native_actual_aggregate_byte_cursor_accepts_publish_response_bits_and_preserves_total_metadata()
{
    let mut f = running();
    let mut b = vec![0x34, 0x12, 2, 0x55];
    for command in [5, 0x85] {
        let r = hostif(command, 7, &input_bytes());
        b.extend_from_slice(&(r.len() as u16).to_le_bytes());
        b.extend_from_slice(&r);
    }
    f.peer.push_client(hostif(0x86, 0, &b));
    for command in [5, 0x85] {
        let r = f.driver.next_input().unwrap().unwrap();
        assert_eq!(r.hostif_command, command);
        assert_eq!(r.aggregate_total_size, Some(0x1234));
        assert_eq!(r.aggregate_flags, Some(0x55));
    }
    retained(&f);
}
#[test]
fn native_first_irq_enable_handles_pending_firmware_reset_without_false_readback_failure() {
    let mut f = prepared();
    f.peer.state.lock().unwrap().first_enable_reset = true;
    f.driver.start().unwrap();
    assert_eq!(f.peer.state.lock().unwrap().reset_acks, 1);
    assert!(f.driver.irq_handled().unwrap() > 0);
    retained(&f);
}
#[test]
fn native_every_actual_rearm_register_boundary_preserves_pending_input_and_masks_callback() {
    let mut baseline = running();
    let start = baseline.peer.state.lock().unwrap().events.len();
    baseline.driver.service().unwrap();
    let count = baseline.peer.state.lock().unwrap().events.len() - start;
    assert!(count > 5);
    for offset in 1..=count {
        let mut f = running();
        let base = f.peer.state.lock().unwrap().events.len();
        f.peer.state.lock().unwrap().inject_at = Some(base + offset);
        f.driver.service().unwrap();
        assert!(f.peer.state.lock().unwrap().injected);
        let packet = f
            .driver
            .next_input()
            .unwrap()
            .expect("no lost native pending input");
        assert_eq!(packet.bytes, input_bytes());
        assert_eq!(
            f.peer.callbacks.load(Ordering::Relaxed),
            f.peer.masks.load(Ordering::Relaxed)
        );
        retained(&f);
    }
}
#[test]
fn native_missing_irq_delivery_is_not_qualified_by_successful_mailbox_polling() {
    let mut f = prepared();
    f.peer.state.lock().unwrap().no_delivery = true;
    assert_eq!(
        f.driver.start(),
        Err(Error::Requirement(
            "actual IRQ callback observed during native startup"
        ))
    );
    assert_eq!(f.driver.irq_handled().unwrap(), 0);
    retained(&f);
}
#[test]
fn actual_profile_admission_rejects_mem_off_wrong_identity_mapping_and_active_dma_before_writes() {
    for variant in 0..5 {
        let (mut i, peer, _, _) = inputs();
        match variant {
            0 => i.function.config().write16(4, 0x400),
            1 => i.function.config().write32(0, 0x9d34_8086),
            2 => i.function.config().write32(0x10, 0x8000),
            3 => peer.raw_write(RMP2, 1),
            _ => peer.raw_write(FWSTS, 0x4000 | IN_DMA),
        }
        let before = peer.state.lock().unwrap().events.len();
        let (error, mut original) = match unsafe { Native::new(i) } {
            Err(v) => v,
            Ok(_) => panic!("invalid profile admitted"),
        };
        assert!(matches!(error, Error::Requirement(_)));
        assert_eq!(
            peer.state.lock().unwrap().events[before..]
                .iter()
                .filter(|(w, _, _)| *w)
                .count(),
            0
        );
        assert_eq!(
            original.function.config().owned_address(),
            Address {
                segment: 0,
                bus: 0,
                device: 0,
                function: 0
            }
        );
    }
}
#[test]
fn native_wrong_guid_properties_stale_reset_duplicate_credit_and_unaddressable_ids_retain_epoch() {
    for fault in 0..6 {
        let mut f = prepared();
        {
            let mut d = f.peer.state.lock().unwrap();
            match fault {
                0 => d.wrong_guid = true,
                1 => d.wrong_reset = true,
                2 => d.duplicate_credit = true,
                3 => d.bad_id = true,
                4 => d.duplicate_id = true,
                _ => d.bad_property = true,
            }
        }
        let expected = match fault {
            0 => Error::Requirement("actual HID client GUID not enumerated"),
            1 => Error::Protocol("stale IPC reset acknowledgement"),
            2 => Error::Protocol("duplicate or wrong HBM credit"),
            3 => Error::Requirement("HostIF cannot address 32-bit HID device ID"),
            4 => Error::Protocol("duplicate HID device ID"),
            _ => Error::Requirement("bounded ordinary HID client properties"),
        };
        assert_eq!(f.driver.start(), Err(expected));
        assert!(f.driver.firmware().is_none());
        assert_eq!(f.peer.raw_read(PIMR) & 1, 0);
        retained(&f);
    }
}
#[test]
fn native_ignored_irq_controls_access_removal_and_busy_mailbox_never_fake_success() {
    for fault in 0..5 {
        let mut f = prepared();
        {
            let mut d = f.peer.state.lock().unwrap();
            match fault {
                0 => d.ignore_pimr = true,
                1 => d.ignore_msi = true,
                2 => d.access_fault = Some(FWSTS),
                3 => d.removed = Some(FWSTS),
                _ => d.busy_mailbox = true,
            }
        }
        let expected = match fault {
            0 => Error::Readback(PIMR),
            1 => Error::Msi(crate::bus::pci::msi::MsiError::Readback { offset: 0x52 }),
            2 => Error::Access(FWSTS),
            3 => Error::Removed,
            _ => Error::Timeout("IPC reset acknowledgement"),
        };
        assert_eq!(f.driver.start(), Err(expected));
        retained(&f);
    }
}
#[test]
fn native_late_same_client_firmware_reset_invalidates_old_descriptors_and_credit() {
    let mut f = running();
    f.peer
        .state
        .lock()
        .unwrap()
        .outgoing
        .push_back(wire(3, 3, vec![1, 0, 0, 0]));
    f.peer.publish();
    assert_eq!(f.driver.service(), Err(Error::FirmwareReset));
    assert!(f.driver.devices().is_empty());
    assert!(f.driver.firmware().is_none());
    assert_eq!(
        f.driver.get_report(7, ReportKind::Feature, 1),
        Err(Error::Terminal)
    );
    retained(&f);
}
#[test]
fn native_corrupt_aggregate_nested_length_and_unsolicited_dma_are_terminal_without_host_memory_access()
 {
    for dma in [false, true] {
        let mut f = running();
        if dma {
            f.peer
                .state
                .lock()
                .unwrap()
                .hbm(&[0x12, 5, 1, 0, 0, 0, 0, 0]);
            f.peer.publish();
        } else {
            f.peer
                .push_client(hostif(6, 0, &[0, 0, 1, 0, 7, 0, 5, 7, 0, 0, 2, 0, 1]));
        }
        assert_eq!(
            f.driver.service(),
            Err(if dma {
                Error::Requirement("unsolicited DMA on mailbox-only client transport")
            } else {
                Error::Protocol("aggregate nested HostIF consistency")
            })
        );
        assert!(f.driver.devices().is_empty());
        assert!(f.driver.firmware().is_none());
        retained(&f);
    }
}
#[test]
fn native_acknowledged_stop_and_domain_failure_keep_original_armed_msi_epoch_retained() {
    for failure in 0..3 {
        let mut f = running();
        {
            let mut s = f.peer.state.lock().unwrap();
            s.stuck_dma = failure == 1;
            s.fail_drain = failure == 2;
        }
        let expected = match failure {
            0 => Error::PostedMsiRetirementUnavailable,
            1 => Error::Timeout("actual firmware DMA stop"),
            _ => Error::Dma(DmaError::DrainUnavailable),
        };
        assert_eq!(f.driver.stop(), Err(expected));
        assert_eq!(f.driver.stop(), Err(Error::Terminal));
        assert_eq!(
            f.peer.drains.load(Ordering::Relaxed),
            usize::from(failure != 1)
        );
        retained(&f);
        let peer = f.peer.clone();
        let cfg = f.config_counts.clone();
        let bar = f.bar_counts.clone();
        drop(f);
        assert_eq!(peer.root_drops.load(Ordering::Relaxed), 0);
        assert_eq!(peer.domain_drops.load(Ordering::Relaxed), 0);
        assert_eq!(cfg.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(bar.unmaps.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn bounded_descriptor_inventory_counts_padding_push_pop_and_rejects_malformed_collections() {
    let d = report_descriptor();
    let r = descriptor::parse(&d).unwrap();
    assert_eq!(
        r[0],
        ReportLayout {
            kind: ReportKind::Input,
            report_id: 1,
            bytes: 9
        }
    );
    assert_eq!(
        r[1],
        ReportLayout {
            kind: ReportKind::Feature,
            report_id: 1,
            bytes: 4
        }
    );
    for bad in [
        vec![0xa0, 0xc0],
        vec![0xc0],
        vec![0xa1, 1, 0xfe],
        vec![0xa1, 1, 0x85, 0, 0xc0],
    ] {
        assert!(descriptor::parse(&bad).is_err());
    }
    let d = [
        0xa1, 1, 0x75, 3, 0x95, 1, 0xa4, 0x75, 5, 0x81, 1, 0xb4, 0x81, 2, 0xc0,
    ];
    assert_eq!(descriptor::parse(&d).unwrap()[0].bytes, 1);
}

#[test]
fn native_full_but_drainable_input_capacity_rejects_control_without_destroying_healthy_epoch() {
    let mut f = running();
    let message = (0..20)
        .flat_map(|_| hostif(5, 7, &input_bytes()))
        .collect::<Vec<_>>();
    f.peer.push_client(message.clone());
    f.peer.push_client(message);
    f.driver.service().unwrap();
    assert_eq!(
        f.driver.get_report(7, ReportKind::Feature, 1),
        Err(Error::Requirement(
            "idle connected HID request with bounded receive capacity"
        ))
    );
    assert_eq!(f.driver.failure(), None);
    assert!(!f.driver.devices().is_empty());
    for _ in 0..40 {
        assert_eq!(f.driver.next_input().unwrap().unwrap().bytes, input_bytes());
    }
    assert_eq!(
        f.driver.get_report(7, ReportKind::Feature, 1).unwrap(),
        [1, 9, 8, 7]
    );
    retained(&f);
}

#[test]
fn native_firmware_notification_during_settle_restarts_readiness_and_actual300ms_interval() {
    let mut f = prepared();
    {
        let mut state = f.peer.state.lock().unwrap();
        state.settle_reset_after = Some(100_000);
        state.hold_ack_us = 500_000;
    }
    f.driver.start().unwrap();
    assert_eq!(f.peer.state.lock().unwrap().reset_acks, 1);
    // Independent peer rejects HBM before its LAST true-ready+300ms boundary.
    assert!(f.driver.irq_handled().unwrap() > 0);
    retained(&f);
}

mod oracle;

fn large_feature_transfer() {
    let mut f = prepared();
    {
        let mut state = f.peer.state.lock().unwrap();
        state.descriptor[15] = 200;
        state.feature_wire_bytes = 201;
    }
    f.driver.start().unwrap();
    let before = f.peer.state.lock().unwrap().client_fragment_lengths.len();
    f.peer.state.lock().unwrap().hold_client_us = 10_000;
    let mut report = vec![1];
    report.extend((0..200).map(|n| n as u8));
    assert_eq!(f.driver.set_feature(7, &report).unwrap(), [0xaa, 0xbb]);
    let state = f.peer.state.lock().unwrap();
    assert_eq!(&state.client_fragment_lengths[before..], &[124, 83]);
    let actual = state.host_messages.last().unwrap();
    assert_eq!(&actual[..6], &[3, 7, 0, 0, 0, 0]);
    assert_eq!(&actual[6..], &report);
    assert!(state.tx_assembly.is_empty());
    drop(state);
    retained(&f);
}

#[test]
fn native_large_descriptor_declared_feature_fragments_once_per_credit_without_busy_mailbox_overwrite()
 {
    large_feature_transfer();
}

#[test]
fn native_led_output_uses_set_report_and_keeps_feature_validation_distinct() {
    let mut f = prepared();
    let descriptor = vec![
        0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 1, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0,
        0x25, 1, 0x75, 1, 0x95, 8, 0x81, 2, 0x75, 8, 0x95, 1, 0x81, 1, 0x19, 0, 0x29, 0x65, 0x15,
        0, 0x25, 0x65, 0x75, 8, 0x95, 6, 0x81, 0, 0x05, 8, 0x19, 1, 0x29, 5, 0x15, 0, 0x25, 1,
        0x75, 1, 0x95, 5, 0x91, 2, 0x75, 3, 0x95, 1, 0x91, 1, 0xc0,
    ];
    {
        let mut state = f.peer.state.lock().unwrap();
        state.descriptor = descriptor.clone();
        state.feature_wire_bytes = 2;
    }
    f.driver.start().unwrap();
    let translator = Translator::describe(&descriptor).unwrap();
    assert!(translator.is_keyboard_or_pointer());
    let (_, report) = translator.led_report(3).unwrap();
    assert_eq!(report, [1, 3]);
    let messages = f.peer.state.lock().unwrap().host_messages.len();
    let accesses = f.peer.state.lock().unwrap().events.len();
    assert!(f.driver.set_feature(7, &report).is_err());
    assert!(f.driver.get_report(7, ReportKind::Output, 1).is_err());
    assert!(f.driver.set_output(7, &[1]).is_err());
    assert!(f.driver.set_output(7, &[2, 3]).is_err());
    assert_eq!(f.peer.state.lock().unwrap().host_messages.len(), messages);
    assert_eq!(f.peer.state.lock().unwrap().events.len(), accesses);
    assert_eq!(f.driver.failure(), None);
    assert_eq!(f.driver.set_output(7, &report).unwrap(), [0xaa, 0xbb]);
    assert_eq!(
        f.peer.state.lock().unwrap().host_messages.last().unwrap(),
        &[3, 7, 0, 0, 0, 0, 1, 3]
    );
    retained(&f);
}
