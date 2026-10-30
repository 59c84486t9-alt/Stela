// SPDX-License-Identifier: GPL-2.0-only
//! PCI/MMIO power-transition and failure models.
//! Addresses/PM sequencing are hardcoded independently of production constants.
use super::*;
use crate::hda::hdmi::{DisplayAudioIdentity, DisplayAudioPort, DisplayAudioState};
use crate::{
    Direction, PcmFormat,
    bus::{
        dma::RegionAllocator,
        pci::{Address, Bar, Function},
    },
    hda::Config,
};
use alloc::{rc::Rc, sync::Arc, vec, vec::Vec};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

#[derive(Clone)]
struct Clock(Arc<AtomicU64>);
impl Timer for Clock {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    fn relax(&self) {
        self.0.fetch_add(10, Ordering::SeqCst);
    }
}
#[derive(Clone, Copy, Debug)]
struct Event {
    pci: bool,
    offset: usize,
    bytes: u8,
    value: u32,
    time: u64,
}
struct State {
    config: [u32; 64],
    mmio: Vec<u8>,
    events: Vec<Event>,
    clock: Clock,
    ready: u64,
    previous_power: u16,
    reject_power: bool,
    reject_command: bool,
    reject_stop: bool,
    reject_reset: bool,
    reject_reset_exit: bool,
    reject_snoop: bool,
    reject_bar: bool,
    fail_power_read: bool,
    mmio_reads: usize,
    required_hdmi_power: Option<Arc<AtomicBool>>,
}
impl State {
    fn config16(&self, offset: u16) -> u16 {
        (self.config[usize::from(offset / 4)] >> ((offset & 2) * 8)) as u16
    }
    fn set_config(&mut self, offset: u16, bytes: u8, value: u32) {
        let shift = (offset & 3) * 8;
        let mask = if bytes == 4 {
            u32::MAX
        } else {
            (1 << (bytes * 8)) - 1
        };
        let i = usize::from(offset / 4);
        self.config[i] = self.config[i] & !(mask << shift) | (value & mask) << shift;
    }
    fn get(&self, offset: usize, bytes: u8) -> u32 {
        (0..bytes).fold(0, |n, i| {
            n | u32::from(self.mmio[offset + usize::from(i)]) << (i * 8)
        })
    }
    fn set(&mut self, offset: usize, bytes: u8, value: u32) {
        for i in 0..bytes {
            self.mmio[offset + usize::from(i)] = (value >> (i * 8)) as u8;
        }
    }
    fn log(&mut self, pci: bool, offset: usize, bytes: u8, value: u32) {
        self.events.push(Event {
            pci,
            offset,
            bytes,
            value,
            time: self.clock.now_us(),
        });
    }
    fn pci_write(&mut self, offset: u16, bytes: u8, value: u32) {
        self.log(true, usize::from(offset), bytes, value);
        match offset {
            4 => {
                assert_eq!(bytes, 2, "PCI status W1C must not be touched");
                if self.reject_command {
                    return;
                }
            }
            0x54 => {
                assert_eq!(bytes, 2);
                assert_eq!(self.config16(4) & 6, 0, "disable decode/master before PM");
                assert_eq!(self.get(0x4c, 1) & 2, 0, "CORB must stop before PM");
                assert_eq!(self.get(0x5c, 1) & 2, 0, "RIRB must stop before PM");
                for index in 0..4 {
                    assert_eq!(self.get(0x80 + index * 0x20, 1) & 2, 0);
                }
                if value & 3 == 3 || self.config16(0x54) & 3 == 3 {
                    assert_eq!(self.get(8, 4) & 1, 0, "link must be in reset before PM");
                }
                if self.reject_power {
                    return;
                }
                let old = self.config16(0x54);
                self.previous_power = old & 3;
                self.ready = self.clock.now_us() + if old & 3 == 3 { 10_000 } else { 0 };
                if old & 3 == 3 && value & 3 == 0 {
                    self.config[4..10].fill(0);
                    // Soft-reset effect: PCI vendor snoop controls lost.
                    self.config[17] = 0xa5a5_fff7;
                    self.config[30] = 0xf91f_7a55;
                }
                self.set_config(
                    offset,
                    bytes,
                    (value & !(1 << 15)) | (u32::from(old) & !value & (1 << 15)),
                );
                return;
            }
            0x10..=0x24 => {
                assert_eq!(bytes, 4);
                assert_eq!(
                    self.config16(4) & 6,
                    0,
                    "BAR restore with active decode/master"
                );
                assert!(
                    self.clock.now_us() >= self.ready,
                    "BAR restore before D0 delay"
                );
                if self.reject_bar {
                    return;
                }
            }
            0x78 => {
                assert_eq!(bytes, 2);
                if self.reject_snoop {
                    return;
                }
            }
            0x44 => assert_eq!(bytes, 1),
            0x48 => assert_eq!(bytes, 4),
            0x62 | 0xb2 => assert_eq!(bytes, 2),
            _ => panic!("unexpected PCI write {offset:x}"),
        }
        self.set_config(offset, bytes, value);
    }
    fn assert_mmio_access(&self) {
        if let Some(powered) = &self.required_hdmi_power {
            assert!(
                powered.load(Ordering::SeqCst),
                "MMIO after HDMI link-power grant retirement"
            );
        }
        assert_eq!(self.config16(0x54) & 3, 0, "MMIO in D3hot");
        assert!(self.clock.now_us() >= self.ready, "MMIO before D0 ready");
        assert_ne!(self.config16(4) & 2, 0, "MMIO while decode disabled");
    }
    fn respond_codec(&mut self, wp: u32) {
        assert_ne!(self.get(0x4c, 1) & 2, 0);
        assert_ne!(self.get(0x5c, 1) & 2, 0);
        let corb = u64::from(self.get(0x40, 4)) | (u64::from(self.get(0x44, 4)) << 32);
        let rirb = u64::from(self.get(0x50, 4)) | (u64::from(self.get(0x54, 4)) << 32);
        // SAFETY: production-programmed ring addresses name the kept
        // unique model RAM, and this synchronous model is its device owner.
        let command =
            u32::from_le(unsafe { (corb as *const u32).add(wp as usize).read_volatile() });
        let node = ((command >> 20) & 127) as u8;
        let verb = ((command >> 8) & 0xfff) as u16;
        let response = match (node, verb, command as u8) {
            (0, 0xf00, 0) => 0x10de0014,
            (0, 0xf00, 2) => 0x00100100,
            (0, 0xf00, 4) => 0x00010001,
            (1, 0xf00, 5) => 1,
            (1, 0xf00, 4) => 0x00020002,
            (1, 0xf00, 0x0f) => 9,
            (1, 0xf00, 0x0a) => 0x000e07f0,
            (1 | 2, 0xf00, 0x0b) => 1,
            (1, 0xf00, 0x0d | 0x12) => 0,
            (2, 0xf00, 9) => 0x00000201,
            (3, 0xf00, 9) => 0x00400301,
            (3, 0xf00, 0x0c) => 0x94,
            (3, 0xf00, 0x0e) => 1,
            (3, 0xf02, 0) => 2,
            (3, 0xf1c, 0) => 0x18560010,
            _ => panic!("unexpected read-only HDMI discovery command {command:08x}"),
        };
        self.set(0x4a, 2, wp);
        let next = (self.get(0x58, 2) + 1) % 256;
        // SAFETY: same production allocation and device ownership.
        unsafe {
            let entry = (rirb as *mut u32).add(next as usize * 2);
            entry.write_volatile(u32::to_le(response));
            entry.add(1).write_volatile((command >> 28).to_le());
        }
        self.set(0x58, 2, next);
        let status = self.get(0x5d, 1);
        self.set(0x5d, 1, status | 1);
    }
    fn mmio_write(&mut self, offset: usize, bytes: u8, value: u32) {
        self.assert_mmio_access();
        self.log(false, offset, bytes, value);
        if offset == 0x4c && self.reject_stop && value & 2 == 0 {
            return;
        }
        if offset == 8 && self.reject_reset_exit && value & 1 != 0 {
            return;
        }
        if offset == 8 && self.reject_reset && value & 1 == 0 {
            return;
        }
        if offset == 0x58 && value & 0x8000 != 0 {
            self.set(offset, bytes, 0);
            return;
        }
        if offset == 0x4d
            || offset == 0x5d
            || offset == 0x0e
            || (offset >= 0x83 && (offset - 0x83).is_multiple_of(0x20))
        {
            let old = self.get(offset, bytes);
            self.set(offset, bytes, old & !value);
            return;
        }
        if offset == 0x4e || offset == 0x5e {
            self.set(offset, bytes, 0x40 | (value & 3));
            return;
        }
        if offset == 8 && value & 1 != 0 && self.get(8, 4) & 1 == 0 {
            self.set(0x0e, 2, 1); // A newly initialized codec reports readiness.
        }
        self.set(offset, bytes, value);
        if offset == 0x48 && self.required_hdmi_power.is_some() && self.get(0x4c, 1) & 2 != 0 {
            self.respond_codec(value);
        }
    }
}
struct Pci(Rc<RefCell<State>>);
impl ConfigSpace for Pci {
    fn read32(&self, offset: u16) -> u32 {
        let s = self.0.borrow();
        let value = s.config[usize::from(offset / 4)];
        if offset == 0x54 {
            if s.fail_power_read {
                return u32::MAX;
            }
            if s.clock.now_us() < s.ready {
                return value & !3 | u32::from(s.previous_power);
            }
        }
        value
    }
    fn write32(&mut self, offset: u16, value: u32) {
        self.0.borrow_mut().pci_write(offset, 4, value);
    }
    fn write16(&mut self, offset: u16, value: u16) {
        self.0.borrow_mut().pci_write(offset, 2, u32::from(value));
    }
    fn write8(&mut self, offset: u16, value: u8) {
        self.0.borrow_mut().pci_write(offset, 1, u32::from(value));
    }
}
#[derive(Clone)]
struct Mmio(Rc<RefCell<State>>);
impl Mmio {
    fn read(&self, offset: usize, bytes: u8) -> u32 {
        let mut s = self.0.borrow_mut();
        s.assert_mmio_access();
        s.mmio_reads += 1;
        s.get(offset, bytes)
    }
}
impl Registers for Mmio {
    fn region_bytes(&self) -> usize {
        0x1000
    }
    fn read8(&mut self, offset: usize) -> u8 {
        self.read(offset, 1) as u8
    }
    fn read16(&mut self, offset: usize) -> u16 {
        self.read(offset, 2) as u16
    }
    fn read32(&mut self, offset: usize) -> u32 {
        self.read(offset, 4)
    }
    fn write8(&mut self, offset: usize, value: u8) {
        self.0.borrow_mut().mmio_write(offset, 1, u32::from(value));
    }
    fn write16(&mut self, offset: usize, value: u16) {
        self.0.borrow_mut().mmio_write(offset, 2, u32::from(value));
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.0.borrow_mut().mmio_write(offset, 4, value);
    }
}
struct Ram {
    _backing: Vec<u64>,
    allocator: RegionAllocator,
}
impl Ram {
    fn new() -> Self {
        let mut backing = vec![0; 64 * 1024];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: this unique vector remains live until after controller drop.
        let allocator = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
        Self {
            _backing: backing,
            allocator,
        }
    }
}
fn fixture(device: u16) -> (Function<Pci>, Mmio, Clock, Rc<RefCell<State>>, Ram) {
    let clock = Clock(Arc::new(AtomicU64::new(0)));
    let mut s = State {
        config: [0; 64],
        mmio: vec![0; 0x1000],
        events: Vec::new(),
        clock: clock.clone(),
        ready: 0,
        previous_power: 0,
        reject_power: false,
        reject_command: false,
        reject_stop: false,
        reject_reset: false,
        reject_reset_exit: false,
        reject_snoop: false,
        reject_bar: false,
        fail_power_read: false,
        mmio_reads: 0,
        required_hdmi_power: None,
    };
    s.config[0] = u32::from(device) << 16 | 0x8086;
    s.config[1] = 0xf910_0406;
    s.config[2] = 0x0403_0001;
    s.config[4] = 0xfebf_0000;
    s.config[5] = 0x1234_0000;
    s.config[11] = 0x1234_abcd;
    s.config[13] = 0x50;
    s.config[17] = 0xa5a5_fff7;
    s.config[18] = 0xa5a5_00c3;
    s.config[20] = 0x0003_6001;
    s.config[21] = 0x0000_8100; // D0, PME enable and pending W1C status.
    s.config[24] = 0x0001_7005;
    s.config[28] = 0x0092_b010;
    s.config[30] = 0xf91f_7a55;
    s.config[44] = 0x8000_0011;
    s.set(0, 4, 0x0100_2201); // HDA1.0, two streams per direction, 64-bit DMA.
    for offset in [4, 6, 0x18, 0x1a] {
        s.set(offset, 2, 0xff);
    }
    s.set(8, 4, 1);
    s.set(0x4e, 1, 0x40);
    s.set(0x5e, 1, 0x40);
    let state = Rc::new(RefCell::new(s));
    let function = Function::new(
        Address {
            segment: 0,
            bus: 0,
            device: 27,
            function: 0,
        },
        Pci(state.clone()),
    )
    .unwrap();
    (function, Mmio(state.clone()), clock, state, Ram::new())
}
fn controller<'a>(
    function: &'a mut Function<Pci>,
    mmio: Mmio,
    clock: Clock,
    ram: &mut Ram,
) -> Controller<PciRegisters<'a, Mmio, Pci>, Clock> {
    let bar = Bar::Memory {
        address: 0xfebf_0000,
        size: 0x4000,
        prefetchable: false,
        wide: false,
    };
    // SAFETY: one isolated stateful hardware model owns PCI/MMIO/RAM.
    let registers = unsafe {
        super::super::prepare_with_registers(
            function,
            bar,
            &clock,
            super::super::Ownership::ExclusiveLegacy,
            mmio,
        )
    }
    .unwrap();
    let config = Config {
        transition_timeout_us: 100,
        ..registers.config()
    };
    // SAFETY: The adapter keeps this test's PCI/MMIO model and ram owns the coherent
    // DMA allocation. Model activity occurs only while the controller is polled.
    unsafe { Controller::new(registers, clock, &mut ram.allocator, config) }.unwrap()
}

#[test]
fn d3hot_resume_invalidates_stream_handles() {
    for device in [
        0x2668, 0x1c20, 0x1d20, 0x1e20, 0x3b56, 0x3b57, 0x811b, 0x080a, 0x0f04, 0x2284, 0xa1f0,
        0xa270, 0x02c8, 0x06c8, 0xa3f0, 0xf0c8, 0xf1c8, 0x38c8, 0x4dc8, 0x4b55, 0x4b58, 0x7a50,
        0x51ca, 0x51cb, 0x51ce, 0x51cf, 0x7f50, 0x7728, 0x3198,
    ] {
        let (mut function, mmio, clock, state, mut ram) = fixture(device);
        let mut c = controller(&mut function, mmio, clock.clone(), &mut ram);
        let format = PcmFormat {
            rate: 48_000,
            channels: 2,
            bits: 16,
        };
        let capture = c
            .allocate_stream(Direction::Capture, format, 512, 4, &mut ram.allocator)
            .unwrap();
        let playback = c
            .allocate_stream(Direction::Playback, format, 512, 4, &mut ram.allocator)
            .unwrap();
        c.start(capture).unwrap();
        c.start(playback).unwrap();
        let command_dma = (c.corb.physical(), c.rirb.physical());
        let old_generation = c.token.generation;
        c.suspend_pci_d3hot().unwrap();
        assert_eq!(state.borrow().config16(0x54), 0x8003);
        assert_eq!(state.borrow().config[1] >> 16, 0xf910);
        assert!(
            c.streams.iter().any(Option::is_some),
            "retain allocations during suspend"
        );
        assert_eq!(c.token.generation, old_generation);
        let reads = state.borrow().mmio_reads;
        assert_eq!(c.start(playback), Err(Error::NeedsReset));
        assert_eq!(c.suspend_pci_d3hot(), Err(PowerError::AlreadySuspended));
        let _ = c.shutdown(); // Generic APIs cannot touch a suspended BAR.
        assert_eq!(state.borrow().mmio_reads, reads);
        c.resume_pci_d0().unwrap();
        assert_eq!((c.corb.physical(), c.rirb.physical()), command_dma);
        assert_eq!(c.token.generation, old_generation + 1);
        assert!(c.streams.iter().all(Option::is_none));
        assert_eq!(c.start(playback), Err(Error::InvalidStream));
        assert_eq!(c.start(capture), Err(Error::InvalidStream));
        assert_eq!(state.borrow().config16(0x54), 0x8000);
        // Linux's ICH6 profile has no SCH/PCH NoSnoop operation. Its
        // word must survive without a write; every other exact
        // profile in this matrix selects SCH/PCH snooping after D0.
        let expected_devc = if device == 0x2668 {
            0xf91f_7a55
        } else {
            0xf91f_7255
        };
        assert_eq!(state.borrow().config[30], expected_devc);
        let snoop_writes = state
            .borrow()
            .events
            .iter()
            .filter(|event| event.pci && event.offset == 0x78)
            .count();
        assert_eq!(snoop_writes, if device == 0x2668 { 0 } else { 2 });
        assert_eq!(state.borrow().config[4], 0xfebf_0000);
        assert_eq!(state.borrow().config[5], 0x1234_0000);
        assert!(clock.now_us() >= 20_000);
        {
            let s = state.borrow();
            let events = &s.events;
            let d3 = events
                .iter()
                .position(|e| e.pci && e.offset == 0x54 && e.value & 3 == 3)
                .unwrap();
            assert!(
                events[..d3]
                    .iter()
                    .any(|e| !e.pci && e.offset == 8 && e.value & 1 == 0)
            );
            let d0 = events
                .iter()
                .rposition(|e| e.pci && e.offset == 0x54 && e.value & 3 == 0)
                .unwrap();
            assert!(
                events[d0 + 1..]
                    .iter()
                    .filter(|e| e.pci && e.offset == 0x10)
                    .all(|e| e.bytes == 4 && e.time >= events[d0].time + 10_000)
            );
        }
        c.shutdown().unwrap();
    }
}

struct HdmiGrant {
    clock: Clock,
    powered: Arc<AtomicBool>,
    retired_at: Arc<AtomicU64>,
}
impl Drop for HdmiGrant {
    fn drop(&mut self) {
        self.retired_at.store(self.clock.now_us(), Ordering::SeqCst);
        self.powered.store(false, Ordering::SeqCst);
    }
}
// SAFETY: this original symbolic provider keeps modeled link power
// through every controller access. Only explicit controller port retirement
// releases its sole Arc. The model refuses playback; it tests idle grants.
unsafe impl DisplayAudioPort for HdmiGrant {
    fn identity(&self) -> DisplayAudioIdentity {
        DisplayAudioIdentity {
            hda_function: Address {
                segment: 0,
                bus: 0,
                device: 27,
                function: 0,
            },
            gpu_function: Address {
                segment: 0,
                bus: 1,
                device: 0,
                function: 0,
            },
            codec: 0,
            pin: 3,
            device: 0,
            port: 7,
        }
    }
    fn observe(&self, _: u64) -> Result<DisplayAudioState, Error> {
        assert!(self.powered.load(Ordering::SeqCst));
        Ok(DisplayAudioState {
            generation: 1,
            connected: false,
        })
    }
    fn enable_audio(&self, _: PcmFormat, _: u64) -> Result<(), Error> {
        Err(Error::SinkUnavailable)
    }
    fn disable_audio(&self, _: u64) -> Result<(), Error> {
        assert!(self.powered.load(Ordering::SeqCst));
        Ok(())
    }
}

#[test]
fn hdmi_grant_survives_failed_suspend() {
    for reject_reset in [false, true] {
        let (mut function, mmio, clock, state, mut ram) = fixture(0x2668);
        let mut c = controller(&mut function, mmio, clock.clone(), &mut ram);
        let powered = Arc::new(AtomicBool::new(true));
        let retired_at = Arc::new(AtomicU64::new(u64::MAX));
        state.borrow_mut().required_hdmi_power = Some(powered.clone());
        // Public discovery/attachment consumes real programmed CORB/RIRB
        // responses, never an invented graph or inserted private Port.
        let graph = c.enumerate_codec(0).unwrap();
        let grant = Arc::new(HdmiGrant {
            clock: clock.clone(),
            powered: powered.clone(),
            retired_at: retired_at.clone(),
        });
        let grant_weak = Arc::downgrade(&grant);
        // SAFETY: original symbolic GPU/HDA grant matches this graph/pin.
        let port = unsafe { c.attach_hdmi_port(&graph, 3, 0, grant) }.unwrap();
        state.borrow_mut().reject_reset = reject_reset;
        let boundary = state.borrow().events.len();
        let result = c.suspend_pci_d3hot();
        if reject_reset {
            assert_eq!(
                result,
                Err(PowerError::Controller(Error::Timeout(
                    Phase::LinkResetEnter
                )))
            );
            assert!(powered.load(Ordering::SeqCst));
            assert_eq!(retired_at.load(Ordering::SeqCst), u64::MAX);
            assert_eq!(grant_weak.strong_count(), 1);
            assert_eq!(c.hdmi_first_error(port), Ok(None));
            assert!(c.registers.suspended.is_none());
            assert!(
                state.borrow().events[boundary..]
                    .iter()
                    .all(|event| !event.pci)
            );
            // Explicit quiet/detach occurs after the retention assertions;
            // no subsequent BAR access relies on the relinquished grant.
            state.borrow_mut().reject_reset = false;
            c.shutdown().unwrap();
            c.detach_hdmi_port(port).unwrap();
        } else {
            result.unwrap();
            assert!(!powered.load(Ordering::SeqCst));
            assert_eq!(grant_weak.strong_count(), 0);
            assert_eq!(c.hdmi_first_error(port), Err(Error::InvalidHdmiPort));
            let s = state.borrow();
            let events = &s.events[boundary..];
            let reset = events
                .iter()
                .find(|event| !event.pci && event.offset == 8 && event.value & 1 == 0)
                .unwrap();
            let retired = retired_at.load(Ordering::SeqCst);
            assert!(retired >= reset.time + 500);
            let first_pci = events.iter().find(|event| event.pci).unwrap();
            assert!(first_pci.time >= retired);
            assert_eq!(s.config16(0x54) & 3, 3);
            assert!(c.registers.suspended.is_some());
        }
    }
}

#[test]
fn subsystem_requires_live_pci_binding() {
    let (mut function, mmio, clock, state, mut ram) = fixture(0x2668);
    let mut c = controller(&mut function, mmio, clock, &mut ram);
    assert_eq!(c.registers.codec_pci_subsystem(), Ok(Some(0x1234_abcd)));
    let boundary = state.borrow().events.len();
    for fault in 0..3 {
        let saved = state.borrow().config;
        match fault {
            0 => state.borrow_mut().config[11] = u32::MAX,
            1 => state.borrow_mut().config[0] ^= 1 << 16,
            _ => state.borrow_mut().config[4] ^= 0x1000,
        }
        assert_eq!(
            c.registers.codec_pci_subsystem(),
            Err(Error::InvalidConfiguration)
        );
        state.borrow_mut().config = saved;
    }
    assert_eq!(state.borrow().events.len(), boundary);
    c.suspend_pci_d3hot().unwrap();
    assert_eq!(
        c.registers.codec_pci_subsystem(),
        Err(Error::InvalidConfiguration)
    );
    c.resume_pci_d0().unwrap();
    assert_eq!(c.registers.codec_pci_subsystem(), Ok(Some(0x1234_abcd)));
    c.shutdown().unwrap();
}

#[test]
fn failed_stop_prevents_d3() {
    for stop_fault in [true, false] {
        let (mut function, mmio, clock, state, mut ram) = fixture(0x2668);
        let mut c = controller(&mut function, mmio, clock, &mut ram);
        let id = c
            .allocate_stream(
                Direction::Playback,
                PcmFormat {
                    rate: 48_000,
                    channels: 2,
                    bits: 16,
                },
                512,
                4,
                &mut ram.allocator,
            )
            .unwrap();
        c.start(id).unwrap();
        state.borrow_mut().reject_stop = stop_fault;
        state.borrow_mut().reject_reset = !stop_fault;
        let boundary = state.borrow().events.len();
        assert!(c.suspend_pci_d3hot().is_err());
        assert!(c.registers.suspended.is_none());
        assert!(c.streams.iter().any(Option::is_some));
        assert!(!state.borrow().events[boundary..].iter().any(|e| e.pci));
        state.borrow_mut().reject_stop = false;
        state.borrow_mut().reject_reset = false;
        c.reinitialize().unwrap();
        assert_eq!(c.start(id), Err(Error::InvalidStream));
        c.shutdown().unwrap();
    }
}

#[test]
fn failed_power_write_keeps_snapshot() {
    for fault in 0..3 {
        let (mut function, mmio, clock, state, mut ram) = fixture(0x2668);
        let mut c = controller(&mut function, mmio, clock, &mut ram);
        match fault {
            0 => state.borrow_mut().reject_power = true,
            1 => state.borrow_mut().reject_command = true,
            _ => state.borrow_mut().fail_power_read = true,
        }
        assert!(c.suspend_pci_d3hot().is_err());
        if fault == 2 {
            // Failed preflight is entirely read-only and has no snapshot.
            assert!(c.registers.suspended.is_none());
            state.borrow_mut().fail_power_read = false;
            c.shutdown().unwrap();
            continue;
        }
        assert!(c.registers.suspended.is_some());
        let reads = state.borrow().mmio_reads;
        assert!(c.reinitialize().is_err());
        assert_eq!(state.borrow().mmio_reads, reads);
        state.borrow_mut().reject_power = false;
        state.borrow_mut().reject_command = false;
        c.resume_pci_d0().unwrap();
        c.shutdown().unwrap();
    }
}

#[test]
fn failed_resume_keeps_owner() {
    for fault in 0..6 {
        let (mut function, mmio, clock, state, mut ram) = fixture(0x7728);
        let mut c = controller(&mut function, mmio, clock, &mut ram);
        c.suspend_pci_d3hot().unwrap();
        let dma = (c.corb.physical(), c.rirb.physical());
        let old_generation = c.token.generation;
        match fault {
            0 => state.borrow_mut().config[0] ^= 1 << 16,
            1 => state.borrow_mut().config[20] &= !0xff,
            2 => state.borrow_mut().reject_bar = true,
            3 => state.borrow_mut().reject_snoop = true,
            4 => state.borrow_mut().reject_power = true,
            _ => state.borrow_mut().reject_reset_exit = true,
        }
        let boundary = state.borrow().events.len();
        assert!(c.resume_pci_d0().is_err(), "fault {fault}");
        assert!(c.registers.suspended.is_some());
        assert_eq!((c.corb.physical(), c.rirb.physical()), dma);
        if fault < 2 {
            assert!(state.borrow().events[boundary..].is_empty());
            assert_eq!(c.token.generation, old_generation);
        }
        match fault {
            0 => state.borrow_mut().config[0] ^= 1 << 16,
            1 => state.borrow_mut().config[20] |= 1,
            2 => state.borrow_mut().reject_bar = false,
            3 => state.borrow_mut().reject_snoop = false,
            4 => state.borrow_mut().reject_power = false,
            _ => state.borrow_mut().reject_reset_exit = false,
        }
        c.resume_pci_d0().unwrap();
        assert_eq!((c.corb.physical(), c.rirb.physical()), dma);
        c.shutdown().unwrap();
    }
}
