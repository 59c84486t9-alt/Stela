// SPDX-License-Identifier: GPL-2.0-only
//! Independent numeric codec, command-ring and BDL playback model. Actual
//! fixture RAM is fetched through programmed CORB/RIRB/BDL addresses. No model
//! imports production verb/register/channel-map constants.
use super::*;
use crate::bus::dma::RegionAllocator;
use alloc::vec;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

#[derive(Clone)]
struct Clock(Arc<AtomicU64>);
impl Timer for Clock {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    fn relax(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[derive(Default)]
struct AnalogCodec {
    pin: u8,
    format: u16,
    binding: u8,
}
struct Hardware {
    analog: AnalogCodec,
    bar: [u8; 0x440],
    clock: Clock,
    commands: Vec<u32>,
    eld: [u8; 32],
    vendor: u32,
    pin_caps: u32,
    pin_default: u32,
    widget: u32,
    sense: u32,
    pin: u8,
    mux: u8,
    digital: u8,
    count: u8,
    format: u16,
    binding: u8,
    slots: [u8; 8],
    packet: [u8; 32],
    packet_index: usize,
    transmit: u8,
    playback: Vec<u8>,
    starts: usize,
    stops: usize,
    reject: Option<u16>,
    drop_reply: Option<u16>,
    bad_eld: Option<u8>,
    stop_stuck: bool,
    reset_stuck: bool,
    late_position: Option<(usize, u32, u64)>,
    position_reads: usize,
}
impl Hardware {
    fn new(clock: Clock, dp: bool) -> Self {
        let mut eld = [0; 32];
        eld[0] = 0x10;
        eld[2] = 7;
        eld[5] = 0x10 | if dp { 4 } else { 0 };
        eld[7] = 0x4f;
        eld[8..16].copy_from_slice(&0x12345678u64.to_le_bytes());
        eld[20] = 0x0f;
        eld[21] = 0x7f;
        eld[22] = 7;
        let mut h = Self {
            analog: AnalogCodec::default(),
            bar: [0; 0x440],
            clock,
            commands: vec![],
            eld,
            vendor: 0x10de0014,
            pin_caps: 0x01000094,
            pin_default: 0x18560010,
            widget: 0x00400705,
            sense: 0xc0000000,
            pin: 0,
            mux: 0,
            digital: 0x10,
            count: 1,
            format: 0,
            binding: 0,
            slots: [0xf0; 8],
            packet: [0; 32],
            packet_index: 0,
            transmit: 0,
            playback: vec![],
            starts: 0,
            stops: 0,
            reject: None,
            drop_reply: None,
            bad_eld: None,
            stop_stuck: false,
            reset_stuck: false,
            late_position: None,
            position_reads: 0,
        };
        h.set(0, 0x1001, 2);
        h.set(2, 0, 1);
        h.set(3, 1, 1);
        h.set(4, 1024, 2);
        h.set(6, 1024, 2);
        h.set(8, 1, 4);
        h.set(0x0e, 3, 2);
        h.set(0x4e, 0x40, 1);
        h.set(0x5e, 0x40, 1);
        h.set(0x90, 127, 2);
        h
    }
    fn tick(&self) {
        self.clock.0.fetch_add(1, Ordering::SeqCst);
    }
    fn set(&mut self, offset: usize, value: u32, bytes: usize) {
        self.bar[offset..offset + bytes].copy_from_slice(&value.to_le_bytes()[..bytes]);
    }
    fn get(&self, offset: usize, bytes: usize) -> u32 {
        let mut value = [0; 4];
        value[..bytes].copy_from_slice(&self.bar[offset..offset + bytes]);
        u32::from_le_bytes(value)
    }
    fn address(&self, offset: usize) -> u64 {
        u64::from(self.get(offset, 4)) | (u64::from(self.get(offset + 4, 4)) << 32)
    }
    fn parameter(&self, node: u8, parameter: u8) -> u32 {
        match (node, parameter) {
            (0, 0) => self.vendor,
            (0, 2) => 0x00100100,
            (0, 4) => 0x00010001,
            (1, 5) => 1,
            (1, 4) => 0x00020003,
            (1, 0x0a) | (2 | 3, 0x0a) => 0x000e07f0,
            (1, 0x0b) | (2 | 3, 0x0b) => 1,
            (1, 0x0f) | (2..=4, 0x0f) => 9,
            (2 | 3, 9) => 0x00006611,
            (4, 9) => self.widget,
            (4, 0x0c) => self.pin_caps,
            (4, 0x0e) => 2,
            (1, 0x12) | (4, 0x12) => 0x80000000,
            _ => 0,
        }
    }
    fn analog_reply(&mut self, command: u32) -> u32 {
        let node = ((command >> 20) & 127) as u8;
        let verb = ((command >> 8) & 0xfff) as u16;
        let byte = command as u8;
        match (command >> 16) & 15 {
            2 => {
                self.analog.format = command as u16;
                return 0;
            }
            0xa => return u32::from(self.analog.format),
            _ => {}
        }
        match verb {
            0xf00 => match (node, byte) {
                (0, 0) => 0x10ec0888,
                (0, 2) => 0x100100,
                (0, 4) => 0x10001,
                (1, 4) => 0x20003,
                (1, 5) => 1,
                (1, 0xa) | (2 | 3, 0xa) => 0x000e07f0,
                (1, 0xb) | (2 | 3, 0xb) => 1,
                (1, 0xf) | (2..=4, 0xf) => 9,
                (2 | 3, 9) => 0x411,
                (4, 9) => 0x400501,
                (4, 0xc) => 0x14,
                (4, 0xe) => 1,
                _ => 0,
            },
            0xf02 => 2,
            0xf1c => 0x01014010,
            0x705 => 0,
            0xf05 => 0,
            0x707 => {
                self.analog.pin = byte;
                0
            }
            0xf07 => u32::from(self.analog.pin),
            0x706 => {
                self.analog.binding = byte;
                0
            }
            0xf06 => u32::from(self.analog.binding),
            _ => panic!("unexpected analog command {command:08x}"),
        }
    }
    fn reply(&mut self, command: u32) -> u32 {
        if command >> 28 == 1 {
            return self.analog_reply(command);
        }
        let node = ((command >> 20) & 127) as u8;
        let verb = ((command >> 8) & 0xfff) as u16;
        let byte = command as u8;
        let long = (command >> 16) & 15;
        if long == 2 {
            self.format = command as u16;
            return 0;
        }
        if long == 0xa {
            return u32::from(self.format);
        }
        if long == 3 {
            assert_eq!(node, 4);
            assert_eq!(command as u16, 0xb000);
            return 0;
        }
        if long == 0xb {
            return 0;
        }
        if self.reject == Some(verb) {
            return 0;
        }
        match verb {
            0xf00 => self.parameter(node, byte),
            0xf1c => self.pin_default,
            0xf02 => 0x0302,
            0x705 => 0,
            0xf05 => 0,
            0xf09 => self.sense,
            0x701 => {
                self.mux = byte;
                0
            }
            0xf01 => u32::from(self.mux),
            0x707 => {
                self.pin = byte;
                0
            }
            0xf07 => u32::from(self.pin),
            0x70d => {
                self.digital = byte;
                0
            }
            0xf0d => 0x9a00 | u32::from(self.digital),
            0x72d => {
                self.count = byte;
                0
            }
            0xf2d => u32::from(self.count),
            0x706 => {
                self.binding = byte;
                0
            }
            0xf06 => u32::from(self.binding),
            0xf2e => 32,
            0xf2f => {
                if self.bad_eld == Some(byte) {
                    0
                } else {
                    0x80000000 | u32::from(self.eld[usize::from(byte)])
                }
            }
            0x730 => {
                assert!(byte < 32);
                self.packet_index = usize::from(byte);
                0
            }
            0xf30 => self.packet_index as u32,
            0x731 => {
                assert_eq!(self.transmit, 0);
                self.packet[self.packet_index] = byte;
                self.packet_index = (self.packet_index + 1) % 32;
                0
            }
            0xf31 => {
                let value = self.packet[self.packet_index];
                self.packet_index = (self.packet_index + 1) % 32;
                u32::from(value)
            }
            0x732 => {
                self.transmit = byte;
                if byte == 0xc0 {
                    assert_eq!(
                        self.packet[..9].iter().fold(0u8, |s, b| s.wrapping_add(*b)),
                        0
                    );
                }
                0
            }
            0xf32 => u32::from(self.transmit),
            0x734 => {
                self.slots[usize::from(byte & 15)] = byte;
                0
            }
            0xf34 => u32::from(self.slots[usize::from(byte)]),
            _ => panic!("unexpected codec command {command:08x}"),
        }
    }
    fn command(&mut self) {
        let wp = self.get(0x48, 2);
        let rp = self.get(0x4a, 2);
        if wp == rp {
            return;
        }
        let command =
            unsafe { ((self.address(0x40) as *const u32).add(wp as usize)).read_volatile() }
                .to_le();
        self.set(0x4a, wp, 2);
        self.commands.push(command);
        let reply = self.reply(command);
        if self.drop_reply == Some(((command >> 8) & 0xfff) as u16) {
            return;
        }
        let next = (self.get(0x58, 2) + 1) % 256;
        let address = self.address(0x50);
        unsafe {
            ((address as *mut u32).add(next as usize * 2)).write_volatile(reply.to_le());
            ((address as *mut u32).add(next as usize * 2 + 1))
                .write_volatile((command >> 28).to_le());
        }
        self.set(0x58, next, 2);
        self.bar[0x5d] |= 1;
    }
    fn write(&mut self, offset: usize, value: u32, bytes: usize) {
        self.tick();
        match offset {
            0x0e | 0x4d | 0x5d | 0x83 => {
                let old = self.get(offset, bytes);
                self.set(offset, old & !value, bytes);
            }
            0x4e | 0x5e => self.set(offset, 0x40 | (value & 3), bytes),
            0x4a => self.set(offset, value, bytes),
            0x58 => self.set(offset, 0, bytes),
            0x48 => {
                self.set(offset, value, bytes);
                if self.bar[0x4c] & 2 != 0 {
                    self.command();
                }
            }
            8 => {
                self.set(offset, value, bytes);
                if value & 1 != 0 {
                    self.set(0x0e, 3, 2);
                }
            }
            0x80 => {
                let old = self.bar[0x80];
                if self.stop_stuck && old & 2 != 0 && value & 2 == 0 {
                    return;
                }
                if self.reset_stuck && value & 1 != 0 {
                    return;
                }
                if value & 1 != 0 {
                    self.set(0x84, 0, 4);
                }
                if old & 2 == 0 && value & 2 != 0 {
                    assert_eq!(self.pin, 0x40);
                    assert_ne!(self.binding, 0);
                    assert_eq!(self.transmit, 0xc0);
                    self.starts += 1;
                }
                if old & 2 != 0 && value & 2 == 0 {
                    self.stops += 1;
                }
                self.set(offset, value, bytes);
            }
            _ => self.set(offset, value, bytes),
        }
    }
    fn read(&mut self, offset: usize, bytes: usize) -> u32 {
        self.tick();
        if offset == 0x84 {
            self.position_reads += 1;
            if let Some((at, pos, elapsed)) = self.late_position
                && at == self.position_reads
            {
                self.clock.0.fetch_add(elapsed, Ordering::SeqCst);
                self.set(0x84, pos, 4);
                self.bar[0x83] |= 4;
            }
        }
        self.get(offset, bytes)
    }
    fn dma(&mut self, bytes: usize) {
        assert_eq!(self.bar[0x80] & 2, 2);
        let ring = self.get(0x88, 4) as usize;
        let bdl = self.address(0x98);
        let entries = self.get(0x8c, 2) as usize + 1;
        let mut pos = self.get(0x84, 4) as usize;
        for _ in 0..bytes {
            let mut base = 0;
            let mut found = false;
            for entry in 0..entries {
                let ptr = (bdl as *const u32).wrapping_add(entry * 4);
                let address = u64::from(unsafe { ptr.read_volatile() }.to_le())
                    | (u64::from(unsafe { ptr.add(1).read_volatile() }.to_le()) << 32);
                let length = unsafe { ptr.add(2).read_volatile() }.to_le() as usize;
                if pos < base + length {
                    self.playback
                        .push(unsafe { ((address as *const u8).add(pos - base)).read_volatile() });
                    if pos + 1 == base + length
                        && unsafe { ptr.add(3).read_volatile() }.to_le() & 1 != 0
                    {
                        self.bar[0x83] |= 4;
                    }
                    found = true;
                    break;
                }
                base += length;
            }
            assert!(found);
            pos = (pos + 1) % ring;
        }
        self.set(0x84, pos as u32, 4);
    }
}
#[derive(Clone)]
struct Regs(Arc<Mutex<Hardware>>);
impl Registers for Regs {
    fn read8(&mut self, o: usize) -> u8 {
        self.0.lock().unwrap().read(o, 1) as u8
    }
    fn read16(&mut self, o: usize) -> u16 {
        self.0.lock().unwrap().read(o, 2) as u16
    }
    fn read32(&mut self, o: usize) -> u32 {
        self.0.lock().unwrap().read(o, 4)
    }
    fn write8(&mut self, o: usize, v: u8) {
        self.0.lock().unwrap().write(o, u32::from(v), 1);
    }
    fn write16(&mut self, o: usize, v: u16) {
        self.0.lock().unwrap().write(o, u32::from(v), 2);
    }
    fn write32(&mut self, o: usize, v: u32) {
        self.0.lock().unwrap().write(o, v, 4);
    }
}
struct OwnerState {
    generation: u64,
    connected: bool,
    enable: usize,
    disable: usize,
    enable_late: bool,
    disable_fault: bool,
    observe_fault: bool,
}
struct Owner {
    clock: Clock,
    state: Mutex<OwnerState>,
}
unsafe impl DisplayAudioPort for Owner {
    fn identity(&self) -> DisplayAudioIdentity {
        DisplayAudioIdentity {
            hda_function: Address {
                segment: 0,
                bus: 1,
                device: 0,
                function: 1,
            },
            gpu_function: Address {
                segment: 0,
                bus: 1,
                device: 0,
                function: 0,
            },
            codec: 0,
            pin: 4,
            port: 7,
        }
    }
    fn observe(&self, _: u64) -> Result<DisplayAudioState, Error> {
        let s = self.state.lock().unwrap();
        if s.observe_fault {
            return Err(Error::SinkUnavailable);
        }
        Ok(DisplayAudioState {
            generation: s.generation,
            connected: s.connected,
        })
    }
    fn enable_audio(&self, _: PcmFormat, deadline: u64) -> Result<(), Error> {
        let mut s = self.state.lock().unwrap();
        s.enable += 1;
        if s.enable_late {
            self.clock.0.store(deadline + 1, Ordering::SeqCst);
        }
        Ok(())
    }
    fn disable_audio(&self, _: u64) -> Result<(), Error> {
        let mut s = self.state.lock().unwrap();
        s.disable += 1;
        if s.disable_fault {
            Err(Error::SinkUnavailable)
        } else {
            Ok(())
        }
    }
}
struct Fixture {
    backing: Vec<u64>,
    allocator: RegionAllocator,
    hardware: Arc<Mutex<Hardware>>,
    clock: Clock,
    owner: Arc<Owner>,
}
impl Fixture {
    fn new(dp: bool) -> Self {
        let mut backing = vec![0u64; 256 * 1024];
        let base = backing.as_mut_ptr() as u64;
        let allocator = unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
        let clock = Clock(Arc::new(AtomicU64::new(0)));
        let hardware = Arc::new(Mutex::new(Hardware::new(clock.clone(), dp)));
        let owner = Arc::new(Owner {
            clock: clock.clone(),
            state: Mutex::new(OwnerState {
                generation: 1,
                connected: true,
                enable: 0,
                disable: 0,
                enable_late: false,
                disable_fault: false,
                observe_fault: false,
            }),
        });
        Self {
            backing,
            allocator,
            hardware,
            clock,
            owner,
        }
    }
    fn controller(&mut self) -> Controller<Regs, Clock> {
        assert!(!self.backing.is_empty());
        unsafe {
            Controller::new(
                Regs(self.hardware.clone()),
                self.clock.clone(),
                &mut self.allocator,
                super::super::Config {
                    transition_timeout_us: 1000,
                    verb_timeout_us: 1000,
                    ..Default::default()
                },
            )
        }
        .unwrap()
    }
    fn attach(&self, c: &mut Controller<Regs, Clock>) -> HdmiPortId {
        let graph = c.enumerate_codec(0).unwrap();
        unsafe { c.attach_hdmi_port(&graph, 4, self.owner.clone()) }.unwrap()
    }
    fn stream(
        &mut self,
        c: &mut Controller<Regs, Clock>,
        channels: u8,
        bits: u8,
    ) -> (StreamId, usize) {
        let format = PcmFormat {
            rate: 48000,
            bits,
            channels,
        };
        let period = format.frame_bytes().unwrap() * 512;
        let stream = c
            .allocate_stream(Direction::Playback, format, period, 4, &mut self.allocator)
            .unwrap();
        (stream, period)
    }
    fn advance(&self, bytes: usize, format: PcmFormat) {
        let micros = (bytes as u64 * 1_000_000)
            .div_ceil(u64::from(format.rate) * format.frame_bytes().unwrap() as u64);
        self.clock.0.fetch_add(micros, Ordering::SeqCst);
        self.hardware.lock().unwrap().dma(bytes);
    }
}
#[test]
fn actual_command_rings_eld_channels_packets_and_24_fresh_periods_without_restart() {
    for dp in [false, true] {
        for channels in [2, 4, 6, 8] {
            let mut f = Fixture::new(dp);
            let mut c = f.controller();
            let port = f.attach(&mut c);
            let (stream, period) = f.stream(&mut c, channels, 24);
            let map = c.prepare_hdmi(port, stream, 2, None).unwrap();
            for n in 0..4 {
                c.write_pcm(stream, n * period, &vec![n as u8; period])
                    .unwrap();
            }
            c.start(stream).unwrap();
            let format = c.stream_format(stream).unwrap();
            for n in 0..24 {
                f.advance(period, format);
                let next = vec![(n + 4) as u8; period];
                let done = c.refill_hdmi_period(stream, &next).unwrap().unwrap();
                assert_eq!(done.sequence, n as u64);
                assert_eq!(done.ring_offset, n % 4 * period);
            }
            {
                let h = f.hardware.lock().unwrap();
                assert_eq!(h.starts, 1);
                assert_eq!(h.stops, 0);
                for (n, chunk) in h.playback.chunks(period).enumerate() {
                    assert!(chunk.iter().all(|b| *b == n as u8));
                }
                assert_eq!(h.packet[0], 0x84);
                assert_eq!(&h.packet[1..3], if dp { &[0x1b, 0x44] } else { &[1, 10] });
                assert_eq!(h.packet[7], map.allocation());
                assert_eq!(h.digital & 0x21, 1);
                assert_eq!(h.count, channels - 1);
            }
            c.close_hdmi(port).unwrap();
            assert_eq!(c.start(stream), Err(Error::SinkUnavailable));
            c.detach_hdmi_port(port).unwrap();
            c.shutdown().unwrap();
            assert_eq!(Arc::strong_count(&f.owner), 1);
        }
    }
}
#[test]
fn invalid_eld_or_missing_pin_and_exact_profile_cannot_enable_gpu_or_codec() {
    for fault in 0..6 {
        let mut f = Fixture::new(false);
        let mut c = f.controller();
        match fault {
            0 => f.hardware.lock().unwrap().vendor = 0x10de0017,
            1 => f.hardware.lock().unwrap().vendor = 0x10de0040,
            2 => f.hardware.lock().unwrap().pin_caps = 0x10,
            3 => f.hardware.lock().unwrap().bad_eld = Some(12),
            4 => f.hardware.lock().unwrap().eld[4] = 31,
            _ => f.owner.state.lock().unwrap().observe_fault = true,
        }
        let graph = c.enumerate_codec(0).unwrap();
        let attached = unsafe { c.attach_hdmi_port(&graph, 4, f.owner.clone()) };
        if fault == 3 || fault == 4 {
            let port = attached.unwrap();
            let (s, _) = f.stream(&mut c, 2, 16);
            assert_eq!(c.prepare_hdmi(port, s, 2, None), Err(Error::InvalidEld));
            c.detach_hdmi_port(port).unwrap();
        } else {
            assert!(attached.is_err());
        }
        assert_eq!(f.owner.state.lock().unwrap().enable, 0);
        assert_eq!(f.hardware.lock().unwrap().pin, 0);
    }
}
#[test]
fn actual_hotplug_stops_then_reprepare_uses_new_sink_and_retains_original_port() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, period) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    {
        let mut o = f.owner.state.lock().unwrap();
        o.generation += 1;
        o.connected = false;
    }
    f.hardware.lock().unwrap().sense = 0;
    assert_eq!(c.status(s).unwrap_err(), Error::SinkChanged);
    assert_eq!(f.hardware.lock().unwrap().bar[0x80] & 2, 0);
    assert_eq!(f.hardware.lock().unwrap().pin, 0);
    assert_eq!(c.start(s), Err(Error::SinkUnavailable));
    assert_eq!(Arc::strong_count(&f.owner), 2);
    {
        let mut o = f.owner.state.lock().unwrap();
        o.generation += 1;
        o.connected = true;
    }
    f.hardware.lock().unwrap().sense = 0xc0000000;
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.write_pcm(s, 0, &vec![0x7a; period * 4]).unwrap();
    c.start(s).unwrap();
    assert_eq!(f.hardware.lock().unwrap().get(0x84, 4), 0);
    c.close_hdmi(port).unwrap();
    c.detach_hdmi_port(port).unwrap();
}
#[test]
fn incomplete_ioc_and_coalesced_events_use_retained_completed_frontier() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, p) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    let fmt = c.stream_format(s).unwrap();
    f.advance(p / 2, fmt);
    assert!(c.refill_hdmi_period(s, &vec![8; p]).unwrap().is_none());
    f.advance(p + p / 2, fmt);
    assert!(c.status(s).unwrap().period_completed);
    for _ in 0..2 {
        assert!(c.refill_hdmi_period(s, &vec![9; p]).unwrap().is_some());
    }
    assert!(c.refill_hdmi_period(s, &vec![10; p]).unwrap().is_none());
    c.close_hdmi(port).unwrap();
    c.detach_hdmi_port(port).unwrap();
}
#[test]
fn elapsed_lap_unfilled_queue_and_late_copy_refuse_success_and_stop() {
    for fault in 0..3 {
        let mut f = Fixture::new(false);
        let mut c = f.controller();
        let port = f.attach(&mut c);
        let (s, p) = f.stream(&mut c, 2, 16);
        c.prepare_hdmi(port, s, 2, None).unwrap();
        c.start(s).unwrap();
        let fmt = c.stream_format(s).unwrap();
        match fault {
            0 => {
                f.clock.0.fetch_add(100000, Ordering::SeqCst);
            }
            1 => f.advance(p * 4 - 64, fmt),
            _ => {
                f.advance(p, fmt);
                let mut h = f.hardware.lock().unwrap();
                h.late_position = Some((h.position_reads + 2, (p * 4 - 64) as u32, 32_000));
            }
        }
        assert_eq!(
            c.refill_hdmi_period(s, &vec![0x39; p]),
            Err(Error::PlaybackUnderrun)
        );
        assert_eq!(f.hardware.lock().unwrap().bar[0x80] & 2, 0);
        assert_eq!(
            c.hdmi_first_error(port).unwrap(),
            Some(Error::PlaybackUnderrun)
        );
        assert_eq!(c.start(s), Err(Error::SinkUnavailable));
        c.detach_hdmi_port(port).unwrap();
    }
}
#[test]
fn failed_gpu_enable_or_codec_ack_quarantines_then_explicit_reset_recovers() {
    for fault in 0..3 {
        let mut f = Fixture::new(false);
        let mut c = f.controller();
        let port = f.attach(&mut c);
        let (s, _) = f.stream(&mut c, 6, 24);
        match fault {
            0 => f.owner.state.lock().unwrap().enable_late = true,
            1 => f.hardware.lock().unwrap().reject = Some(0x72d),
            _ => f.hardware.lock().unwrap().drop_reply = Some(0x706),
        }
        let error = c.prepare_hdmi(port, s, 2, None).unwrap_err();
        assert_eq!(c.hdmi_first_error(port).unwrap(), Some(error));
        assert_eq!(Arc::strong_count(&f.owner), 2);
        assert_eq!(c.start(s), Err(Error::NeedsReset));
        f.owner.state.lock().unwrap().enable_late = false;
        {
            let mut h = f.hardware.lock().unwrap();
            h.reject = None;
            h.drop_reply = None;
        }
        c.reinitialize().unwrap();
        assert_eq!(Arc::strong_count(&f.owner), 1);
        assert_eq!(c.hdmi_first_error(port), Err(Error::InvalidHdmiPort));
    }
}
#[test]
fn failed_dma_stop_and_gpu_quiet_keep_whole_owner_and_first_cause() {
    for dma_fault in [false, true] {
        let mut f = Fixture::new(false);
        let mut c = f.controller();
        let port = f.attach(&mut c);
        let (s, _) = f.stream(&mut c, 2, 16);
        c.prepare_hdmi(port, s, 2, None).unwrap();
        c.start(s).unwrap();
        if dma_fault {
            f.hardware.lock().unwrap().stop_stuck = true;
        } else {
            f.owner.state.lock().unwrap().disable_fault = true;
        }
        assert!(c.close_hdmi(port).is_err());
        let first = c.hdmi_first_error(port).unwrap();
        assert!(first.is_some());
        assert_eq!(Arc::strong_count(&f.owner), 2);
        assert!(c.detach_hdmi_port(port).is_err());
        assert_eq!(c.hdmi_first_error(port).unwrap(), first);
        f.hardware.lock().unwrap().stop_stuck = false;
        f.owner.state.lock().unwrap().disable_fault = false;
        c.reinitialize().unwrap();
        assert_eq!(Arc::strong_count(&f.owner), 1);
    }
}
#[test]
fn active_or_faulted_controller_drop_does_not_release_actual_gpu_hda_owner() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, _) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    drop(c);
    assert_eq!(Arc::strong_count(&f.owner), 2);
    assert_eq!(f.hardware.lock().unwrap().bar[0x80] & 2, 2);
}
#[test]
fn one_stream_cannot_own_distinct_analog_and_hdmi_converters_in_either_order() {
    for analog_first in [false, true] {
        let mut f = Fixture::new(false);
        let mut c = f.controller();
        let port = f.attach(&mut c);
        let (s, _) = f.stream(&mut c, 2, 16);
        let analog = c.enumerate_codec(1).unwrap();
        let route = analog.analog_route(Direction::Playback, 4, 2).unwrap();
        let options = super::super::PinOptions::Playback {
            headphone: false,
            eapd: None,
        };
        if analog_first {
            c.configure_analog_route(&analog, &route, s, 0, options)
                .unwrap();
            let before = f.hardware.lock().unwrap().commands.len();
            assert_eq!(c.prepare_hdmi(port, s, 2, None), Err(Error::RouteInUse));
            assert_eq!(f.owner.state.lock().unwrap().enable, 0);
            assert!(
                f.hardware.lock().unwrap().commands[before..]
                    .iter()
                    .all(|command| command & (1 << 19) != 0)
            );
        } else {
            c.prepare_hdmi(port, s, 2, None).unwrap();
            let before = f.hardware.lock().unwrap().commands.len();
            assert_eq!(
                c.configure_analog_route(&analog, &route, s, 0, options),
                Err(Error::RouteInUse)
            );
            let h = f.hardware.lock().unwrap();
            assert_eq!(h.commands.len(), before);
            assert_eq!(h.analog.binding, 0);
            assert_eq!(h.analog.pin, 0);
        }
        c.close_hdmi(port).unwrap();
        c.detach_hdmi_port(port).unwrap();
        c.shutdown().unwrap();
    }
}
#[test]
fn acknowledged_stop_can_park_past_ring_duration_and_restart_a_fresh_epoch() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, p) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    let fmt = c.stream_format(s).unwrap();
    f.advance(p, fmt);
    c.stop(s).unwrap();
    f.clock.0.fetch_add(1_000_000, Ordering::SeqCst);
    assert!(!c.status(s).unwrap().running);
    assert_eq!(c.hdmi_first_error(port).unwrap(), None);
    assert_eq!(f.owner.state.lock().unwrap().disable, 0);
    c.write_pcm(s, 0, &vec![0x6d; p * 4]).unwrap();
    c.start(s).unwrap();
    f.hardware.lock().unwrap().playback.clear();
    f.advance(p, fmt);
    assert!(c.refill_hdmi_period(s, &vec![0x91; p]).unwrap().is_some());
    assert!(
        f.hardware
            .lock()
            .unwrap()
            .playback
            .iter()
            .all(|v| *v == 0x6d)
    );
    c.close_hdmi(port).unwrap();
    c.detach_hdmi_port(port).unwrap();
}
#[test]
fn actual_digital_enable_control_preserves_status_and_live_pcm_ownership() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, p) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    for enabled in [false, true, false, true] {
        c.set_hdmi_enabled(port, enabled).unwrap();
        assert_eq!(f.hardware.lock().unwrap().digital, 0x10 | u8::from(enabled));
        assert!(c.status(s).unwrap().running);
    }
    let fmt = c.stream_format(s).unwrap();
    f.advance(p, fmt);
    assert!(c.refill_hdmi_period(s, &vec![0x53; p]).unwrap().is_some());
    assert_eq!(f.owner.state.lock().unwrap().enable, 1);
    c.close_hdmi(port).unwrap();
    assert_eq!(c.set_hdmi_enabled(port, false), Err(Error::SinkUnavailable));
    c.detach_hdmi_port(port).unwrap();
}
#[test]
fn rejected_live_digital_control_keeps_effects_owner_and_cause_until_reset() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, _) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    f.hardware.lock().unwrap().reject = Some(0x70d);
    assert_eq!(c.set_hdmi_enabled(port, false), Err(Error::RouteRejected));
    assert_eq!(
        c.hdmi_first_error(port).unwrap(),
        Some(Error::RouteRejected)
    );
    assert_eq!(Arc::strong_count(&f.owner), 2);
    f.hardware.lock().unwrap().reject = None;
    c.reinitialize().unwrap();
    assert_eq!(Arc::strong_count(&f.owner), 1);
}
#[test]
fn polled_observation_cause_survives_simultaneous_dma_stop_failure() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, _) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    f.owner.state.lock().unwrap().observe_fault = true;
    f.hardware.lock().unwrap().stop_stuck = true;
    assert_eq!(c.poll_hdmi_sink(port), Err(Error::SinkUnavailable));
    assert_eq!(
        c.hdmi_first_error(port).unwrap(),
        Some(Error::SinkUnavailable)
    );
    assert_eq!(Arc::strong_count(&f.owner), 2);
    assert_eq!(f.hardware.lock().unwrap().bar[0x80] & 2, 2);
    f.owner.state.lock().unwrap().observe_fault = false;
    f.hardware.lock().unwrap().stop_stuck = false;
    c.reinitialize().unwrap();
    assert_eq!(Arc::strong_count(&f.owner), 1);
}
#[test]
fn pci_suspend_retires_only_after_real_dma_codec_gpu_and_command_quiet() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, _) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    let before = f.hardware.lock().unwrap().commands.len();
    assert_eq!(c.retire_hdmi_for_pci_suspend(), Err(Error::NeedsReset));
    assert_eq!(f.hardware.lock().unwrap().commands.len(), before);
    assert_eq!(Arc::strong_count(&f.owner), 2);
    c.shutdown().unwrap();
    assert_eq!(f.hardware.lock().unwrap().pin, 0);
    assert_eq!(f.hardware.lock().unwrap().transmit, 0);
    assert_eq!(f.hardware.lock().unwrap().binding, 0);
    assert_eq!(f.hardware.lock().unwrap().bar[0x80] & 2, 0);
    assert_eq!(f.hardware.lock().unwrap().bar[0x4c] & 2, 0);
    assert_eq!(f.hardware.lock().unwrap().bar[0x5c] & 2, 0);
    assert_eq!(Arc::strong_count(&f.owner), 2);
    c.retire_hdmi_for_pci_suspend().unwrap();
    assert_eq!(Arc::strong_count(&f.owner), 1);
    assert_eq!(c.hdmi_first_error(port), Err(Error::InvalidHdmiPort));
    c.reinitialize().unwrap();
    assert_eq!(c.hdmi_first_error(port), Err(Error::InvalidHdmiPort));
}
#[test]
fn pci_d3_grant_is_refused_after_uncertain_gpu_quiet_even_with_stopped_dma() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, _) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    f.owner.state.lock().unwrap().disable_fault = true;
    assert_eq!(c.shutdown(), Err(Error::SinkUnavailable));
    assert_eq!(f.hardware.lock().unwrap().bar[0x80] & 2, 0);
    assert_eq!(c.retire_hdmi_for_pci_suspend(), Err(Error::NeedsReset));
    assert_eq!(Arc::strong_count(&f.owner), 2);
    assert_eq!(
        c.hdmi_first_error(port).unwrap(),
        Some(Error::SinkUnavailable)
    );
    f.owner.state.lock().unwrap().disable_fault = false;
    c.reinitialize().unwrap();
    assert_eq!(Arc::strong_count(&f.owner), 1);
}
#[test]
fn mmio_codec_graph_does_not_fabricate_an_original_pci_subsystem() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let before = f.hardware.lock().unwrap().commands.len();
    assert_eq!(c.registers.codec_pci_subsystem().unwrap(), None);
    assert_eq!(f.hardware.lock().unwrap().commands.len(), before);
    c.shutdown().unwrap();
}
#[test]
fn raw_converter_binding_cannot_share_an_hdmi_stream_in_either_order() {
    for raw_first in [false, true] {
        let mut f = Fixture::new(false);
        let mut c = f.controller();
        let port = f.attach(&mut c);
        let (s, _) = f.stream(&mut c, 2, 16);
        let analog = c.enumerate_codec(1).unwrap();
        if raw_first {
            c.bind_converter(&analog, 2, s, 0).unwrap();
            let before = f.hardware.lock().unwrap().commands.len();
            assert_eq!(c.prepare_hdmi(port, s, 2, None), Err(Error::RouteInUse));
            assert_eq!(f.owner.state.lock().unwrap().enable, 0);
            assert!(
                f.hardware.lock().unwrap().commands[before..]
                    .iter()
                    .all(|v| v & (1 << 19) != 0)
            );
        } else {
            c.prepare_hdmi(port, s, 2, None).unwrap();
            let before = f.hardware.lock().unwrap().commands.len();
            assert_eq!(c.bind_converter(&analog, 2, s, 0), Err(Error::RouteInUse));
            assert_eq!(f.hardware.lock().unwrap().commands.len(), before);
        }
        c.close_hdmi(port).unwrap();
        c.detach_hdmi_port(port).unwrap();
        c.shutdown().unwrap();
    }
}
