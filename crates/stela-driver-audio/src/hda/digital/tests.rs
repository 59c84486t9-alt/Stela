// SPDX-License-Identifier: GPL-2.0-only
//! Independent native-width CORB/RIRB DMA peer. Commands are consumed from the
//! published coherent allocation, never by bypassing Controller::verb.
extern crate std;

use super::*;
use crate::bus::dma::RegionAllocator;
use alloc::{
    collections::{BTreeMap, VecDeque},
    rc::Rc,
    vec,
    vec::Vec,
};
use core::cell::{Cell, RefCell};

#[derive(Clone)]
struct Clock(Rc<Cell<u64>>);
impl crate::bus::i2c::Timer for Clock {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get() + 1);
    }
}
struct Ram {
    _bytes: Vec<u64>,
    allocator: RegionAllocator,
}
impl Ram {
    fn new() -> Self {
        let mut bytes = vec![0u64; 4096];
        let base = bytes.as_mut_ptr() as u64;
        // SAFETY: bytes owns the aligned allocation for the entire controller
        // test. This synchronous peer accesses it only during register polling.
        let allocator = unsafe { RegionAllocator::new(base..base + (bytes.len() * 8) as u64) };
        Self {
            _bytes: bytes,
            allocator,
        }
    }
}
struct Peer {
    registers: Vec<u8>,
    commands: Vec<u32>,
    accesses: usize,
    pin_default: u32,
    selected: u8,
    count: u8,
    images: Vec<Vec<u8>>,
    reads: usize,
    parameters: BTreeMap<(u8, u8), u32>,
    senses: VecDeque<u32>,
    sizes: VecDeque<u32>,
    size: u32,
    invalid_byte: Option<u8>,
    change_image: bool,
    drop_verb: Option<u16>,
    wrong_codec: bool,
    overrun: bool,
    reject_set: Option<u8>,
    shrink_on_set: bool,
}
impl Peer {
    fn new() -> Self {
        let mut peer = Self {
            registers: vec![0; 0x440],
            commands: Vec::new(),
            accesses: 0,
            pin_default: 0,
            selected: 0,
            count: 1,
            images: vec![image(false), image(true)],
            reads: 0,
            parameters: BTreeMap::new(),
            senses: VecDeque::new(),
            sizes: VecDeque::new(),
            size: 32,
            invalid_byte: None,
            change_image: false,
            drop_verb: None,
            wrong_codec: false,
            overrun: false,
            reject_set: None,
            shrink_on_set: false,
        };
        peer.put(0x00, 0x1001, 2); // one output, 64-bit DMA
        peer.put(0x03, 1, 1);
        peer.put(0x04, 512, 2);
        peer.put(0x06, 512, 2);
        peer.put(0x4e, 0x40, 1);
        peer.put(0x5e, 0x40, 1);
        peer
    }
    fn get(&self, offset: usize, bytes: usize) -> u32 {
        (0..bytes).fold(0, |value, index| {
            value | (u32::from(self.registers[offset + index]) << (index * 8))
        })
    }
    fn put(&mut self, offset: usize, value: u32, bytes: usize) {
        for index in 0..bytes {
            self.registers[offset + index] = (value >> (index * 8)) as u8;
        }
    }
    fn response(&mut self, command: u32) -> u32 {
        let node = ((command >> 20) & 127) as u8;
        let verb = ((command >> 8) & 0xfff) as u16;
        let payload = command as u8;
        match verb {
            0xf00 => {
                if let Some(value) = self.parameters.get(&(node, payload)) {
                    return *value;
                }
                match (node, payload) {
                    (0, 0) => 0x10de_0099,
                    (0, 2) => 0x100100,
                    (0, 4) => 0x0001_0001,
                    (1, 5) => 1,
                    (1, 4) => 0x0002_0003,
                    (1, 0x0a) => 0x000e_07f0,
                    (1, 0x0b) => 1,
                    (2, 9) => 0x201,          // digital stereo output, inherited PCM
                    (3, 9) => 0x6231,         // digital 8ch output, format override
                    (3, 0x0a) => 0x0008_0040, // 48kHz,24bit only
                    (4, 9) => 0x0040_0300,
                    (4, 0x0c) => 0x0100_0090, // DP,HDMI,output
                    (4, 0x0e) => 1,
                    (4, 0x15) => u32::from(self.count - 1),
                    _ => 0,
                }
            }
            0xf02 if node == 4 => u32::from(2 + self.selected),
            0xf1c => self.pin_default,
            0xf35 => u32::from(self.selected),
            0x735 => {
                assert!(payload < self.count, "out-of-range selector publication");
                if self.reject_set != Some(payload) {
                    self.selected = payload;
                }
                if self.shrink_on_set {
                    self.count = 1;
                }
                0
            }
            0xf09 => self.senses.pop_front().unwrap_or(0xc000_0000),
            0xf2e => {
                assert_eq!(payload, 8);
                self.sizes.pop_front().unwrap_or(self.size)
            }
            0xf2f => {
                if payload == 0 {
                    self.reads += 1;
                }
                let byte = self.images[usize::from(self.selected)][usize::from(payload)];
                if self.invalid_byte == Some(payload) {
                    return u32::from(byte);
                }
                let byte = if self.change_image && self.reads.is_multiple_of(2) && payload == 20 {
                    byte ^ 1
                } else {
                    byte
                };
                0x8000_0000 | u32::from(byte)
            }
            _ => panic!("unexpected codec write/verb {command:08x}"),
        }
    }
    fn consume(&mut self, wp: u16) {
        if self.get(0x4c, 1) & 2 == 0 {
            return;
        }
        let corb = u64::from(self.get(0x40, 4)) | (u64::from(self.get(0x44, 4)) << 32);
        // SAFETY: corb names a controller-allocated ring in kept fixture RAM;
        // wp is its published in-range entry. Polling serializes peer and CPU use.
        let command =
            unsafe { core::ptr::read_volatile((corb as *const u32).add(usize::from(wp))) }.to_le();
        self.commands.push(command);
        self.put(0x4a, u32::from(wp), 2);
        let verb = ((command >> 8) & 0xfff) as u16;
        if self.drop_verb == Some(verb) {
            return;
        }
        let response = self.response(command);
        let rirb = u64::from(self.get(0x50, 4)) | (u64::from(self.get(0x54, 4)) << 32);
        let next = (self.get(0x58, 2) + 1) % 256;
        let extra = if self.wrong_codec { 1 } else { command >> 28 };
        // SAFETY: rirb names the 256-entry fixture ring. next is reduced
        // modulo 256, and each entry has two aligned u32 words.
        unsafe {
            let destination = (rirb as *mut u32).add(next as usize * 2);
            core::ptr::write_volatile(destination, response.to_le());
            core::ptr::write_volatile(destination.add(1), extra.to_le());
        }
        self.put(0x58, next, 2);
        self.put(0x5d, if self.overrun { 5 } else { 1 }, 1);
    }
    fn width(offset: usize, bytes: usize) {
        let expected = match offset {
            0x02 | 0x03 | 0x4c..=0x4e | 0x5c..=0x5e | 0x80 | 0x83 => 1,
            0x00 | 0x04 | 0x06 | 0x0c | 0x0e | 0x18 | 0x1a | 0x48 | 0x4a | 0x58 | 0x5a | 0x68 => 2,
            0x08 | 0x20 | 0x40 | 0x44 | 0x50 | 0x54 | 0x60 | 0x64 | 0x70 | 0x74 => 4,
            _ => panic!("unexpected register {offset:x}"),
        };
        assert_eq!(bytes, expected);
    }
}
#[derive(Clone)]
struct RegistersPeer(Rc<RefCell<Peer>>);
impl RegistersPeer {
    fn read(&self, offset: usize, bytes: usize) -> u32 {
        Peer::width(offset, bytes);
        let mut peer = self.0.borrow_mut();
        peer.accesses += 1;
        peer.get(offset, bytes)
    }
    fn write(&self, offset: usize, value: u32, bytes: usize) {
        Peer::width(offset, bytes);
        let mut peer = self.0.borrow_mut();
        peer.accesses += 1;
        match offset {
            0x0e | 0x4d | 0x5d | 0x83 => {
                let old = peer.get(offset, bytes);
                peer.put(offset, old & !value, bytes);
            }
            0x4e | 0x5e => peer.put(offset, 0x40 | value, bytes),
            0x58 if value == 0x8000 => peer.put(offset, 0, bytes),
            0x08 => {
                peer.put(offset, value, bytes);
                if value & 1 != 0 {
                    peer.put(0x0e, 1, 2);
                }
            }
            0x48 => {
                peer.put(offset, value, bytes);
                peer.consume(value as u16);
            }
            _ => peer.put(offset, value, bytes),
        }
    }
}
impl Registers for RegistersPeer {
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
        self.write(offset, u32::from(value), 1);
    }
    fn write16(&mut self, offset: usize, value: u16) {
        self.write(offset, u32::from(value), 2);
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.write(offset, value, 4);
    }
}
fn controller(ram: &mut Ram) -> (Controller<RegistersPeer, Clock>, Rc<RefCell<Peer>>) {
    let peer = Rc::new(RefCell::new(Peer::new()));
    let registers = RegistersPeer(peer.clone());
    let clock = Clock(Rc::new(Cell::new(0)));
    // SAFETY: the Rc peer is used synchronously by this controller, with no
    // firmware or background DMA. ram keeps its coherent allocation until
    // the controller is dropped.
    let controller = unsafe {
        Controller::new(
            registers,
            clock,
            &mut ram.allocator,
            super::super::Config {
                verb_timeout_us: 4,
                transition_timeout_us: 4,
                ..Default::default()
            },
        )
        .map_err(|failure| failure.error)
    }
    .unwrap();
    (controller, peer)
}
fn image(dp: bool) -> Vec<u8> {
    // Two independent LPCM SADs: 8ch48k24 and 2ch192k16/20.
    let mut bytes = vec![0; 32];
    bytes[0] = 0x10;
    bytes[2] = 7;
    bytes[4] = 0x64;
    bytes[5] = 0x23 | if dp { 4 } else { 0 };
    bytes[6] = 7;
    bytes[7] = 0x0f;
    bytes[8..16].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    bytes[16..20].copy_from_slice(&[0x34, 0x12, 0x78, 0x56]);
    bytes[20..24].copy_from_slice(b"TEST");
    bytes[24..30].copy_from_slice(&[0x0f, 4, 4, 9, 64, 3]);
    bytes
}
fn pcm(rate: u32, bits: u8, channels: u8) -> PcmFormat {
    PcmFormat {
        rate,
        bits,
        channels,
    }
}

#[test]
fn single_entry_pcm_capabilities() {
    let mut ram = Ram::new();
    let (mut controller, peer) = controller(&mut ram);
    let mut pins = controller.discover_digital_pins(0).unwrap();
    assert_eq!(pins.len(), 1);
    let pin = &mut pins[0];
    assert_eq!(
        (
            pin.codec(),
            pin.function_group(),
            pin.node(),
            pin.device_entry()
        ),
        (0, 1, 4, 0)
    );
    assert_eq!(pin.converters()[0].node(), 2);
    assert_eq!(pin.converters()[0].channels(), 2);
    assert_eq!(
        controller.poll_digital_pin(pin),
        Ok(DigitalPresence::Stable)
    );
    let sink = pin.last_observation().unwrap();
    assert_eq!(sink.monitor_name(), b"TEST");
    assert_eq!(sink.port_id, 0x0807_0605_0403_0201);
    assert_eq!((sink.manufacturer, sink.product), (0x1234, 0x5678));
    assert_eq!(
        (sink.sync_delay_ms, sink.speaker_mask, sink.edid_version),
        (14, 15, 3)
    );
    assert!(sink.supports_ai && sink.reports_hdcp && !sink.partial);
    assert_eq!(sink.connection, DigitalConnection::Hdmi);
    assert_eq!(sink.descriptors().len(), 2);
    assert!(sink.supports_pcm(pcm(48_000, 24, 8)));
    assert!(sink.supports_pcm(pcm(192_000, 20, 2)));
    assert!(!sink.supports_pcm(pcm(192_000, 24, 8)));
    assert!(!sink.supports_pcm(pcm(48_000, 32, 2)));
    assert!(
        controller
            .digital_pcm_supported(pin, 2, pcm(192_000, 20, 2))
            .unwrap()
    );
    assert!(
        !controller
            .digital_pcm_supported(pin, 2, pcm(48_000, 24, 8))
            .unwrap()
    );
    assert!(
        !controller
            .digital_pcm_supported(pin, 99, pcm(192_000, 20, 2))
            .unwrap()
    );
    let peer = peer.borrow();
    let bytes: Vec<_> = peer
        .commands
        .iter()
        .filter(|word| (*word >> 8) & 0xfff == 0xf2f)
        .map(|word| *word as u8)
        .collect();
    assert_eq!(
        &bytes[..64],
        &[(0u8..32).collect::<Vec<_>>(), (0u8..32).collect()].concat()
    );
    assert!(peer.commands.iter().all(|word| matches!(
        (word >> 8) & 0xfff,
        0xf00 | 0xf02 | 0xf1c | 0xf35 | 0xf09 | 0xf2e | 0xf2f
    )));
}

#[test]
fn mst_connections_restore_selector() {
    let mut ram = Ram::new();
    let (mut controller, peer) = controller(&mut ram);
    {
        let mut peer = peer.borrow_mut();
        peer.count = 2;
        peer.selected = 1;
    }
    let mut pins = controller.discover_digital_pins(0).unwrap();
    assert_eq!(pins.len(), 2);
    assert_eq!(pins[0].converters()[0].node(), 2);
    assert_eq!(pins[1].converters()[0].node(), 3);
    assert_eq!(pins[1].converters()[0].channels(), 8);
    assert_eq!(peer.borrow().selected, 1);
    assert_eq!(
        controller.poll_digital_pin(&mut pins[0]),
        Ok(DigitalPresence::Stable)
    );
    assert_eq!(
        pins[0].last_observation().unwrap().connection,
        DigitalConnection::Hdmi
    );
    assert_eq!(peer.borrow().selected, 1);
    assert!(
        controller
            .digital_pcm_supported(&mut pins[1], 3, pcm(48_000, 24, 8))
            .unwrap()
    );
    assert!(
        !controller
            .digital_pcm_supported(&mut pins[1], 3, pcm(192_000, 20, 2))
            .unwrap()
    );
    assert_eq!(
        pins[1].last_observation().unwrap().connection,
        DigitalConnection::DisplayPort
    );
    assert_eq!(peer.borrow().selected, 1);
    let sets: Vec<_> = peer
        .borrow()
        .commands
        .iter()
        .filter(|word| (*word >> 8) & 0xfff == 0x735)
        .map(|word| *word as u8)
        .collect();
    assert_eq!(sets, [0, 1, 0, 1]);
}

#[test]
fn unsupported_audio_paths() {
    for (parameter, value) in [(9, 0x0040_0100), (0x0c, 0x10), (0x0c, 0x0100_0080)] {
        let mut ram = Ram::new();
        let (mut controller, peer) = controller(&mut ram);
        peer.borrow_mut().parameters.insert((4, parameter), value);
        assert!(controller.discover_digital_pins(0).unwrap().is_empty());
    }
    let mut ram = Ram::new();
    let (mut controller, peer) = controller(&mut ram);
    peer.borrow_mut().pin_default = 1 << 30;
    assert!(controller.discover_digital_pins(0).unwrap().is_empty());
    peer.borrow_mut().pin_default = 0;
    peer.borrow_mut().parameters.insert((2, 9), 0x0030_0201);
    assert_eq!(
        controller.discover_digital_pins(0).unwrap_err(),
        DigitalError::UnsupportedTopology
    );
    peer.borrow_mut().parameters.insert((1, 5), 2);
    assert_eq!(
        controller.discover_digital_pins(0).unwrap_err(),
        DigitalError::Controller(Error::UnsupportedTopology)
    );
}

#[test]
fn eld_acquisition_bounds() {
    for size in [0, 19, 257, u32::MAX] {
        let mut ram = Ram::new();
        let (mut controller, peer) = controller(&mut ram);
        let mut pins = controller.discover_digital_pins(0).unwrap();
        peer.borrow_mut().size = size;
        assert_eq!(
            controller.poll_digital_pin(&mut pins[0]),
            Err(DigitalError::InvalidEldSize(size))
        );
        assert!(pins[0].last_observation().is_none());
        assert!(
            !peer
                .borrow()
                .commands
                .iter()
                .any(|word| (word >> 8) & 0xfff == 0xf2f)
        );
    }
    let mut ram = Ram::new();
    let (mut controller, peer) = controller(&mut ram);
    let mut pins = controller.discover_digital_pins(0).unwrap();
    {
        let mut peer = peer.borrow_mut();
        peer.size = 256;
        peer.images[0].resize(256, 0);
    }
    assert_eq!(
        controller.poll_digital_pin(&mut pins[0]),
        Ok(DigitalPresence::Stable)
    );
    assert_eq!(pins[0].last_observation().unwrap().raw().len(), 256);
    assert_eq!(
        peer.borrow()
            .commands
            .iter()
            .filter(|word| **word & 0x000f_ffff == 0x000f_2fff)
            .count(),
        2
    );
}

#[test]
fn malformed_eld_rejected() {
    for (index, value, expected) in [
        (0, 8, DigitalError::UnsupportedEldVersion(1)),
        (4, 17, DigitalError::InvalidEld),
        (5, 0x28, DigitalError::UnsupportedConnection),
        (5, 0x2c, DigitalError::UnsupportedConnection),
        (2, 3, DigitalError::InvalidEld),
        (2, 8, DigitalError::InvalidEld),
        (5, 0xf0, DigitalError::InvalidEld),
    ] {
        let mut ram = Ram::new();
        let (mut controller, peer) = controller(&mut ram);
        let mut pins = controller.discover_digital_pins(0).unwrap();
        peer.borrow_mut().images[0][index] = value;
        assert_eq!(controller.poll_digital_pin(&mut pins[0]), Err(expected));
        assert!(pins[0].last_observation().is_none());
    }
}

#[test]
fn sad_capabilities_are_not_combined() {
    let mut ram = Ram::new();
    let (mut controller, peer) = controller(&mut ram);
    let mut pins = controller.discover_digital_pins(0).unwrap();
    {
        let mut peer = peer.borrow_mut();
        peer.images[0][7] = 0;
        peer.images[0][24] = 0x17;
        peer.images[0][27] = 0x17;
    }
    assert_eq!(
        controller.poll_digital_pin(&mut pins[0]),
        Ok(DigitalPresence::Stable)
    );
    let sink = pins[0].last_observation().unwrap();
    assert_eq!(sink.speaker_mask, 0);
    assert_eq!(sink.descriptors()[0].coding(), 2);
    assert!(!sink.supports_pcm(pcm(48_000, 24, 2)));
    {
        let mut peer = peer.borrow_mut();
        peer.images[0] = image(false);
        peer.images[0][0] = 0xf8;
    }
    assert_eq!(
        controller.poll_digital_pin(&mut pins[0]),
        Ok(DigitalPresence::Stable)
    );
    assert!(pins[0].last_observation().unwrap().partial);
    assert!(
        !pins[0]
            .last_observation()
            .unwrap()
            .supports_pcm(pcm(48_000, 24, 2))
    );
}

#[test]
fn sink_change_invalidates_session() {
    for fault in 0..7 {
        let mut ram = Ram::new();
        let (mut controller, peer) = controller(&mut ram);
        let mut pins = controller.discover_digital_pins(0).unwrap();
        assert_eq!(
            controller.poll_digital_pin(&mut pins[0]),
            Ok(DigitalPresence::Stable)
        );
        {
            let mut peer = peer.borrow_mut();
            match fault {
                0 => peer.senses.push_back(0),
                1 => peer.senses.push_back(0x8000_0000),
                2 => peer.senses.extend([0xc000_0000, 0]),
                3 => peer.sizes.extend([32, 31]),
                4 => peer.invalid_byte = Some(12),
                5 => peer.change_image = true,
                6 => peer.images[0][0] = 0,
                _ => unreachable!(),
            }
        }
        let result = controller.poll_digital_pin(&mut pins[0]);
        match fault {
            0 => assert_eq!(result, Ok(DigitalPresence::Disconnected)),
            1 => assert_eq!(result, Ok(DigitalPresence::AwaitingEld)),
            2 | 3 | 5 => assert_eq!(result, Err(DigitalError::UnstableSink)),
            4 => assert_eq!(result, Err(DigitalError::InvalidEldByte(12))),
            6 => assert_eq!(result, Err(DigitalError::InvalidEldByte(0))),
            _ => unreachable!(),
        }
        assert!(pins[0].last_observation().is_none());
    }
}

#[test]
fn transport_falls_back_to_single_commands() {
    for fault in 0..3 {
        let mut ram = Ram::new();
        let (mut controller, peer) = controller(&mut ram);
        let mut pins = controller.discover_digital_pins(0).unwrap();
        {
            let mut peer = peer.borrow_mut();
            match fault {
                0 => peer.drop_verb = Some(0xf2f),
                1 => peer.wrong_codec = true,
                2 => peer.overrun = true,
                _ => unreachable!(),
            }
        }
        let result = controller.poll_digital_pin(&mut pins[0]);
        if fault == 2 {
            // azx_interrupt acknowledges an overrun and carries on.
            assert!(result.is_ok());
            continue;
        }
        // Silence and another codec's answer both time the verb out.
        assert_eq!(
            result,
            Err(DigitalError::Controller(Error::Timeout(crate::Phase::Verb)))
        );
        assert!(controller.single_command && !controller.command_poisoned);
    }
}

#[test]
fn reset_invalidates_sessions() {
    let mut ram = Ram::new();
    let (mut controller, peer) = controller(&mut ram);
    let mut pins = controller.discover_digital_pins(0).unwrap();
    assert_eq!(
        controller.poll_digital_pin(&mut pins[0]),
        Ok(DigitalPresence::Stable)
    );
    controller.reinitialize().unwrap();
    let accesses = peer.borrow().accesses;
    assert_eq!(
        controller.poll_digital_pin(&mut pins[0]),
        Err(DigitalError::StaleSession)
    );
    assert_eq!(peer.borrow().accesses, accesses);
    assert!(pins[0].last_observation().is_none());
    let mut fresh = controller.discover_digital_pins(0).unwrap();
    assert_eq!(
        controller.poll_digital_pin(&mut fresh[0]),
        Ok(DigitalPresence::Stable)
    );
    controller.shutdown().unwrap();
    let accesses = peer.borrow().accesses;
    assert_eq!(
        controller.poll_digital_pin(&mut fresh[0]),
        Err(DigitalError::Controller(Error::NeedsReset))
    );
    assert_eq!(peer.borrow().accesses, accesses);
    assert!(fresh[0].last_observation().is_none());
}

#[test]
fn mst_shrink_quarantines_owner() {
    let mut ram = Ram::new();
    let (mut controller, peer) = controller(&mut ram);
    peer.borrow_mut().count = 2;
    let mut pins = controller.discover_digital_pins(0).unwrap();
    peer.borrow_mut().count = 1;
    let commands = peer.borrow().commands.len();
    assert_eq!(
        controller.poll_digital_pin(&mut pins[1]),
        Err(DigitalError::DeviceEntryGone)
    );
    assert_eq!(peer.borrow().commands.len(), commands + 1);
    {
        let mut peer = peer.borrow_mut();
        peer.count = 2;
        peer.reject_set = Some(1);
    }
    assert_eq!(
        controller.poll_digital_pin(&mut pins[1]),
        Err(DigitalError::DeviceSelection)
    );
    assert!(!controller.lifecycle_failed); // original selection restored
    {
        let mut peer = peer.borrow_mut();
        peer.reject_set = Some(0);
    }
    assert_eq!(
        controller.poll_digital_pin(&mut pins[1]),
        Err(DigitalError::DeviceSelection)
    );
    assert!(controller.lifecycle_failed);
    assert!(pins[1].last_observation().is_none());
    let count = peer.borrow().commands.len();
    assert_eq!(
        controller.discover_digital_pins(0).unwrap_err(),
        DigitalError::Controller(Error::NeedsReset)
    );
    assert_eq!(peer.borrow().commands.len(), count);
}

#[test]
fn failed_acquisition_restores_selector() {
    let mut ram = Ram::new();
    let (mut controller, peer) = controller(&mut ram);
    {
        let mut peer = peer.borrow_mut();
        peer.count = 2;
        peer.selected = 1;
    }
    let mut pins = controller.discover_digital_pins(0).unwrap();
    peer.borrow_mut().invalid_byte = Some(7);
    assert_eq!(
        controller.poll_digital_pin(&mut pins[0]),
        Err(DigitalError::InvalidEldByte(7))
    );
    assert_eq!(peer.borrow().selected, 1);
    assert!(!controller.lifecycle_failed);
    {
        let mut peer = peer.borrow_mut();
        peer.invalid_byte = None;
        peer.shrink_on_set = true;
    }
    assert_eq!(
        controller.poll_digital_pin(&mut pins[0]),
        Err(DigitalError::DeviceEntryGone)
    );
    assert!(controller.lifecycle_failed);
    assert_eq!(peer.borrow().selected, 0);
}

#[test]
fn changed_connection_rejects_pcm() {
    let mut ram = Ram::new();
    let (mut controller, peer) = controller(&mut ram);
    let mut pins = controller.discover_digital_pins(0).unwrap();
    controller.capabilities.output_stream_payload_words = 1;
    assert!(
        !controller
            .digital_pcm_supported(&mut pins[0], 2, pcm(192_000, 20, 2))
            .unwrap()
    );
    peer.borrow_mut().parameters.insert((2, 9), 0x200);
    assert_eq!(
        controller.poll_digital_pin(&mut pins[0]),
        Err(DigitalError::StaleSession)
    );
    assert!(pins[0].last_observation().is_none());
}

#[test]
fn masked_device_count_refreshes_entries() {
    let mut ram = Ram::new();
    let (mut controller, peer) = controller(&mut ram);
    {
        let mut peer = peer.borrow_mut();
        peer.count = 2;
        peer.selected = 1;
        peer.parameters.insert((4, 0x15), 0xa500_0001);
    }
    let mut pins = controller.discover_digital_pins(0).unwrap();
    assert_eq!(pins.len(), 2);
    for (index, pin) in pins.iter_mut().enumerate() {
        assert_eq!(pin.device_entry(), index as u8);
        assert_eq!(pin.converters().len(), 1);
        assert_eq!(pin.converters()[0].node(), 2 + index as u8);
        assert_eq!(pin.converters()[0].channels(), [2, 8][index]);
        assert_eq!(
            controller.poll_digital_pin(pin),
            Ok(DigitalPresence::Stable)
        );
        let sink = pin.last_observation().unwrap();
        assert_eq!(sink.raw(), image(index == 1));
        assert_eq!(
            sink.connection,
            [DigitalConnection::Hdmi, DigitalConnection::DisplayPort][index]
        );
        assert_eq!(peer.borrow().selected, 1);
    }
    let peer = peer.borrow();
    let sets: Vec<_> = peer
        .commands
        .iter()
        .filter(|word| (*word >> 8) & 0xfff == 0x735)
        .map(|word| *word as u8)
        .collect();
    assert_eq!(sets, [0, 1, 0, 1]);
    assert_eq!(peer.reads, 4);
    assert_eq!(peer.selected, 1);
}

#[test]
fn device_count_boundaries() {
    for (response, count) in [(0, 1), (63, 64), (0xa500_0000, 1), (0xa500_003f, 64)] {
        let mut ram = Ram::new();
        let (mut controller, peer) = controller(&mut ram);
        peer.borrow_mut().parameters.insert((4, 0x15), response);
        let commands = peer.borrow().commands.len();
        assert_eq!(controller.device_count(0, 4), Ok(count));
        let peer = peer.borrow();
        assert_eq!(peer.commands.len(), commands + 1);
        assert_eq!(peer.commands[commands] & 0x000f_ffff, 0x000f_0015);
    }
}

#[test]
fn failed_device_count_rejected() {
    let mut ram = Ram::new();
    let (mut controller, peer) = controller(&mut ram);
    {
        let mut peer = peer.borrow_mut();
        peer.count = 2;
        peer.selected = 1;
        peer.parameters.insert((4, 0x15), u32::MAX);
    }
    assert_eq!(
        controller.discover_digital_pins(0).unwrap_err(),
        DigitalError::InvalidDeviceList
    );
    let peer = peer.borrow();
    assert_eq!(peer.selected, 1);
    assert!(
        peer.commands
            .iter()
            .all(|word| (*word >> 8) & 0xfff != 0x735)
    );
    assert!(!controller.command_poisoned);
    assert!(!controller.lifecycle_failed);
}

/// Display-side counterpart for the CORB/RIRB peer. Its attachment
/// goes through the legacy ownership API; no controller field is forged.
struct LegacyDisplayPeer {
    state: std::sync::Mutex<super::super::hdmi::DisplayAudioState>,
    observations: core::sync::atomic::AtomicUsize,
}
// SAFETY: this test exclusively owns the modeled HDA and display connector.
// The attached Arc keeps its link/power state until port detachment.
// No playback is requested; unexpected clock/link effects fail the model.
unsafe impl super::super::hdmi::DisplayAudioPort for LegacyDisplayPeer {
    fn identity(&self) -> super::super::hdmi::DisplayAudioIdentity {
        use crate::bus::pci::Address;
        super::super::hdmi::DisplayAudioIdentity {
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
            device: 0,
            port: 7,
        }
    }
    fn observe(&self, _deadline_us: u64) -> Result<super::super::hdmi::DisplayAudioState, Error> {
        self.observations
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        Ok(*self.state.lock().unwrap())
    }
    fn enable_audio(&self, _format: PcmFormat, _deadline_us: u64) -> Result<(), Error> {
        panic!("digital observation must not enable the retained display route")
    }
    fn disable_audio(&self, _deadline_us: u64) -> Result<(), Error> {
        panic!("digital observation must not disable the retained display route")
    }
}

#[test]
fn legacy_port_excludes_sessions() {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    let mut ram = Ram::new();
    let (mut controller, peer) = controller(&mut ram);
    {
        let mut peer = peer.borrow_mut();
        peer.count = 2;
        peer.selected = 1;
        // The real graph enumeration admits the existing legacy profile and
        // reads AFG/widget D0 capabilities from this command-ring peer.
        peer.parameters.insert((0, 0), 0x10de_0008);
        peer.parameters.insert((1, 0x0f), 1);
        peer.parameters.insert((4, 9), 0x0040_0700);
        peer.parameters.insert((4, 0x0f), 1);
    }
    let mut pins = controller.discover_digital_pins(0).unwrap();
    assert_eq!(pins.len(), 2);
    for pin in &mut pins {
        assert_eq!(
            controller.poll_digital_pin(pin),
            Ok(DigitalPresence::Stable)
        );
        assert!(pin.last_observation().is_some());
    }
    let owner = Arc::new(LegacyDisplayPeer {
        state: std::sync::Mutex::new(super::super::hdmi::DisplayAudioState {
            generation: 1,
            connected: true,
        }),
        observations: AtomicUsize::new(0),
    });
    let graph = controller.enumerate_codec(0).unwrap();
    // SAFETY: display peer owns this modeled codec/pin; the
    // controller validates the token and freshly re-enumerates its real graph.
    let port = unsafe { controller.attach_hdmi_port(&graph, 4, 0, owner.clone()) }.unwrap();
    assert_eq!(owner.observations.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&owner), 2);
    assert!(controller.hdmi_owns_node(0, 4));
    assert!(controller.streams.iter().all(Option::is_none));
    // Stopped/unprepared is still owned. A close alone does not detach it.
    controller.close_hdmi(port).unwrap();
    let commands = peer.borrow().commands.len();
    let accesses = peer.borrow().accesses;
    let eld_reads = peer.borrow().reads;
    for pin in &mut pins {
        let attempt = pin.attempt();
        assert_eq!(
            controller.poll_digital_pin(pin),
            Err(DigitalError::Controller(Error::RouteInUse))
        );
        assert_eq!(pin.attempt(), attempt + 1);
        assert!(pin.last_observation().is_none());
    }
    assert_eq!(peer.borrow().commands.len(), commands);
    assert_eq!(peer.borrow().accesses, accesses);
    assert_eq!(
        controller.digital_pcm_supported(&mut pins[0], 2, pcm(48_000, 24, 2)),
        Err(DigitalError::Controller(Error::RouteInUse))
    );
    assert_eq!(peer.borrow().commands.len(), commands);
    assert_eq!(peer.borrow().accesses, accesses);
    assert_eq!(
        controller.discover_digital_pins(0).unwrap_err(),
        DigitalError::Controller(Error::RouteInUse)
    );
    {
        let peer = peer.borrow();
        assert!(
            peer.commands[commands..]
                .iter()
                .all(|word| matches!((word >> 8) & 0xfff, 0xf00 | 0xf02 | 0xf1c))
        );
        assert_eq!(peer.reads, eld_reads);
        assert_eq!(peer.selected, 1);
    }
    assert_eq!(Arc::strong_count(&owner), 2);
    assert_eq!(owner.observations.load(Ordering::SeqCst), 1);
    assert_eq!(controller.hdmi_first_error(port), Ok(None));
    assert!(controller.hdmi_owns_node(0, 4));
    assert!(controller.streams.iter().all(Option::is_none));
    assert!(!controller.routing_failed);
    assert!(!controller.lifecycle_failed);
    assert!(!controller.command_poisoned);
    // Acknowledged owner release reopens observation of the same pin;
    // refusal did not silently detach, replace, or poison the owner.
    controller.detach_hdmi_port(port).unwrap();
    assert_eq!(Arc::strong_count(&owner), 1);
    assert!(!controller.hdmi_owns_node(0, 4));
    assert_eq!(
        controller.poll_digital_pin(&mut pins[0]),
        Ok(DigitalPresence::Stable)
    );
    assert_eq!(peer.borrow().selected, 1);
    assert_eq!(peer.borrow().reads, eld_reads + 2);
}

// SAFETY: this private synchronous peripheral model measures virtual microseconds;
// no physical timer, CPU or native hardware permission follows from it.
unsafe impl crate::bus::pci::power::Timer for Clock {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        Ok(())
    }
    fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.0.set(
            self.0
                .get()
                .checked_add(us)
                .expect("bounded model minimum wait"),
        );
        Ok(())
    }
}
