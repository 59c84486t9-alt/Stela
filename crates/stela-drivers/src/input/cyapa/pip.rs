// SPDX-License-Identifier: GPL-2.0-only
//! Cypress Gen5 PIP I2C FIFO, serialized command replies and physical reports.
use super::{Interrupt, InterruptError, Recovery};
use crate::bus::i2c::{self, Address, Bus, Operation, Timer};
use alloc::collections::VecDeque;
mod device;
mod report;
pub use report::{Contact, ContactType, Event, Frame, Record, Touches};

const MAX_PACKET: usize = 256;
const MAX_PENDING: usize = 16;
/// Complete actual FIFO read, including the actual little-endian length field.
/// A two-byte reset notice advertises zero, without manufacturing missing bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    bytes: [u8; MAX_PACKET],
    received: u16,
}
impl Packet {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.received)]
    }
    pub fn declared_length(&self) -> u16 {
        u16::from_le_bytes([self.bytes[0], self.bytes[1]])
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Fresh,
    Starting,
    Ready,
    DeepSleep,
    ButtonsOnly,
    Stopped,
    Uncertain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidAddress,
    NotReady,
    AlreadyActive,
    NeedsReset,
    Bus(i2c::Error),
    Interrupt(InterruptError),
    Length(u16),
    ChangedLength { peek: u16, actual: u16 },
    QueueFull,
    DrainLimit,
    Timeout,
    UnexpectedReset,
    Descriptor,
    FirmwareLaunch,
    UnsupportedGeneration { family: u8, silicon_high: u8 },
    CommandStatus { command: u8, status: u8 },
    UnsupportedCommand(u8),
    UnsupportedReport(u8),
    ReportLength { id: u8, actual: u16 },
    ContactCount(u8),
    ContactType(u8),
    DuplicateId(u8),
    Coordinate { id: u8, x: u16, y: u16 },
    InvalidGeometry,
    ProductFamily(u16),
    UnsupportedProduct,
    IdentityChanged,
    Orientation(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub recovery: Recovery,
}
impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            recovery: Recovery::NotAttempted,
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Cypress PIP {:?} ({:?})", self.kind, self.recovery)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub descriptor: [u8; 32],
    pub system_info: [u8; 71],
    pub product_id: [u8; 15],
    pub platform_version: u8,
    pub firmware_version: (u8, u8),
    pub electrodes: (u8, u8),
    pub physical_size_mm: (u16, u16),
    pub maximum: (u16, u16),
    pub maximum_z: u16,
    pub origins: (bool, bool),
    pub button_capabilities: u8,
}
pub struct Device<B, I, T> {
    bus: B,
    interrupt: I,
    timer: T,
    address: Address,
    state: State,
    capabilities: Option<Capabilities>,
    pending: VecDeque<Packet>,
    failed_packet: Option<Packet>,
}
impl<B: Bus, I: Interrupt, T: Timer> Device<B, I, T> {
    /// The platform grants exclusive ownership of the powered peripheral, bus and IRQ.
    /// No prior ownership epoch may have an outstanding command: six idle headers
    /// drain currently queued data but cannot exclude a delayed identical-opcode reply.
    /// An uncertain prior owner must be retired through platform reset before this grant.
    pub fn new(bus: B, interrupt: I, timer: T, address: Address) -> Result<Self, Error> {
        if !matches!(address, Address::SevenBit(value @ 0x08..=0x77) if value & 1 == 0) {
            return Err(ErrorKind::InvalidAddress.into());
        }
        Ok(Self {
            bus,
            interrupt,
            timer,
            address,
            state: State::Fresh,
            capabilities: None,
            pending: VecDeque::new(),
            failed_packet: None,
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.capabilities.as_ref()
    }
    /// Earlier physical packets remain owned even if a later command fails.
    pub fn take_pending_packet(&mut self) -> Option<Packet> {
        self.pending.pop_front()
    }
    /// Most recent complete header/packet associated with a failed transfer.
    pub fn take_failed_packet(&mut self) -> Option<Packet> {
        self.failed_packet.take()
    }
}

#[cfg(test)]
mod tests {
    //! Independent length-prefixed FIFO and actual asynchronous command effects.
    use super::*;
    use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
    use core::cell::{Cell, RefCell};
    struct Hardware {
        queue: VecDeque<Vec<u8>>,
        deferred: Vec<(u64, Vec<u8>)>,
        clock: Rc<Cell<u64>>,
        bootloader: bool,
        boot_info_length: usize,
        deep: bool,
        power: u8,
        info: Vec<u8>,
        descriptor_bad: bool,
        launch_failure: bool,
        effects: Vec<(Vec<u8>, usize)>,
        fail: Option<usize>,
        fail_irq: bool,
        masked: bool,
        no_reply_irq: bool,
        omit: Option<u8>,
        bad_status: Option<(u8, u8)>,
        inject: Option<(u8, Vec<Vec<u8>>)>,
        change_length: bool,
        jump: Option<(usize, u64)>,
    }
    fn hardware(bootloader: bool, platform: u8) -> Rc<RefCell<Hardware>> {
        let mut info = vec![0xa5; 71];
        info[..6].copy_from_slice(&[71, 0, 0x1f, 0, 0x82, 0]);
        info[7..9].copy_from_slice(&0x1000u16.to_le_bytes());
        info[9..11].copy_from_slice(&[3, 4]);
        info[15..17].copy_from_slice(&[1, 2]);
        info[19] = 0x91;
        info[22] = 0x02;
        info[33..46].copy_from_slice(b"CYTRA12345678");
        info[49] = platform << 4;
        info[52] = 12;
        info[53] = 10;
        for (offset, value) in [
            (54, 10000u16),
            (56, 5000),
            (58, 4095),
            (60, 2047),
            (62, 255),
        ] {
            info[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        info[64] = 0;
        info[65] = 0;
        info[70] = 7;
        Rc::new(RefCell::new(Hardware {
            queue: VecDeque::new(),
            deferred: Vec::new(),
            clock: Rc::new(Cell::new(0)),
            bootloader,
            boot_info_length: 19,
            deep: true,
            power: 0,
            info,
            descriptor_bad: false,
            launch_failure: false,
            effects: Vec::new(),
            fail: None,
            fail_irq: false,
            masked: false,
            no_reply_irq: false,
            omit: None,
            bad_status: None,
            inject: None,
            change_length: false,
            jump: None,
        }))
    }
    struct Wire(Rc<RefCell<Hardware>>);
    struct Irq(Rc<RefCell<Hardware>>);
    struct Time(Rc<Cell<u64>>);
    fn failure() -> i2c::Error {
        i2c::Error {
            kind: i2c::ErrorKind::Aborted {
                kind: i2c::AbortKind::DataNack,
                source: 8,
            },
            recovery: i2c::Recovery::Disabled,
        }
    }
    impl Hardware {
        fn schedule(&mut self, code: u8, mut response: Vec<u8>) {
            if self.omit == Some(code) {
                return;
            }
            if let Some((expected, status)) = self.bad_status
                && expected == code
            {
                response[5] = status;
            }
            if self
                .inject
                .as_ref()
                .is_some_and(|(expected, _)| *expected == code)
            {
                let (_, packets) = self.inject.take().unwrap();
                for packet in packets {
                    self.deferred.push((self.clock.get() + 3000, packet));
                }
            }
            self.deferred.push((self.clock.get() + 3000, response));
        }
        fn update(&mut self) {
            let mut ready = Vec::new();
            let now = self.clock.get();
            self.deferred.retain(|(time, packet)| {
                if *time <= now {
                    ready.push(packet.clone());
                    false
                } else {
                    true
                }
            });
            self.queue.extend(ready);
        }
    }
    impl Bus for Wire {
        fn transaction(
            &mut self,
            address: Address,
            operations: &mut [Operation<'_>],
        ) -> Result<(), i2c::Error> {
            assert_eq!(address, Address::SevenBit(0x24));
            let mut h = self.0.borrow_mut();
            assert!(h.masked);
            h.update();
            match operations {
                [Operation::Write(bytes)] => {
                    h.effects.push((bytes.to_vec(), 0));
                    match **bytes {
                        [1, 0] => {
                            let mut descriptor = vec![0xa5; 32];
                            descriptor[..3].copy_from_slice(&[
                                32,
                                0,
                                if h.bootloader { 0xff } else { 0xf7 },
                            ]);
                            let maximum = if h.descriptor_bad {
                                0x123u16
                            } else if h.bootloader {
                                0x100
                            } else {
                                0xfe
                            };
                            descriptor[16..18].copy_from_slice(&maximum.to_le_bytes());
                            h.schedule(0xf7, descriptor);
                        }
                        [5, 0, state, 8] => {
                            assert!(state <= 1);
                            h.deep = state != 0;
                            h.schedule(0xf0, vec![5, 0, 0xf0, state, 0x88]);
                        }
                        [4, 0, 6, 0, 0x2f, 0, 8, state] => {
                            assert!(!h.bootloader && !h.deep);
                            assert!(matches!(state, 1 | 5));
                            h.power = state;
                            h.schedule(8, vec![6, 0, 0x1f, 0, 0x88, 0]);
                        }
                        [4, 0, 5, 0, 0x2f, 0, 2] => {
                            assert!(!h.bootloader && !h.deep);
                            let info = h.info.clone();
                            h.schedule(2, info);
                        }
                        [4, 0, 6, 0, 0x2f, 0, 0x49, 1] => {
                            assert!(h.info[49] >> 4 >= 2);
                            h.schedule(0x49, vec![6, 0, 0x1f, 0, 0xc9, 0]);
                        }
                        [4, 0, 0x0b, 0, 0x40, 0, 1, 0x38, 0, 0, 0x70, 0x9e, 0x17] => {
                            assert!(h.bootloader);
                            let mut response = vec![0xa5; 19];
                            response[..5].copy_from_slice(&[19, 0, 0x30, 0, 1]);
                            response[8] = h.info[19];
                            response[11] = h.info[22];
                            response.truncate(h.boot_info_length);
                            let length = response.len() as u16;
                            response[..2].copy_from_slice(&length.to_le_bytes());
                            h.schedule(0x38, response);
                        }
                        [4, 0, 0x0b, 0, 0x40, 0, 1, 0x3b, 0, 0, 0x20, 0xc7, 0x17] => {
                            assert!(h.bootloader);
                            if h.launch_failure {
                                h.schedule(0x3b, vec![11, 0, 0x30, 0, 1, 0x0c, 0, 0, 0, 0, 0x17]);
                            } else {
                                h.bootloader = false;
                                h.schedule(0x3b, vec![0, 0]);
                            }
                        }
                        _ => panic!("unexpected physical command"),
                    }
                }
                [Operation::Read(output)] => {
                    h.effects.push((vec![], output.len()));
                    if output.len() == 2 {
                        if let Some(front) = h.queue.front() {
                            output.copy_from_slice(&front[..2]);
                            if front.len() == 2 {
                                h.queue.pop_front();
                            }
                        } else {
                            output.copy_from_slice(&[2, 0]);
                        }
                    } else {
                        let packet = h.queue.pop_front().expect("complete queued packet");
                        assert_eq!(output.len(), packet.len());
                        output.copy_from_slice(&packet);
                        if h.change_length {
                            let length = output.len() as u16 - 1;
                            output[..2].copy_from_slice(&length.to_le_bytes());
                            h.change_length = false;
                        }
                    }
                }
                _ => panic!("PIP uses actual raw FIFO transfers"),
            }
            if let Some((index, delta)) = h.jump
                && index == h.effects.len()
            {
                h.clock.set(h.clock.get().wrapping_add(delta));
                h.jump = None;
            }
            if h.fail == Some(h.effects.len()) {
                return Err(failure());
            }
            Ok(())
        }
    }
    impl Interrupt for Irq {
        fn mask_and_drain(&mut self) -> Result<(), InterruptError> {
            let mut h = self.0.borrow_mut();
            if h.fail_irq {
                Err(InterruptError::Hardware(1))
            } else {
                h.masked = true;
                Ok(())
            }
        }
        fn asserted(&mut self) -> Result<bool, InterruptError> {
            let mut h = self.0.borrow_mut();
            h.update();
            if h.fail_irq {
                return Err(InterruptError::Hardware(2));
            }
            Ok(h.queue
                .iter()
                .any(|p| !h.no_reply_irq || p.len() > 2 && matches!(p[2], 1 | 3..=7)))
        }
    }
    impl Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
        fn relax(&self) {
            self.0.set(self.0.get().wrapping_add(1000));
        }
    }
    fn device(h: &Rc<RefCell<Hardware>>) -> Device<Wire, Irq, Time> {
        Device::new(
            Wire(h.clone()),
            Irq(h.clone()),
            Time(h.borrow().clock.clone()),
            Address::SevenBit(0x24),
        )
        .unwrap()
    }
    fn touch(count: u8, first: u8, event: u8, orientation: u8) -> Vec<u8> {
        let mut packet = vec![0xa5; 7 + usize::from(count) * 12];
        let length = packet.len() as u16;
        packet[..2].copy_from_slice(&length.to_le_bytes());
        packet[2] = 1;
        packet[5] = count | 0xa0;
        for index in 0..count {
            let offset = 7 + usize::from(index) * 12;
            let x = 7 + u16::from(index) * 400;
            let y = 9 + u16::from(index) * 200;
            let id = (first + index * 3) & 31;
            packet[offset..offset + 12].copy_from_slice(&[
                index % 3,
                id | (event << 5) | if event == 3 { 0x80 } else { 0 },
                x as u8,
                (x >> 8) as u8,
                y as u8,
                (y >> 8) as u8,
                index,
                5 + index,
                3 + index,
                9 + index,
                7 + index,
                orientation,
            ]);
        }
        packet
    }
    #[test]
    fn gen5_actual_descriptor_wake_active_info_proximity_and_boot_exit_have_real_replies() {
        for boot in [false, true] {
            for platform in [0, 1, 2, 15] {
                let h = hardware(boot, platform);
                h.borrow_mut().no_reply_irq = true;
                let mut d = device(&h);
                d.initialize().unwrap();
                assert_eq!(d.state(), State::Ready);
                let c = d.capabilities().unwrap();
                assert_eq!(&c.product_id, b"CYTRA-123456-78");
                assert_eq!(
                    c.firmware_version,
                    if platform < 2 { (1, 2) } else { (3, 4) }
                );
                assert_eq!(
                    (c.maximum, c.physical_size_mm, c.electrodes, c.maximum_z),
                    ((4095, 2047), (100, 50), (12, 10), 255)
                );
                assert_eq!(c.system_info.as_slice(), h.borrow().info);
                let h = h.borrow();
                assert!(!h.bootloader && !h.deep && h.power == 1);
                assert_eq!(
                    h.effects
                        .iter()
                        .filter(|(b, _)| b.len() == 13 && b[7] == 0x3b)
                        .count(),
                    usize::from(boot)
                );
                assert_eq!(
                    h.effects
                        .iter()
                        .filter(|(b, _)| b.len() == 8 && b[6] == 0x49)
                        .count(),
                    usize::from(platform >= 2)
                );
            }
        }
    }
    #[test]
    fn gen5_full_five_bit_tracking_ids_events_polarities_and_signed_orientation_are_exact() {
        for origins in [(false, false), (true, false), (false, true), (true, true)] {
            let h = hardware(false, 2);
            h.borrow_mut().info[64] = u8::from(origins.0);
            h.borrow_mut().info[65] = u8::from(origins.1);
            let mut d = device(&h);
            d.initialize().unwrap();
            for count in 0..=10 {
                for first in 0..32 {
                    for event in 0..4 {
                        for orientation in [0, 127, 129, 255] {
                            let packet = touch(count, first, event, orientation);
                            h.borrow_mut().queue.push_back(packet.clone());
                            let Some(Frame::Touches { raw, touches }) = d.poll().unwrap() else {
                                panic!()
                            };
                            assert_eq!(raw.as_bytes(), packet);
                            assert_eq!(touches.count, count);
                            assert_eq!(
                                touches.active.iter().flatten().count(),
                                if event == 3 { 0 } else { usize::from(count) }
                            );
                            for index in 0..count {
                                let record = touches.records[usize::from(index)].unwrap();
                                if event == 3 {
                                    let Record::Liftoff {
                                        id, tip_liftoff, ..
                                    } = record
                                    else {
                                        panic!()
                                    };
                                    assert_eq!(id, (first + index * 3) & 31);
                                    assert!(tip_liftoff);
                                    continue;
                                }
                                let Record::Contact(c) = record else { panic!() };
                                let x = 7 + u16::from(index) * 400;
                                let y = 9 + u16::from(index) * 200;
                                assert_eq!(c.id, (first + index * 3) & 31);
                                assert_eq!(
                                    (c.raw_x, c.raw_y, c.x, c.y),
                                    (
                                        x,
                                        y,
                                        if origins.0 { 4095 - x } else { x },
                                        if origins.1 { 2047 - y } else { y }
                                    )
                                );
                                assert_eq!(c.orientation, orientation as i8);
                                assert_eq!(c.orientation_raw, orientation);
                                assert_eq!(c.tip_liftoff, event == 3);
                                assert_eq!(c.axes, (5 + index, 3 + index));
                                assert_eq!(c.tool_axes, (9 + index, 7 + index));
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn gen5_pending_reports_before_command_response_remain_in_real_fifo_order() {
        let h = hardware(false, 2);
        let first = touch(1, 31, 1, 255);
        let second = vec![6, 0, 3, 0, 0, 7];
        let third = vec![6, 0, 7, 0, 0, 1];
        h.borrow_mut().inject = Some((8, vec![first.clone(), second.clone(), third.clone()]));
        let mut d = device(&h);
        d.initialize().unwrap();
        let Some(Frame::Touches { raw, .. }) = d.poll().unwrap() else {
            panic!()
        };
        assert_eq!(raw.as_bytes(), first);
        let Some(Frame::Buttons {
            raw,
            raw_buttons,
            buttons,
        }) = d.poll().unwrap()
        else {
            panic!()
        };
        assert_eq!(raw.as_bytes(), second);
        assert_eq!((raw_buttons, buttons), (7, 7));
        let Some(Frame::Proximity { raw, distance }) = d.poll().unwrap() else {
            panic!()
        };
        assert_eq!(raw.as_bytes(), third);
        assert_eq!(distance, 1);
        assert!(d.poll().unwrap().is_none());
    }
    #[test]
    fn gen5_actual_button_wake_proximity_and_retained_startup_notices_are_distinct() {
        let h = hardware(false, 1);
        h.borrow_mut().queue.push_back(vec![0, 0]);
        h.borrow_mut().queue.push_back(vec![6, 0, 0x1f, 0, 0x88, 0]);
        h.borrow_mut().info[70] = 5;
        let mut d = device(&h);
        d.initialize().unwrap();
        assert!(matches!(d.poll().unwrap(), Some(Frame::ResetNotice(_))));
        assert!(matches!(d.poll().unwrap(), Some(Frame::StaleResponse(_))));
        for id in [3, 5, 6] {
            for buttons in 0..16 {
                h.borrow_mut()
                    .queue
                    .push_back(vec![6, 0, id, 0, 0, buttons]);
                let Some(Frame::Buttons {
                    raw_buttons,
                    buttons: filtered,
                    ..
                }) = d.poll().unwrap()
                else {
                    panic!()
                };
                assert_eq!((raw_buttons, filtered), (buttons, buttons & 5));
            }
        }
        h.borrow_mut().queue.push_back(vec![4, 0, 4, 0x91]);
        assert!(matches!(d.poll().unwrap(), Some(Frame::Wake(_))));
    }
    #[test]
    fn gen5_malformed_extents_counts_ids_orientation_and_coordinates_are_explicit() {
        let mut cases = Vec::new();
        let mut short = touch(1, 0, 1, 0);
        short.truncate(7);
        short[..2].copy_from_slice(&7u16.to_le_bytes());
        cases.push((short, ErrorKind::ReportLength { id: 1, actual: 7 }));
        let mut count = touch(0, 0, 0, 0);
        count[5] = 11;
        cases.push((count, ErrorKind::ContactCount(11)));
        let mut duplicate = touch(2, 0, 1, 0);
        duplicate[20] = duplicate[8];
        cases.push((duplicate, ErrorKind::DuplicateId(0)));
        let mut kind = touch(1, 0, 1, 0);
        kind[7] = 3;
        cases.push((kind, ErrorKind::ContactType(3)));
        cases.push((touch(1, 0, 1, 128), ErrorKind::Orientation(128)));
        let mut coordinate = touch(1, 0, 1, 0);
        coordinate[9..11].copy_from_slice(&4096u16.to_le_bytes());
        cases.push((
            coordinate,
            ErrorKind::Coordinate {
                id: 0,
                x: 4096,
                y: 9,
            },
        ));
        cases.push((
            vec![5, 0, 3, 0, 0],
            ErrorKind::ReportLength { id: 3, actual: 5 },
        ));
        cases.push((vec![3, 0, 0x55], ErrorKind::UnsupportedReport(0x55)));
        for (packet, error) in cases {
            let h = hardware(false, 2);
            let mut d = device(&h);
            d.initialize().unwrap();
            h.borrow_mut().queue.push_back(packet.clone());
            assert_eq!(d.poll().unwrap_err().kind, error);
            assert_eq!(d.take_failed_packet().unwrap().as_bytes(), packet);
            assert_eq!(d.state(), State::Uncertain);
        }
        let h = hardware(false, 2);
        let mut d = device(&h);
        d.initialize().unwrap();
        let mut oversized = vec![0; 300];
        oversized[..2].copy_from_slice(&300u16.to_le_bytes());
        h.borrow_mut().queue.push_back(oversized);
        assert_eq!(d.poll().unwrap_err().kind, ErrorKind::Length(300));
        assert_eq!(d.take_failed_packet().unwrap().as_bytes(), [44, 1]);
        assert_eq!(h.borrow().queue.len(), 1);
        let h = hardware(false, 2);
        let mut d = device(&h);
        d.initialize().unwrap();
        h.borrow_mut().queue.push_back(touch(1, 0, 1, 0));
        h.borrow_mut().change_length = true;
        assert_eq!(
            d.poll().unwrap_err().kind,
            ErrorKind::ChangedLength {
                peek: 19,
                actual: 18
            }
        );
        assert!(h.borrow().queue.is_empty());
    }
    #[test]
    fn gen5_all_initialization_late_effects_preserve_original_error_without_replay() {
        for boot in [false, true] {
            let baseline = hardware(boot, 2);
            device(&baseline).initialize().unwrap();
            let operations = baseline.borrow().effects.len();
            for index in 1..=operations {
                let h = hardware(boot, 2);
                h.borrow_mut().fail = Some(index);
                let mut d = device(&h);
                assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::Bus(failure()));
                assert_eq!(h.borrow().effects.len(), index);
                assert_eq!(d.state(), State::Uncertain);
                assert!(d.capabilities().is_none());
                assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::NeedsReset);
                assert_eq!(h.borrow().effects.len(), index);
            }
        }
    }
    #[test]
    fn gen5_real_sleep_buttons_wake_identity_and_stop_preserve_known_capabilities() {
        for buttons in [false, true] {
            let h = hardware(false, 2);
            let mut d = device(&h);
            d.initialize().unwrap();
            if buttons {
                d.buttons_only().unwrap();
                assert_eq!(h.borrow().power, 5);
            } else {
                d.deep_sleep().unwrap();
                assert!(h.borrow().deep);
            }
            assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NotReady);
            d.wake().unwrap();
            assert!(!h.borrow().deep);
            assert_eq!(h.borrow().power, 1);
            d.deep_sleep().unwrap();
            h.borrow_mut().info[10] ^= 1;
            assert_eq!(d.wake().unwrap_err().kind, ErrorKind::IdentityChanged);
            assert_eq!(d.capabilities().unwrap().firmware_version, (3, 4));
        }
        let h = hardware(false, 2);
        let mut d = device(&h);
        d.initialize().unwrap();
        d.stop().unwrap();
        assert!(h.borrow().deep);
        assert_eq!(d.state(), State::Stopped);
        assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NotReady);
    }
    #[test]
    fn gen5_failed_status_timeout_boot_exit_and_irq_do_not_become_successful_transitions() {
        let h = hardware(false, 2);
        h.borrow_mut().bad_status = Some((8, 7));
        let mut d = device(&h);
        assert_eq!(
            d.initialize().unwrap_err().kind,
            ErrorKind::CommandStatus {
                command: 8,
                status: 7
            }
        );
        assert_eq!(h.borrow().power, 1);
        assert!(d.capabilities().is_none());
        let h = hardware(false, 2);
        h.borrow_mut().omit = Some(8);
        let mut d = device(&h);
        assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::Timeout);
        assert!(h.borrow().clock.get() >= 500_000);
        let h = hardware(true, 2);
        h.borrow_mut().launch_failure = true;
        let mut d = device(&h);
        assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::FirmwareLaunch);
        assert!(h.borrow().bootloader);
        let h = hardware(false, 2);
        h.borrow_mut().descriptor_bad = true;
        let mut d = device(&h);
        assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::Descriptor);
        let h = hardware(false, 2);
        let mut d = device(&h);
        d.initialize().unwrap();
        h.borrow_mut().fail_irq = true;
        let before = h.borrow().effects.len();
        let error = d.poll().unwrap_err();
        assert_eq!(
            error.kind,
            ErrorKind::Interrupt(InterruptError::Hardware(2))
        );
        assert_eq!(error.recovery, Recovery::MaskFailed);
        assert_eq!(h.borrow().effects.len(), before);
    }
    #[test]
    fn gen5_late_report_and_power_writes_retain_consumed_state_and_preceding_packets() {
        let h = hardware(false, 2);
        let mut d = device(&h);
        d.initialize().unwrap();
        h.borrow_mut().queue.push_back(touch(1, 0, 1, 0));
        let next = h.borrow().effects.len() + 2;
        h.borrow_mut().fail = Some(next);
        assert_eq!(d.poll().unwrap_err().kind, ErrorKind::Bus(failure()));
        assert!(h.borrow().queue.is_empty());
        assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NeedsReset);
        for target in [0, 1, 2] {
            let h = hardware(false, 2);
            let mut d = device(&h);
            d.initialize().unwrap();
            let previous = touch(1, 31, 1, 0);
            h.borrow_mut().queue.push_back(previous.clone());
            let next = h.borrow().effects.len() + 9;
            h.borrow_mut().fail = Some(next);
            let result = match target {
                0 => d.deep_sleep(),
                1 => d.buttons_only(),
                _ => d.stop(),
            };
            assert_eq!(result.unwrap_err().kind, ErrorKind::Bus(failure()));
            assert_eq!(d.take_pending_packet().unwrap().as_bytes(), previous);
            assert_eq!(d.state(), State::Uncertain);
            assert_eq!(d.capabilities().unwrap().firmware_version, (3, 4));
        }
    }

    #[test]
    fn gen5_liftoff_keeps_unavailable_record_bytes_without_fake_active_coordinates() {
        let h = hardware(false, 2);
        let mut d = device(&h);
        d.initialize().unwrap();
        let mut packet = touch(1, 31, 3, 128);
        packet[7] = 7;
        packet[9..13].fill(0xff);
        h.borrow_mut().queue.push_back(packet.clone());
        let Some(Frame::Touches { raw, touches }) = d.poll().unwrap() else {
            panic!()
        };
        assert_eq!(raw.as_bytes(), packet);
        assert!(touches.active.iter().all(Option::is_none));
        let Some(Record::Liftoff {
            id,
            tip_liftoff,
            raw,
        }) = touches.records[0]
        else {
            panic!()
        };
        assert_eq!(id, 31);
        assert!(tip_liftoff);
        assert_eq!(raw.as_slice(), &packet[7..]);
    }
    #[test]
    fn gen5_old_replies_never_acknowledge_new_writes_and_overflow_retains_every_read() {
        let h = hardware(false, 2);
        let mut d = device(&h);
        d.initialize().unwrap();
        let old = vec![5, 0, 0xf0, 1, 8];
        h.borrow_mut().queue.push_back(old.clone());
        h.borrow_mut().omit = Some(0xf0);
        assert_eq!(d.deep_sleep().unwrap_err().kind, ErrorKind::Timeout);
        assert!(h.borrow().deep);
        assert_eq!(d.take_pending_packet().unwrap().as_bytes(), old);
        let h = hardware(false, 2);
        let mut d = device(&h);
        d.initialize().unwrap();
        let packets = (0..17).map(|id| touch(1, id, 1, 0)).collect::<Vec<_>>();
        h.borrow_mut().inject = Some((0xf0, packets.clone()));
        assert_eq!(d.deep_sleep().unwrap_err().kind, ErrorKind::QueueFull);
        for packet in packets.iter().take(16) {
            assert_eq!(d.take_pending_packet().unwrap().as_bytes(), packet);
        }
        assert_eq!(d.take_failed_packet().unwrap().as_bytes(), packets[16]);
        assert!(h.borrow().deep);
        let h = hardware(false, 2);
        for _ in 0..8 {
            h.borrow_mut().queue.push_back(vec![0, 0]);
        }
        let mut d = device(&h);
        assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::DrainLimit);
        assert!(h.borrow().effects.iter().all(|(bytes, _)| bytes.is_empty()));
    }
    #[test]
    fn gen5_late_wake_failures_keep_previous_capabilities_and_actual_power_effects() {
        let baseline = hardware(false, 2);
        let mut sample = device(&baseline);
        sample.initialize().unwrap();
        sample.deep_sleep().unwrap();
        let before = baseline.borrow().effects.len();
        sample.wake().unwrap();
        let count = baseline.borrow().effects.len() - before;
        for index in 1..=count {
            let h = hardware(false, 2);
            let mut d = device(&h);
            d.initialize().unwrap();
            d.deep_sleep().unwrap();
            let next = h.borrow().effects.len() + index;
            h.borrow_mut().fail = Some(next);
            assert_eq!(d.wake().unwrap_err().kind, ErrorKind::Bus(failure()));
            assert_eq!(d.capabilities().unwrap().firmware_version, (3, 4));
            assert_eq!(d.state(), State::Uncertain);
            assert_eq!(h.borrow().effects.len(), next);
            if index >= 7 {
                assert!(!h.borrow().deep);
            }
        }
    }

    #[test]
    fn gen5_full_sixteen_bit_coordinate_boundaries_use_queried_origin_and_geometry() {
        for origins in [(false, false), (true, false), (false, true), (true, true)] {
            let h = hardware(false, 2);
            h.borrow_mut().info[58..62].fill(0xff);
            h.borrow_mut().info[64] = u8::from(origins.0);
            h.borrow_mut().info[65] = u8::from(origins.1);
            let mut d = device(&h);
            d.initialize().unwrap();
            assert_eq!(d.capabilities().unwrap().maximum, (65535, 65535));
            for x in [0u16, 255, 256, 4095, 4096, 32768, 65535] {
                let y = 65535 - x;
                let mut packet = touch(1, 31, 1, 255);
                packet[9..11].copy_from_slice(&x.to_le_bytes());
                packet[11..13].copy_from_slice(&y.to_le_bytes());
                h.borrow_mut().queue.push_back(packet.clone());
                let Some(Frame::Touches { raw, touches }) = d.poll().unwrap() else {
                    panic!()
                };
                assert_eq!(raw.as_bytes(), packet);
                let Some(Record::Contact(contact)) = touches.records[0] else {
                    panic!()
                };
                assert_eq!((contact.raw_x, contact.raw_y), (x, y));
                assert_eq!(
                    (contact.x, contact.y),
                    (
                        if origins.0 { 65535 - x } else { x },
                        if origins.1 { 65535 - y } else { y }
                    )
                );
            }
        }
    }

    #[test]
    fn gen5_late_matching_reply_peek_and_body_preserve_observed_bytes_and_stop_commands() {
        for index in [8, 9] {
            let h = hardware(false, 2);
            h.borrow_mut().jump = Some((index, 300_000));
            let mut d = device(&h);
            assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::Timeout);
            assert_eq!(d.state(), State::Uncertain);
            assert!(d.capabilities().is_none());
            let packet = d.take_failed_packet().unwrap();
            assert_eq!(packet.declared_length(), 32);
            assert_eq!(packet.as_bytes().len(), if index == 8 { 2 } else { 32 });
            assert_eq!(h.borrow().queue.len(), usize::from(index == 8));
            assert_eq!(h.borrow().effects.len(), index);
            assert_eq!(
                h.borrow()
                    .effects
                    .iter()
                    .filter(|(b, _)| !b.is_empty())
                    .count(),
                1
            );
            assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::NeedsReset);
        }
        for offset in [10, 11] {
            let h = hardware(false, 2);
            let mut d = device(&h);
            d.initialize().unwrap();
            let earlier = touch(1, 31, 1, 0);
            h.borrow_mut().queue.push_back(earlier.clone());
            let next = h.borrow().effects.len() + offset;
            h.borrow_mut().jump = Some((next, 500_000));
            assert_eq!(d.deep_sleep().unwrap_err().kind, ErrorKind::Timeout);
            assert_eq!(d.state(), State::Uncertain);
            assert!(h.borrow().deep);
            assert!(d.capabilities().is_some());
            assert_eq!(d.take_pending_packet().unwrap().as_bytes(), earlier);
            assert_eq!(
                d.take_failed_packet().unwrap().as_bytes(),
                if offset == 10 {
                    &[5, 0][..]
                } else {
                    &[5, 0, 0xf0, 1, 0x88][..]
                }
            );
            assert_eq!(h.borrow().effects.len(), next);
            assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NeedsReset);
            assert_eq!(h.borrow().effects.len(), next);
        }
    }
    #[test]
    fn gen5_matching_descriptors_cannot_admit_gen6_or_unknown_app_or_boot_identity() {
        for boot in [false, true] {
            for (family, silicon_high) in [(0x9b, 0x0b), (0xa5, 0xa5), (0x91, 0x0b), (0x9b, 2)] {
                let h = hardware(boot, 2);
                h.borrow_mut().info[19] = family;
                h.borrow_mut().info[22] = silicon_high;
                let mut d = device(&h);
                assert_eq!(
                    d.initialize().unwrap_err().kind,
                    ErrorKind::UnsupportedGeneration {
                        family,
                        silicon_high
                    }
                );
                assert_eq!(d.state(), State::Uncertain);
                assert!(d.capabilities().is_none());
                assert_eq!(
                    d.take_failed_packet().unwrap().as_bytes().len(),
                    if boot { 19 } else { 71 }
                );
                assert_eq!(h.borrow().power, 0);
                assert_eq!(h.borrow().bootloader, boot);
                assert!(
                    h.borrow().effects.iter().all(|(b, _)| b.len() < 7
                        || !matches!(b[6], 8 | 0x49) && b.get(7) != Some(&0x3b))
                );
            }
        }
        for length in 11..19 {
            let h = hardware(true, 2);
            h.borrow_mut().boot_info_length = length;
            let mut d = device(&h);
            assert_eq!(
                d.initialize().unwrap_err().kind,
                ErrorKind::ReportLength {
                    id: 0x30,
                    actual: length as u16
                }
            );
            assert_eq!(d.take_failed_packet().unwrap().as_bytes().len(), length);
            assert_eq!(d.state(), State::Uncertain);
            assert!(h.borrow().bootloader);
            assert_eq!(h.borrow().power, 0);
            assert!(
                h.borrow()
                    .effects
                    .iter()
                    .all(|(b, _)| b.get(7) != Some(&0x3b))
            );
        }
        let h = hardware(false, 2);
        let mut d = device(&h);
        d.initialize().unwrap();
        d.deep_sleep().unwrap();
        h.borrow_mut().info[19] = 0x9b;
        h.borrow_mut().info[22] = 0x0b;
        h.borrow_mut().power = 5;
        assert_eq!(
            d.wake().unwrap_err().kind,
            ErrorKind::UnsupportedGeneration {
                family: 0x9b,
                silicon_high: 0x0b
            }
        );
        assert_eq!(h.borrow().power, 5);
        assert_eq!(d.capabilities().unwrap().system_info[19], 0x91);
    }
}
