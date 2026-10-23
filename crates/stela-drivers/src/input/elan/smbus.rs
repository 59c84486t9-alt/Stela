// SPDX-License-Identifier: GPL-2.0-only
//! Native count-bearing SMBus transport for the donor's ordinary format.
//! The platform supplies an exclusively owned powered peripheral, physical IRQ
//! and SMBus host. No power-rail or reset operation is inferred from a no-op.
use super::{Error, ErrorKind, Frame, Interrupt, Packet, Recovery, State, report};
use crate::bus::{
    i2c::Timer,
    smbus::{Address, Block, Bus, Transaction},
};
mod device;

/// Actual SMBus query responses. There are no I2C descriptors on this transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queries {
    pub hello: Block,
    pub product: Block,
    pub sample: Block,
    pub firmware: Block,
    pub checksum: Block,
    pub iap_version: Block,
    pub iap_control: Block,
    pub range: Block,
    pub traces: Block,
    pub resolution: Block,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub queries: Queries,
    pub product_id: u16,
    pub ic_type: u8,
    pub sample_version: u8,
    pub clickpad: bool,
    pub firmware_version: u8,
    pub firmware_checksum: u16,
    pub iap_version: u8,
    pub maximum: (u16, u16),
    pub traces: (u8, u8),
    pub raw_resolution: (u8, u8),
    pub resolution_per_mm: (u32, u32),
}
impl Capabilities {
    fn geometry(&self) -> report::Geometry {
        report::Geometry {
            maximum: self.maximum,
            traces: self.traces,
            pressure_adjustment: 25,
        }
    }
    fn same_identity(&self, other: &Self) -> bool {
        // Unknown trailing query bytes are retained but are not an invented
        // identity contract. Compare the actual source-declared fields.
        self.product_id == other.product_id
            && self.ic_type == other.ic_type
            && self.sample_version == other.sample_version
            && self.clickpad == other.clickpad
            && self.firmware_version == other.firmware_version
            && self.firmware_checksum == other.firmware_checksum
            && self.iap_version == other.iap_version
            && self.maximum == other.maximum
            && self.traces == other.traces
            && self.raw_resolution == other.raw_resolution
    }
}
pub struct Device<B, I, T> {
    bus: B,
    interrupt: I,
    timer: T,
    address: Address,
    state: State,
    capabilities: Option<Capabilities>,
}
impl<B: Bus, I: Interrupt, T: Timer> Device<B, I, T> {
    pub fn new(bus: B, interrupt: I, timer: T, address: Address) -> Self {
        Self {
            bus,
            interrupt,
            timer,
            address,
            state: State::Fresh,
            capabilities: None,
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    /// Last completely queried metadata; input is available only in Ready.
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.capabilities.as_ref()
    }
}

#[cfg(test)]
mod tests {
    //! Independent SMBus peripheral: actual count-bearing responses and commands.
    use super::super::InterruptError;
    use super::*;
    use crate::bus::smbus as wire;
    use alloc::{
        collections::{BTreeMap, VecDeque},
        rc::Rc,
        vec,
        vec::Vec,
    };
    use core::cell::{Cell, RefCell};

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Effect {
        Read(u8),
        Send(u8),
        Write(u8, Vec<u8>),
    }
    struct Hardware {
        blocks: BTreeMap<u8, Vec<u8>>,
        reports: VecDeque<Vec<u8>>,
        effects: Vec<Effect>,
        awake: bool,
        absolute: bool,
        masked: bool,
        fail_operation: Option<usize>,
        fail_irq: bool,
        force_irq: bool,
        clock: Rc<Cell<u64>>,
    }
    fn hardware() -> Rc<RefCell<Hardware>> {
        Rc::new(RefCell::new(Hardware {
            blocks: BTreeMap::from([
                (0xa7, vec![0x55; 5]),
                (0xa3, vec![0x11, 8, 0x91, 0xa5]),
                (0xa1, vec![0xaa, 0xbb, 0x43, 0xcc]),
                (0xae, vec![0x12, 0x34, 0x99]),
                (0xac, vec![0x89, 0x10, 0x23, 0xee]),
                (0xad, vec![0x02, 0x00, 0xff]),
                (0xa0, vec![0x7f, 0xff, 0xff]),
                (0xa2, vec![0xf0, 12, 10]),
                (0xa4, vec![0x99, 0xa2, 0x55]),
            ]),
            reports: VecDeque::new(),
            effects: Vec::new(),
            awake: false,
            absolute: false,
            masked: false,
            fail_operation: None,
            fail_irq: false,
            force_irq: false,
            clock: Rc::new(Cell::new(0)),
        }))
    }
    struct Wire(Rc<RefCell<Hardware>>);
    struct Irq(Rc<RefCell<Hardware>>);
    struct Time(Rc<Cell<u64>>);
    fn failure() -> wire::Error {
        wire::Error {
            kind: wire::ErrorKind::Device,
            status: 0x84,
            recovery: wire::Recovery::Cleared,
        }
    }
    impl Bus for Wire {
        fn transaction(
            &mut self,
            address: Address,
            operation: Transaction<'_>,
            pec: bool,
        ) -> Result<(), wire::Error> {
            assert_eq!(address.get(), 0x15);
            assert!(!pec);
            let mut h = self.0.borrow_mut();
            assert!(h.masked);
            let mut completed = None;
            match operation {
                Transaction::ReadBlock { command, data } => {
                    h.effects.push(Effect::Read(command));
                    let bytes = if command == 0xa8 {
                        assert!(h.awake && h.absolute);
                        h.reports.pop_front().expect("real queued report")
                    } else {
                        h.blocks[&command].clone()
                    };
                    completed = Some((data, Block::from_slice(&bytes)?));
                }
                Transaction::SendByte(value) => {
                    h.effects.push(Effect::Send(value));
                    match value {
                        0x20 => h.awake = true,
                        0x21 => h.awake = false,
                        _ => panic!("unexpected send"),
                    }
                }
                Transaction::WriteBlock { command, data } => {
                    h.effects.push(Effect::Write(command, data.to_vec()));
                    assert_eq!((command, data), (0, &[0, 7, 0, 1][..]));
                    assert!(h.awake);
                    h.absolute = true;
                }
                _ => panic!("wrong SMBus protocol"),
            }
            // A destructive read or mutation has already happened, but host
            // outputs are committed only on actual successful completion.
            if h.fail_operation == Some(h.effects.len()) {
                return Err(failure());
            }
            if let Some((output, block)) = completed {
                *output = block;
            }
            Ok(())
        }
    }
    impl Interrupt for Irq {
        fn mask_and_drain(&mut self) -> Result<(), InterruptError> {
            let mut h = self.0.borrow_mut();
            if h.fail_irq {
                return Err(InterruptError::Hardware(1));
            }
            h.masked = true;
            Ok(())
        }
        fn asserted(&mut self) -> Result<bool, InterruptError> {
            let h = self.0.borrow();
            if h.fail_irq {
                return Err(InterruptError::Hardware(2));
            }
            Ok((h.awake && !h.reports.is_empty()) || h.force_irq)
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
            Address::new(0x15).unwrap(),
        )
    }
    fn ordinary(bitmap: u8, buttons: u8, pressure: u8) -> Vec<u8> {
        let mut bytes = vec![0xa5; 32];
        bytes[0] = 0x5d;
        bytes[1] = (bitmap << 3) | buttons;
        let mut record = 2;
        for slot in 0..5 {
            if bitmap & (1 << slot) == 0 {
                continue;
            }
            let x = 7 + slot * 513u16;
            let y = 9 + slot * 257u16;
            bytes[record..record + 5].copy_from_slice(&[
                ((x >> 4) & 0xf0) as u8 | (y >> 8) as u8,
                x as u8,
                y as u8,
                ((15 - slot) << 4 | (slot + 1)) as u8,
                pressure,
            ]);
            record += 5;
        }
        bytes[28] = 0x40;
        bytes
    }
    #[test]
    fn elan_smbus_real_hello_enable_queries_and_metadata_have_no_i2c_descriptors() {
        let h = hardware();
        let mut d = device(&h);
        assert!(h.borrow().effects.is_empty());
        d.initialize().unwrap();
        assert_eq!(
            h.borrow().effects,
            vec![
                Effect::Read(0xa7),
                Effect::Send(0x20),
                Effect::Read(0xa3),
                Effect::Read(0xa3),
                Effect::Write(0, vec![0, 7, 0, 1]),
                Effect::Read(0xa1),
                Effect::Read(0xae),
                Effect::Read(0xac),
                Effect::Read(0xad),
                Effect::Read(0xa0),
                Effect::Read(0xa2),
                Effect::Read(0xa4)
            ]
        );
        let c = d.capabilities().unwrap();
        assert_eq!(
            (c.product_id, c.ic_type, c.sample_version, c.clickpad),
            (0x1108, 8, 0x11, true)
        );
        assert_eq!(
            (c.firmware_version, c.firmware_checksum, c.iap_version),
            (0x43, 0x1234, 0x23)
        );
        assert_eq!(
            (c.maximum, c.traces, c.raw_resolution, c.resolution_per_mm),
            ((4095, 2047), (12, 10), (2, 10), (31, 35))
        );
        assert_eq!(c.queries.product.as_slice(), [0x11, 8, 0x91, 0xa5]);
        assert_eq!(d.state(), State::Ready);
        let count = h.borrow().effects.len();
        assert!(d.poll().unwrap().is_none());
        assert_eq!(h.borrow().effects.len(), count);
        assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::AlreadyActive);
    }
    #[test]
    fn elan_smbus_all_sparse_contact_packets_preserve_actual_payload_without_padding() {
        let h = hardware();
        let mut d = device(&h);
        d.initialize().unwrap();
        for bitmap in 0..32 {
            for buttons in 0..8 {
                for pressure in [0, 230, 231, 255] {
                    let packet = ordinary(bitmap, buttons, pressure);
                    h.borrow_mut().reports.push_back(packet.clone());
                    let Some(Frame::Absolute(frame)) = d.poll().unwrap() else {
                        panic!()
                    };
                    assert_eq!(frame.raw.as_bytes(), packet);
                    assert!(matches!(frame.raw, Packet::Smbus(_)));
                    assert_eq!((frame.buttons, frame.hover), (buttons, true));
                    for slot in 0..5 {
                        if bitmap & (1 << slot) == 0 {
                            assert!(frame.contacts[slot].is_none());
                            continue;
                        }
                        let c = frame.contacts[slot].unwrap();
                        assert_eq!(
                            (c.x, c.y, c.y_top_down),
                            (
                                7 + slot as u16 * 513,
                                9 + slot as u16 * 257,
                                2047 - (9 + slot as u16 * 257)
                            )
                        );
                        assert_eq!(
                            (c.raw_pressure, c.pressure),
                            (pressure, pressure.saturating_add(25))
                        );
                        assert_eq!(c.width_marks, (slot as u8 + 1, 15 - slot as u8));
                        assert_eq!(c.areas, ((slot as u32 + 1) * 251, (15 - slot as u32) * 114));
                    }
                }
            }
        }
    }
    #[test]
    fn elan_smbus_short_trackpoint_and_full_trackpoint_counts_are_distinct() {
        let h = hardware();
        let mut d = device(&h);
        d.initialize().unwrap();
        for id in [0x5e, 0x5f] {
            for a in [0u8, 127, 128, 255] {
                for b in [0u8, 127, 128, 255] {
                    let mut packet = vec![0x88; if id == 0x5f { 7 } else { 32 }];
                    packet[..7].copy_from_slice(&[id, 7, a, b, 6, 255, 0]);
                    h.borrow_mut().reports.push_back(packet.clone());
                    let Some(Frame::Trackpoint(frame)) = d.poll().unwrap() else {
                        panic!()
                    };
                    assert_eq!(frame.raw.as_bytes(), packet);
                    assert_eq!(frame.buttons, 7);
                    assert_eq!(
                        frame.motion,
                        Some((255 - (i16::from(a ^ 0x80) << 1), i16::from(b ^ 0x80) << 1))
                    );
                }
            }
        }
    }
    #[test]
    fn elan_smbus_strict_lengths_hello_and_actual_mode_are_not_zero_filled_successes() {
        for command in [0xa7, 0xa3, 0xa1, 0xae, 0xac, 0xad, 0xa0, 0xa2, 0xa4] {
            for length in 1..=32 {
                let h = hardware();
                let original = h.borrow().blocks[&command].clone();
                let mut changed = vec![0; length];
                let count = length.min(original.len());
                changed[..count].copy_from_slice(&original[..count]);
                h.borrow_mut().blocks.insert(command, changed);
                let mut d = device(&h);
                let valid = match command {
                    0xa7 => length == 5,
                    0xa0 | 0xa2 | 0xa4 => length == 3,
                    0xa1 | 0xac => length >= 3,
                    _ => length >= 2,
                };
                if valid {
                    d.initialize().unwrap();
                } else {
                    assert!(
                        matches!(d.initialize().unwrap_err().kind, ErrorKind::BlockLength { command: actual, .. } if actual == command)
                    );
                    assert!(d.capabilities().is_none());
                    assert_eq!(d.state(), State::Uncertain);
                }
            }
        }
        let h = hardware();
        h.borrow_mut()
            .blocks
            .insert(0xa7, vec![0x55, 0x55, 0x54, 0x55, 0x55]);
        let mut d = device(&h);
        assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::HelloPacket);
        assert_eq!(h.borrow().effects, vec![Effect::Read(0xa7)]);
        let h = hardware();
        h.borrow_mut().blocks.insert(0xad, vec![0, 0x40]);
        let mut d = device(&h);
        assert_eq!(
            d.initialize().unwrap_err().kind,
            ErrorKind::FirmwareMode(0x40)
        );
    }
    #[test]
    fn elan_smbus_all_initialization_late_faults_remain_uncertain_without_replay() {
        for index in 1..=12 {
            let h = hardware();
            h.borrow_mut().fail_operation = Some(index);
            let mut d = device(&h);
            let error = d.initialize().unwrap_err();
            assert_eq!(
                (error.kind, error.recovery),
                (ErrorKind::Smbus(failure()), Recovery::IrqMasked)
            );
            assert_eq!(h.borrow().effects.len(), index);
            assert!(d.capabilities().is_none());
            assert_eq!(d.state(), State::Uncertain);
            assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::NeedsReset);
            assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NeedsReset);
            assert_eq!(h.borrow().effects.len(), index);
            if index >= 2 {
                assert!(h.borrow().awake);
            }
            if index >= 5 {
                assert!(h.borrow().absolute);
            }
        }
    }
    #[test]
    fn elan_smbus_sleep_resume_enable_preserves_actual_pending_queue_and_identity() {
        let h = hardware();
        let mut d = device(&h);
        let packet = ordinary(16, 7, 255);
        h.borrow_mut().reports.push_back(packet.clone());
        d.initialize().unwrap();
        // HELLO/ENABLE is not a reset and may not manufacture a fresh queue.
        assert_eq!(h.borrow().reports.len(), 1);
        d.sleep().unwrap();
        assert!(!h.borrow().awake);
        assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NotReady);
        let mut metadata = h.borrow().blocks[&0xa3].clone();
        metadata[2] ^= 0xff;
        h.borrow_mut().blocks.insert(0xa3, metadata);
        d.wake().unwrap();
        assert!(h.borrow().awake);
        let Some(Frame::Absolute(frame)) = d.poll().unwrap() else {
            panic!()
        };
        assert_eq!(frame.raw.as_bytes(), packet);
        assert_eq!(
            h.borrow()
                .effects
                .iter()
                .filter(|e| **e == Effect::Send(0x20))
                .count(),
            2
        );
        d.sleep().unwrap();
        h.borrow_mut().blocks.get_mut(&0xa3).unwrap()[1] ^= 1;
        assert_eq!(d.wake().unwrap_err().kind, ErrorKind::IdentityChanged);
        assert_eq!(d.capabilities().unwrap().ic_type, 8);
        assert_eq!(d.state(), State::Uncertain);
    }
    #[test]
    fn elan_smbus_consumed_reports_late_sleep_and_irq_faults_keep_real_effects() {
        let h = hardware();
        let mut d = device(&h);
        d.initialize().unwrap();
        h.borrow_mut().reports.push_back(ordinary(31, 7, 255));
        let next = h.borrow().effects.len() + 1;
        h.borrow_mut().fail_operation = Some(next);
        assert_eq!(d.poll().unwrap_err().kind, ErrorKind::Smbus(failure()));
        assert!(h.borrow().reports.is_empty());
        assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NeedsReset);
        let h = hardware();
        let mut d = device(&h);
        d.initialize().unwrap();
        let next = h.borrow().effects.len() + 1;
        h.borrow_mut().fail_operation = Some(next);
        assert_eq!(d.sleep().unwrap_err().kind, ErrorKind::Smbus(failure()));
        assert!(!h.borrow().awake);
        assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NeedsReset);
        let h = hardware();
        let mut d = device(&h);
        d.initialize().unwrap();
        h.borrow_mut().fail_irq = true;
        let count = h.borrow().effects.len();
        let error = d.poll().unwrap_err();
        assert_eq!(
            (error.kind, error.recovery),
            (
                ErrorKind::Interrupt(InterruptError::Hardware(2)),
                Recovery::MaskFailed
            )
        );
        assert_eq!(h.borrow().effects.len(), count);
    }
    #[test]
    fn elan_smbus_invalid_packets_geometry_and_stop_do_not_become_fake_contacts() {
        for id in [0x5d, 0x5e, 0x5f, 0x60, 0x55, 0] {
            for length in [1, 7, 31, 32] {
                let h = hardware();
                let mut d = device(&h);
                d.initialize().unwrap();
                let mut packet = vec![0; length];
                packet[0] = id;
                h.borrow_mut().reports.push_back(packet);
                let result = d.poll();
                if (id == 0x5d || id == 0x5e) && length == 32 || id == 0x5f && length == 7 {
                    assert!(result.is_ok());
                } else {
                    assert!(result.is_err());
                    assert_eq!(d.state(), State::Uncertain);
                }
            }
        }
        for (command, bytes) in [(0xa0, vec![0, 0, 0]), (0xa2, vec![0, 0, 1])] {
            let h = hardware();
            h.borrow_mut().blocks.insert(command, bytes);
            let mut d = device(&h);
            assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::InvalidGeometry);
        }
        let h = hardware();
        let mut d = device(&h);
        d.initialize().unwrap();
        d.stop().unwrap();
        assert_eq!(d.state(), State::Stopped);
        assert!(!h.borrow().awake);
        let count = h.borrow().effects.len();
        assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NotReady);
        assert_eq!(h.borrow().effects.len(), count);
    }
}
