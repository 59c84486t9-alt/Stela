//! Independent ELAN peripheral with command effects, ACK timing,
//! physical attention, compressed reports and late fault injection.
use super::*;
use crate::bus::i2c::Operation;
use alloc::{
    collections::{BTreeMap, VecDeque},
    rc::Rc,
    vec,
    vec::Vec,
};
use core::cell::{Cell, RefCell};
struct Hardware {
    address: Address,
    registers: BTreeMap<u16, Vec<u8>>,
    reports: VecDeque<Vec<u8>>,
    time: Rc<Cell<u64>>,
    reset_at: u64,
    ack: bool,
    reset_response: [u8; 2],
    masked: bool,
    awake: bool,
    absolute: bool,
    wake_first: bool,
    writes: Vec<(u16, u16, u64)>,
    reads: Vec<(Option<u16>, usize)>,
    resets: usize,
    fail_write: Option<u16>,
    fail_command: Option<(u16, u16)>,
    fail_read: Option<usize>,
    fail_irq: bool,
    force_irq: bool,
}
impl Hardware {
    fn new(pattern: u8, product: u16, ic: u16) -> Self {
        let mut registers = BTreeMap::new();
        registers.insert(1, (0..30).collect());
        registers.insert(2, (0..158).collect());
        for (reg, val) in [
            (0x0101, product.to_le_bytes()),
            (0x0100, [0, pattern]),
            (0x0102, [0x45, 0x67]),
            (
                0x0103,
                if pattern == 0 {
                    [0x11, 0]
                } else {
                    ic.to_be_bytes()
                },
            ),
            (0x0104, [0x10, 0x33]),
            (0x0110, [ic as u8, 0x21]),
            (0x0111, [0x22, 0x44]),
            (0x0105, [12, 10]),
            (0x0106, 4095u16.to_le_bytes()),
            (0x0107, 2047u16.to_le_bytes()),
            (0x0108, [0, 10]),
            (0x010a, [0, 0]),
            (0x030f, [0x34, 0x12]),
            (0x0310, [0, 2]),
            (0x0307, [0xa4, 0x5a]),
        ] {
            registers.insert(reg, val.to_vec());
        }
        Self {
            address: Address::SevenBit(0x15),
            registers,
            reports: VecDeque::new(),
            time: Rc::new(Cell::new(0)),
            reset_at: 0,
            ack: false,
            reset_response: [0, 0],
            masked: false,
            awake: false,
            absolute: false,
            wake_first: (ic == 0x0e && matches!(product, 5..=7 | 9 | 0x13))
                || (ic == 8 && product == 0x26),
            writes: Vec::new(),
            reads: Vec::new(),
            resets: 0,
            fail_write: None,
            fail_command: None,
            fail_read: None,
            fail_irq: false,
            force_irq: false,
        }
    }
}
#[derive(Clone)]
struct Wire(Rc<RefCell<Hardware>>);
struct Irq(Rc<RefCell<Hardware>>);
struct Time(Rc<Cell<u64>>);
fn bus_error() -> i2c::Error {
    i2c::Error {
        kind: i2c::ErrorKind::Aborted {
            kind: i2c::AbortKind::DataNack,
            source: 8,
        },
        recovery: i2c::Recovery::Disabled,
    }
}
impl Bus for Wire {
    fn transaction(
        &mut self,
        address: Address,
        operations: &mut [Operation<'_>],
    ) -> Result<(), i2c::Error> {
        let mut h = self.0.borrow_mut();
        assert_eq!(address, h.address);
        assert!(h.masked);
        match operations {
            [Operation::Write(data)] => {
                assert_eq!(data.len(), 4);
                let reg = u16::from_le_bytes([data[0], data[1]]);
                let value = u16::from_le_bytes([data[2], data[3]]);
                let now = h.time.get();
                h.writes.push((reg, value, now));
                match (reg, value) {
                    (5, 0x0100) => {
                        h.resets += 1;
                        h.reset_at = now;
                        h.ack = true;
                        h.awake = false;
                        h.absolute = false;
                        h.reports.clear();
                    }
                    (5, 0x0800) => h.awake = true,
                    (5, 0x0801) => h.awake = false,
                    (0x0300, 1) => {
                        assert!(!h.wake_first || h.awake);
                        h.absolute = true;
                    }
                    (0x0307, _) => {
                        h.registers.insert(reg, value.to_le_bytes().to_vec());
                    }
                    _ => panic!("unsupported command {reg:x} {value:x}"),
                }
                if h.fail_write == Some(reg) || h.fail_command == Some((reg, value)) {
                    h.fail_write = None;
                    h.fail_command = None;
                    return Err(bus_error());
                }
            }
            [Operation::Write(reg), Operation::Read(output)] => {
                assert_eq!(reg.len(), 2);
                let reg = u16::from_le_bytes([reg[0], reg[1]]);
                if h.ack {
                    assert!(h.time.get().wrapping_sub(h.reset_at) >= 100_000);
                }
                h.reads.push((Some(reg), output.len()));
                output.copy_from_slice(&h.registers[&reg]);
                if h.fail_read == Some(h.reads.len()) {
                    return Err(bus_error());
                }
            }
            [Operation::Read(output)] => {
                h.reads.push((None, output.len()));
                if h.ack {
                    assert_eq!(output.len(), 2);
                    assert!(h.time.get().wrapping_sub(h.reset_at) >= 100_000);
                    output.copy_from_slice(&h.reset_response);
                    h.ack = false;
                } else {
                    assert!(matches!(output.len(), 34 | 39));
                    assert!(h.awake && h.absolute);
                    output.copy_from_slice(
                        &h.reports
                            .pop_front()
                            .unwrap_or_else(|| vec![0; output.len()]),
                    );
                }
                if h.fail_read == Some(h.reads.len()) {
                    return Err(bus_error());
                }
            }
            _ => panic!("incorrect transfer shape"),
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
        Ok(h.ack || !h.reports.is_empty() || h.force_irq)
    }
}
impl Timer for Time {
    fn start(&self) -> u64 {
        !self.now_us().rotate_left(17)
    }
    fn elapsed_us(&self, marker: u64) -> u64 {
        self.now_us().wrapping_sub((!marker).rotate_right(17))
    }
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get().wrapping_add(1000));
    }
}
fn hardware(pattern: u8, product: u16, ic: u16) -> Rc<RefCell<Hardware>> {
    Rc::new(RefCell::new(Hardware::new(pattern, product, ic)))
}
fn device(h: &Rc<RefCell<Hardware>>) -> I2cDevice<Wire, Irq, Time> {
    I2cDevice::new(
        Wire(h.clone()),
        Irq(h.clone()),
        Time(h.borrow().time.clone()),
        Address::SevenBit(0x15),
    )
    .unwrap()
}
fn absolute(bitmap: u8, buttons: u8, pressure: u8, hover: bool) -> [u8; 34] {
    let mut raw = [0; 34];
    raw[..4].copy_from_slice(&[34, 0, 0x5d, (bitmap << 3) | buttons]);
    let mut index = 4;
    for slot in 0..5 {
        if bitmap & (1 << slot) == 0 {
            continue;
        }
        let x = 7 + slot * 513;
        let y = 9 + slot * 257;
        raw[index..index + 5].copy_from_slice(&[
            ((x >> 4) & 0xf0) as u8 | (y >> 8) as u8,
            x as u8,
            y as u8,
            ((15 - slot) << 4 | (slot + 1)) as u8,
            pressure,
        ]);
        index += 5;
    }
    raw[30] = u8::from(hover) << 6;
    raw[31..].copy_from_slice(&[0xa5, 0x5a, 0x99]);
    raw
}
#[test]
fn elan_queries_real_commands_descriptors_geometry_and_both_ordinary_patterns() {
    for pattern in 0..=1 {
        let h = hardware(pattern, 0x42, 8);
        let mut d = device(&h);
        d.initialize().unwrap();
        assert_eq!(d.state(), State::Ready);
        let c = d.capabilities().unwrap();
        assert_eq!(c.pattern, pattern);
        assert_eq!(c.product_id, 0x42);
        assert_eq!(c.ic_type, 8);
        assert_eq!(c.sample_version, if pattern == 0 { 0x11 } else { 0x33 });
        assert_eq!(c.maximum, (4095, 2047));
        assert_eq!(c.traces, (12, 10));
        assert_eq!(c.resolution_per_mm, (31, 35));
        assert_eq!(c.firmware_version, 0x45);
        assert_eq!(c.firmware_checksum, 0x1234);
        assert_eq!(c.iap_version, if pattern == 0 { 0x22 } else { 0x21 });
        assert_eq!(c.descriptor, core::array::from_fn(|i| i as u8));
        assert_eq!(c.report_descriptor, core::array::from_fn(|i| i as u8));
        assert_eq!(
            h.borrow()
                .writes
                .iter()
                .map(|(reg, value, _)| (*reg, *value))
                .collect::<Vec<_>>(),
            [(5, 0x100), (0x300, 1), (5, 0x800)]
        );
        assert!(h.borrow().writes[1].2 >= 100_000);
        assert!(d.poll().unwrap().is_none());
    }
    let h = hardware(0, 0x42, 8);
    h.borrow_mut().registers.insert(0x0100, vec![255, 255]);
    let mut d = device(&h);
    d.initialize().unwrap();
    assert_eq!(d.capabilities().unwrap().pattern, 0);
}
#[test]
fn elan_compressed_slots_all_buttons_hover_pressure_and_raw_bytes_are_exact() {
    for adjustment in [0, 25] {
        let h = hardware(0, 0x42, 8);
        if adjustment == 0 {
            h.borrow_mut().registers.insert(0x010a, vec![16, 0]);
        }
        let mut d = device(&h);
        d.initialize().unwrap();
        for bitmap in 0..32 {
            for buttons in 0..8 {
                for hover in [false, true] {
                    let raw = absolute(bitmap, buttons, 245, hover);
                    h.borrow_mut().reports.push_back(raw.to_vec());
                    let Frame::Absolute(frame) = d.poll().unwrap().unwrap() else {
                        panic!("wrong report");
                    };
                    assert_eq!(frame.raw.as_bytes(), raw);
                    assert_eq!(frame.buttons, buttons);
                    assert_eq!(frame.hover, hover);
                    for slot in 0..5 {
                        if bitmap & (1 << slot) == 0 {
                            assert_eq!(frame.contacts[slot], None);
                            continue;
                        }
                        let c = frame.contacts[slot].unwrap();
                        assert_eq!(c.x, 7 + slot as u16 * 513);
                        assert_eq!(c.y, 9 + slot as u16 * 257);
                        assert_eq!(c.y_top_down, 2047 - c.y);
                        assert_eq!(c.pressure, 245u8.saturating_add(adjustment));
                        assert_eq!(c.raw_pressure, 245);
                        assert_eq!(c.width_marks, (slot as u8 + 1, 15 - slot as u8));
                        assert_eq!(c.areas, ((slot as u32 + 1) * 251, (15 - slot as u32) * 114));
                    }
                }
            }
        }
    }
}
#[test]
fn elan_trackpoint_real_format_and_motion_limits_preserve_both_report_ids() {
    let h = hardware(0, 0x42, 8);
    let mut d = device(&h);
    d.initialize().unwrap();
    for id in [0x5e, 0x5f] {
        for value in 0u8..=255 {
            for has_motion in [false, true] {
                let mut raw = [0; 34];
                raw[..9].copy_from_slice(&[
                    34,
                    0,
                    id,
                    value & 7,
                    value,
                    value ^ 0xff,
                    if has_motion { 6 } else { 5 },
                    value ^ 0x55,
                    value ^ 0xaa,
                ]);
                h.borrow_mut().reports.push_back(raw.to_vec());
                let Frame::Trackpoint(frame) = d.poll().unwrap().unwrap() else {
                    panic!("wrong report");
                };
                assert_eq!(frame.raw.as_bytes(), raw);
                assert_eq!(frame.buttons, value & 7);
                assert_eq!(
                    frame.motion,
                    has_motion.then_some((
                        i16::from(value ^ 0x55) - i16::from(value ^ 0x80) * 2,
                        i16::from((value ^ 0xff) ^ 0x80) * 2 - i16::from(value ^ 0xaa)
                    ))
                );
            }
        }
    }
}
#[test]
fn elan_actual_wake_before_mode_profiles_wait_two_hundred_ms_and_neighbors_do_not() {
    for (ic, product, early) in [
        (0x0e, 5, true),
        (0x0e, 6, true),
        (0x0e, 7, true),
        (0x0e, 9, true),
        (0x0e, 0x13, true),
        (8, 0x26, true),
        (0x0e, 8, false),
        (0x0e, 0x12, false),
        (8, 0x25, false),
        (9, 0x26, false),
    ] {
        let h = hardware(0, product, ic);
        let mut d = device(&h);
        d.initialize().unwrap();
        let h = h.borrow();
        let mode = h
            .writes
            .iter()
            .position(|(reg, _, _)| *reg == 0x300)
            .unwrap();
        let wake = h
            .writes
            .iter()
            .position(|(reg, value, _)| *reg == 5 && *value == 0x800)
            .unwrap();
        assert_eq!(wake < mode, early);
        if early {
            assert!(h.writes[mode].2.wrapping_sub(h.writes[wake].2) >= 200_000);
        }
    }
}
#[test]
fn elan_quick_and_normal_resume_preserve_identity_real_power_bits_and_stopped_state() {
    for (ic, product, quick) in [
        (0x0d, 0xc2, true),
        (0x0d, 0xb8, true),
        (0x10, 0xbf, true),
        (0x14, 0x120, true),
        (0x14, 0x121, true),
        (0x0d, 0x123, true),
        (0x0c, 0x123, false),
        (0x0d, 0xc1, false),
        (8, 0x42, false),
    ] {
        let h = hardware(1, product, ic);
        let mut d = device(&h);
        d.initialize().unwrap();
        assert_eq!(d.capabilities().unwrap().quick_wakeup, quick);
        d.sleep().unwrap();
        let reads = h.borrow().reads.len();
        assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NotReady);
        assert_eq!(h.borrow().reads.len(), reads);
        d.wake().unwrap();
        assert_eq!(h.borrow().resets, if quick { 1 } else { 2 });
        d.power_down().unwrap();
        assert_eq!(h.borrow().registers[&0x307], [0xa5, 0x5a]);
        d.wake().unwrap();
        assert_eq!(h.borrow().registers[&0x307], [0xa4, 0x5a]);
        assert_eq!(d.state(), State::Ready);
        d.stop().unwrap();
        assert_eq!(d.state(), State::Stopped);
        assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NotReady);
        d.initialize().unwrap();
        assert_eq!(d.state(), State::Ready);
    }
    let h = hardware(0, 0x42, 8);
    let mut d = device(&h);
    d.initialize().unwrap();
    d.sleep().unwrap();
    h.borrow_mut().registers.insert(0x101, vec![0x43, 0]);
    assert_eq!(d.wake().unwrap_err().kind, ErrorKind::IdentityChanged);
    assert_eq!(d.state(), State::Uncertain);
    assert_eq!(d.capabilities().unwrap().product_id, 0x42);
}
#[test]
fn elan_bootloader_geometry_and_reports_fail_explicitly() {
    for (reg, value, error) in [
        (0x310, vec![0, 0], ErrorKind::FirmwareMode(0)),
        (0x105, vec![0, 1], ErrorKind::InvalidGeometry),
        (0x106, vec![0, 0], ErrorKind::InvalidGeometry),
        (0x108, vec![0x80, 0], ErrorKind::InvalidGeometry),
    ] {
        let h = hardware(0, 0x42, 8);
        h.borrow_mut().registers.insert(reg, value);
        let mut d = device(&h);
        assert_eq!(d.initialize().unwrap_err().kind, error);
        assert!(d.capabilities().is_none());
    }
    let h = hardware(0, 0x42, 8);
    h.borrow_mut().reset_response = [1, 0];
    let mut d = device(&h);
    assert_eq!(
        d.initialize().unwrap_err().kind,
        ErrorKind::ResetResponse([1, 0])
    );
    assert_eq!(h.borrow().reads.len(), 1);
    for id in [0x60, 0x55, 0] {
        let h = hardware(0, 0x42, 8);
        let mut d = device(&h);
        d.initialize().unwrap();
        let mut report = [0; 34];
        report[2] = id;
        h.borrow_mut().reports.push_back(report.to_vec());
        let error = d.poll().unwrap_err();
        assert_eq!(
            error.kind,
            if id == 0 {
                ErrorKind::UnexpectedReset
            } else {
                ErrorKind::ReportId(id)
            }
        );
        assert_eq!(d.state(), State::Uncertain);
    }
    let h = hardware(0, 0x42, 8);
    h.borrow_mut()
        .registers
        .insert(0x106, 100u16.to_le_bytes().to_vec());
    let mut d = device(&h);
    d.initialize().unwrap();
    h.borrow_mut()
        .reports
        .push_back(absolute(2, 0, 0, false).to_vec());
    assert_eq!(
        d.poll().unwrap_err().kind,
        ErrorKind::Coordinate {
            slot: 1,
            x: 520,
            y: 266
        }
    );
}
#[test]
fn elan_late_mutable_and_report_effects_quarantine_without_automatic_replay() {
    for register in [5, 0x300] {
        let h = hardware(0, 0x42, 8);
        h.borrow_mut().fail_write = Some(register);
        let mut d = device(&h);
        let error = d.initialize().unwrap_err();
        assert!(matches!(error.kind, ErrorKind::Bus(_)));
        assert_eq!(error.recovery, Recovery::IrqMasked);
        assert_eq!(d.state(), State::Uncertain);
        let writes = h.borrow().writes.len();
        assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NeedsReset);
        assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NeedsReset);
        assert_eq!(h.borrow().writes.len(), writes);
        // Only a new explicit initialization starts another real reset sequence.
        d.initialize().unwrap();
        assert_eq!(d.state(), State::Ready);
        assert_eq!(h.borrow().resets, 2);
    }
    let h = hardware(0, 0x42, 8);
    let mut d = device(&h);
    d.initialize().unwrap();
    h.borrow_mut().fail_write = Some(0x307);
    assert!(matches!(
        d.power_down().unwrap_err().kind,
        ErrorKind::Bus(_)
    ));
    assert_eq!(h.borrow().registers[&0x307], [0xa5, 0x5a]);
    let count = h.borrow().writes.len();
    assert_eq!(d.power_down().unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(h.borrow().writes.len(), count);
    d.initialize().unwrap();
    assert_eq!(h.borrow().registers[&0x307], [0xa4, 0x5a]);
    let h = hardware(0, 0x42, 8);
    let mut d = device(&h);
    d.initialize().unwrap();
    h.borrow_mut()
        .reports
        .push_back(absolute(31, 7, 255, true).to_vec());
    let fail = h.borrow().reads.len() + 1;
    h.borrow_mut().fail_read = Some(fail);
    assert!(matches!(d.poll().unwrap_err().kind, ErrorKind::Bus(_)));
    assert!(h.borrow().reports.is_empty());
    assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NeedsReset);
    let h = hardware(0, 0x42, 8);
    let mut d = device(&h);
    h.borrow_mut().fail_irq = true;
    let error = d.initialize().unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Interrupt(_)));
    assert_eq!(error.recovery, Recovery::MaskFailed);
    assert!(h.borrow().writes.is_empty());
}
#[test]
fn elan_each_initialization_read_failure_preserves_no_partial_capability_or_retry() {
    let baseline = hardware(0, 0x42, 8);
    let mut d = device(&baseline);
    d.initialize().unwrap();
    let reads = baseline.borrow().reads.len();
    for read in 1..=reads {
        let h = hardware(0, 0x42, 8);
        h.borrow_mut().fail_read = Some(read);
        let mut d = device(&h);
        assert!(matches!(
            d.initialize().unwrap_err().kind,
            ErrorKind::Bus(_)
        ));
        assert!(d.capabilities().is_none());
        assert_eq!(d.state(), State::Uncertain);
        assert_eq!(h.borrow().reads.len(), read);
    }
    let h = hardware(0, 0x42, 8);
    h.borrow().time.set(u64::MAX - 50_000);
    let mut d = device(&h);
    d.initialize().unwrap();
    assert_eq!(h.borrow().resets, 1);
}

#[test]
fn elan_supplied_addresses_are_validated_and_ten_bit_ownership_is_preserved() {
    for address in [Address::SevenBit(0x15), Address::TenBit(0x215)] {
        let h = hardware(0, 0x42, 8);
        h.borrow_mut().address = address;
        let mut d = I2cDevice::new(
            Wire(h.clone()),
            Irq(h.clone()),
            Time(h.borrow().time.clone()),
            address,
        )
        .unwrap();
        d.initialize().unwrap();
        assert_eq!(d.state(), State::Ready);
    }
    for address in [
        Address::SevenBit(7),
        Address::SevenBit(0x78),
        Address::TenBit(0x400),
    ] {
        let h = hardware(0, 0x42, 8);
        let result = I2cDevice::new(
            Wire(h.clone()),
            Irq(h.clone()),
            Time(h.borrow().time.clone()),
            address,
        );
        assert!(matches!(
            result,
            Err(Error {
                kind: ErrorKind::InvalidAddress,
                ..
            })
        ));
        assert!(h.borrow().writes.is_empty());
    }
}
#[test]
fn elan_pressure_width_nibbles_coordinate_limits_and_wide_areas_are_not_truncated() {
    let h = hardware(1, 0x42, 8);
    let mut d = device(&h);
    d.initialize().unwrap();
    for value in 0u8..=255 {
        let mut raw = absolute(1, 0, value, false);
        raw[7] = value;
        h.borrow_mut().reports.push_back(raw.to_vec());
        let Frame::Absolute(frame) = d.poll().unwrap().unwrap() else {
            panic!("wrong report");
        };
        let c = frame.contacts[0].unwrap();
        assert_eq!(c.pressure, value.saturating_add(25));
        assert_eq!(c.width_marks, (value & 15, value >> 4));
        assert_eq!(
            c.areas,
            (u32::from(value & 15) * 251, u32::from(value >> 4) * 114)
        );
    }
    let h = hardware(0, 0x42, 8);
    {
        let mut h = h.borrow_mut();
        h.registers.insert(0x106, 65535u16.to_le_bytes().to_vec());
        h.registers.insert(0x107, 65535u16.to_le_bytes().to_vec());
        h.registers.insert(0x105, vec![1, 1]);
    }
    let mut d = device(&h);
    d.initialize().unwrap();
    for x in [0u16, 4095] {
        for y in [0u16, 4095] {
            let mut raw = absolute(1, 0, 255, false);
            raw[4..9].copy_from_slice(&[
                (((x >> 8) << 4) | (y >> 8)) as u8,
                x as u8,
                y as u8,
                255,
                255,
            ]);
            h.borrow_mut().reports.push_back(raw.to_vec());
            let Frame::Absolute(frame) = d.poll().unwrap().unwrap() else {
                panic!("wrong report");
            };
            let c = frame.contacts[0].unwrap();
            assert_eq!((c.x, c.y, c.y_top_down), (x, y, 65535 - y));
            assert_eq!(c.areas, (981675, 981675));
        }
    }
}
#[test]
fn elan_early_and_late_wake_sleep_power_and_stop_failures_keep_actual_effects_uncertain() {
    for (ic, product) in [(8, 0x42), (8, 0x26)] {
        let h = hardware(0, product, ic);
        h.borrow_mut().fail_command = Some((5, 0x800));
        let mut d = device(&h);
        assert!(matches!(
            d.initialize().unwrap_err().kind,
            ErrorKind::Bus(_)
        ));
        assert!(h.borrow().awake);
        assert_eq!(d.state(), State::Uncertain);
        let writes = h.borrow().writes.len();
        assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NeedsReset);
        assert_eq!(h.borrow().writes.len(), writes);
        assert_eq!(h.borrow().absolute, product != 0x26);
    }
    let h = hardware(0, 0x42, 8);
    let mut d = device(&h);
    d.initialize().unwrap();
    h.borrow_mut().fail_command = Some((5, 0x801));
    assert!(matches!(d.stop().unwrap_err().kind, ErrorKind::Bus(_)));
    assert!(!h.borrow().awake);
    assert_eq!(d.state(), State::Uncertain);
    let h = hardware(0, 0x42, 8);
    let mut d = device(&h);
    d.initialize().unwrap();
    d.power_down().unwrap();
    h.borrow_mut().fail_command = Some((0x307, 0x5aa4));
    assert!(matches!(d.wake().unwrap_err().kind, ErrorKind::Bus(_)));
    assert_eq!(h.borrow().registers[&0x307], [0xa4, 0x5a]);
    assert_eq!(d.state(), State::Uncertain);
    let h = hardware(0, 0x42, 8);
    let mut d = device(&h);
    d.initialize().unwrap();
    d.sleep().unwrap();
    h.borrow_mut().fail_irq = true;
    assert_eq!(d.stop().unwrap_err().recovery, Recovery::MaskFailed);
    assert_eq!(d.state(), State::Uncertain);
}
#[test]
fn elan_resume_reset_and_source_quick_wake_have_distinct_real_queue_effects() {
    for (ic, product, quick) in [(8, 0x42, false), (0x0d, 0xc2, true)] {
        let h = hardware(1, product, ic);
        let mut d = device(&h);
        d.initialize().unwrap();
        let pending = absolute(17, 5, 123, false);
        h.borrow_mut().reports.push_back(pending.to_vec());
        d.sleep().unwrap();
        assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NotReady);
        assert_eq!(h.borrow().reports.len(), 1);
        d.wake().unwrap();
        if quick {
            let Frame::Absolute(frame) = d.poll().unwrap().unwrap() else {
                panic!("wrong report");
            };
            assert_eq!(frame.raw.as_bytes(), pending);
        } else {
            assert!(d.poll().unwrap().is_none());
        }
    }
}

#[path = "high_precision_tests.rs"]
mod high_precision_tests;
