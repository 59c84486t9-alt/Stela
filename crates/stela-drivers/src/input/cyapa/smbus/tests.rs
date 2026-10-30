//! Independent encoded/count-bearing and fixed/no-count peripheral model.
use super::*;
use crate::bus::i2c::Timer;
use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
use core::cell::{Cell, RefCell};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Effect {
    FixedRead(u8, usize),
    FixedWrite(u8, Vec<u8>),
    Block(u8),
    ReadByte(u8),
    WriteByte(u8, u8),
}
struct Hardware {
    status: [u8; 3],
    encoded: bool,
    query: [u8; 27],
    power: u8,
    reports: VecDeque<Vec<u8>>,
    clock: Rc<Cell<u64>>,
    transition: Option<(u64, [u8; 3], bool)>,
    launch_delay: u64,
    no_launch: bool,
    settling: u64,
    reject_power: bool,
    masked: bool,
    irq_fail: bool,
    probe: smbus::Error,
    count: Option<(u8, usize)>,
    effects: Vec<(Effect, u64)>,
    fail: Option<usize>,
    jump: Option<(usize, u64)>,
}
fn bus_error(kind: smbus::ErrorKind, recovery: smbus::Recovery) -> smbus::Error {
    let status = match kind {
        smbus::ErrorKind::Device => {
            if recovery == smbus::Recovery::Killed {
                5
            } else {
                4
            }
        }
        smbus::ErrorKind::ArbitrationLost => 8,
        smbus::ErrorKind::Failed => 16,
        smbus::ErrorKind::InvalidBlockLength(_) => 2,
        smbus::ErrorKind::Busy => 1,
        smbus::ErrorKind::Timeout(_) if recovery == smbus::Recovery::Killed => 1,
        _ => 0,
    };
    smbus::Error {
        kind,
        status,
        recovery,
    }
}
fn probe_error() -> smbus::Error {
    bus_error(smbus::ErrorKind::Device, smbus::Recovery::Cleared)
}
fn late_error() -> smbus::Error {
    bus_error(smbus::ErrorKind::ArbitrationLost, smbus::Recovery::Cleared)
}
fn hardware(status: [u8; 3], power: u8) -> Rc<RefCell<Hardware>> {
    let mut query = [0xa5; 27];
    query[..13].copy_from_slice(b"CYTRA12345678");
    query[15..17].copy_from_slice(&[1, 2]);
    query[19] = 0x38;
    query[20] = 3;
    query[21..].copy_from_slice(&[0xf7, 0xff, 0xff, 0, 100, 50]);
    Rc::new(RefCell::new(Hardware {
        status,
        encoded: status == [0x0c, 8, 0],
        query,
        power,
        reports: VecDeque::new(),
        clock: Rc::new(Cell::new(0)),
        transition: None,
        launch_delay: 50_000,
        no_launch: false,
        settling: 0,
        reject_power: false,
        masked: false,
        irq_fail: false,
        probe: probe_error(),
        count: None,
        effects: Vec::new(),
        fail: None,
        jump: None,
    }))
}
fn scan_delay(power: u8) -> u64 {
    match power >> 2 {
        0 | 1 | 63 => 20_000,
        n @ 2..=9 => (u64::from(n) * 10 + 50) * 1000,
        n => (u64::from(n) - 5) * 20_000 + 50_000,
    }
}
impl Hardware {
    fn update(&mut self) {
        if let Some((at, status, encoded)) = self.transition
            && self.clock.get() >= at
        {
            self.status = status;
            self.encoded = encoded;
            self.transition = None;
        }
    }
    fn begin(&mut self, effect: Effect) {
        assert!(self.masked);
        assert!(
            self.clock.get() >= self.settling,
            "old scan interval has not settled"
        );
        self.update();
        self.effects.push((effect, self.clock.get()));
    }
    fn finish(&mut self) -> Result<(), smbus::Error> {
        if let Some((index, elapsed)) = self.jump
            && self.effects.len() == index
        {
            self.clock.set(self.clock.get().wrapping_add(elapsed));
            self.jump = None;
            self.update();
        }
        if self.fail == Some(self.effects.len()) {
            Err(late_error())
        } else {
            Ok(())
        }
    }
}
struct Wire(Rc<RefCell<Hardware>>);
struct Irq(Rc<RefCell<Hardware>>);
struct Time(Rc<Cell<u64>>);
impl smbus::Bus for Wire {
    fn transaction(
        &mut self,
        address: smbus::Address,
        op: Transaction<'_>,
        pec: bool,
    ) -> Result<(), smbus::Error> {
        assert_eq!(address.get(), 0x67);
        assert!(!pec);
        let mut h = self.0.borrow_mut();
        match op {
            Transaction::ReadBlock { command, data } => {
                h.begin(Effect::Block(command));
                assert!(h.encoded);
                let mut reply = match command {
                    0xc1 => h.status.to_vec(),
                    0x99 => {
                        assert_eq!(h.power & 0xfc, 0xfc);
                        h.query.to_vec()
                    }
                    0x81 => {
                        assert_eq!(h.power & 0xfc, 0xfc);
                        h.reports.pop_front().expect("actual report")
                    }
                    _ => panic!("wrong encoded block command"),
                };
                if let Some((expected, count)) = h.count
                    && command == expected
                {
                    reply.resize(count, 0xee);
                }
                h.finish()?;
                if !(1..=32).contains(&reply.len()) {
                    return Err(bus_error(
                        smbus::ErrorKind::InvalidBlockLength(reply.len()),
                        smbus::Recovery::Cleared,
                    ));
                }
                *data = Block::from_slice(&reply).unwrap();
                Ok(())
            }
            Transaction::ReadByte { command, data } => {
                h.begin(Effect::ReadByte(command));
                assert!(h.encoded);
                assert_eq!(command, 3);
                let power = h.power;
                h.finish()?;
                *data = power;
                Ok(())
            }
            Transaction::WriteByte { command, data } => {
                h.begin(Effect::WriteByte(command, data));
                assert!(h.encoded);
                assert_eq!(command, 2);
                assert_eq!(data & 3, h.power & 3);
                let until = h.clock.get() + scan_delay(h.power);
                if !h.reject_power {
                    h.power = data;
                    h.settling = until;
                }
                h.finish()
            }
            _ => panic!("no count-bearing write/word/fabricated I2C framing"),
        }
    }
}
impl I2cBlockBus for Wire {
    fn read_i2c_block(
        &mut self,
        address: smbus::Address,
        command: u8,
        bytes: &mut [u8],
    ) -> Result<(), smbus::Error> {
        assert_eq!(address.get(), 0x67);
        let mut h = self.0.borrow_mut();
        h.begin(Effect::FixedRead(command, bytes.len()));
        assert_eq!((command, bytes.len()), (0, 3));
        let raw = h.status;
        let encoded = h.encoded;
        h.finish()?;
        if encoded {
            return Err(h.probe);
        }
        bytes.copy_from_slice(&raw);
        Ok(())
    }
    fn write_i2c_block(
        &mut self,
        address: smbus::Address,
        command: u8,
        bytes: &[u8],
    ) -> Result<(), smbus::Error> {
        assert_eq!(address.get(), 0x67);
        let mut h = self.0.borrow_mut();
        h.begin(Effect::FixedWrite(command, bytes.to_vec()));
        assert!(!h.encoded);
        assert_eq!(command, 0);
        assert_eq!(bytes.len(), 11);
        assert_eq!(&bytes[..2], &[0, 0xff]);
        assert_eq!(&bytes[3..], &[0, 1, 2, 3, 4, 5, 6, 7]);
        match bytes[2] {
            0x3b => {
                assert_eq!(h.status, [0, 0x10, 0x20]);
                h.status = [0, 0x90, 0x20];
                h.transition = Some((h.clock.get() + 100_000, [0, 0x11, 0], false));
            }
            0xa5 => {
                assert_eq!(h.status[1] & 1, 1);
                h.status = [0, 0x90, 0x20];
                if !h.no_launch {
                    h.transition = Some((h.clock.get() + h.launch_delay, [0x0c, 8, 0], true));
                }
            }
            _ => panic!("no firmware page programming"),
        }
        h.finish()
    }
}
impl Interrupt for Irq {
    fn mask_and_drain(&mut self) -> Result<(), super::super::InterruptError> {
        let mut h = self.0.borrow_mut();
        if h.irq_fail {
            Err(super::super::InterruptError::Hardware(1))
        } else {
            h.masked = true;
            Ok(())
        }
    }
    fn asserted(&mut self) -> Result<bool, super::super::InterruptError> {
        let mut h = self.0.borrow_mut();
        h.update();
        if h.irq_fail {
            Err(super::super::InterruptError::Hardware(2))
        } else {
            Ok(!h.reports.is_empty())
        }
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
fn device(h: &Rc<RefCell<Hardware>>) -> Device<Wire, Irq, Time> {
    Device::new_smbus(
        Wire(h.clone()),
        Irq(h.clone()),
        Time(h.borrow().clock.clone()),
        smbus::Address::new(0x67).unwrap(),
    )
    .unwrap()
}
fn packet(count: u8, first: u8, buttons: u8, pressure: u8) -> Vec<u8> {
    let mut bytes = vec![0xa5; 27];
    bytes[0] = 0x8f;
    bytes[1] = (count << 4) | 8 | buttons;
    for i in 0..count {
        let offset = 2 + usize::from(i) * 5;
        let x = 7 + u16::from(i) * 900;
        let y = 9 + u16::from(i) * 400;
        bytes[offset..offset + 5].copy_from_slice(&[
            ((x >> 8) as u8) << 4 | (y >> 8) as u8,
            x as u8,
            y as u8,
            pressure,
            ((first - 1 + i * 3) % 15) + 1,
        ]);
    }
    bytes
}
#[test]
fn smbus_real_cold_boot_fixed_security_and_operational_encoded_query_power() {
    for status in [[0x0c, 8, 0], [0, 0x11, 0], [0, 0x10, 0x20]] {
        let h = hardware(status, 0x17);
        let mut d = device(&h);
        d.initialize().unwrap();
        assert_eq!(d.state(), State::Ready);
        assert_eq!(d.last_status(), Some([0x0c, 8, 0]));
        assert_eq!(d.take_probe_notice(), Some(probe_error()));
        let caps = d.capabilities().unwrap();
        assert_eq!(caps.query, h.borrow().query);
        assert_eq!(&caps.product_id, b"CYTRA-123456-78");
        assert_eq!(caps.maximum, (4095, 2047));
        assert_eq!(h.borrow().power, 0xff);
        assert_eq!(d.take_last_block().unwrap().as_slice(), h.borrow().query);
        let writes = h
            .borrow()
            .effects
            .iter()
            .filter(|(e, _)| matches!(e, Effect::FixedWrite(..)))
            .count();
        assert_eq!(
            writes,
            if status[0] != 0 {
                0
            } else if status[2] == 0x20 {
                2
            } else {
                1
            }
        );
    }
}
#[test]
fn smbus_counts_are_required_and_complete_malformed_blocks_remain_owned() {
    for command in [0xc1, 0x99, 0x81] {
        for count in 0..=33 {
            let h = hardware([0x0c, 8, 0], 0x17);
            let mut d = device(&h);
            if command == 0x81 {
                d.initialize().unwrap();
                h.borrow_mut().reports.push_back(packet(5, 1, 7, 255));
            }
            h.borrow_mut().count = Some((command, count));
            let outcome = if command == 0x81 {
                d.poll().map(|_| ())
            } else {
                d.initialize()
            };
            let expected = if command == 0xc1 { 3 } else { 27 };
            if count == expected {
                outcome.unwrap();
                assert_eq!(d.state(), State::Ready);
            } else {
                let error = outcome.unwrap_err();
                if count == 0 || count == 33 {
                    assert_eq!(
                        error.kind,
                        ErrorKind::Smbus(bus_error(
                            smbus::ErrorKind::InvalidBlockLength(count),
                            smbus::Recovery::Cleared
                        ))
                    );
                } else {
                    assert_eq!(
                        error.kind,
                        ErrorKind::BlockLength {
                            command,
                            expected,
                            actual: count
                        }
                    );
                    assert_eq!(d.take_last_block().unwrap().as_slice().len(), count);
                }
                assert_eq!(d.state(), State::Uncertain);
                assert_eq!(d.capabilities().is_some(), command == 0x81);
            }
            if command == 0x81 {
                assert!(h.borrow().reports.is_empty());
            }
        }
    }
}
#[test]
fn smbus_all_source_contact_counts_ids_buttons_and_pressure_keep_exact_raw_payload() {
    let h = hardware([0x0c, 8, 0], 0xfc);
    let mut d = device(&h);
    d.initialize().unwrap();
    for count in 0..=5 {
        for first in 1..=15 {
            for buttons in 0..8 {
                for pressure in [0, 255] {
                    let bytes = packet(count, first, buttons, pressure);
                    h.borrow_mut().reports.push_back(bytes.clone());
                    let frame = d.poll().unwrap().unwrap();
                    assert_eq!(frame.raw.as_slice(), bytes);
                    assert_eq!(frame.count, count);
                    assert_eq!(frame.buttons, buttons);
                    assert_eq!(frame.contacts.iter().flatten().count(), usize::from(count));
                    for i in 0..count {
                        let id = ((first - 1 + i * 3) % 15) + 1;
                        let c = frame.contacts[usize::from(id - 1)].unwrap();
                        assert_eq!(
                            (c.id, c.x, c.y, c.pressure),
                            (id, 7 + u16::from(i) * 900, 9 + u16::from(i) * 400, pressure)
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn smbus_recovered_probe_contract_keeps_original_and_other_failures_never_fallback() {
    for kind in [
        smbus::ErrorKind::Device,
        smbus::ErrorKind::Timeout(smbus::Phase::Completion),
        smbus::ErrorKind::Timeout(smbus::Phase::ByteDone),
    ] {
        for recovery in [smbus::Recovery::Cleared, smbus::Recovery::Killed] {
            let h = hardware([0x0c, 8, 0], 0xfc);
            let original = bus_error(kind, recovery);
            h.borrow_mut().probe = original;
            let mut d = device(&h);
            d.initialize().unwrap();
            assert_eq!(d.take_probe_notice(), Some(original));
        }
    }
    for original in [
        bus_error(smbus::ErrorKind::Device, smbus::Recovery::NotAttempted),
        bus_error(smbus::ErrorKind::Device, smbus::Recovery::Failed),
        bus_error(
            smbus::ErrorKind::Timeout(smbus::Phase::Completion),
            smbus::Recovery::Failed,
        ),
        late_error(),
        bus_error(smbus::ErrorKind::Busy, smbus::Recovery::Cleared),
        bus_error(
            smbus::ErrorKind::UnsupportedTransaction,
            smbus::Recovery::NotAttempted,
        ),
    ] {
        let h = hardware([0x0c, 8, 0], 0xfc);
        h.borrow_mut().probe = original;
        let mut d = device(&h);
        assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::Smbus(original));
        assert_eq!(h.borrow().effects.len(), 1);
        assert!(d.take_probe_notice().is_none());
        assert!(d.capabilities().is_none());
    }
    let h = hardware([0x0c, 8, 0], 0xfc);
    let error = Device::new_smbus(
        Wire(h.clone()),
        Irq(h.clone()),
        Time(h.borrow().clock.clone()),
        smbus::Address::new(0x24).unwrap(),
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::UnsupportedSmbusAddress(0x24));
    assert!(h.borrow().effects.is_empty());
}
#[test]
fn smbus_every_initialization_late_effect_preserves_original_error_without_replay() {
    for status in [[0x0c, 8, 0], [0, 0x11, 0], [0, 0x10, 0x20]] {
        let sample = hardware(status, 0x17);
        device(&sample).initialize().unwrap();
        let count = sample.borrow().effects.len();
        for index in 1..=count {
            let h = hardware(status, 0x17);
            h.borrow_mut().fail = Some(index);
            let mut d = device(&h);
            assert_eq!(
                d.initialize().unwrap_err().kind,
                ErrorKind::Smbus(late_error())
            );
            assert_eq!(d.state(), State::Uncertain);
            assert!(d.capabilities().is_none());
            assert_eq!(h.borrow().effects.len(), index);
            assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::NeedsReset);
            assert_eq!(h.borrow().effects.len(), index);
        }
    }
}
#[test]
fn smbus_late_power_faults_keep_capabilities() {
    for action in 0..4 {
        let sample = hardware([0x0c, 8, 0], 0xfc);
        let mut baseline = device(&sample);
        baseline.initialize().unwrap();
        let before = sample.borrow().effects.len();
        match action {
            0 => baseline.sleep().unwrap(),
            1 => baseline.buttons_only().unwrap(),
            2 => baseline.power_down().unwrap(),
            _ => baseline.stop().unwrap(),
        };
        let count = sample.borrow().effects.len() - before;
        for index in 1..=count {
            let h = hardware([0x0c, 8, 0], 0xff);
            let mut d = device(&h);
            d.initialize().unwrap();
            let next = h.borrow().effects.len() + index;
            h.borrow_mut().fail = Some(next);
            let result = match action {
                0 => d.sleep(),
                1 => d.buttons_only(),
                2 => d.power_down(),
                _ => d.stop(),
            };
            assert_eq!(result.unwrap_err().kind, ErrorKind::Smbus(late_error()));
            assert_eq!(d.state(), State::Uncertain);
            assert_eq!(d.capabilities().unwrap().firmware_version, (1, 2));
            assert_eq!(h.borrow().effects.len(), next);
            let changed = h
                .borrow()
                .effects
                .iter()
                .any(|(effect, _)| matches!(effect, Effect::WriteByte(2, _)));
            let target = match action {
                0 => 0x17,
                1 => 7,
                _ => 3,
            };
            assert_eq!(h.borrow().power, if changed { target } else { 0xff });
            assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NeedsReset);
            assert_eq!(h.borrow().effects.len(), next);
        }
    }
    let sample = hardware([0x0c, 8, 0], 0xff);
    let mut baseline = device(&sample);
    baseline.initialize().unwrap();
    baseline.sleep().unwrap();
    let before = sample.borrow().effects.len();
    baseline.wake().unwrap();
    let count = sample.borrow().effects.len() - before;
    for index in 1..=count {
        let h = hardware([0x0c, 8, 0], 0xff);
        let mut d = device(&h);
        d.initialize().unwrap();
        d.sleep().unwrap();
        let next = h.borrow().effects.len() + index;
        h.borrow_mut().fail = Some(next);
        assert_eq!(d.wake().unwrap_err().kind, ErrorKind::Smbus(late_error()));
        assert_eq!(d.state(), State::Uncertain);
        assert_eq!(h.borrow().effects.len(), next);
        assert_eq!(d.capabilities().unwrap().firmware_version, (1, 2));
        let woke = h.borrow().effects[before..]
            .iter()
            .any(|(effect, _)| matches!(effect, Effect::WriteByte(2, 0xff)));
        assert_eq!(h.borrow().power, if woke { 0xff } else { 0x17 });
        let after = h.borrow().effects.len();
        assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NeedsReset);
        assert_eq!(h.borrow().effects.len(), after);
    }
    let h = hardware([0x0c, 8, 0], 0xff);
    let mut d = device(&h);
    d.initialize().unwrap();
    d.power_down().unwrap();
    assert_eq!(h.borrow().power, 3);
    d.wake().unwrap();
    assert_eq!(h.borrow().power, 0xff);
    d.sleep().unwrap();
    h.borrow_mut().query[16] = 9;
    assert_eq!(d.wake().unwrap_err().kind, ErrorKind::IdentityChanged);
    assert_eq!(d.capabilities().unwrap().firmware_version, (1, 2));
}
#[test]
fn smbus_completed_status_deadlines_and_failed_probe_budget_block_next_commands() {
    for (status, index) in [([0, 0x11, 0], 1), ([0x0c, 8, 0], 2)] {
        let h = hardware(status, 0x17);
        h.borrow_mut().jump = Some((index, 4_000_000));
        let mut d = device(&h);
        let observed = if index == 1 {
            super::super::HardwareState::BootloaderIdle
        } else {
            super::super::HardwareState::Operational
        };
        assert_eq!(
            d.initialize().unwrap_err().kind,
            ErrorKind::Timeout(observed)
        );
        assert_eq!(d.last_status(), Some(status));
        assert_eq!(h.borrow().effects.len(), index);
        assert!(d.capabilities().is_none());
    }
    let h = hardware([0x0c, 8, 0], 0x17);
    h.borrow_mut().jump = Some((1, 4_000_000));
    let mut d = device(&h);
    assert_eq!(
        d.initialize().unwrap_err().kind,
        ErrorKind::Smbus(probe_error())
    );
    assert_eq!(d.take_probe_notice(), Some(probe_error()));
    assert!(d.last_status().is_none());
    assert_eq!(h.borrow().effects.len(), 1);
    let h = hardware([0, 0x11, 0], 0x17);
    h.borrow_mut().jump = Some((4, 4_000_000));
    let mut d = device(&h);
    assert_eq!(
        d.initialize().unwrap_err().kind,
        ErrorKind::Timeout(super::super::HardwareState::Operational)
    );
    assert_eq!(d.last_status(), Some([0x0c, 8, 0]));
    assert_eq!(h.borrow().effects.len(), 4);
    assert!(h.borrow().encoded);
    assert_eq!(h.borrow().power, 0x17);
}
#[test]
fn smbus_failed_report_identity_firmware_power_and_irq_never_publish_false_state() {
    let h = hardware([0, 0x10, 0], 0x17);
    let mut d = device(&h);
    assert_eq!(
        d.initialize().unwrap_err().kind,
        ErrorKind::InvalidFirmware([0, 0x10, 0])
    );
    assert!(
        h.borrow()
            .effects
            .iter()
            .all(|(e, _)| !matches!(e, Effect::FixedWrite(..)))
    );
    let h = hardware([0, 0x11, 0], 0x17);
    h.borrow_mut().no_launch = true;
    let mut d = device(&h);
    assert_eq!(
        d.initialize().unwrap_err().kind,
        ErrorKind::Timeout(super::super::HardwareState::BootloaderBusy)
    );
    assert_eq!(h.borrow().power, 0x17);
    let h = hardware([0x0c, 8, 0], 0x17);
    h.borrow_mut().reject_power = true;
    let mut d = device(&h);
    assert_eq!(
        d.initialize().unwrap_err().kind,
        ErrorKind::PowerReadback {
            expected: 0xff,
            actual: 0x17
        }
    );
    assert!(d.capabilities().is_none());
    let h = hardware([0x0c, 8, 0], 0xfc);
    let mut d = device(&h);
    d.initialize().unwrap();
    let bytes = packet(1, 1, 0, 255);
    h.borrow_mut().reports.push_back(bytes);
    let next = h.borrow().effects.len() + 1;
    h.borrow_mut().fail = Some(next);
    assert_eq!(d.poll().unwrap_err().kind, ErrorKind::Smbus(late_error()));
    assert!(h.borrow().reports.is_empty());
    assert_eq!(d.capabilities().unwrap().firmware_version, (1, 2));
    let h = hardware([0x0c, 8, 0], 0xfc);
    let mut d = device(&h);
    d.initialize().unwrap();
    let mut bad = packet(2, 1, 0, 0);
    bad[11] = bad[6];
    h.borrow_mut().reports.push_back(bad.clone());
    assert_eq!(d.poll().unwrap_err().kind, ErrorKind::DuplicateId(1));
    assert_eq!(d.take_last_block().unwrap().as_slice(), bad);
    let h = hardware([0x0c, 8, 0], 0xfc);
    h.borrow_mut().irq_fail = true;
    let mut d = device(&h);
    let error = d.initialize().unwrap_err();
    assert_eq!(error.recovery, super::super::Recovery::MaskFailed);
    assert!(h.borrow().effects.is_empty());
}
