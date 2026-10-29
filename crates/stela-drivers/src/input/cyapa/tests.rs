//! Independent timed peripheral, bootloader transitions and contact packets.
use super::*;
use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
use core::cell::{Cell, RefCell};
struct Hardware {
    status: [u8; 3],
    query: [u8; 27],
    power: u8,
    reports: VecDeque<[u8; 27]>,
    transition: Option<(u64, [u8; 3])>,
    launch_delay: u64,
    settling: u64,
    time: Rc<Cell<u64>>,
    masked: bool,
    effects: Vec<(Vec<u8>, usize, u64)>,
    fail: Option<usize>,
    jump: Option<(usize, u64)>,
    fail_irq: bool,
    reject_power: bool,
    never_launch: bool,
}
fn hardware(status: [u8; 3], power: u8) -> Rc<RefCell<Hardware>> {
    let mut query = [0xa5; 27];
    query[..13].copy_from_slice(b"CYTRA12345678");
    query[15] = 1;
    query[16] = 2;
    query[19] = 0x38;
    query[20] = 3;
    query[21..].copy_from_slice(&[0xf7, 0xff, 0xff, 0, 100, 50]);
    Rc::new(RefCell::new(Hardware {
        status,
        query,
        power,
        reports: VecDeque::new(),
        transition: None,
        launch_delay: 50_000,
        settling: 0,
        time: Rc::new(Cell::new(0)),
        masked: false,
        effects: Vec::new(),
        fail: None,
        jump: None,
        fail_irq: false,
        reject_power: false,
        never_launch: false,
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
fn previous_scan_wait(power: u8) -> u64 {
    match power >> 2 {
        0 | 1 | 63 => 20_000,
        encoded @ 2..=9 => (u64::from(encoded) * 10 + 50) * 1000,
        encoded => (u64::from(encoded) - 5) * 20_000 + 50_000,
    }
}
impl Bus for Wire {
    fn transaction(
        &mut self,
        address: Address,
        operations: &mut [Operation<'_>],
    ) -> Result<(), i2c::Error> {
        assert_eq!(address, Address::SevenBit(0x67));
        let mut h = self.0.borrow_mut();
        assert!(h.masked);
        let now = h.time.get();
        assert!(now >= h.settling, "command before previous power settled");
        if let Some((deadline, status)) = h.transition
            && now >= deadline
        {
            h.status = status;
            h.transition = None;
        }
        match operations {
            [Operation::Write(bytes), Operation::Read(output)] => {
                assert_eq!(bytes.len(), 1);
                h.effects.push((bytes.to_vec(), output.len(), now));
                match (bytes[0], output.len()) {
                    (0, 3) => output.copy_from_slice(&h.status),
                    (0, 27) => {
                        assert_eq!(h.power & 0xfc, 0xfc);
                        output.copy_from_slice(&h.reports.pop_front().expect("actual report"));
                    }
                    (0x29, 1) => output[0] = h.power,
                    (0x2a, 27) => {
                        assert_eq!(h.power & 0xfc, 0xfc, "full power required before query");
                        output.copy_from_slice(&h.query);
                    }
                    _ => panic!("unsupported query"),
                }
            }
            [Operation::Write(bytes)] => {
                h.effects.push((bytes.to_vec(), 0, now));
                if bytes.len() == 2 {
                    assert_eq!(bytes[0], 0x29);
                    assert_eq!(bytes[1] & 3, h.power & 3);
                    let deadline = now + previous_scan_wait(h.power);
                    if !h.reject_power {
                        h.power = bytes[1];
                        h.settling = deadline;
                    }
                } else {
                    assert_eq!(bytes.len(), 12);
                    assert_eq!(&bytes[..3], &[0, 0, 0xff]);
                    assert_eq!(&bytes[4..], &[0, 1, 2, 3, 4, 5, 6, 7]);
                    match bytes[3] {
                        0x3b => {
                            assert_eq!(h.status, [0, 0x10, 0x20]);
                            h.status = [0, 0x90, 0x20];
                            h.transition = Some((now + 100_000, [0, 0x11, 0]));
                        }
                        0xa5 => {
                            assert_eq!(h.status[1] & 1, 1);
                            h.status = [0, 0x90, 0x20];
                            if !h.never_launch {
                                h.transition = Some((now + h.launch_delay, [0x8f, 8, 0]));
                            }
                        }
                        _ => panic!("unexpected bootloader command"),
                    }
                }
            }
            _ => panic!("incorrect transaction shape"),
        }
        if let Some((index, elapsed)) = h.jump
            && index == h.effects.len()
        {
            h.time.set(h.time.get().wrapping_add(elapsed));
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
        Ok(!h.reports.is_empty())
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
    Device::new(
        Wire(h.clone()),
        Irq(h.clone()),
        Time(h.borrow().time.clone()),
        Address::SevenBit(0x67),
    )
    .unwrap()
}
fn packet(count: u8, first_id: u8, buttons: u8, pressure: u8) -> [u8; 27] {
    let mut bytes = [0xa5; 27];
    bytes[0] = 0x8f;
    bytes[1] = count << 4 | 8 | buttons;
    for index in 0..count.min(5) {
        let x = 7 + u16::from(index) * 900;
        let y = 9 + u16::from(index) * 400;
        let id = ((first_id - 1 + index * 3) % 15) + 1;
        let offset = 2 + usize::from(index) * 5;
        bytes[offset..offset + 5].copy_from_slice(&[
            (((x >> 8) << 4) | (y >> 8)) as u8,
            x as u8,
            y as u8,
            pressure,
            id,
        ]);
    }
    bytes
}
#[test]
fn cyapa_real_operational_query_power_settling_and_complete_raw_identity() {
    let h = hardware([0x8f, 8, 0], 0x17);
    let mut d = device(&h);
    assert!(h.borrow().effects.is_empty());
    d.initialize().unwrap();
    let c = d.capabilities().unwrap();
    assert_eq!(&c.product_id, b"CYTRA-123456-78");
    assert_eq!(c.firmware_version, (1, 2));
    assert_eq!(c.button_capabilities, 0x38);
    assert_eq!(c.maximum, (4095, 2047));
    assert_eq!(c.physical_size, (100, 50));
    assert_eq!(c.query, h.borrow().query);
    let h = h.borrow();
    assert_eq!(h.power, 0xff);
    assert_eq!(
        h.effects
            .iter()
            .map(|(w, n, _)| (w.clone(), *n))
            .collect::<Vec<_>>(),
        vec![
            (vec![0], 3),
            (vec![0x29], 1),
            (vec![0x29, 0xff], 0),
            (vec![0x29], 1),
            (vec![0x2a], 27)
        ]
    );
    assert_eq!(h.time.get(), 100_000);
}
#[test]
fn cyapa_all_old_power_fields_preserve_low_bits_and_wait_real_previous_scanrate() {
    for power in 0..=255 {
        let h = hardware([0x8f, 8, 0], power);
        let mut d = device(&h);
        d.initialize().unwrap();
        assert_eq!(h.borrow().power, (power & 3) | 0xfc);
        let expected = if power & 0xfc == 0xfc {
            0
        } else {
            previous_scan_wait(power)
        };
        assert_eq!(h.borrow().time.get(), expected);
    }
}
#[test]
fn cyapa_real_cold_idle_active_and_calibrating_firmware_launch_commands() {
    for initial in [[0, 0x11, 0], [0, 0x10, 0x20]] {
        for delay in [50_000, 150_000, 2_050_000] {
            let h = hardware(initial, 3);
            h.borrow_mut().launch_delay = delay;
            let mut d = device(&h);
            d.initialize().unwrap();
            assert_eq!(d.state(), State::Ready);
            assert_eq!(h.borrow().power, 0xff);
            let h = h.borrow();
            let commands = h
                .effects
                .iter()
                .filter(|(b, n, _)| b.len() == 12 && *n == 0)
                .map(|(b, _, _)| b[3])
                .collect::<Vec<_>>();
            assert_eq!(
                commands,
                if initial[2] == 0x20 {
                    vec![0x3b, 0xa5]
                } else {
                    vec![0xa5]
                }
            );
            assert!(h.time.get() >= delay + 20_000 + if initial[2] == 0x20 { 100_000 } else { 0 });
        }
    }
}
#[test]
fn cyapa_all_counts_ids_buttons_pressure_and_full_packets_preserve_tracking_slots() {
    let h = hardware([0x8f, 8, 0], 0xff);
    let mut d = device(&h);
    d.initialize().unwrap();
    for count in 0..=5 {
        for first in 1..=15 {
            for buttons in 0..8 {
                for pressure in [0, 255] {
                    let raw = packet(count, first, buttons, pressure);
                    h.borrow_mut().reports.push_back(raw);
                    let frame = d.poll().unwrap().unwrap();
                    assert_eq!(frame.raw, raw);
                    assert_eq!(
                        (frame.count, frame.raw_buttons, frame.buttons),
                        (count, buttons, buttons)
                    );
                    assert_eq!(frame.contacts.iter().flatten().count(), usize::from(count));
                    for index in 0..count {
                        let id = ((first - 1 + index * 3) % 15) + 1;
                        let c = frame.contacts[usize::from(id - 1)].unwrap();
                        assert_eq!(c.id, id);
                        assert_eq!(
                            (c.x, c.y, c.pressure),
                            (
                                7 + u16::from(index) * 900,
                                9 + u16::from(index) * 400,
                                pressure
                            )
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn cyapa_button_capabilities_filter_only_logical_bits_and_absent_ids_are_released() {
    for capabilities in 0..8 {
        let h = hardware([0x8f, 8, 0], 0xff);
        h.borrow_mut().query[19] = capabilities << 3;
        let mut d = device(&h);
        d.initialize().unwrap();
        for buttons in 0..8 {
            h.borrow_mut().reports.push_back(packet(5, 1, buttons, 0));
            let frame = d.poll().unwrap().unwrap();
            assert_eq!(
                (frame.raw_buttons, frame.buttons),
                (buttons, buttons & capabilities)
            );
        }
        h.borrow_mut().reports.push_back(packet(0, 1, 0, 0));
        assert!(
            d.poll()
                .unwrap()
                .unwrap()
                .contacts
                .iter()
                .all(Option::is_none)
        );
    }
}
#[test]
fn cyapa_bad_counts_ids_duplicates_status_and_coordinates_fail_before_publication() {
    let mut cases = Vec::new();
    for count in 6..16 {
        let mut raw = packet(0, 1, 0, 0);
        raw[1] = count << 4 | 8;
        cases.push((raw, ErrorKind::ContactCount(count)));
    }
    for id in 0..=255 {
        if (1..=15).contains(&id) {
            continue;
        }
        let mut raw = packet(1, 1, 0, 0);
        raw[6] = id;
        cases.push((raw, ErrorKind::ContactId(id)));
    }
    let mut raw = packet(2, 1, 0, 0);
    raw[11] = raw[6];
    cases.push((raw, ErrorKind::DuplicateId(1)));
    for status in [0, 0x80, 0x81, 0x82, 3, 0x7f] {
        let mut raw = packet(1, 1, 0, 0);
        raw[0] = status;
        cases.push((raw, ErrorKind::InvalidReportStatus([status, raw[1]])));
    }
    let mut raw = packet(1, 1, 0, 0);
    raw[1] &= !8;
    cases.push((raw, ErrorKind::InvalidReportStatus([raw[0], raw[1]])));
    let mut raw = packet(1, 1, 0, 0);
    raw[2..5].copy_from_slice(&[0x0f, 7, 0xff]);
    cases.push((
        raw,
        ErrorKind::Coordinate {
            id: 1,
            x: 7,
            y: 4095,
        },
    ));
    for (raw, error) in cases {
        let h = hardware([0x8f, 8, 0], 0xff);
        let mut d = device(&h);
        d.initialize().unwrap();
        h.borrow_mut().reports.push_back(raw);
        assert_eq!(d.poll().unwrap_err().kind, error);
        assert_eq!(d.state(), State::Uncertain);
        assert!(h.borrow().reports.is_empty());
    }
}
#[test]
fn cyapa_real_suspend_wake_identity_and_stop_have_actual_power_ownership() {
    for target in [State::Sleeping, State::ButtonsOnly, State::PoweredDown] {
        let h = hardware([0x8f, 8, 0], 0xff);
        let mut d = device(&h);
        d.initialize().unwrap();
        match target {
            State::Sleeping => d.sleep(),
            State::ButtonsOnly => d.buttons_only(),
            _ => d.power_down(),
        }
        .unwrap();
        assert_eq!(d.state(), target);
        assert_eq!(
            h.borrow().power,
            match target {
                State::Sleeping => 0x17,
                State::ButtonsOnly => 7,
                _ => 3,
            }
        );
        assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NotReady);
        d.wake().unwrap();
        assert_eq!(h.borrow().power, 0xff);
        assert_eq!(d.state(), State::Ready);
        d.sleep().unwrap();
        h.borrow_mut().query[16] ^= 1;
        assert_eq!(d.wake().unwrap_err().kind, ErrorKind::IdentityChanged);
        assert_eq!(d.capabilities().unwrap().firmware_version, (1, 2));
    }
    let h = hardware([0x8f, 8, 0], 0xff);
    let mut d = device(&h);
    d.initialize().unwrap();
    d.stop().unwrap();
    assert_eq!(d.state(), State::Stopped);
    assert_eq!(h.borrow().power, 3);
    assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NotReady);
}
#[test]
fn cyapa_late_init_launch_power_read_and_packet_faults_quarantine_without_replay() {
    for initial in [[0x8f, 8, 0], [0, 0x11, 0], [0, 0x10, 0x20]] {
        let baseline = hardware(initial, 0x17);
        device(&baseline).initialize().unwrap();
        let count = baseline.borrow().effects.len();
        for index in 1..=count {
            let h = hardware(initial, 0x17);
            h.borrow_mut().fail = Some(index);
            let mut d = device(&h);
            assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::Bus(failure()));
            assert_eq!(d.state(), State::Uncertain);
            assert!(d.capabilities().is_none());
            assert_eq!(h.borrow().effects.len(), index);
            assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::NeedsReset);
            assert_eq!(h.borrow().effects.len(), index);
        }
    }
    let h = hardware([0x8f, 8, 0], 0xff);
    let mut d = device(&h);
    d.initialize().unwrap();
    h.borrow_mut().reports.push_back(packet(5, 1, 7, 255));
    let next = h.borrow().effects.len() + 1;
    h.borrow_mut().fail = Some(next);
    assert_eq!(d.poll().unwrap_err().kind, ErrorKind::Bus(failure()));
    assert!(h.borrow().reports.is_empty());
    assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NeedsReset);
}
#[test]
fn cyapa_invalid_firmware_query_power_ack_timeout_and_irq_remain_explicit() {
    let h = hardware([0, 0x10, 0], 3);
    let mut d = device(&h);
    assert_eq!(
        d.initialize().unwrap_err().kind,
        ErrorKind::InvalidFirmware([0, 0x10, 0])
    );
    assert_eq!(h.borrow().effects.len(), 1);
    let h = hardware([0, 0x11, 0], 3);
    h.borrow_mut().never_launch = true;
    let mut d = device(&h);
    assert_eq!(
        d.initialize().unwrap_err().kind,
        ErrorKind::Timeout(HardwareState::BootloaderBusy)
    );
    assert!(h.borrow().time.get() >= 4_050_000);
    for (index, value, error) in [
        (20, 5, ErrorKind::UnsupportedGeneration(5)),
        (0, b'X', ErrorKind::UnsupportedProduct),
        (25, 0, ErrorKind::InvalidGeometry),
    ] {
        let h = hardware([0x8f, 8, 0], 0xff);
        h.borrow_mut().query[index] = value;
        let mut d = device(&h);
        assert_eq!(d.initialize().unwrap_err().kind, error);
        assert!(d.capabilities().is_none());
    }
    let h = hardware([0x8f, 8, 0], 0x17);
    h.borrow_mut().reject_power = true;
    let mut d = device(&h);
    assert_eq!(
        d.initialize().unwrap_err().kind,
        ErrorKind::PowerReadback {
            expected: 0xff,
            actual: 0x17
        }
    );
    assert!(!h.borrow().effects.iter().any(|(b, _, _)| b == &[0x2a]));
    let h = hardware([0x8f, 8, 0], 0xff);
    let mut d = device(&h);
    d.initialize().unwrap();
    h.borrow_mut().fail_irq = true;
    let count = h.borrow().effects.len();
    let error = d.poll().unwrap_err();
    assert_eq!(error.recovery, Recovery::MaskFailed);
    assert_eq!(
        error.kind,
        ErrorKind::Interrupt(InterruptError::Hardware(2))
    );
    assert_eq!(h.borrow().effects.len(), count);
}

#[test]
fn cyapa_late_suspend_stop_and_wake_power_effects_keep_original_fault_and_caps() {
    for target in [
        State::Sleeping,
        State::ButtonsOnly,
        State::PoweredDown,
        State::Stopped,
    ] {
        for offset in [2, 3] {
            let h = hardware([0x8f, 8, 0], 0xff);
            let mut d = device(&h);
            d.initialize().unwrap();
            let next = h.borrow().effects.len() + offset;
            h.borrow_mut().fail = Some(next);
            let result = match target {
                State::Sleeping => d.sleep(),
                State::ButtonsOnly => d.buttons_only(),
                State::PoweredDown => d.power_down(),
                _ => d.stop(),
            };
            assert_eq!(result.unwrap_err().kind, ErrorKind::Bus(failure()));
            assert_eq!(d.state(), State::Uncertain);
            assert_eq!(
                h.borrow().power,
                match target {
                    State::Sleeping => 0x17,
                    State::ButtonsOnly => 7,
                    _ => 3,
                }
            );
            assert_eq!(h.borrow().effects.len(), next);
            assert_eq!(d.capabilities().unwrap().firmware_version, (1, 2));
            assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NeedsReset);
            assert_eq!(h.borrow().effects.len(), next);
        }
    }
    for offset in 1..=5 {
        let h = hardware([0x8f, 8, 0], 0xff);
        let mut d = device(&h);
        d.initialize().unwrap();
        d.sleep().unwrap();
        let next = h.borrow().effects.len() + offset;
        h.borrow_mut().fail = Some(next);
        assert_eq!(d.wake().unwrap_err().kind, ErrorKind::Bus(failure()));
        assert_eq!(d.state(), State::Uncertain);
        assert_eq!(d.capabilities().unwrap().firmware_version, (1, 2));
        assert_eq!(h.borrow().effects.len(), next);
        if offset >= 3 {
            assert_eq!(h.borrow().power, 0xff);
        }
    }
}

#[test]
fn cyapa_i2c_complete_late_status_retains_actual_header_without_power_or_launch() {
    for raw in [[0x8f, 8, 0], [0, 0x11, 0]] {
        let h = hardware(raw, 0x17);
        h.borrow_mut().jump = Some((1, 4_000_000));
        let mut d = device(&h);
        assert_eq!(
            d.initialize().unwrap_err().kind,
            ErrorKind::Timeout(device::classify(raw))
        );
        assert_eq!(d.last_status(), Some(raw));
        assert_eq!(d.state(), State::Uncertain);
        assert_eq!(h.borrow().effects.len(), 1);
        assert_eq!(h.borrow().power, 0x17);
        assert!(d.capabilities().is_none());
    }
}
