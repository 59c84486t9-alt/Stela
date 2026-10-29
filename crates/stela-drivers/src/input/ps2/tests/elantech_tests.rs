//! Elantech sliced/custom commands, register effects and i8042 reports.
use super::*;
use alloc::collections::BTreeMap;
#[path = "elantech_tests/controls_tests.rs"]
mod controls_tests;
#[path = "elantech_tests/trackpoint_tests.rs"]
mod trackpoint_tests;
#[path = "elantech_tests/v3_tests.rs"]
mod v3_tests;
#[path = "elantech_tests/v4_tests.rs"]
mod v4_tests;
pub(super) struct Action {
    pub(super) reply: Vec<u8>,
    pub(super) late_ack: bool,
    pub(super) late_byte: Option<usize>,
}
pub(super) struct Peripheral {
    pub(super) queries: BTreeMap<u8, [u8; 3]>,
    pub(super) registers: BTreeMap<u8, u8>,
    pub(super) parameter_writes: Vec<(u8, [u8; 2])>,
    parameter_registers: BTreeMap<u8, [u8; 2]>,
    pub(super) writes: Vec<(u8, u8)>,
    pub(super) knock: [u8; 3],
    pub(super) readback: Option<[u8; 3]>,
    pub(super) omit: Option<(usize, usize)>,
    pub(super) late: Option<(usize, usize)>,
    pub(super) late_write: Option<u8>,
    pub(super) late_write_number: Option<usize>,
    pub(super) before_disable: Vec<u8>,
    pub(super) firmware_second: Option<[u8; 3]>,
    scale_count: u8,
    sliced: u8,
    quarters: u8,
    resolution_argument: bool,
    slices: Vec<u8>,
    custom_literal: bool,
    custom: Vec<u8>,
    info_count: usize,
    firmware_queries: u8,
}
impl Peripheral {
    pub(super) fn command(&mut self, byte: u8) -> Option<Action> {
        let mut action = Action {
            reply: Vec::new(),
            late_ack: false,
            late_byte: None,
        };
        if self.custom_literal {
            self.custom_literal = false;
            self.custom.push(byte);
            return Some(action);
        }
        if self.resolution_argument {
            self.resolution_argument = false;
            assert!(byte < 4);
            self.sliced = (self.sliced << 2) | byte;
            self.quarters += 1;
            if self.quarters == 4 {
                self.slices.push(self.sliced);
                self.quarters = 0;
            }
            return Some(action);
        }
        match byte {
            RESET | DEFAULTS => {
                self.registers.clear();
                self.parameter_registers.clear();
                self.scale_count = 0;
                self.slices.clear();
                self.custom.clear();
                self.custom_literal = false;
                self.resolution_argument = false;
                self.quarters = 0;
                self.info_count = 0;
                self.firmware_queries = 0;
                return None;
            }
            DISABLE_REPORTING | ENABLE_REPORTING => {
                self.scale_count = 0;
                self.quarters = 0;
                self.slices.clear();
                self.custom.clear();
                return None;
            }
            SET_RATE | GET_ID => {
                if byte == SET_RATE && self.queries.get(&1) == Some(&[0x38, 0x1f, 0x17]) {
                    self.registers.insert(7, 0);
                }
                return None;
            }
            SCALE_ONE_TO_ONE => {
                let command = if self.slices.len() == 3 {
                    Some(self.slices.clone())
                } else if self.custom.len() == 3 || self.custom.len() == 4 {
                    Some(self.custom.clone())
                } else {
                    None
                };
                if let Some(command) = command {
                    assert!(matches!(command[0], 0x11 | 0));
                    let value = if command.len() == 4 {
                        let parameters = [command[2], command[3]];
                        self.parameter_writes.push((command[1], parameters));
                        self.parameter_registers.insert(command[1], parameters);
                        command[3]
                    } else {
                        command[2]
                    };
                    self.registers.insert(command[1], value);
                    self.writes.push((command[1], value));
                    action.late_ack = self.late_write == Some(command[1])
                        && self
                            .late_write_number
                            .is_none_or(|number| number == self.writes.len());
                    self.slices.clear();
                    self.custom.clear();
                }
                self.scale_count += 1;
                self.sliced = 0;
                self.quarters = 0;
            }
            SET_RESOLUTION => {
                self.resolution_argument = true;
                self.scale_count = 0;
            }
            0xf8 => {
                self.custom_literal = true;
                self.scale_count = 0;
            }
            0xe9 => {
                self.info_count += 1;
                let register = if self.slices.len() == 2 && self.slices[0] == 0x10 {
                    Some(self.slices[1])
                } else if self.custom.len() == 2 && matches!(self.custom[0], 0x10 | 0) {
                    Some(self.custom[1])
                } else {
                    None
                };
                let bytes = if let Some(reg) = register {
                    self.readback.unwrap_or_else(|| {
                        if let Some(parameters) = self.parameter_registers.get(&reg)
                            && parameters[0] != 0
                        {
                            return [parameters[0], parameters[1], 0xfe];
                        }
                        let value = *self.registers.get(&reg).unwrap_or(&0);
                        if (self.queries[&1][0] & 15) >= 6 {
                            [0xa5, value, 0x5a]
                        } else {
                            [value, 0xa5, 0x5a]
                        }
                    })
                } else if self.slices.len() == 1 || self.custom.len() == 1 {
                    let id = if self.slices.len() == 1 {
                        self.slices[0]
                    } else {
                        self.custom[0]
                    };
                    if id == 1 {
                        self.firmware_queries += 1;
                    }
                    if id == 1
                        && self.firmware_queries == 2
                        && let Some(firmware) = self.firmware_second
                    {
                        firmware
                    } else {
                        *self
                            .queries
                            .get(&id)
                            .expect("actual vendor query supported")
                    }
                } else {
                    assert!(self.scale_count >= 3, "unexpected GETINFO state");
                    self.knock
                };
                let take = self
                    .omit
                    .filter(|(number, _)| *number == self.info_count)
                    .map_or(3, |(_, take)| take);
                action.reply.extend_from_slice(&bytes[..take]);
                action.late_byte = self
                    .late
                    .filter(|(number, _)| *number == self.info_count)
                    .map(|(_, index)| index);
                self.scale_count = 0;
                self.slices.clear();
                self.custom.clear();
            }
            _ => panic!("unknown actual Elantech byte{byte:02x}"),
        }
        Some(action)
    }
}
fn target(firmware: u32) -> (Controller<Model, Time>, Rc<RefCell<Hardware>>) {
    target_profile(firmware, false)
}
fn target_profile(
    firmware: u32,
    trackpoint: bool,
) -> (Controller<Model, Time>, Rc<RefCell<Hardware>>) {
    let (base, h) = controller(Config::default());
    h.borrow_mut().elantech = Some(Peripheral {
        queries: [
            (0, [0, 0, 0]),
            (
                1,
                [
                    (firmware >> 16) as u8,
                    (firmware >> 8) as u8,
                    firmware as u8,
                ],
            ),
            (2, [4, 18, 12]),
            (3, [0, 10, 20]),
        ]
        .into(),
        registers: BTreeMap::new(),
        parameter_writes: Vec::new(),
        parameter_registers: BTreeMap::new(),
        writes: Vec::new(),
        knock: [0x3c, 3, 0xc8],
        readback: None,
        omit: None,
        late: None,
        late_write: None,
        late_write_number: None,
        before_disable: Vec::new(),
        firmware_second: None,
        scale_count: 0,
        sliced: 0,
        quarters: 0,
        resolution_argument: false,
        slices: Vec::new(),
        custom_literal: false,
        custom: Vec::new(),
        info_count: 0,
        firmware_queries: 0,
    });
    let constructor = if trackpoint {
        Controller::new_elantech_trackpoint
    } else {
        Controller::new_elantech
    };
    let c = constructor(Model(h.clone()), Time(h.borrow().time.clone()), base.config).unwrap();
    (c, h)
}
#[test]
fn actual_elantech_identity_register_programming_and_readback_precede_reporting() {
    for firmware in [
        0x010000, 0x020022, 0x020600, 0x020030, 0x020800, 0x020b00, 0x020801, 0x040216, 0x040219,
        0x140900,
    ] {
        let (mut c, h) = target(firmware);
        c.initialize().unwrap();
        let cap = c.elantech_capabilities().unwrap();
        assert_eq!(cap.firmware, firmware);
        assert!(cap.mode_accepted);
        let v1 = firmware < 0x020030 || firmware == 0x020600;
        assert_eq!(cap.hardware, if v1 { 1 } else { 2 });
        let expected: Vec<_> = if v1 {
            vec![(0x10, 0x16), (0x11, 0x8f)]
        } else {
            vec![(0x10, 0x54), (0x11, 0x88), (0x21, 0x60)]
        };
        assert_eq!(h.borrow().elantech.as_ref().unwrap().writes, expected);
        assert!(cap.registers.iter().all(|r| r.acknowledged));
        assert_eq!(
            cap.registers[0].readback,
            Some([if v1 { 0x16 } else { 0x54 }, 0xa5, 0x5a])
        );
        assert!(h.borrow().scanning[1]);
        assert_eq!(c.mouse_protocol(), None);
        assert!(!c.has_wheel());
    }
}
fn v1_packet(firmware: u32, x: u16, y: u16, fingers: u8, buttons: u8) -> [u8; 4] {
    let old = firmware < 0x020000;
    let mut p = [
        8 | (buttons & 3),
        (((x >> 6) & 12) | ((y >> 8) & 3)) as u8,
        x as u8,
        y as u8,
    ];
    if old {
        p[0] |= ((buttons & 16) << 2) | ((buttons & 8) << 4);
        p[1] |= if fingers == 4 { 0xb0 } else { fingers << 4 };
    } else {
        p[0] |= fingers << 6;
    }
    let parity = |byte: u8| u8::from(byte.count_ones() & 1 == 0);
    p[0] |= parity(p[1]) << if old { 5 } else { 4 };
    p[0] |= parity(p[2]) << if old { 4 } else { 5 };
    p[0] |= parity(p[3]) << 2;
    p
}
fn v2_packet(
    pressure: bool,
    x: u16,
    y: u16,
    fingers: u8,
    buttons: u8,
    z: u8,
    width: u8,
) -> [u8; 6] {
    let mut p = [
        (fingers.min(3) << 6) | (buttons & 3),
        ((x >> 8) & 15) as u8,
        x as u8,
        0,
        ((y >> 8) & 15) as u8,
        y as u8,
    ];
    if pressure {
        p[0] |= 4 | ((width & 12) << 2);
        p[3] = 2 | ((width & 3) << 4);
        p[1] |= z & 0xf0;
        p[4] |= (z & 15) << 4;
    } else {
        p[0] |= 0x3c;
        p[3] = 0x38;
    }
    if fingers == 4 {
        p[3] |= 0x80;
    }
    p
}
fn v2_two(pressure: bool, x1: u16, y1: u16, x2: u16, y2: u16, buttons: u8) -> [u8; 6] {
    [
        0x80 | if pressure { 4 } else { 12 }
            | ((x1 >> 6) & 16) as u8
            | ((y1 >> 5) & 32) as u8
            | (buttons & 3),
        (x1 >> 2) as u8,
        (y1 >> 2) as u8,
        if pressure { 2 } else { 8 } | ((x2 >> 6) & 16) as u8 | ((y2 >> 5) & 32) as u8,
        (x2 >> 2) as u8,
        (y2 >> 2) as u8,
    ]
}
#[test]
fn real_v1_parity_rocker_and_startup_quirk_reports_retain_suppressed_packets() {
    let (mut c, h) = target(0x010000);
    c.initialize().unwrap();
    let raw = v1_packet(0x010000, 300, 200, 2, 17);
    emit(&h, Port::Mouse, &raw);
    let polled = c.poll_elantech().unwrap();
    assert_eq!(polled.frames[0].bytes(), raw);
    let elantech::Report::Contacts(contact) = polled.frames[0].report else {
        panic!()
    };
    assert_eq!(contact.fingers, 2);
    assert_eq!(contact.primary, Some((300, 152)));
    assert_eq!(contact.buttons, 17);
    assert_eq!(contact.pressure, None);
    assert!(polled.inputs.contains(&Input::MouseButtons(17)));
    assert!(c.stop().unwrap().contains(&Input::MouseButtons(0)));
    for firmware in [0x020022, 0x020600] {
        let (mut c, h) = target(firmware);
        c.initialize().unwrap();
        let raw = v1_packet(firmware, 300, 200, 1, 1);
        for _ in 0..3 {
            emit(&h, Port::Mouse, &raw);
        }
        let polled = c.poll_elantech().unwrap();
        assert_eq!(polled.frames.len(), 3);
        assert_eq!(polled.frames[0].report, elantech::Report::StartupSuppressed);
        assert_eq!(polled.frames[1].report, elantech::Report::StartupSuppressed);
        assert!(matches!(
            polled.frames[2].report,
            elantech::Report::Contacts(_)
        ));
        assert_eq!(
            polled
                .inputs
                .iter()
                .filter(|e| **e == Input::Buttons(1))
                .count(),
            1
        );
        emit(&h, Port::Mouse, &v1_packet(firmware, 300, 200, 2, 0));
        c.poll_elantech().unwrap();
        emit(&h, Port::Mouse, &raw);
        assert_eq!(
            c.poll_elantech().unwrap().frames[0].report,
            elantech::Report::StartupSuppressed
        );
    }
}
#[test]
fn real_v2_packets_preserve_two_coordinates_count_pressure_origin_and_debounce() {
    for firmware in [0x020030, 0x020800] {
        let pressure = firmware >= 0x020800;
        let (mut c, h) = target(firmware);
        c.initialize().unwrap();
        for fingers in [0, 1, 3, 4] {
            let raw = v2_packet(pressure, 500, 300, fingers, 1, 42, 9);
            emit(&h, Port::Mouse, &raw);
            let polled = c.poll_elantech().unwrap();
            let elantech::Report::Contacts(contact) = polled.frames[0].report else {
                panic!()
            };
            assert_eq!(contact.fingers, fingers);
            assert_eq!(
                contact.primary,
                if fingers == 0 { None } else { Some((500, 468)) }
            );
            assert_eq!(contact.secondary, None);
            assert_eq!(
                contact.pressure,
                if !pressure {
                    None
                } else if fingers == 0 {
                    Some(elantech::Pressure::SourceFallback {
                        pressure: 0,
                        width: 0,
                    })
                } else {
                    Some(elantech::Pressure::Observed {
                        pressure: 42,
                        width: 9,
                    })
                }
            );
        }
        emit(&h, Port::Mouse, &v2_two(pressure, 400, 500, 800, 100, 0));
        let polled = c.poll_elantech().unwrap();
        let elantech::Report::Contacts(contact) = polled.frames[0].report else {
            panic!()
        };
        assert_eq!(
            (contact.primary, contact.secondary),
            (Some((400, 268)), Some((800, 668)))
        );
        assert_eq!(
            contact.pressure,
            pressure.then_some(elantech::Pressure::SourceFallback {
                pressure: 127,
                width: 7
            })
        );
        emit(&h, Port::Mouse, &[0x84, 0xff, 0xff, 2, 0xff, 0xff]);
        let poll = c.poll_elantech().unwrap();
        assert!(poll.inputs.is_empty());
        assert_eq!(poll.frames[0].report, elantech::Report::Debounce);
    }
}
#[test]
fn every_initial_query_byte_is_required_and_late_actual_data_survives_failure() {
    for firmware in [0x010000, 0x020800] {
        let count = if firmware == 0x010000 { 5 } else { 6 };
        for number in 1..=count {
            for byte in 0..3 {
                for late in [false, true] {
                    let (mut c, h) = target(firmware);
                    {
                        let mut hw = h.borrow_mut();
                        let e = hw.elantech.as_mut().unwrap();
                        if late {
                            e.late = Some((number, byte));
                        } else {
                            e.omit = Some((number, byte));
                        }
                    }
                    assert!(matches!(
                        c.initialize().unwrap_err().kind,
                        ErrorKind::Timeout(Phase::Response)
                    ));
                    assert!(c.needs_reset());
                    assert!(!h.borrow().scanning[1]);
                    let progress = c.elantech_query_progress().unwrap();
                    assert_eq!(
                        usize::from(progress.received),
                        if late { byte + 1 } else { byte }
                    );
                    if number == count {
                        assert!(matches!(progress.kind, elantech::QueryKind::Register(0x10)));
                        assert!(
                            c.elantech_capabilities()
                                .unwrap()
                                .registers
                                .iter()
                                .all(|r| r.acknowledged)
                        );
                        assert_eq!(
                            c.elantech_capabilities().unwrap().registers[0].readback,
                            None
                        );
                    }
                    let writes = h.borrow().writes.len();
                    assert_eq!(c.initialize().unwrap_err().kind, ErrorKind::NeedsReset);
                    assert_eq!(h.borrow().writes.len(), writes);
                }
            }
        }
    }
}
#[test]
fn late_register_ack_keeps_effects_and_source_readback_admission_remains_versioned() {
    for firmware in [0x010000, 0x020800] {
        for register in if firmware == 0x010000 {
            vec![0x10, 0x11]
        } else {
            vec![0x10, 0x11, 0x21]
        } {
            let (mut c, h) = target(firmware);
            h.borrow_mut().elantech.as_mut().unwrap().late_write = Some(register);
            assert_eq!(
                c.initialize().unwrap_err().kind,
                ErrorKind::Timeout(Phase::Response)
            );
            let cap = c.elantech_capabilities().unwrap();
            let last = *cap.registers.last().unwrap();
            assert_eq!(last.address, register);
            assert!(!last.acknowledged);
            assert!(!cap.mode_accepted);
            assert_eq!(
                h.borrow()
                    .elantech
                    .as_ref()
                    .unwrap()
                    .registers
                    .get(&register),
                Some(&last.requested)
            );
            let writes = h.borrow().writes.len();
            assert_eq!(c.initialize().unwrap_err().kind, ErrorKind::NeedsReset);
            assert_eq!(h.borrow().writes.len(), writes);
        }
        let (mut c, h) = target(firmware);
        h.borrow_mut().elantech.as_mut().unwrap().readback = Some([0, 0xfa, 0xfe]);
        if firmware == 0x010000 {
            assert!(matches!(
                c.initialize().unwrap_err().kind,
                ErrorKind::Elantech(elantech::Error::Readback { observed: 0, .. })
            ));
        } else {
            c.initialize().unwrap();
        }
        assert_eq!(
            c.elantech_capabilities().unwrap().registers[0].readback,
            Some([0, 0xfa, 0xfe])
        );
        assert_eq!(
            c.elantech_capabilities().unwrap().mode_accepted,
            firmware != 0x010000
        );
    }
}
#[test]
#[ignore = "oracle: STELA_ELANTECH_REJECTED_ORACLE"]
fn unchanged_linux_known_rejection_service_budget_and_delay_match_actual_native_retry() {
    extern crate std;
    let records =
        std::fs::read_to_string(std::env::var("STELA_ELANTECH_REJECTED_ORACLE").unwrap()).unwrap();
    let mut cases = 0;
    for line in records.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 4);
        let number = |i: usize| fields[i].parse::<i32>().unwrap();
        let (mut c, h) = target(0x020800);
        c.initialize().unwrap();
        let first = h.borrow().writes.len();
        h.borrow_mut().resend = Some((Port::Mouse, 0xf8, number(0) as usize * 2));
        let start = h.borrow().time.get();
        let result = c.read_elantech_register(7);
        assert_eq!(result.is_ok(), number(3) == 0);
        assert_eq!(
            h.borrow().time.get().wrapping_sub(start) / 1000,
            number(2) as u64
        );
        let mut routed = false;
        let mut f8 = 0;
        for (command, byte) in &h.borrow().writes[first..] {
            if *command {
                routed = *byte == SEND_MOUSE;
            } else if routed {
                if *byte == 0xf8 {
                    f8 += 1;
                }
                routed = false;
            }
        }
        assert_eq!(
            f8,
            if result.is_ok() {
                (number(1) - 1) * 2 + 2
            } else {
                number(1) * 2
            }
        );
        cases += 1;
    }
    assert_eq!(cases, 5);
}

#[test]
#[ignore = "oracle: STELA_ELANTECH_CONTROLS_ORACLE"]
fn unchanged_linux_elantech_configuration_matches_actual_i8042_transactions() {
    extern crate std;
    let records =
        std::fs::read_to_string(std::env::var("STELA_ELANTECH_CONTROLS_ORACLE").unwrap()).unwrap();
    compare_control_records(&records, 448);
}
fn compare_control_records(records: &str, expected: usize) {
    let hex = |value: &str| -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    };
    let mut cases = 0;
    for line in records.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 16);
        let number = |i: usize| fields[i].parse::<i32>().unwrap();
        let (mut c, h) = target(number(0) as u32);
        {
            let mut hw = h.borrow_mut();
            let e = hw.elantech.as_mut().unwrap();
            for (index, id) in [(1, 2), (2, 3), (3, 0)] {
                e.queries.insert(id, hex(fields[index]).try_into().unwrap());
            }
            e.knock[2] = number(4) as u8;
            e.readback = Some([number(5) as u8, 0xfa, 0xfe]);
        }
        let result = c.initialize();
        assert_eq!(result.is_ok(), number(6) == 0, "source record {line}");
        let cap = c.elantech_capabilities().unwrap();
        assert_eq!(cap.hardware, i32::try_into(number(7)).unwrap());
        assert_eq!(cap.bounds.minimum, (number(8) as u16, number(9) as u16));
        assert_eq!(cap.bounds.maximum, (number(10) as u16, number(11) as u16));
        assert_eq!(cap.reports_pressure, number(12) != 0);
        assert_eq!(cap.jumpy_cursor, number(13) != 0);
        assert_eq!(cap.mode_accepted, number(6) == 0);
        assert_eq!(
            cap.registers[0].readback,
            Some([number(5) as u8, 0xfa, 0xfe])
        );
        if let Err(error) = result {
            assert!(matches!(
                error.kind,
                ErrorKind::Elantech(elantech::Error::Readback { .. })
            ));
        } else {
            assert_eq!(
                c.read_elantech_register(7).unwrap(),
                [number(14) as u8, 0xfa, 0xfe]
            );
        }
        let mut routed = false;
        let mut mouse_wire = Vec::new();
        for (command, byte) in &h.borrow().writes {
            if *command {
                routed = *byte == SEND_MOUSE;
            } else if routed {
                mouse_wire.push(*byte);
                routed = false;
            }
        }
        assert_eq!(
            &mouse_wire[..4],
            &[DISABLE_REPORTING, RESET, DEFAULTS, DISABLE_REPORTING]
        );
        assert_eq!(&mouse_wire[4..], hex(fields[15]), "source record {line}");
        cases += 1;
    }
    assert_eq!(cases, expected);
}

#[test]
#[ignore = "oracle: STELA_ELANTECH_REPORTS_ORACLE"]
fn unchanged_linux_elantech_reports_match_actual_configured_i8042_device() {
    extern crate std;
    let records =
        std::fs::read_to_string(std::env::var("STELA_ELANTECH_REPORTS_ORACLE").unwrap()).unwrap();
    let mut group = None;
    let mut device = None;
    let (mut touch, mut tools, mut buttons) = (0, 0, 0);
    let mut primary = (0, 0);
    let mut slot_mask = 0;
    let mut slots = [(0, 0); 2];
    let mut pressure = (-1, -1);
    let mut cases = 0;
    for line in records.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 18);
        let number = |i: usize| fields[i].parse::<i32>().unwrap();
        if group != Some(number(0)) {
            let (mut c, h) = target(number(1) as u32);
            {
                let mut hw = h.borrow_mut();
                let q = &mut hw.elantech.as_mut().unwrap().queries;
                if number(2) != 0 {
                    q.get_mut(&0).unwrap()[1] |= 0x10;
                }
                if number(3) == 0 {
                    q.get_mut(&2).unwrap()[0] &= !4;
                }
            }
            c.initialize().unwrap();
            device = Some((c, h));
            group = Some(number(0));
            touch = 0;
            tools = 0;
            buttons = 0;
            primary = (0, 0);
            slot_mask = 0;
            slots = [(0, 0); 2];
            pressure = (-1, -1);
        }
        let (c, h) = device.as_mut().unwrap();
        let raw: Vec<_> = fields[4]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        emit(h, Port::Mouse, &raw);
        let polled = c.poll_elantech().unwrap();
        assert_eq!(polled.frames.len(), 1);
        let frame = polled.frames[0];
        assert_eq!(frame.bytes(), raw);
        let hardware = c.elantech_capabilities().unwrap().hardware;
        match frame.report {
            elantech::Report::Multitouch(_) => panic!("v1/v2 has no v4 report"),
            elantech::Report::Trackpoint(_) => panic!("ordinary profile has no trackpoint"),
            elantech::Report::Head { .. } => panic!("v1/v2 has no head record"),
            elantech::Report::Debounce => {
                assert_eq!(fields[5], "B");
                assert!(polled.inputs.is_empty());
            }
            elantech::Report::StartupSuppressed => {
                assert_eq!(fields[5], "S");
                assert!(polled.inputs.is_empty());
            }
            elantech::Report::Contacts(contact) => {
                assert_eq!(fields[5], "F");
                touch = i32::from(contact.fingers != 0);
                tools = if contact.fingers == 0 || (hardware == 1 && contact.fingers == 4) {
                    0
                } else {
                    1 << (contact.fingers - 1)
                };
                buttons = i32::from(contact.buttons);
                if let Some(point) = contact.primary {
                    primary = point;
                }
                if hardware == 2 {
                    slot_mask = if contact.fingers != 0 { 1 } else { 0 }
                        | if contact.fingers >= 2 { 2 } else { 0 };
                    if let Some(point) = contact.primary {
                        slots[0] = point;
                    }
                    // Original semi-MT software publishes zero for an unencoded
                    // secondary point in3/4-finger reports. Native keeps None;
                    // this projection does not invent a hardware coordinate.
                    if contact.fingers >= 2 {
                        slots[1] = contact.secondary.unwrap_or((0, 0));
                    }
                }
                if let Some(observed) = contact.pressure {
                    assert_eq!(
                        matches!(observed, elantech::Pressure::SourceFallback { .. }),
                        matches!(contact.fingers, 0 | 2)
                    );
                    pressure = match observed {
                        elantech::Pressure::Observed { pressure, width }
                        | elantech::Pressure::SourceFallback { pressure, width } => {
                            (i32::from(pressure), i32::from(width))
                        }
                    };
                }
            }
        }
        assert_eq!(
            (touch, tools, buttons),
            (number(6), number(7), number(8)),
            "source record {line}"
        );
        assert_eq!(primary, (number(9), number(10)), "source record {line}");
        assert_eq!(
            (slot_mask, slots[0], slots[1]),
            (
                number(11),
                (number(12), number(13)),
                (number(14), number(15))
            ),
            "source record {line}"
        );
        assert_eq!(pressure, (number(16), number(17)), "source record {line}");
        cases += 1;
    }
    assert_eq!(cases, 8192);
}
#[test]
fn source_v2_admits_every_successful_register_read_without_fabricating_echo_confirmation() {
    for firmware in [0x010000, 0x020800] {
        for value in 0..=255 {
            let (mut c, h) = target(firmware);
            h.borrow_mut().elantech.as_mut().unwrap().readback = Some([value, 0xfa, 0xfe]);
            let accepted = firmware == 0x020800 || value & 4 != 0;
            let result = c.initialize();
            assert_eq!(
                result.is_ok(),
                accepted,
                "firmware{firmware:06x} readback{value:02x}"
            );
            let cap = c.elantech_capabilities().unwrap();
            assert_eq!(cap.registers[0].readback, Some([value, 0xfa, 0xfe]));
            assert_eq!(cap.mode_accepted, accepted);
            assert_eq!(
                cap.registers[0].requested,
                if firmware == 0x010000 { 0x16 } else { 0x54 }
            );
            assert!(cap.registers[0].acknowledged);
        }
    }
    for firmware in [0x010000, 0x020800] {
        let (mut c, h) = target(firmware);
        c.initialize().unwrap();
        h.borrow_mut().elantech.as_mut().unwrap().readback = Some([0, 0xfa, 0xfe]);
        for address in if firmware == 0x010000 {
            vec![0x10, 0x11]
        } else {
            vec![0x10, 0x11, 0x21]
        } {
            assert_eq!(c.read_elantech_register(address).unwrap(), [0, 0xfa, 0xfe]);
            assert_eq!(
                c.elantech_capabilities()
                    .unwrap()
                    .registers
                    .iter()
                    .find(|r| r.address == address)
                    .unwrap()
                    .readback,
                Some([0, 0xfa, 0xfe])
            );
            assert!(c.is_ready());
            assert!(c.elantech_capabilities().unwrap().mode_accepted);
        }
    }
}
#[test]
fn failed_profiles_and_changed_observed_identity_never_arm_register_programming() {
    for (firmware, kind) in [(0, 0), (0x030001, 1), (0x100f01, 1)] {
        let (mut c, h) = target(firmware);
        let error = c.initialize().unwrap_err();
        assert!(match kind {
            0 => matches!(
                error.kind,
                ErrorKind::Elantech(elantech::Error::Signature(0))
            ),
            _ => matches!(error.kind, ErrorKind::Elantech(elantech::Error::Version(_))),
        });
        assert!(h.borrow().elantech.as_ref().unwrap().writes.is_empty());
    }
    let (mut c, h) = target(0x020800);
    h.borrow_mut()
        .elantech
        .as_mut()
        .unwrap()
        .queries
        .get_mut(&2)
        .unwrap()[0] |= 0x80;
    assert_eq!(
        c.initialize().unwrap_err().kind,
        ErrorKind::Elantech(elantech::Error::Trackpoint)
    );
    assert!(h.borrow().elantech.as_ref().unwrap().writes.is_empty());
    let (mut c, h) = target(0x020800);
    c.initialize().unwrap();
    c.stop().unwrap();
    let count = h.borrow().elantech.as_ref().unwrap().writes.len();
    h.borrow_mut()
        .elantech
        .as_mut()
        .unwrap()
        .queries
        .get_mut(&2)
        .unwrap()[1] += 1;
    assert_eq!(
        c.initialize().unwrap_err().kind,
        ErrorKind::Elantech(elantech::Error::IdentityChanged)
    );
    assert_eq!(h.borrow().elantech.as_ref().unwrap().writes.len(), count);
}
#[test]
fn bad_packet_and_idle_prefix_keep_fault_bytes_even_after_explicit_input_release() {
    for firmware in [0x010000, 0x020800] {
        let (mut c, h) = target(firmware);
        c.initialize().unwrap();
        let mut raw = if firmware == 0x010000 {
            v1_packet(firmware, 300, 200, 1, 1).to_vec()
        } else {
            v2_packet(true, 500, 300, 1, 1, 42, 9).to_vec()
        };
        raw[0] ^= if firmware == 0x010000 { 0x10 } else { 4 };
        emit(&h, Port::Mouse, &raw);
        assert_eq!(
            c.poll().unwrap_err().kind,
            ErrorKind::Elantech(elantech::Error::Packet)
        );
        assert_eq!(c.elantech_fragment().unwrap(), raw);
        c.release_inputs();
        assert_eq!(c.elantech_fragment().unwrap(), raw);
        let (mut c, h) = target(firmware);
        c.initialize().unwrap();
        let raw = if firmware == 0x010000 {
            v1_packet(firmware, 300, 200, 1, 0).to_vec()
        } else {
            v2_packet(true, 500, 300, 1, 0, 42, 9).to_vec()
        };
        emit(&h, Port::Mouse, &raw[..2]);
        c.poll().unwrap();
        h.borrow().time.set(h.borrow().time.get() + 501);
        assert_eq!(
            c.poll().unwrap_err().kind,
            ErrorKind::PacketTimeout(Port::Mouse)
        );
        c.release_inputs();
        assert_eq!(c.elantech_fragment().unwrap(), &raw[..2]);
    }
}
#[test]
fn real_register_reads_quiesce_preserve_full_values_and_apply_bounded_query_backpressure() {
    for firmware in [0x010000, 0x020800] {
        let (mut c, h) = target(firmware);
        c.initialize().unwrap();
        let raw = if firmware == 0x010000 {
            v1_packet(firmware, 0x1fa, 0xfe, 2, 1).to_vec()
        } else {
            v2_packet(true, 0xfa, 0xfe, 1, 1, 0xfe, 9).to_vec()
        };
        h.borrow_mut().elantech.as_mut().unwrap().before_disable = raw.clone();
        assert_eq!(
            c.read_elantech_register(0x10).unwrap(),
            [if firmware == 0x010000 { 0x16 } else { 0x54 }, 0xa5, 0x5a]
        );
        assert_eq!(c.drain_elantech_frames()[0].bytes(), raw);
        assert!(h.borrow().scanning[1]);
        for invalid in [0, 6, 0x12, 0x1f, 0x27, 0xff] {
            let writes = h.borrow().writes.len();
            assert_eq!(
                c.read_elantech_register(invalid).unwrap_err().kind,
                ErrorKind::Elantech(elantech::Error::Register(invalid))
            );
            assert_eq!(h.borrow().writes.len(), writes);
        }
        while c.elantech_queries().unwrap().len() < 32 {
            c.read_elantech_register(0x07).unwrap();
        }
        let writes = h.borrow().writes.len();
        assert_eq!(
            c.read_elantech_register(0x07).unwrap_err().kind,
            ErrorKind::QueueFull
        );
        assert_eq!(h.borrow().writes.len(), writes);
        assert!(c.is_ready());
        assert_eq!(c.drain_elantech_queries().len(), 32);
        c.read_elantech_register(0x07).unwrap();
    }
}
#[test]
fn source_v2_retries_only_explicit_rejection_with_original_service_budget_and_delay() {
    for rejections in [0, 1, 2, 3, 4, 5, 6, 8] {
        let (mut c, h) = target(0x020800);
        h.borrow_mut().resend = Some((Port::Mouse, 0xf8, rejections));
        let start = h.borrow().time.get();
        let result = c.initialize();
        let elapsed = h.borrow().time.get().wrapping_sub(start);
        let failed_services = (rejections / 2).min(3);
        assert!(elapsed >= failed_services as u64 * 500_000);
        assert!(elapsed < (failed_services as u64 + 1) * 500_000);
        if rejections < 6 {
            result.unwrap();
            assert!(c.is_ready());
            assert_eq!(
                h.borrow().elantech.as_ref().unwrap().writes,
                [(0x10, 0x54), (0x11, 0x88), (0x21, 0x60)]
            );
        } else {
            assert_eq!(
                result.unwrap_err().kind,
                ErrorKind::ResendLimit {
                    port: Port::Mouse,
                    byte: 0xf8
                }
            );
            assert!(h.borrow().elantech.as_ref().unwrap().writes.is_empty());
            assert!(c.needs_reset());
        }
    }
    let (mut c, h) = target(0x020800);
    h.borrow_mut().no_ack = Some((Port::Mouse, 0xf8));
    let start = h.borrow().time.get();
    assert_eq!(
        c.initialize().unwrap_err().kind,
        ErrorKind::Timeout(Phase::Response)
    );
    assert!(h.borrow().time.get().wrapping_sub(start) < 500_000);
    assert!(
        h.borrow().elantech.as_ref().unwrap().custom_literal,
        "the unacknowledged byte really reached the device, so replay would reinterpret it"
    );
    let writes = h.borrow().writes.len();
    assert_eq!(c.initialize().unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(h.borrow().writes.len(), writes);
}
#[test]
fn known_rejection_retry_delay_retains_sibling_input_and_v1_keeps_its_source_budget() {
    let (mut c, h) = target(0x020800);
    c.initialize().unwrap();
    {
        let mut hw = h.borrow_mut();
        hw.resend = Some((Port::Mouse, 0xf8, 2));
        hw.resend_inject = vec![(Port::Keyboard, 0x1c)];
    }
    let start = h.borrow().time.get();
    assert_eq!(c.read_elantech_register(7).unwrap(), [0, 0xa5, 0x5a]);
    assert!(h.borrow().time.get().wrapping_sub(start) >= 500_000);
    assert!(c.drain_events().contains(&Input::Key {
        usage: 4,
        pressed: true
    }));
    assert!(c.is_ready());
    let (mut c, h) = target(0x010000);
    c.initialize().unwrap();
    h.borrow_mut().resend = Some((Port::Mouse, SET_RESOLUTION, 2));
    let start = h.borrow().time.get();
    assert_eq!(
        c.read_elantech_register(7).unwrap_err().kind,
        ErrorKind::ResendLimit {
            port: Port::Mouse,
            byte: SET_RESOLUTION
        }
    );
    assert!(h.borrow().time.get().wrapping_sub(start) < 500_000);
}

#[test]
fn runtime_register_reply_and_resume_failures_retain_data_without_rearming() {
    for firmware in [0x010000, 0x020800] {
        for byte in 0..3 {
            let (mut c, h) = target(firmware);
            c.initialize().unwrap();
            let number = h.borrow().elantech.as_ref().unwrap().info_count + 1;
            h.borrow_mut().elantech.as_mut().unwrap().late = Some((number, byte));
            assert_eq!(
                c.read_elantech_register(0x07).unwrap_err().kind,
                ErrorKind::Timeout(Phase::Response)
            );
            assert_eq!(
                usize::from(c.elantech_query_progress().unwrap().received),
                byte + 1
            );
            assert!(c.needs_reset());
        }
    }
    let (mut c, h) = target(0x020800);
    c.initialize().unwrap();
    h.borrow_mut().no_ack = Some((Port::Mouse, ENABLE_REPORTING));
    assert_eq!(
        c.read_elantech_register(0x07).unwrap_err().kind,
        ErrorKind::Timeout(Phase::Response)
    );
    assert_eq!(c.elantech_query_progress().unwrap().bytes, [0, 0xa5, 0x5a]);
    assert_eq!(c.elantech_query_progress().unwrap().received, 3);
    assert!(h.borrow().scanning[1]);
}
