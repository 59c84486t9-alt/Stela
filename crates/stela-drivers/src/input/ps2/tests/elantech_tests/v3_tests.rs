use super::*;

fn configured(firmware: u32) -> (Controller<Model, Time>, Rc<RefCell<Hardware>>) {
    let (mut c, h) = target(firmware);
    h.borrow_mut()
        .elantech
        .as_mut()
        .unwrap()
        .queries
        .insert(0, [0x35, 0x78, 0x84]);
    c.initialize().unwrap();
    (c, h)
}
fn packet(crc: bool, head: bool, fingers: u8, x: u16, y: u16, buttons: u8) -> [u8; 6] {
    [
        (fingers << 6) | buttons | if head { 4 } else { 12 },
        0xa0 | ((x >> 8) as u8 & 15),
        x as u8,
        if crc {
            if head { 8 } else { 9 }
        } else if head {
            2
        } else {
            12
        },
        0x50 | ((y >> 8) as u8 & 15),
        y as u8,
    ]
}
#[test]
fn v3_actual_fast_queries_rw_mode_and_every_readback_byte_are_source_admitted() {
    for firmware in [0x050001, 0x051001, 0x054001, 0x055001] {
        for byte in 0..=255 {
            let (mut c, h) = target(firmware);
            {
                let mut hw = h.borrow_mut();
                let e = hw.elantech.as_mut().unwrap();
                e.queries.insert(0, [0x35, 0x78, 0x84]);
                e.readback = Some([byte, 0xfa, 0xfe]);
            }
            c.initialize().unwrap();
            let cap = c.elantech_capabilities().unwrap();
            assert_eq!(cap.hardware, 3);
            assert!(cap.mode_accepted);
            assert_eq!(cap.bounds.maximum, (1400, 900));
            assert_eq!(
                cap.registers,
                vec![elantech::RegisterWrite {
                    address: 0x10,
                    requested: 11,
                    acknowledged: true,
                    readback: Some([byte, 0xfa, 0xfe])
                }]
            );
            assert_eq!(cap.crc_enabled, firmware & 0x4000 != 0);
            assert_eq!(cap.buttonpad, firmware & 0x1000 != 0);
            assert_eq!(c.read_elantech_register(0x10).unwrap(), [byte, 0xfa, 0xfe]);
        }
    }
}
#[test]
fn v3_head_tail_and_early_tail_keep_actual_head_provenance_and_clickpad_effects() {
    for firmware in [0x050001, 0x051001, 0x054001, 0x055001] {
        let (mut c, h) = configured(firmware);
        let crc = firmware & 0x4000 != 0;
        emit(&h, Port::Mouse, &packet(crc, false, 2, 500, 300, 2));
        let polled = c.poll_elantech().unwrap();
        let elantech::Report::Contacts(contact) = polled.frames[0].report else {
            panic!()
        };
        assert_eq!(contact.primary, None);
        assert_eq!(contact.secondary, Some((500, 600)));
        assert_eq!(contact.head_sequence, None);
        assert!(polled.inputs.contains(&Input::Move { x: 0, y: 0 }));
        assert_eq!(contact.buttons, if firmware & 0x1000 != 0 { 1 } else { 2 });
        emit(&h, Port::Mouse, &packet(crc, true, 2, 200, 100, 1));
        let head = c.poll_elantech().unwrap();
        assert!(head.inputs.is_empty());
        assert_eq!(
            head.frames[0].report,
            elantech::Report::Head { point: (200, 800) }
        );
        // Source caches the actual head even across an intervening single report.
        emit(&h, Port::Mouse, &packet(crc, true, 1, 700, 800, 0));
        c.poll_elantech().unwrap();
        emit(&h, Port::Mouse, &packet(crc, false, 2, 900, 700, 3));
        let tail = c.poll_elantech().unwrap();
        let elantech::Report::Contacts(contact) = tail.frames[0].report else {
            panic!()
        };
        assert_eq!(contact.primary, Some((200, 800)));
        assert_eq!(contact.secondary, Some((900, 200)));
        assert_eq!(contact.head_sequence, Some(head.frames[0].native_sequence));
        assert_eq!(
            contact.pressure,
            Some(elantech::Pressure::Observed {
                pressure: 0xa5,
                width: 0
            })
        );
    }
}

#[test]
fn v3_late_rw_mode_ack_retains_actual_effect_without_readback_reporting_or_replay() {
    let (mut c, h) = target(0x050001);
    {
        let mut hw = h.borrow_mut();
        let e = hw.elantech.as_mut().unwrap();
        e.queries.insert(0, [0x35, 0x78, 0x84]);
        e.late_write = Some(0x10);
    }
    let error = c.initialize().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::Response));
    assert_eq!(error.response.unwrap().data, ACK);
    assert_eq!(h.borrow().elantech.as_ref().unwrap().writes, [(0x10, 0x0b)]);
    let cap = c.elantech_capabilities().unwrap();
    assert!(!cap.mode_accepted);
    assert!(!cap.registers[0].acknowledged);
    assert_eq!(cap.registers[0].readback, None);
    let writes = h.borrow().writes.len();
    c.poll().unwrap_err();
    assert_eq!(h.borrow().writes.len(), writes);
}

#[test]
fn v3_raw_head_backpressure_refuses_live_reads_without_losing_hardware_bytes() {
    let (mut c, h) = configured(0x050001);
    let raw = packet(false, true, 2, 100, 200, 0);
    for _ in 0..40 {
        emit(&h, Port::Mouse, &raw);
    }
    for _ in 0..4 {
        c.poll().unwrap();
    }
    let consumed = h.borrow().consumed;
    let writes = h.borrow().writes.len();
    assert_eq!(
        c.read_elantech_register(0x10).unwrap_err().kind,
        ErrorKind::QueueFull
    );
    assert_eq!(h.borrow().consumed, consumed);
    assert_eq!(h.borrow().writes.len(), writes);
    let frames = c.drain_elantech_frames();
    assert_eq!(frames.len(), 32);
    assert!(
        frames
            .iter()
            .all(|frame| matches!(frame.report, elantech::Report::Head { .. }))
    );
    let more = c.poll_elantech().unwrap();
    assert_eq!(more.frames.len(), 8);
    assert_eq!(more.frames[0].native_sequence, 32);
    assert!(c.is_ready());
}
#[test]
fn v3_broken_samples_and_all_late_or_missing_query_bytes_never_arm_reporting_or_replay() {
    let (mut c, h) = target(0x050001);
    h.borrow_mut()
        .elantech
        .as_mut()
        .unwrap()
        .queries
        .get_mut(&3)
        .unwrap()[1] = 0x74;
    assert_eq!(
        c.initialize().unwrap_err().kind,
        ErrorKind::Elantech(elantech::Error::BrokenAbsolute)
    );
    assert!(h.borrow().elantech.as_ref().unwrap().writes.is_empty());
    for query in 1..=7 {
        for byte in 0..3 {
            for late in [false, true] {
                let (mut c, h) = target(0x050001);
                {
                    let mut hw = h.borrow_mut();
                    let e = hw.elantech.as_mut().unwrap();
                    e.queries.insert(0, [0x35, 0x78, 0x84]);
                    if late {
                        e.late = Some((query, byte));
                    } else {
                        e.omit = Some((query, byte));
                    }
                }
                c.initialize().unwrap_err();
                assert!(c.needs_reset());
                assert!(!c.is_ready());
                assert_eq!(
                    c.elantech_query_progress().unwrap().received,
                    byte as u8 + u8::from(late)
                );
                let count = h.borrow().writes.len();
                c.poll().unwrap_err();
                assert_eq!(h.borrow().writes.len(), count);
                assert!(!h.borrow().scanning[1]);
            }
        }
    }
}
#[test]
fn v3_debounce_invalid_signatures_stop_and_requery_retain_source_cached_head_provenance() {
    for firmware in [0x050001, 0x054001] {
        let (mut c, h) = configured(firmware);
        let crc = firmware & 0x4000 != 0;
        emit(&h, Port::Mouse, &[0xc4, 0xff, 0xff, 2, 0xff, 0xff]);
        assert_eq!(
            c.poll_elantech().unwrap().frames[0].report,
            elantech::Report::Debounce
        );
        emit(&h, Port::Mouse, &packet(crc, true, 2, 100, 200, 3));
        let head = c.poll_elantech().unwrap();
        c.stop().unwrap();
        c.initialize().unwrap();
        emit(&h, Port::Mouse, &packet(crc, false, 2, 500, 600, 0));
        let elantech::Report::Contacts(contact) = c.poll_elantech().unwrap().frames[0].report
        else {
            panic!()
        };
        assert_eq!(contact.primary, Some((100, 700)));
        assert_eq!(contact.head_sequence, Some(head.frames[0].native_sequence));
        let mut raw = packet(crc, true, 1, 400, 300, 0);
        raw[3] ^= if crc { 8 } else { 2 };
        emit(&h, Port::Mouse, &raw);
        assert_eq!(
            c.poll().unwrap_err().kind,
            ErrorKind::Elantech(elantech::Error::Packet)
        );
        c.release_inputs();
        assert_eq!(c.elantech_fragment(), Some(raw.as_slice()));
    }
}

#[test]
#[ignore = "requires STELA_ELANTECH_V3_CONTROLS_ORACLE from complete pinned configuration bodies"]
fn unchanged_linux_v3_configuration_matches_actual_fast_query_and_register_transactions() {
    extern crate std;
    let records =
        std::fs::read_to_string(std::env::var("STELA_ELANTECH_V3_CONTROLS_ORACLE").unwrap())
            .unwrap();
    compare_control_records(&records, 128);
}

#[test]
#[ignore = "requires STELA_ELANTECH_V3_REPORTS_ORACLE from complete pinned sequential report bodies"]
fn unchanged_linux_v3_head_tail_reports_match_actual_configured_i8042_device() {
    extern crate std;
    let records =
        std::fs::read_to_string(std::env::var("STELA_ELANTECH_V3_REPORTS_ORACLE").unwrap())
            .unwrap();
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
        assert_eq!(fields.len(), 16);
        let number = |i: usize| fields[i].parse::<i32>().unwrap();
        if group != Some(number(0)) {
            device = Some(configured(number(1) as u32));
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
        let raw: Vec<_> = fields[2]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        emit(h, Port::Mouse, &raw);
        let polled = c.poll_elantech().unwrap();
        assert_eq!(polled.frames.len(), 1);
        assert_eq!(polled.frames[0].bytes(), raw);
        match polled.frames[0].report {
            elantech::Report::Debounce => {
                assert_eq!(fields[3], "B");
                assert!(polled.inputs.is_empty());
            }
            elantech::Report::Head { .. } => {
                assert_eq!(fields[3], "H");
                assert!(polled.inputs.is_empty());
            }
            elantech::Report::StartupSuppressed => {
                panic!("v3 does not select source jumpy workaround")
            }
            elantech::Report::Contacts(contact) => {
                assert_eq!(fields[3], "F");
                touch = i32::from(contact.fingers != 0);
                tools = if contact.fingers == 0 {
                    0
                } else {
                    1 << (contact.fingers - 1)
                };
                buttons = i32::from(contact.buttons);
                let projected_primary = contact
                    .primary
                    .or_else(|| (contact.fingers == 2).then_some((0, 0)));
                if let Some(point) = projected_primary {
                    primary = point;
                }
                slot_mask =
                    u8::from(contact.fingers != 0) | if contact.fingers >= 2 { 2 } else { 0 };
                if let Some(point) = projected_primary {
                    slots[0] = point;
                }
                if contact.fingers >= 2 {
                    slots[1] = contact.secondary.unwrap_or((0, 0));
                }
                let Some(elantech::Pressure::Observed {
                    pressure: z,
                    width: w,
                }) = contact.pressure
                else {
                    panic!()
                };
                pressure = (i32::from(z), i32::from(w));
            }
        }
        assert_eq!(
            (touch, tools, buttons),
            (number(4), number(5), number(6)),
            "source record {line}"
        );
        assert_eq!(primary, (number(7), number(8)), "source record {line}");
        assert_eq!(
            (i32::from(slot_mask), slots[0], slots[1]),
            (
                number(9),
                (number(10), number(11)),
                (number(12), number(13))
            ),
            "source record {line}"
        );
        assert_eq!(pressure, (number(14), number(15)), "source record {line}");
        cases += 1;
    }
    assert_eq!(cases, 8192);
}
