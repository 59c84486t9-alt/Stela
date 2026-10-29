use super::*;

fn target_point(firmware: u32, product: u8) -> (Controller<Model, Time>, Rc<RefCell<Hardware>>) {
    let (c, h) = target_profile(firmware, true);
    {
        let mut hw = h.borrow_mut();
        let e = hw.elantech.as_mut().unwrap();
        e.queries.get_mut(&2).unwrap()[0] |= 0x80;
        e.queries.get_mut(&3).unwrap()[1] = product;
        e.queries.insert(0, [0x35, 0x78, 0x84]);
        e.queries.insert(4, [0, 0xab, 0]);
        e.queries.insert(5, [0, 0x11, 0x17]);
    }
    (c, h)
}
fn configured(firmware: u32) -> (Controller<Model, Time>, Rc<RefCell<Hardware>>) {
    let (mut c, h) = target_point(firmware, 10);
    c.initialize().unwrap();
    (c, h)
}

#[test]
fn default_attachment_admits_queried_child_without_predicted_presence_and_requeries_same_identity()
{
    for firmware in [0x050001, 0x060001, 0x064001, 0x0f0001] {
        for present in [false, true] {
            let (mut c, h) = target(firmware);
            {
                let mut hw = h.borrow_mut();
                let e = hw.elantech.as_mut().unwrap();
                if present {
                    e.queries.get_mut(&2).unwrap()[0] |= 0x80;
                }
                e.queries.insert(0, [0x35, 0x78, 0x84]);
                e.queries.insert(4, [0, 0xab, 0]);
                e.queries.insert(5, [0, 0x11, 0x17]);
                if firmware == 0x0f0001 {
                    e.queries.get_mut(&3).unwrap()[1] = 8;
                }
            }
            c.initialize().unwrap();
            assert_eq!(c.elantech_capabilities().unwrap().trackpoint, present);
            assert_eq!(c.elantech_trackpoint_buttons(), present.then_some(0));
            if present {
                emit(&h, Port::Mouse, &packet(0x36808000, 1, 1, 3));
                let polled = c.poll_elantech().unwrap();
                assert!(matches!(
                    polled.frames[0].report,
                    elantech::Report::Trackpoint(elantech::TrackpointReport::Motion { .. })
                ));
                assert!(polled.inputs.contains(&Input::MouseButtons(3)));
            }
            c.stop().unwrap();
            c.initialize().unwrap();
            assert_eq!(c.elantech_capabilities().unwrap().trackpoint, present);
            assert_eq!(c.elantech_trackpoint_buttons(), present.then_some(0));
            if present {
                h.borrow_mut()
                    .elantech
                    .as_mut()
                    .unwrap()
                    .queries
                    .get_mut(&2)
                    .unwrap()[0] &= !0x80;
            } else {
                h.borrow_mut()
                    .elantech
                    .as_mut()
                    .unwrap()
                    .queries
                    .get_mut(&2)
                    .unwrap()[0] |= 0x80;
            }
            c.stop().unwrap();
            let before = h.borrow().elantech.as_ref().unwrap().parameter_writes.len();
            assert_eq!(
                c.initialize().unwrap_err().kind,
                ErrorKind::Elantech(elantech::Error::IdentityChanged)
            );
            assert_eq!(
                h.borrow().elantech.as_ref().unwrap().parameter_writes.len(),
                before
            );
        }
    }
}
fn packet(prefix: u32, x: u8, y: u8, buttons: u8) -> [u8; 6] {
    let p = (prefix | u32::from(buttons)).to_le_bytes();
    [p[0], p[1], p[2], p[3], x, y]
}

#[test]
fn integrated_profile_matches_presence_and_report_id_verification_precedes_mode_and_ready() {
    for firmware in [0x050001, 0x060001, 0x064001, 0x0f0001, 0x0f2002] {
        for product in [8, 9, 0x0d, 0x0e, 10, 0x74] {
            let (mut c, h) = target_point(firmware, product);
            if firmware == 0x050001 && product == 0x74 {
                continue;
            }
            c.initialize().unwrap();
            assert!(c.elantech_capabilities().unwrap().trackpoint);
            assert_eq!(c.elantech_trackpoint_buttons(), Some(0));
            let changed =
                matches!(firmware, 0x0f0001 | 0x0f2002) && matches!(product, 8 | 9 | 0x0d | 0x0e);
            assert_eq!(c.elantech_report_id_change().is_some(), changed);
            if changed {
                assert_eq!(
                    c.elantech_report_id_change(),
                    Some(&elantech::ReportIdChange {
                        requested: [0x10, 3],
                        write_acknowledged: true,
                        readback: Some([0x10, 3, 0xfe]),
                        verified: true
                    })
                );
                assert_eq!(
                    h.borrow().elantech.as_ref().unwrap().parameter_writes,
                    [(7, [0x10, 3]), (7, [0, 1])]
                );
                let queries = c.elantech_queries().unwrap();
                let index = queries
                    .iter()
                    .position(|q| q.kind == elantech::QueryKind::ReportId)
                    .unwrap();
                assert_eq!(queries[index + 1].kind, elantech::QueryKind::Resolution);
            }
        }
    }
    let (mut c, h) = target_profile(0x060001, true);
    assert_eq!(
        c.initialize().unwrap_err().kind,
        ErrorKind::Elantech(elantech::Error::TrackpointAbsent)
    );
    assert!(h.borrow().elantech.as_ref().unwrap().writes.is_empty());
    for firmware in [0x010000, 0x020800] {
        let (mut c, h) = target_point(firmware, 10);
        assert!(matches!(
            c.initialize().unwrap_err().kind,
            ErrorKind::Elantech(elantech::Error::TrackpointHardware(_))
        ));
        assert!(h.borrow().elantech.as_ref().unwrap().writes.is_empty());
    }
}

#[test]
fn integrated_motion_and_touchpad_state_stay_distinct_through_interleaving_and_stop() {
    let (mut c, h) = configured(0x0f2002);
    let raw = packet(0x06000030, 255, 255, 5);
    emit(&h, Port::Mouse, &raw);
    let polled = c.poll_elantech().unwrap();
    assert_eq!(
        polled.frames[0].report,
        elantech::Report::Trackpoint(elantech::TrackpointReport::Motion {
            buttons: 5,
            dx: -1,
            dy: 1
        })
    );
    assert!(polled.inputs.contains(&Input::MouseButtons(5)));
    assert!(polled.inputs.contains(&Input::Motion { dx: -1, dy: 1 }));
    assert_eq!(c.elantech_multitouch().unwrap().fingers, 0);
    emit(&h, Port::Mouse, &[1, 0xa0, 100, 0x31, 0x50, 200]);
    let pad = c.poll_elantech().unwrap();
    assert!(matches!(
        pad.frames[0].report,
        elantech::Report::Multitouch(_)
    ));
    assert_eq!(c.elantech_multitouch().unwrap().fingers, 1);
    assert_eq!(c.elantech_trackpoint_buttons(), Some(5));
    let ignored = packet(0x06000030, 0x80, 255, 0);
    emit(&h, Port::Mouse, &ignored);
    let polled = c.poll_elantech().unwrap();
    assert_eq!(
        polled.frames[0].report,
        elantech::Report::Trackpoint(elantech::TrackpointReport::Ignored)
    );
    assert!(polled.inputs.is_empty());
    assert_eq!(c.elantech_trackpoint_buttons(), Some(5));
    let release = c.stop().unwrap();
    assert!(release.contains(&Input::MouseButtons(0)));
    assert!(release.contains(&Input::Buttons(0)));
    c.initialize().unwrap();
    assert_eq!(c.elantech_trackpoint_buttons(), Some(0));
}

#[test]
fn report_id_uses_only_source_two_byte_echo_and_keeps_late_or_missing_reply() {
    for byte in 0..=255 {
        let (mut c, h) = target_point(0x0f0001, 8);
        h.borrow_mut().elantech.as_mut().unwrap().readback = Some([0x10, 3, byte]);
        c.initialize().unwrap();
        assert_eq!(
            c.elantech_report_id_change().unwrap().readback,
            Some([0x10, 3, byte])
        );
    }
    for observed in [[0, 3, 0], [0x10, 0, 0]] {
        let (mut c, h) = target_point(0x0f0001, 8);
        h.borrow_mut().elantech.as_mut().unwrap().readback = Some(observed);
        assert_eq!(
            c.initialize().unwrap_err().kind,
            ErrorKind::Elantech(elantech::Error::ReportId(observed))
        );
        let change = c.elantech_report_id_change().unwrap();
        assert!(change.write_acknowledged && !change.verified);
        assert_eq!(change.readback, Some(observed));
        assert_eq!(
            h.borrow().elantech.as_ref().unwrap().parameter_writes,
            [(7, [0x10, 3])]
        );
        assert!(!h.borrow().scanning[1]);
    }
    for byte in 0..3 {
        for late in [false, true] {
            let (mut c, h) = target_point(0x0f0001, 8);
            {
                let mut hw = h.borrow_mut();
                let e = hw.elantech.as_mut().unwrap();
                if late {
                    e.late = Some((7, byte));
                } else {
                    e.omit = Some((7, byte));
                }
            }
            c.initialize().unwrap_err();
            let progress = c.elantech_query_progress().unwrap();
            assert_eq!(progress.kind, elantech::QueryKind::ReportId);
            assert_eq!(progress.received, byte as u8 + u8::from(late));
            assert!(c.elantech_report_id_change().unwrap().write_acknowledged);
            assert!(!c.elantech_report_id_change().unwrap().verified);
            assert_eq!(
                h.borrow().elantech.as_ref().unwrap().parameter_writes,
                [(7, [0x10, 3])]
            );
            assert!(!h.borrow().scanning[1]);
            let writes = h.borrow().writes.len();
            c.poll().unwrap_err();
            assert_eq!(h.borrow().writes.len(), writes);
        }
    }
}

#[test]
fn report_id_late_write_and_changed_known_identity_never_replay_or_arm_reporting() {
    let (mut c, h) = target_point(0x0f0001, 8);
    h.borrow_mut().elantech.as_mut().unwrap().late_write = Some(7);
    let error = c.initialize().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::Response));
    assert_eq!(error.response.unwrap().data, ACK);
    assert!(!c.elantech_report_id_change().unwrap().write_acknowledged);
    assert_eq!(
        h.borrow().elantech.as_ref().unwrap().parameter_writes,
        [(7, [0x10, 3])]
    );
    let (mut c, h) = configured(0x0f0001);
    c.stop().unwrap();
    h.borrow_mut()
        .elantech
        .as_mut()
        .unwrap()
        .queries
        .get_mut(&3)
        .unwrap()[1] = 8;
    let writes = h.borrow().elantech.as_ref().unwrap().parameter_writes.len();
    assert_eq!(
        c.initialize().unwrap_err().kind,
        ErrorKind::Elantech(elantech::Error::IdentityChanged)
    );
    assert_eq!(
        h.borrow().elantech.as_ref().unwrap().parameter_writes.len(),
        writes
    );
}

#[test]
#[ignore = "oracle: STELA_ELANTECH_TRACKPOINT_ORACLE"]
fn unchanged_linux_integrated_trackpoint_records_match_native_profiles() {
    extern crate std;
    let records =
        std::fs::read_to_string(std::env::var("STELA_ELANTECH_TRACKPOINT_ORACLE").unwrap())
            .unwrap();
    let mut profile = None;
    let mut device = None;
    let mut cases = 0;
    for line in records.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 9);
        let number = |i: usize| fields[i].parse::<i32>().unwrap();
        if profile != Some(number(0)) || number(4) == 0 {
            let firmware = if number(1) == 3 {
                if number(2) != 0 { 0x054001 } else { 0x050001 }
            } else if number(2) != 0 {
                0x064001
            } else {
                0x060001
            };
            device = Some(configured(firmware));
            profile = Some(number(0));
        }
        let (c, h) = device.as_mut().unwrap();
        let raw: Vec<_> = fields[3]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        emit(h, Port::Mouse, &raw);
        if number(4) == 0 {
            assert_eq!(
                c.poll_elantech().unwrap_err().kind,
                ErrorKind::Elantech(elantech::Error::Packet)
            );
            assert_eq!(c.elantech_fragment(), Some(raw.as_slice()));
            assert_eq!(number(5), 0);
        } else {
            let polled = c.poll_elantech().unwrap();
            assert_eq!(polled.frames.len(), 1);
            assert_eq!(polled.frames[0].bytes(), raw);
            let elantech::Report::Trackpoint(report) = polled.frames[0].report else {
                panic!()
            };
            if number(5) != 0 {
                assert_eq!(
                    report,
                    elantech::TrackpointReport::Motion {
                        buttons: number(6) as u8,
                        dx: number(7) as i16,
                        dy: number(8) as i16
                    }
                );
                let motion: Vec<_> = polled
                    .inputs
                    .iter()
                    .filter_map(|event| {
                        if let Input::Motion { dx, dy } = event {
                            Some((*dx, *dy))
                        } else {
                            None
                        }
                    })
                    .collect();
                assert_eq!(
                    motion,
                    if number(7) != 0 || number(8) != 0 {
                        vec![(number(7) as i16, number(8) as i16)]
                    } else {
                        vec![]
                    }
                );
            } else {
                assert_eq!(report, elantech::TrackpointReport::Ignored);
                assert!(polled.inputs.is_empty());
            }
            assert_eq!(c.elantech_trackpoint_buttons(), Some(number(6) as u8));
        }
        cases += 1;
    }
    assert_eq!(cases, 8192);
}
#[test]
#[ignore = "oracle: STELA_ELANTECH_TRACKPOINT_CONTROLS_ORACLE"]
fn unchanged_linux_integrated_report_id_configuration_matches_native_transactions() {
    extern crate std;
    let records = std::fs::read_to_string(
        std::env::var("STELA_ELANTECH_TRACKPOINT_CONTROLS_ORACLE").unwrap(),
    )
    .unwrap();
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
        assert_eq!(fields.len(), 29);
        let number = |i: usize| fields[i].parse::<i32>().unwrap();
        let sample: [u8; 3] = hex(fields[2]).try_into().unwrap();
        let (mut c, h) = target_point(number(0) as u32, sample[1]);
        {
            let mut hw = h.borrow_mut();
            let e = hw.elantech.as_mut().unwrap();
            for (index, id) in [(1, 2), (2, 3), (3, 0)] {
                e.queries.insert(id, hex(fields[index]).try_into().unwrap());
            }
            e.queries
                .insert(4, [0x55, (cases % 32 * 17) as u8, (cases % 32 % 5) as u8]);
            e.knock[2] = number(4) as u8;
        }
        c.initialize().unwrap();
        let cap = c.elantech_capabilities().unwrap();
        let info = cap.v4.unwrap();
        assert!(cap.mode_accepted && number(6) == 0);
        assert_eq!(cap.hardware, number(7) as u8);
        assert_eq!(cap.bounds.minimum, (number(8) as u16, number(9) as u16));
        assert_eq!(cap.bounds.maximum, (number(10) as u16, number(11) as u16));
        assert_eq!(
            (cap.reports_pressure, cap.jumpy_cursor),
            (number(12) != 0, number(13) != 0)
        );
        assert_eq!(
            (
                i32::from(info.pattern),
                i32::from(info.ic_version),
                i32::from(info.trace_width)
            ),
            (number(15), number(16), number(17))
        );
        assert_eq!(info.traces, (number(18) as u8, number(19) as u8));
        assert_eq!(info.counts_per_mm, (number(20) as u16, number(21) as u16));
        assert_eq!(
            (
                i32::from(info.bus),
                info.middle_button,
                cap.crc_enabled,
                cap.trackpoint
            ),
            (
                number(22),
                number(23) != 0,
                number(24) != 0,
                number(25) != 0
            )
        );
        assert!(
            cap.registers.iter().all(|r| r.address == 7
                && r.requested == 1
                && r.acknowledged
                && r.readback.is_none())
        );
        assert_eq!(
            i32::from(c.elantech_report_id_change().is_some()),
            number(26)
        );
        if let Some(change) = c.elantech_report_id_change() {
            assert_eq!(change.requested, [0x10, 3]);
            assert!(change.write_acknowledged && change.verified);
            assert_eq!(change.readback, Some(hex(fields[27]).try_into().unwrap()));
        } else {
            assert_eq!(fields[27], "000000");
        }
        h.borrow_mut().elantech.as_mut().unwrap().readback = Some([0xfa, number(5) as u8, 0xfe]);
        assert_eq!(
            c.read_elantech_register(7).unwrap(),
            [0xfa, number(14) as u8, 0xfe]
        );
        let mut routed = false;
        let mut wire = Vec::new();
        for (command, byte) in &h.borrow().writes {
            if *command {
                routed = *byte == SEND_MOUSE;
            } else if routed {
                wire.push(*byte);
                routed = false;
            }
        }
        assert_eq!(
            &wire[..4],
            &[DISABLE_REPORTING, RESET, DEFAULTS, DISABLE_REPORTING]
        );
        assert_eq!(&wire[4..], hex(fields[28]), "{line}");
        cases += 1;
    }
    assert_eq!(cases, 128);
}
