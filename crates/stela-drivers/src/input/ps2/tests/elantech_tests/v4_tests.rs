//! V4 configuration, five-contact I/O, kept failures and software MT.
use super::*;

fn target_v4(firmware: u32) -> (Controller<Model, Time>, Rc<RefCell<Hardware>>) {
    let (c, h) = target(firmware);
    {
        let mut hw = h.borrow_mut();
        let e = hw.elantech.as_mut().unwrap();
        e.queries.insert(0, [0x35, 0x78, 0x84]);
        e.queries.insert(4, [0x55, 0xab, 0]);
        e.queries.insert(5, [0, 0x11, 0x17]);
    }
    (c, h)
}
fn configured(firmware: u32) -> (Controller<Model, Time>, Rc<RefCell<Hardware>>) {
    let (mut c, h) = target_v4(firmware);
    c.initialize().unwrap();
    (c, h)
}
fn packet(crc: bool, kind: u8, id: u8) -> [u8; 6] {
    [
        0,
        0,
        0,
        (id << 5) | if crc { kind } else { 0x10 | kind },
        0,
        0,
    ]
}
fn read_frame(
    c: &mut Controller<Model, Time>,
    h: &Rc<RefCell<Hardware>>,
    raw: [u8; 6],
) -> (elantech::Frame, elantech::V4Frame, Vec<Input>) {
    emit(h, Port::Mouse, &raw);
    let mut polled = c.poll_elantech().unwrap();
    assert_eq!(polled.frames.len(), 1);
    let frame = polled.frames.remove(0);
    assert_eq!(frame.bytes(), raw);
    let elantech::Report::Multitouch(mt) = frame.report else {
        panic!()
    };
    assert_eq!(c.elantech_multitouch(), Some(&mt.state));
    (frame, mt, polled.inputs)
}

#[test]
fn v4_real_mode_is_ack_only_and_firmware_rate_restore_precedes_ready() {
    for firmware in [0x060001, 0x070001, 0x0f0000, 0x0f0001, 0x0f2002, 0x381f17] {
        let (mut c, h) = configured(firmware);
        let cap = c.elantech_capabilities().unwrap();
        assert_eq!(cap.hardware, 4);
        assert!(cap.mode_accepted);
        assert_eq!(cap.bounds.maximum, (1400, 900));
        let info = cap.v4.unwrap();
        assert_eq!(info.counts_per_mm, (35, 35));
        assert_eq!(info.traces, (18, 12));
        assert_eq!(info.trace_width, 82);
        assert_eq!(
            info.pattern,
            if matches!(firmware, 0x0f0001 | 0x0f2002) {
                firmware as u8
            } else {
                0
            }
        );
        assert_eq!(info.ic_body.is_some(), info.pattern != 0);
        assert!(
            cap.registers.iter().all(|r| r.address == 7
                && r.requested == 1
                && r.acknowledged
                && r.readback.is_none())
        );
        assert_eq!(
            cap.registers.len(),
            if firmware == 0x381f17 { 2 } else { 1 }
        );
        assert_eq!(h.borrow().elantech.as_ref().unwrap().registers[&7], 1);
        assert!(
            !c.elantech_queries()
                .unwrap()
                .iter()
                .any(|q| matches!(q.kind, elantech::QueryKind::Register(_)))
        );
        for byte in 0..=255 {
            h.borrow_mut().elantech.as_mut().unwrap().readback = Some([0xfa, byte, 0xfe]);
            assert_eq!(c.read_elantech_register(7).unwrap(), [0xfa, byte, 0xfe]);
            c.drain_elantech_queries();
        }
    }
}

#[test]
fn v4_status_never_invents_heads_and_motion_preserves_unsigned_cache_provenance() {
    let (mut c, h) = configured(0x060001);
    let mut motion = packet(false, 2, 2);
    motion[0] = (2 << 5) | 0x10;
    motion[1] = 0x80;
    motion[2] = 127;
    motion[4] = 127;
    motion[5] = 0x80;
    let (_, mt, input) = read_frame(&mut c, &h, motion);
    assert_eq!(mt.state.fingers, 0);
    assert!(input.is_empty());
    assert_eq!(mt.state.slots[1].position, ((-5i32) as u32, 5));
    assert_eq!(mt.state.slots[1].head_sequence, None);
    let mut status = packet(false, 0, 0);
    status[1] = 31;
    assert_eq!(read_frame(&mut c, &h, status).1.state.fingers, 0);
    let mut head = packet(false, 1, 2);
    head[0] = 0x33;
    head[1] = 0xa0;
    head[2] = 100;
    head[4] = 0x50;
    head[5] = 200;
    let (frame, mt, _) = read_frame(&mut c, &h, head);
    assert_eq!(mt.state.slots[1].position, (100, 700));
    assert_eq!(mt.state.slots[1].head_sequence, Some(frame.native_sequence));
    assert_eq!(mt.state.slots[1].tracking_id, Some(0));
    assert_eq!(mt.state.pressure, 0xa5);
    assert_eq!(mt.state.width, 3);
    let (_, mt, _) = read_frame(&mut c, &h, motion);
    assert_eq!(mt.state.slots[1].position, (95, 705));
    assert_eq!(mt.state.slots[1].head_sequence, Some(frame.native_sequence));
    status[1] = 0;
    let (_, released, _) = read_frame(&mut c, &h, status);
    assert_eq!(released.state.slots[1].tracking_id, None);
    assert_eq!(released.state.pointer, (95, 705));
    let (_, new_head, _) = read_frame(&mut c, &h, head);
    assert_eq!(new_head.state.slots[1].tracking_id, Some(1));
}

#[test]
fn v4_five_contacts_oldest_pointer_middle_buttons_and_invalid_ids_follow_source() {
    let (mut c, h) = configured(0x0f2002);
    for id in (1..=5).rev() {
        let mut head = packet(false, 1, id);
        head[0] = 0x14;
        head[2] = id * 10;
        let (_, mt, _) = read_frame(&mut c, &h, head);
        assert_eq!(mt.state.pointer, (50, 900));
        assert_eq!(mt.state.buttons, 4);
        assert_eq!(mt.state.fingers, 6 - id);
    }
    assert_eq!(c.elantech_multitouch().unwrap().tools, 0);
    for id in [0, 6, 7] {
        let before = *c.elantech_multitouch().unwrap();
        let (_, mt, input) = read_frame(&mut c, &h, packet(false, 1, id));
        assert!(!mt.synchronized);
        assert_eq!(mt.state, before);
        assert!(input.is_empty());
        let mut raw = packet(false, 2, 1);
        raw[0] = id << 5;
        raw[4] = 50;
        let (_, mt, input) = read_frame(&mut c, &h, raw);
        assert!(!mt.synchronized);
        assert_eq!(mt.state, before);
        assert!(input.is_empty());
    }
    let (_, mt, _) = read_frame(&mut c, &h, packet(false, 0, 0));
    assert_eq!(
        (mt.state.fingers, mt.state.tools, mt.state.pressure),
        (0, 0, 0)
    );
    assert_eq!(mt.state.pointer, (50, 900));
}

#[test]
fn v4_every_query_loss_and_late_byte_retains_progress_and_never_replays_or_enables() {
    for query in 1..=8 {
        for byte in 0..3 {
            for late in [false, true] {
                let (mut c, h) = target_v4(0x0f0001);
                {
                    let mut hw = h.borrow_mut();
                    let e = hw.elantech.as_mut().unwrap();
                    if late {
                        e.late = Some((query, byte));
                    } else {
                        e.omit = Some((query, byte));
                    }
                }
                c.initialize().unwrap_err();
                assert!(!c.is_ready());
                assert!(c.needs_reset());
                assert_eq!(
                    c.elantech_query_progress().unwrap().received,
                    byte as u8 + u8::from(late)
                );
                assert!(!h.borrow().scanning[1]);
                let count = h.borrow().writes.len();
                c.poll().unwrap_err();
                assert_eq!(h.borrow().writes.len(), count);
            }
        }
    }
}

#[test]
fn v4_rate_restore_late_ack_retains_both_real_mode_writes_without_claiming_current_mode() {
    let (mut c, h) = target_v4(0x381f17);
    {
        let mut hw = h.borrow_mut();
        let e = hw.elantech.as_mut().unwrap();
        e.late_write = Some(7);
        e.late_write_number = Some(2);
    }
    let error = c.initialize().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::Response));
    assert_eq!(error.response.unwrap().data, ACK);
    let cap = c.elantech_capabilities().unwrap();
    assert!(!cap.mode_accepted);
    assert!(cap.registers[0].acknowledged);
    assert!(!cap.registers[1].acknowledged);
    assert_eq!(
        h.borrow().elantech.as_ref().unwrap().writes,
        [(7, 1), (7, 1)]
    );
    assert!(!h.borrow().scanning[1]);
    let writes = h.borrow().writes.len();
    assert_eq!(c.initialize().unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(h.borrow().writes.len(), writes);
}

#[test]
fn v4_tracking_wrap_preserves_oldest_contact_and_exact_source_counter() {
    let (mut c, h) = configured(0x060001);
    // Advance the owner through framed heads/releases rather
    // than injecting a tracking counter into production state.
    for _ in 0..65534 {
        read_frame(&mut c, &h, packet(false, 1, 1));
        read_frame(&mut c, &h, packet(false, 0, 0));
    }
    for (id, expected) in [(3, 65534), (1, 65535), (5, 0)] {
        let mut head = packet(false, 1, id);
        head[2] = id * 10;
        let (_, mt, _) = read_frame(&mut c, &h, head);
        assert_eq!(
            mt.state.slots[usize::from(id - 1)].tracking_id,
            Some(expected)
        );
        assert_eq!(mt.state.pointer, (30, 900));
    }
    assert_eq!(c.elantech_multitouch().unwrap().next_tracking_id, 65537);
    let mut status = packet(false, 0, 0);
    status[1] = 1 | 16;
    assert_eq!(read_frame(&mut c, &h, status).1.state.pointer, (10, 900));
}

#[test]
fn v4_late_mode_effect_backpressure_bad_signature_and_stop_are_retained() {
    let (mut c, h) = target_v4(0x060001);
    h.borrow_mut().elantech.as_mut().unwrap().late_write = Some(7);
    let error = c.initialize().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::Response));
    assert_eq!(error.response.unwrap().data, ACK);
    assert_eq!(h.borrow().elantech.as_ref().unwrap().writes, [(7, 1)]);
    assert!(!c.elantech_capabilities().unwrap().mode_accepted);
    assert!(!c.elantech_capabilities().unwrap().registers[0].acknowledged);
    let (mut c, h) = configured(0x060001);
    let mut head = packet(false, 1, 1);
    head[0] = 3;
    for _ in 0..40 {
        emit(&h, Port::Mouse, &head);
    }
    for _ in 0..4 {
        c.poll().unwrap();
    }
    let consumed = h.borrow().consumed;
    let writes = h.borrow().writes.len();
    assert_eq!(
        c.read_elantech_register(7).unwrap_err().kind,
        ErrorKind::QueueFull
    );
    assert_eq!(
        (h.borrow().consumed, h.borrow().writes.len()),
        (consumed, writes)
    );
    assert_eq!(c.drain_elantech_frames().len(), 32);
    assert_eq!(c.poll_elantech().unwrap().frames.len(), 8);
    let released = c.stop().unwrap();
    assert_eq!(c.elantech_multitouch().unwrap().fingers, 0);
    assert!(released.contains(&Input::Buttons(0)));
    c.initialize().unwrap();
    head[0] |= 8;
    emit(&h, Port::Mouse, &head);
    assert_eq!(
        c.poll().unwrap_err().kind,
        ErrorKind::Elantech(elantech::Error::Packet)
    );
    c.release_inputs();
    assert_eq!(c.elantech_fragment(), Some(head.as_slice()));
}

#[test]
fn v4_geometry_and_signature_refusals_precede_mode_or_preserve_exact_bad_packet() {
    for x_traces in [0, 1, 11, 255] {
        let (mut c, h) = target_v4(0x060001);
        {
            let mut hw = h.borrow_mut();
            let e = hw.elantech.as_mut().unwrap();
            e.queries.get_mut(&2).unwrap()[1] = x_traces;
            e.queries.insert(0, [0x30, 10, 0x84]);
        }
        assert_eq!(
            c.initialize().unwrap_err().kind,
            ErrorKind::Elantech(elantech::Error::Geometry)
        );
        assert!(h.borrow().elantech.as_ref().unwrap().writes.is_empty());
        assert!(!h.borrow().scanning[1]);
    }
    for firmware in [0x060001, 0x064001, 0x070001] {
        for kind in 0..=3 {
            let (mut c, h) = target_v4(firmware);
            if firmware == 0x070001 {
                h.borrow_mut()
                    .elantech
                    .as_mut()
                    .unwrap()
                    .queries
                    .get_mut(&3)
                    .unwrap()[1] = 0x2a;
            }
            c.initialize().unwrap();
            let crc = firmware & 0x4000 != 0;
            let mut raw = packet(crc, kind, 1);
            if kind != 3 {
                raw[3] ^= if crc { 8 } else { 4 };
            }
            emit(&h, Port::Mouse, &raw);
            assert_eq!(
                c.poll().unwrap_err().kind,
                ErrorKind::Elantech(elantech::Error::Packet)
            );
            assert_eq!(c.elantech_fragment(), Some(raw.as_slice()));
            assert_eq!(c.elantech_multitouch().unwrap().fingers, 0);
        }
    }
}

#[test]
#[ignore = "oracle: STELA_ELANTECH_V4_CONTROLS_ORACLE"]
fn unchanged_linux_v4_configuration_matches_actual_mode_rate_and_register_transactions() {
    extern crate std;
    let records =
        std::fs::read_to_string(std::env::var("STELA_ELANTECH_V4_CONTROLS_ORACLE").unwrap())
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
        assert_eq!(fields.len(), 26);
        let number = |i: usize| fields[i].parse::<i32>().unwrap();
        let (mut c, h) = target_v4(number(0) as u32);
        {
            let mut hw = h.borrow_mut();
            let e = hw.elantech.as_mut().unwrap();
            for (index, id) in [(1, 2), (2, 3), (3, 0)] {
                e.queries.insert(id, hex(fields[index]).try_into().unwrap());
            }
            e.queries
                .insert(4, [0x55, (cases % 32 * 17) as u8, (cases % 32 % 5) as u8]);
            e.knock[2] = number(4) as u8;
            e.readback = Some([0xfa, number(5) as u8, 0xfe]);
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
            (i32::from(info.bus), info.middle_button, cap.crc_enabled),
            (number(22), number(23) != 0, number(24) != 0)
        );
        assert!(
            cap.registers.iter().all(|r| r.address == 7
                && r.requested == 1
                && r.acknowledged
                && r.readback.is_none())
        );
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
        assert_eq!(&wire[4..], hex(fields[25]), "source record {line}");
        cases += 1;
    }
    assert_eq!(cases, 352);
}

#[test]
#[ignore = "oracle: STELA_ELANTECH_V4_REPORTS_ORACLE"]
fn unchanged_linux_v4_reports_and_mt_policy_match_actual_configured_i8042_device() {
    extern crate std;
    let records =
        std::fs::read_to_string(std::env::var("STELA_ELANTECH_V4_REPORTS_ORACLE").unwrap())
            .unwrap();
    let mut device = None;
    let mut group = None;
    let mut cases = 0;
    for line in records.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 37);
        let number = |i: usize| fields[i].parse::<i32>().unwrap();
        if group != Some(number(0)) {
            let (mut c, h) = target_v4(number(1) as u32);
            {
                let mut hw = h.borrow_mut();
                let e = hw.elantech.as_mut().unwrap();
                e.queries.insert(2, [0, 16 + (number(0) & 15) as u8, 12]);
                if number(1) == 0x070001 {
                    e.queries.get_mut(&3).unwrap()[1] = 0x2a;
                }
            }
            c.initialize().unwrap();
            device = Some((c, h));
            group = Some(number(0));
        }
        let (c, h) = device.as_mut().unwrap();
        let raw: Vec<_> = fields[2]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        let (_, mt, inputs) = read_frame(c, h, raw.try_into().unwrap());
        let state = mt.state;
        assert_eq!(
            (
                mt.synchronized,
                i32::from(state.buttons),
                i32::from(state.fingers != 0),
                i32::from(state.tools)
            ),
            (number(3) != 0, number(4), number(5), number(6)),
            "{line}"
        );
        assert_eq!(state.pointer, (number(7), number(8)), "{line}");
        assert_eq!(
            (
                i32::from(state.pressure),
                i32::from(state.width),
                state.next_tracking_id as i32
            ),
            (number(9), number(10), number(11)),
            "{line}"
        );
        for (i, slot) in state.slots.iter().enumerate() {
            let start = 12 + i * 5;
            assert_eq!(
                (
                    slot.tracking_id.map_or(-1, i32::from),
                    slot.position.0 as i32,
                    slot.position.1 as i32,
                    i32::from(slot.pressure),
                    i32::from(slot.touch_major)
                ),
                (
                    number(start),
                    number(start + 1),
                    number(start + 2),
                    number(start + 3),
                    number(start + 4)
                ),
                "{line}"
            );
        }
        if !mt.synchronized {
            assert!(inputs.is_empty());
        }
        cases += 1;
    }
    assert_eq!(cases, 8192);
}
