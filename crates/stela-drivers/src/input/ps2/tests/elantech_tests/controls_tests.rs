use super::*;

fn configured(hardware: u8) -> (Controller<Model, Time>, Rc<RefCell<Hardware>>) {
    let firmware = match hardware {
        1 => 0x010000,
        2 => 0x020800,
        3 => 0x050001,
        _ => 0x060001,
    };
    let (mut c, h) = target(firmware);
    if hardware >= 3 {
        let mut hw = h.borrow_mut();
        let e = hw.elantech.as_mut().unwrap();
        e.queries.insert(0, [0x35, 0x78, 0x84]);
        e.queries.insert(4, [0x55, 0xab, 0]);
    }
    c.initialize().unwrap();
    (c, h)
}
fn mouse_wire(h: &Hardware, from: usize) -> Vec<u8> {
    let mut routed = false;
    let mut wire = Vec::new();
    for (command, byte) in &h.writes[from..] {
        if *command {
            routed = *byte == SEND_MOUSE;
        } else if routed {
            wire.push(*byte);
            routed = false;
        }
    }
    wire
}

#[test]
fn hardware_register_mutations_force_only_v1_bits_and_preserve_actual_progress() {
    for hardware in 1..=4 {
        let (mut c, h) = configured(hardware);
        for address in [7, 0x10, 0x11, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26] {
            for requested in [0, 1, 2, 4, 0xe6, 0xe9, 0xf4, 0xf5, 0xf8, 0xff] {
                let control = c.write_elantech_register(address, requested).unwrap();
                let effective = requested
                    | if hardware == 1 {
                        match address {
                            0x10 => 4,
                            0x11 => 2,
                            _ => 0,
                        }
                    } else {
                        0
                    };
                assert_eq!(
                    control,
                    elantech::RegisterControl {
                        address,
                        requested,
                        effective,
                        quiesced: true,
                        acknowledged: true,
                        reporting_resumed: true
                    }
                );
                assert_eq!(
                    h.borrow().elantech.as_ref().unwrap().registers[&address],
                    effective
                );
                assert_eq!(c.drain_elantech_register_controls(), [control]);
                assert!(c.is_ready());
            }
        }
        assert!(!c.elantech_capabilities().unwrap().mode_accepted);
        c.stop().unwrap();
        c.initialize().unwrap();
        assert!(c.elantech_capabilities().unwrap().mode_accepted);
    }
}

#[test]
fn mutable_register_bad_attribute_and_full_retention_queue_refuse_before_effects() {
    let (mut c, h) = configured(4);
    for address in [0, 6, 8, 9, 0x12, 0x1f, 0x27, 255] {
        let before = (h.borrow().writes.len(), h.borrow().consumed);
        assert_eq!(
            c.write_elantech_register(address, 0).unwrap_err().kind,
            ErrorKind::Elantech(elantech::Error::Register(address))
        );
        assert_eq!((h.borrow().writes.len(), h.borrow().consumed), before);
    }
    for value in 0..32 {
        c.write_elantech_register(0x20, value).unwrap();
    }
    let before = (h.borrow().writes.len(), h.borrow().consumed);
    assert_eq!(
        c.write_elantech_register(0x20, 32).unwrap_err().kind,
        ErrorKind::QueueFull
    );
    assert_eq!((h.borrow().writes.len(), h.borrow().consumed), before);
    let retained = c.drain_elantech_register_controls();
    assert_eq!(retained.len(), 32);
    for (index, control) in retained.iter().enumerate() {
        assert_eq!(control.requested, index as u8);
    }
    c.write_elantech_register(0x20, 32).unwrap();
}

#[test]
fn pending_bad_packet_before_live_control_retains_fragment_without_stale_response_or_new_command() {
    for write in [false, true] {
        let (mut c, h) = configured(4);
        let raw = [8, 0x21, 0x43, 0x11, 0x65, 0x87];
        // Route actual mouse bytes into the owner side queue while the sibling
        // keyboard command receives its own real ACK. No internal queue/state
        // injection bypasses the actual controller read/routing path.
        h.borrow_mut().inject_led = raw.iter().map(|data| (Port::Mouse, *data)).collect();
        c.set_leds(1).unwrap();
        assert_eq!(c.observed_response.unwrap().data, ACK);
        assert_eq!(c.observed_response.unwrap().port, Port::Keyboard);
        assert_eq!(c.pending.len(), 6);
        let writes = h.borrow().writes.len();
        let error = if write {
            c.write_elantech_register(0x20, 0xa5).unwrap_err()
        } else {
            c.read_elantech_register(0x20).unwrap_err()
        };
        assert_eq!(error.kind, ErrorKind::Elantech(elantech::Error::Packet));
        assert_eq!(error.response, None);
        assert_eq!(c.elantech_fragment(), Some(raw.as_slice()));
        // Containment uses controller port-disable commands, never a new
        // mouse register/device command after the actual packet failure.
        assert!(mouse_wire(&h.borrow(), writes).is_empty());
        if write {
            let control = c.elantech_register_controls().unwrap()[0];
            assert!(!control.quiesced && !control.acknowledged && !control.reporting_resumed);
        }
    }
}

#[test]
fn mutable_register_quiesce_write_and_resume_failures_retain_acknowledged_effects_without_replay() {
    for hardware in 1..=4 {
        for stage in 0..3 {
            let (mut c, h) = configured(hardware);
            {
                let mut hw = h.borrow_mut();
                match stage {
                    0 => hw.no_ack = Some((Port::Mouse, DISABLE_REPORTING)),
                    1 => hw.elantech.as_mut().unwrap().late_write = Some(0x20),
                    _ => hw.no_ack = Some((Port::Mouse, ENABLE_REPORTING)),
                }
            }
            let error = c.write_elantech_register(0x20, 0xa5).unwrap_err();
            assert_eq!(error.kind, ErrorKind::Timeout(Phase::Response));
            let control = c.elantech_register_controls().unwrap()[0];
            assert_eq!(control.requested, 0xa5);
            assert_eq!(control.quiesced, stage != 0);
            assert_eq!(control.acknowledged, stage == 2);
            assert!(!control.reporting_resumed);
            if stage != 0 {
                assert_eq!(h.borrow().elantech.as_ref().unwrap().registers[&0x20], 0xa5);
            }
            if stage == 1 {
                assert_eq!(error.response.unwrap().data, ACK);
            }
            assert!(c.needs_reset());
            let writes = h.borrow().writes.len();
            c.write_elantech_register(0x20, 0xa5).unwrap_err();
            c.poll().unwrap_err();
            assert_eq!(h.borrow().writes.len(), writes);
            assert_eq!(c.drain_elantech_register_controls(), [control]);
        }
    }
}

#[test]
#[ignore = "oracle: STELA_ELANTECH_REGISTER_ORACLE"]
fn unchanged_linux_mutable_register_values_and_transactions_match_actual_native_controls() {
    extern crate std;
    let records =
        std::fs::read_to_string(std::env::var("STELA_ELANTECH_REGISTER_ORACLE").unwrap()).unwrap();
    let mut hardware = None;
    let mut device = None;
    let mut cases = 0;
    for line in records.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 6);
        let number = |i: usize| fields[i].parse::<u8>().unwrap();
        if hardware != Some(number(0)) {
            device = Some(configured(number(0)));
            hardware = Some(number(0));
        }
        let (c, h) = device.as_mut().unwrap();
        let from = h.borrow().writes.len();
        let control = c.write_elantech_register(number(1), number(2)).unwrap();
        assert_eq!(control.effective, number(3));
        assert!(control.quiesced && control.acknowledged && control.reporting_resumed);
        assert_eq!(
            h.borrow().elantech.as_ref().unwrap().registers[&number(1)],
            number(3)
        );
        let raw = if number(0) == 4 {
            [0xfa, number(4), 0xfe]
        } else {
            [number(4), 0xfa, 0xfe]
        };
        h.borrow_mut().elantech.as_mut().unwrap().readback = Some(raw);
        assert_eq!(c.read_elantech_register(number(1)).unwrap(), raw);
        c.drain_elantech_queries();
        assert_eq!(c.drain_elantech_register_controls(), [control]);
        let expected: Vec<_> = fields[5]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(mouse_wire(&h.borrow(), from), expected, "{line}");
        cases += 1;
    }
    assert_eq!(cases, 10240);
}
