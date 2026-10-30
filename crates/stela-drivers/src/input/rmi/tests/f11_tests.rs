//! Independent F11 query/control packets and report records.
use super::*;

fn install(h: &Rc<RefCell<Hardware>>, gesture7: u8, gesture8: u8, extra: &[u8]) -> usize {
    let mut h = h.borrow_mut();
    h.memory[0xe8] = 0; // replace the unconfigured page0 discovery fixture
    h.memory[0x1e9..0x1ef].copy_from_slice(&[0x10, 0x30, 0x40, 0x80, 2, 0x11]);
    h.windows.insert((0x110, 1), vec![0]);
    h.windows.insert((0x111, 4), vec![0x39, 5, 6, 7]); //2fingers,abs,rel,gestures
    h.windows.insert((0x115, 1), vec![0x10]); //ordinary absolute format,dribble
    h.windows.insert((0x116, 1), vec![0]);
    h.windows.insert((0x117, 2), vec![gesture7, gesture8]);
    if gesture8 & 4 != 0 {
        h.windows.insert((0x119, 1), vec![8]);
    }
    h.windows.insert(
        (0x140, 12),
        vec![
            0x88, 0x55, 0x22, 0x33, 0x44, 0x55, 0xff, 0x0f, 0xff, 7, 0x66, 0xa0,
        ],
    );
    let mut packet = vec![
        9, 0x12, 0x45, 0x63, 0x54, 0x80, 0xab, 0xde, 0xfc, 0x87, 0x55, 0x80, 0x7f, 0xfe, 3,
    ];
    if gesture7 != 0 {
        packet.push(gesture7);
    }
    if gesture7 != 0 || gesture8 != 0 {
        packet.push(gesture8);
    }
    packet.extend_from_slice(extra);
    let length = packet.len();
    h.windows.insert((0x180, length), packet);
    length
}
fn frame(poll: &InputPoll) -> &f11::Frame {
    assert_eq!(poll.error, None);
    match &poll.reports[0] {
        FunctionReport::F11(frame) => frame,
        _ => panic!("wrong function report"),
    }
}

#[test]
fn f11_reports_contacts_from_configured_bank() {
    let h = hardware();
    let length = install(&h, 0x50, 7, &[0xff, 0x23, 0x45, 0xa5, 0x5a]);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    let configuration = f11::Configuration {
        dribble: Some(true),
        palm_detect: Some(true),
        delta_x_threshold: Some(3),
        delta_y_threshold: Some(4),
        ..f11::Configuration::default()
    };
    d.initialize_f11(configuration).unwrap();
    assert_eq!(h.borrow().memory[0x41], 3); //F01 + F11absolute,relative stays off
    let capability = d.f11_capabilities().next().unwrap();
    assert_eq!(capability.maximum, (4095, 2047));
    assert_eq!(capability.packet_size, length);
    assert!(capability.reports_absolute);
    assert_eq!(h.borrow().windows[&(0x140, 12)][0], 0xc9);
    assert_eq!(h.borrow().windows[&(0x140, 12)][2..4], [3, 4]);
    assert_eq!(h.borrow().windows[&(0x140, 12)][11], 0xa1);
    assert!(
        h.borrow()
            .writes
            .iter()
            .all(|(address, _)| !(0x110..0x140).contains(address))
    );
    assert!(d.poll_input().reports.is_empty());
    h.borrow_mut().memory[0x81] = 2;
    let poll = d.poll_input();
    let frame = frame(&poll);
    assert_eq!(
        frame.contacts[0],
        f11::Contact {
            object_index: 0,
            state: 1,
            x: 0x123,
            y: 0x456,
            pressure: 0x80,
            width_x: 4,
            width_y: 5
        }
    );
    assert_eq!(frame.contacts[1].state, 2);
    assert_eq!(frame.contacts[1].x, 0xabc);
    assert_eq!(frame.contacts[1].y, 0xdef);
    assert_eq!(frame.relative, [(-128, 127), (-2, 3)]);
    assert_eq!(
        &frame.raw_packet[length - 5..],
        &[0xff, 0x23, 0x45, 0xa5, 0x5a]
    );
}

#[test]
fn all_shared_gesture_layouts_capture_complete_flick_and_rotation_records() {
    for (gesture7, gesture8, extra) in [
        (0x40, 0, &[1][..]),
        (0x10, 0, &[1, 2, 3][..]),
        (0, 2, &[2, 3][..]),
        (0x50, 0, &[1, 2, 3][..]),
        (0x40, 2, &[1, 2, 3][..]),
        (0x10, 2, &[1, 2, 3][..]),
        (0x50, 2, &[1, 2, 3][..]),
    ] {
        let h = hardware();
        let length = install(&h, gesture7, gesture8, extra);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        d.initialize_f11(f11::Configuration::default()).unwrap();
        assert_eq!(d.f11_capabilities().next().unwrap().packet_size, length);
        h.borrow_mut().memory[0x81] = 2;
        let poll = d.poll_input();
        let frame = frame(&poll);
        assert_eq!(&frame.raw_packet[length - extra.len()..], extra);
    }
}

#[test]
fn relative_preference_selects_real_second_irq_and_relative_only_devices_work() {
    let h = hardware();
    install(&h, 0, 0, &[]);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f11(f11::Configuration {
        prefer_relative: true,
        ..f11::Configuration::default()
    })
    .unwrap();
    assert_eq!(h.borrow().memory[0x41], 5);
    h.borrow_mut().memory[0x81] = 4;
    let poll = d.poll_input();
    assert_eq!(frame(&poll).relative, [(-128, 127), (-2, 3)]);
    let h = hardware();
    install(&h, 0, 0, &[]);
    h.borrow_mut().windows.insert((0x111, 4), vec![9, 5, 6, 7]);
    h.borrow_mut().windows.insert((0x115, 1), vec![0]); //reserved relative query6
    h.borrow_mut()
        .windows
        .insert((0x180, 5), vec![0, 0x80, 0x7f, 0xfe, 3]);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f11(f11::Configuration::default()).unwrap();
    h.borrow_mut().memory[0x81] = 4;
    let poll = d.poll_input();
    let frame = frame(&poll);
    assert!(frame.contacts.is_empty());
    assert_eq!(frame.relative, [(-128, 127), (-2, 3)]);
}

#[test]
fn alternate_absolute_formats_and_missing_requested_controls_do_not_enable_irq() {
    for format in 1..=3 {
        let h = hardware();
        install(&h, 0, 0, &[]);
        h.borrow_mut().windows.insert((0x115, 1), vec![format]);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        assert_eq!(
            d.initialize_f11(f11::Configuration::default()),
            Err(Error::UnsupportedFormat {
                function: 0x11,
                format
            })
        );
        assert_eq!(h.borrow().memory[0x41], 1);
        assert_eq!(d.f11_capabilities().count(), 0);
    }
    let h = hardware();
    install(&h, 0, 0, &[]);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    assert_eq!(
        d.initialize_f11(f11::Configuration {
            palm_detect: Some(true),
            ..f11::Configuration::default()
        }),
        Err(Error::UnsupportedControl(11))
    );
    assert_eq!(h.borrow().memory[0x41], 1);
}

#[test]
fn mixed_f11_f12_consume_one_observed_attention_in_pdt_order() {
    let h = hardware();
    install(&h, 0, 0, &[]);
    super::f12_tests::install_f12(&h, 2);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f12(None).unwrap();
    d.initialize_f11(f11::Configuration::default()).unwrap();
    assert_eq!(h.borrow().memory[0x41], 0xb);
    h.borrow_mut().memory[0x81] = 0xa;
    assert_eq!(d.poll_control(), Err(Error::InputConsumerActive));
    assert_eq!(d.poll_f12().error, Some(Error::InputConsumerActive));
    let poll = d.poll_input();
    assert_eq!(poll.error, None);
    assert_eq!(poll.reports.len(), 2);
    assert!(matches!(poll.reports[0], FunctionReport::F11(_)));
    assert!(matches!(poll.reports[1], FunctionReport::F12(_)));
    let fail_read = h.borrow().reads + 4;
    h.borrow_mut().fail_read_number = Some(fail_read);
    h.borrow_mut().memory[0x81] = 0xa;
    let poll = d.poll_input();
    assert!(matches!(poll.error, Some(Error::I2c(_))));
    assert_eq!(poll.reports.len(), 1);
    assert!(matches!(poll.reports[0], FunctionReport::F11(_)));
    assert_eq!(poll.control.unwrap().interrupts, [0xa]);
}

#[test]
fn resume_rezero_waits_on_clock_and_late_effect_error_never_replays() {
    let h = hardware();
    install(&h, 0, 0, &[]);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f11(f11::Configuration {
        rezero_wait_us: 500,
        ..f11::Configuration::default()
    })
    .unwrap();
    d.sleep().unwrap();
    let start = h.borrow().time.get();
    d.wake().unwrap();
    let h_ref = h.borrow();
    let (_, time) = h_ref
        .written_at
        .iter()
        .rev()
        .find(|(address, _)| *address == 0x130)
        .unwrap();
    assert!(time.wrapping_sub(start) >= 500);
    drop(h_ref);
    d.sleep().unwrap();
    h.borrow_mut().fail_address = Some(0x130);
    assert!(matches!(d.wake(), Err(Error::I2c(_))));
    assert_eq!(h.borrow().memory[0x130], 1);
    assert_eq!(d.control_state(), ControlState::Uncertain);
    let count = h.borrow().writes.len();
    assert_eq!(d.wake(), Err(Error::NeedsReset));
    assert_eq!(h.borrow().writes.len(), count);
}

#[test]
fn optional_query_addresses_preserve_the_full_page_and_physical_metadata() {
    let h = hardware();
    install(&h, 0, 0, &[]);
    {
        let mut h = h.borrow_mut();
        h.windows.insert((0x110, 1), vec![0xf8]);
        h.windows.insert((0x115, 1), vec![0x90]);
        for (address, value) in [
            (0x119, 1),
            (0x11a, 0xff),
            (0x11b, 0x30),
            (0x11c, 0x65),
            (0x11d, 0x7c),
            (0x12b, 0x40),
            (0x12d, 0),
        ] {
            h.windows.insert((address, 1), vec![value]);
        }
        h.windows.insert((0x11e, 4), vec![0xe8, 3, 0xf4, 1]);
    }
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f11(f11::Configuration::default()).unwrap();
    let c = d.f11_capabilities().next().unwrap();
    assert_eq!(c.dimensions_mm, Some((100, 50)));
    assert_eq!(c.general_information2, Some(0x7c));
    assert_eq!(
        c.queries
            .iter()
            .map(|q| (q.number, q.address))
            .collect::<Vec<_>>(),
        [
            (0, 0x110),
            (1, 0x111),
            (5, 0x115),
            (6, 0x116),
            (7, 0x117),
            (9, 0x119),
            (11, 0x11a),
            (12, 0x11b),
            (13, 0x11c),
            (14, 0x11d),
            (15, 0x11e),
            (28, 0x12b),
            (36, 0x12d)
        ]
    );
}

#[test]
fn ten_finger_records_preserve_all_states_and_slot_boundaries() {
    let h = hardware();
    install(&h, 0, 0, &[]);
    let mut packet = vec![0xe4, 0xe4, 0x04];
    for index in 0..10 {
        packet.extend_from_slice(&[index, 0xff - index, 0xa5, 0x69, 0x80 + index]);
    }
    {
        let mut h = h.borrow_mut();
        h.windows.insert((0x111, 4), vec![0x15, 0, 0, 0]);
        h.windows.insert((0x180, packet.len()), packet.clone());
    }
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f11(f11::Configuration::default()).unwrap();
    h.borrow_mut().memory[0x81] = 2;
    let poll = d.poll_input();
    let f = frame(&poll);
    assert_eq!(f.raw_packet, packet);
    assert_eq!(f.contacts.len(), 10);
    for (index, contact) in f.contacts.iter().enumerate() {
        assert_eq!(contact.state, (index % 4) as u8);
        assert_eq!(contact.object_index, index as u8);
        assert_eq!(contact.x, ((index as u16) << 4) | 5);
        assert_eq!(contact.y, ((255 - index as u16) << 4) | 10);
    }
}

#[test]
fn extended_records_fail_explicitly_before_control_writes_or_irq_enable() {
    for (query, address, flags, general) in [
        (5, 0x115, 0x20, 0),
        (5, 0x115, 0x40, 0),
        (9, 0x119, 0x20, 8),
        (9, 0x119, 0x40, 8),
        (12, 0x119, 2, 32),
        (12, 0x119, 4, 32),
        (36, 0x11b, 0x20, 128),
    ] {
        let h = hardware();
        install(&h, 0, 0, &[]);
        {
            let mut h = h.borrow_mut();
            h.windows.insert((0x110, 1), vec![general]);
            if query == 36 {
                h.windows.insert((0x119, 1), vec![0x40]);
            }
            h.windows.insert((address, 1), vec![flags]);
        }
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        assert_eq!(
            d.initialize_f11(f11::Configuration::default()),
            Err(Error::UnsupportedF11Extension { query, flags })
        );
        assert_eq!(h.borrow().memory[0x41], 1);
        assert!(
            h.borrow()
                .writes
                .iter()
                .all(|(address, _)| *address != 0x140)
        );
    }
    for (gesture7, gesture8, query, flags) in [(0x80, 0, 7, 0x80), (0, 0xf8, 8, 0xf8)] {
        let h = hardware();
        install(&h, gesture7, gesture8, &[]);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        assert_eq!(
            d.initialize_f11(f11::Configuration::default()),
            Err(Error::UnsupportedF11Extension { query, flags })
        );
        assert_eq!(h.borrow().memory[0x41], 1);
    }
}

#[test]
fn late_f11_control_and_data_failures_fault_without_publishing_or_replay() {
    for address in [0x140, 0x41] {
        let h = hardware();
        install(&h, 0, 0, &[]);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        h.borrow_mut().fail_address = Some(address);
        assert!(matches!(
            d.initialize_f11(f11::Configuration::default()),
            Err(Error::I2c(_))
        ));
        assert_eq!(d.control_state(), ControlState::Uncertain);
        assert_eq!(d.f11_capabilities().count(), 0);
        let writes = h.borrow().writes.len();
        assert_eq!(
            d.initialize_f11(f11::Configuration::default()),
            Err(Error::NeedsReset)
        );
        assert_eq!(h.borrow().writes.len(), writes);
    }
    let h = hardware();
    install(&h, 0, 0, &[]);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f11(f11::Configuration::default()).unwrap();
    h.borrow_mut().memory[0x81] = 2;
    let fail = h.borrow().reads + 3;
    h.borrow_mut().fail_read_number = Some(fail);
    let poll = d.poll_input();
    assert!(matches!(poll.error, Some(Error::I2c(_))));
    assert!(poll.reports.is_empty());
    assert_eq!(poll.control.unwrap().interrupts, [2]);
    assert_eq!(d.poll_input().error, Some(Error::NeedsReset));
}
