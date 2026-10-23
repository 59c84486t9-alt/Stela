//! Independent read-to-drain F03 peripheral and passthrough fault tests.
use super::*;
fn install(h: &Rc<RefCell<Hardware>>, query: u8, queue: u8) {
    let mut h = h.borrow_mut();
    h.memory[0xe8] = 0;
    h.memory[0x1e9..0x1ef].copy_from_slice(&[0x10, 0x30, 0x40, 0x80, 2, 3]);
    h.memory[0x110] = query;
    h.memory[0x111] = queue;
    let length = if query & 7 == 0 || query & 0x70 == 0 {
        7
    } else {
        queue & 15
    };
    let mut stale = vec![0; usize::from(length) * 2];
    for record in stale.as_chunks_mut::<2>().0 {
        record.copy_from_slice(&[1, 0xaa]);
    }
    h.fifo_windows.insert(0x182, stale);
}
fn frame(poll: &InputPoll) -> &f03::Frame {
    assert_eq!(poll.error, None);
    match &poll.reports[0] {
        FunctionReport::F03(frame) => frame,
        _ => panic!("wrong function report"),
    }
}
#[test]
fn f03_drains_stale_announcements_and_preserves_every_status_and_data_byte() {
    let h = hardware();
    install(&h, 0x21, 15);
    h.borrow_mut().memory[0x112] = 0x5a;
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f03().unwrap();
    let cap = d.f03_capabilities().next().unwrap();
    assert_eq!(cap.queries, [0x21, 15, 0x5a]);
    assert!(!cap.legacy);
    assert_eq!(cap.receive_queue_length, 15);
    assert_eq!(h.borrow().memory[0x41], 7);
    assert_eq!(d.poll_control(), Err(Error::InputConsumerActive));
    assert_eq!(d.poll_f12().error, Some(Error::InputConsumerActive));
    h.borrow_mut().memory[0x81] = 4;
    assert!(frame(&d.poll_input()).received().next().is_none());
    for value in 0..=255 {
        let mut packet = vec![0; 30];
        packet[..8].copy_from_slice(&[value, value ^ 0xa5, 0xc1, value, 0x40, 0xfe, 0x80, 0xff]);
        h.borrow_mut().fifo_windows.insert(0x182, packet);
        h.borrow_mut().memory[0x81] = 2;
        let poll = d.poll_input();
        let f = frame(&poll);
        assert_eq!(f.slots.len(), 15);
        assert_eq!(f.slots[0].status, value);
        assert_eq!(f.slots[0].data, value ^ 0xa5);
        assert_eq!(f.slots[0].available(), value & 1 != 0);
        assert_eq!(f.slots[0].timeout(), value & 0x40 != 0);
        assert_eq!(f.slots[0].parity_error(), value & 0x80 != 0);
        assert_eq!(f.slots[1].data, value);
        assert_eq!(f.received().count(), 1 + usize::from(value & 1 != 0));
    }
}
#[test]
fn f03_legacy_query_rules_and_all_nonzero_queue_lengths_are_source_qualified() {
    for query in [0, 1, 0x10, 7, 0x70] {
        let h = hardware();
        install(&h, query, 0);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        d.initialize_f03().unwrap();
        let cap = d.f03_capabilities().next().unwrap();
        assert!(cap.legacy);
        assert_eq!(cap.receive_queue_length, 7);
        assert_eq!(cap.queries, [query]);
    }
    for queue in 1..=15 {
        let h = hardware();
        install(&h, 0x11, queue | 0xf0);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        d.initialize_f03().unwrap();
        assert_eq!(
            d.f03_capabilities().next().unwrap().receive_queue_length,
            queue
        );
    }
    for (query, queue, error) in [
        (0x11, 0, Error::InvalidF03QueueLength),
        (0x12, 7, Error::UnsupportedPassthroughDevices(2)),
    ] {
        let h = hardware();
        install(&h, query, queue);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        assert_eq!(d.initialize_f03(), Err(error));
        assert_eq!(h.borrow().memory[0x41], 1);
        assert_eq!(d.f03_capabilities().count(), 0);
    }
}
#[test]
fn f03_transmit_and_close_are_real_acknowledged_bus_effects_without_replay() {
    let h = hardware();
    install(&h, 0x11, 3);
    super::f12_tests::install_f12(&h, 2);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f03().unwrap();
    d.initialize_f12(None).unwrap();
    let function = d.f03_capabilities().next().unwrap().function;
    for byte in 0..=255 {
        d.write_f03(function, byte).unwrap();
        assert_eq!(h.borrow().writes.last().unwrap(), &(0x180, vec![byte]));
    }
    d.close_f03(function).unwrap();
    assert_eq!(d.f03_capabilities().count(), 0);
    assert_eq!(h.borrow().memory[0x41], 9);
    assert_eq!(d.write_f03(function, 0xff), Err(Error::MissingFunction(3)));
    d.initialize_f03().unwrap();
    assert_eq!(h.borrow().memory[0x41], 15);
    h.borrow_mut().fail_address = Some(0x180);
    assert!(matches!(d.write_f03(function, 0xff), Err(Error::I2c(_))));
    assert_eq!(h.borrow().memory[0x180], 0xff);
    let writes = h.borrow().writes.len();
    assert_eq!(d.write_f03(function, 0xff), Err(Error::NeedsReset));
    assert_eq!(h.borrow().writes.len(), writes);
}
#[test]
fn f03_drain_irq_close_and_receive_faults_never_publish_false_bytes_or_readiness() {
    for fail_after in [1, 2, 3] {
        let h = hardware();
        install(&h, 0x11, 3);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        let fail = h.borrow().reads + fail_after;
        h.borrow_mut().fail_read_number = Some(fail);
        assert!(matches!(d.initialize_f03(), Err(Error::I2c(_))));
        assert_eq!(d.f03_capabilities().count(), 0);
        assert_eq!(h.borrow().memory[0x41], 1);
        assert_eq!(d.control_state(), ControlState::Uncertain);
    }
    let h = hardware();
    install(&h, 0x11, 3);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    h.borrow_mut().fail_address = Some(0x41);
    assert!(matches!(d.initialize_f03(), Err(Error::I2c(_))));
    assert_eq!(d.f03_capabilities().count(), 0);
    assert_eq!(d.control_state(), ControlState::Uncertain);
    let h = hardware();
    install(&h, 0x11, 3);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f03().unwrap();
    let function = d.f03_capabilities().next().unwrap().function;
    h.borrow_mut().fail_address = Some(0x41);
    assert!(matches!(d.close_f03(function), Err(Error::I2c(_))));
    assert_eq!(d.f03_capabilities().count(), 1);
    assert_eq!(d.close_f03(function), Err(Error::NeedsReset));
    let h = hardware();
    install(&h, 0x11, 3);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f03().unwrap();
    let fail = h.borrow().reads + 3;
    h.borrow_mut().fail_read_number = Some(fail);
    h.borrow_mut().memory[0x81] = 2;
    let poll = d.poll_input();
    assert!(matches!(poll.error, Some(Error::I2c(_))));
    assert!(poll.reports.is_empty());
    assert_eq!(poll.control.unwrap().interrupts, [2]);
    assert_eq!(d.poll_input().error, Some(Error::NeedsReset));
}
#[test]
fn f03_mixed_attention_and_sleep_reinitialize_preserve_exact_transport_ownership() {
    let h = hardware();
    install(&h, 0x11, 3);
    super::f12_tests::install_f12(&h, 2);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f12(None).unwrap();
    d.initialize_f03().unwrap();
    h.borrow_mut()
        .fifo_windows
        .insert(0x182, vec![1, 0xfa, 0xc1, 0xaa, 0, 0]);
    h.borrow_mut().memory[0x81] = 0xa;
    let poll = d.poll_input();
    assert_eq!(poll.reports.len(), 2);
    assert_eq!(
        frame(&poll)
            .received()
            .map(|byte| byte.data)
            .collect::<Vec<_>>(),
        [0xfa, 0xaa]
    );
    assert!(matches!(poll.reports[1], FunctionReport::F12(_)));
    let fail = h.borrow().reads + 4;
    h.borrow_mut().fail_read_number = Some(fail);
    h.borrow_mut().memory[0x81] = 0xa;
    let poll = d.poll_input();
    assert!(matches!(poll.error, Some(Error::I2c(_))));
    assert_eq!(poll.reports.len(), 1);
    assert!(matches!(poll.reports[0], FunctionReport::F03(_)));
    let h = hardware();
    install(&h, 0x11, 3);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f03().unwrap();
    let function = d.f03_capabilities().next().unwrap().function;
    d.sleep().unwrap();
    let writes = h.borrow().writes.len();
    assert_eq!(d.write_f03(function, 0xf4), Err(Error::NotActive));
    assert_eq!(d.poll_input().error, Some(Error::NotActive));
    assert_eq!(h.borrow().writes.len(), writes);
    d.wake().unwrap();
    d.stop().unwrap();
    d.initialize_control().unwrap();
    assert_eq!(d.f03_capabilities().count(), 0);
    assert_eq!(h.borrow().memory[0x41], 1);
}
