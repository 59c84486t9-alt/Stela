//! Independent peripheral records and fault boundaries for one-byte F1A input.
use super::*;
fn install(h: &Rc<RefCell<Hardware>>) {
    let mut h = h.borrow_mut();
    h.memory[0xe8] = 0;
    // Three F1A interrupt sources; all belong to the same record.
    h.memory[0x1e9..0x1ef].copy_from_slice(&[0x10, 0x30, 0x40, 0x80, 3, 0x1a]);
}
fn frame(poll: &InputPoll) -> &f1a::Frame {
    assert_eq!(poll.error, None);
    match &poll.reports[0] {
        FunctionReport::F1A(frame) => frame,
        _ => panic!("wrong function report"),
    }
}
#[test]
fn all_f1a_data_bytes_preserve_active_high_buttons_and_unmapped_bits() {
    for buttons in 1..=8 {
        let h = hardware();
        install(&h);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        d.initialize_f1a(buttons).unwrap();
        assert_eq!(h.borrow().memory[0x41], 15);
        assert_eq!(d.f1a_capabilities().next().unwrap().buttons, buttons);
        assert_eq!(d.initialize_f1a(buttons), Err(Error::AlreadyActive));
        assert_eq!(d.poll_control(), Err(Error::InputConsumerActive));
        assert_eq!(d.poll_f12().error, Some(Error::InputConsumerActive));
        assert!(d.poll_input().reports.is_empty());
        for raw in 0..=255 {
            h.borrow_mut().memory[0x180] = raw;
            h.borrow_mut().memory[0x81] = 8;
            let poll = d.poll_input();
            let f = frame(&poll);
            assert_eq!(f.raw, raw);
            assert_eq!(f.buttons().count(), usize::from(buttons));
            for (index, pressed) in f.buttons() {
                assert_eq!(pressed, (raw >> index) & 1 == 1);
            }
        }
        // No F1A query/control transactions or invented hardware configuration.
        assert!(
            h.borrow()
                .writes
                .iter()
                .all(|(address, _)| *address < 0x100)
        );
    }
}
#[test]
fn f1a_requires_a_real_function_irq_and_verified_representable_button_count() {
    for buttons in [0, 9, 255] {
        let h = hardware();
        install(&h);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        let writes = h.borrow().writes.len();
        assert_eq!(
            d.initialize_f1a(buttons),
            Err(Error::InvalidButtonCount(buttons))
        );
        assert_eq!(h.borrow().writes.len(), writes);
        assert_eq!(d.control_state(), ControlState::Configured);
    }
    let h = hardware();
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    assert_eq!(d.initialize_f1a(3), Err(Error::MissingFunction(0x1a)));
    let h = hardware();
    install(&h);
    h.borrow_mut().memory[0x1ed] = 0;
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    assert_eq!(d.initialize_f1a(3), Err(Error::InterruptLimit));
    assert_eq!(h.borrow().memory[0x41], 1);
}
#[test]
fn f1a_uses_one_mixed_attention_and_keeps_complete_earlier_reports() {
    let h = hardware();
    install(&h);
    super::f12_tests::install_f12(&h, 2);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f12(None).unwrap();
    d.initialize_f1a(3).unwrap();
    h.borrow_mut().memory[0x180] = 5;
    h.borrow_mut().memory[0x81] = 0x18;
    let poll = d.poll_input();
    assert_eq!(poll.error, None);
    assert_eq!(poll.reports.len(), 2);
    assert_eq!(frame(&poll).raw, 5);
    assert!(matches!(poll.reports[1], FunctionReport::F12(_)));
    let fail = h.borrow().reads + 4;
    h.borrow_mut().fail_read_number = Some(fail);
    h.borrow_mut().memory[0x81] = 0x18;
    let poll = d.poll_input();
    assert!(matches!(poll.error, Some(Error::I2c(_))));
    assert_eq!(poll.reports.len(), 1);
    assert!(matches!(poll.reports[0], FunctionReport::F1A(_)));
    assert_eq!(poll.control.unwrap().interrupts, [0x18]);
}
#[test]
fn f1a_sleep_reinitialize_and_late_effect_errors_preserve_readiness() {
    let h = hardware();
    install(&h);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f1a(3).unwrap();
    d.sleep().unwrap();
    assert_eq!(d.poll_input().error, Some(Error::NotActive));
    d.wake().unwrap();
    d.stop().unwrap();
    d.initialize_control().unwrap();
    assert_eq!(d.f1a_capabilities().count(), 0);
    assert_eq!(d.poll_input().error, Some(Error::NotActive));
    h.borrow_mut().fail_address = Some(0x41);
    assert!(matches!(d.initialize_f1a(3), Err(Error::I2c(_))));
    assert_eq!(d.f1a_capabilities().count(), 0);
    assert_eq!(d.control_state(), ControlState::Uncertain);
    let writes = h.borrow().writes.len();
    assert_eq!(d.initialize_f1a(3), Err(Error::NeedsReset));
    assert_eq!(h.borrow().writes.len(), writes);
    let h = hardware();
    install(&h);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f1a(3).unwrap();
    let fail = h.borrow().reads + 3;
    h.borrow_mut().fail_read_number = Some(fail);
    h.borrow_mut().memory[0x81] = 2;
    let poll = d.poll_input();
    assert!(matches!(poll.error, Some(Error::I2c(_))));
    assert!(poll.reports.is_empty());
    assert_eq!(poll.control.unwrap().interrupts, [2]);
    assert_eq!(d.poll_input().error, Some(Error::NeedsReset));
}
