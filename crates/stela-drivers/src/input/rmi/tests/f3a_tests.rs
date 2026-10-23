//! Independent F3A existence/direction/level bitmaps across all 127 GPIO pins.
use super::*;
fn install(h: &Rc<RefCell<Hardware>>, count: u8) -> (Vec<u8>, Vec<u8>) {
    let length = usize::from(count).div_ceil(8);
    let exists: Vec<_> = (0..length)
        .map(|index| 0xa5u8.wrapping_add(index as u8 * 7))
        .collect();
    let directions: Vec<_> = (0..length)
        .map(|index| 0x38u8.wrapping_add(index as u8 * 13))
        .collect();
    let mut h = h.borrow_mut();
    h.memory[0xe8] = 0;
    h.memory[0x1e9..0x1ef].copy_from_slice(&[0x10, 0x30, 0x40, 0x80, 2, 0x3a]);
    h.memory[0x110] = count | 0x80;
    h.windows.insert((0x111, length), exists.clone());
    h.windows.insert((0x141, length), directions.clone());
    (exists, directions)
}
fn frame(poll: &InputPoll) -> &f3a::Frame {
    assert_eq!(poll.error, None);
    let FunctionReport::F3A(frame) = &poll.reports[0] else {
        panic!("wrong function");
    };
    frame
}
#[test]
fn f3a_all_declared_gpio_counts_preserve_full_bitmaps_and_input_eligibility() {
    for count in 1..=127 {
        let h = hardware();
        let (exists, directions) = install(&h, count);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        d.initialize_f3a().unwrap();
        let c = d.f3a_capabilities().next().unwrap();
        assert_eq!(c.query, count | 0x80);
        assert_eq!(c.gpio_count, count);
        assert_eq!(c.exists, exists);
        assert_eq!(c.directions, directions);
        assert_eq!(h.borrow().memory[0x41], 7);
        let levels: Vec<_> = (0..exists.len())
            .map(|index| 0x5au8.wrapping_add(index as u8 * 17))
            .collect();
        h.borrow_mut()
            .windows
            .insert((0x180, levels.len()), levels.clone());
        h.borrow_mut().memory[0x81] = 4;
        let poll = d.poll_input();
        let f = frame(&poll);
        assert_eq!(f.levels, levels);
        let expected: Vec<_> = (0..count)
            .filter_map(|index| {
                let bit = 1 << (index % 8);
                let byte = usize::from(index / 8);
                (exists[byte] & bit != 0 && directions[byte] & bit == 0)
                    .then_some((index, levels[byte] & bit == 0))
            })
            .collect();
        assert_eq!(
            f.buttons
                .iter()
                .map(|button| (button.gpio_index, button.pressed))
                .collect::<Vec<_>>(),
            expected
        );
        assert!(
            h.borrow()
                .writes
                .iter()
                .all(|(address, _)| *address < 0x100)
        );
    }
}
#[test]
fn f3a_every_level_byte_spans_all_sixteen_registers_without_aliasing_high_pins() {
    let h = hardware();
    install(&h, 127);
    {
        let mut h = h.borrow_mut();
        h.windows.insert((0x111, 16), vec![255; 16]);
        h.windows.insert((0x141, 16), vec![0; 16]);
    }
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f3a().unwrap();
    assert_eq!(d.initialize_f3a(), Err(Error::AlreadyActive));
    assert_eq!(d.poll_control(), Err(Error::InputConsumerActive));
    assert_eq!(d.poll_f12().error, Some(Error::InputConsumerActive));
    assert!(d.poll_input().reports.is_empty());
    for value in 0u8..=255 {
        let levels: Vec<_> = (0..16)
            .map(|index| value.wrapping_add(index * 17))
            .collect();
        h.borrow_mut().windows.insert((0x180, 16), levels.clone());
        h.borrow_mut().memory[0x81] = 2;
        let poll = d.poll_input();
        let f = frame(&poll);
        assert_eq!(f.levels, levels);
        assert_eq!(f.buttons.len(), 127);
        for (index, button) in f.buttons.iter().enumerate() {
            assert_eq!(usize::from(button.gpio_index), index);
            assert_eq!(button.pressed, (levels[index / 8] >> (index % 8)) & 1 == 0);
        }
    }
}
#[test]
fn f3a_empty_count_missing_irq_query_direction_and_late_irq_faults_fail_readiness() {
    let h = hardware();
    install(&h, 0);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    assert_eq!(d.initialize_f3a(), Err(Error::InvalidGpioCount(0)));
    assert_eq!(h.borrow().memory[0x41], 1);
    let h = hardware();
    install(&h, 127);
    h.borrow_mut().memory[0x1ed] = 0;
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    assert_eq!(d.initialize_f3a(), Err(Error::InterruptLimit));
    for offset in 1..=4 {
        let h = hardware();
        install(&h, 127);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        let fail = h.borrow().reads + offset;
        h.borrow_mut().fail_read_number = Some(fail);
        assert!(matches!(d.initialize_f3a(), Err(Error::I2c(_))));
        assert_eq!(d.f3a_capabilities().count(), 0);
        assert_eq!(d.control_state(), ControlState::Uncertain);
    }
    let h = hardware();
    install(&h, 127);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    h.borrow_mut().fail_address = Some(0x41);
    assert!(matches!(d.initialize_f3a(), Err(Error::I2c(_))));
    assert_eq!(d.f3a_capabilities().count(), 0);
    assert_eq!(h.borrow().memory[0x41], 7);
    let writes = h.borrow().writes.len();
    assert_eq!(d.initialize_f3a(), Err(Error::NeedsReset));
    assert_eq!(h.borrow().writes.len(), writes);
}
#[test]
fn f3a_mixed_attention_earlier_reports_sleep_reset_and_read_faults_keep_ownership() {
    let h = hardware();
    install(&h, 127);
    super::f12_tests::install_f12(&h, 2);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f12(None).unwrap();
    d.initialize_f3a().unwrap();
    h.borrow_mut().memory[0x81] = 0xa;
    let poll = d.poll_input();
    assert_eq!(poll.error, None);
    assert_eq!(poll.reports.len(), 2);
    assert!(matches!(poll.reports[0], FunctionReport::F3A(_)));
    assert!(matches!(poll.reports[1], FunctionReport::F12(_)));
    let fail = h.borrow().reads + 4;
    h.borrow_mut().fail_read_number = Some(fail);
    h.borrow_mut().memory[0x81] = 0xa;
    let poll = d.poll_input();
    assert!(matches!(poll.error, Some(Error::I2c(_))));
    assert_eq!(poll.reports.len(), 1);
    assert!(matches!(poll.reports[0], FunctionReport::F3A(_)));
    assert_eq!(poll.control.unwrap().interrupts, [0xa]);
    let h = hardware();
    install(&h, 127);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f3a().unwrap();
    d.sleep().unwrap();
    let reads = h.borrow().reads;
    assert_eq!(d.poll_input().error, Some(Error::NotActive));
    assert_eq!(h.borrow().reads, reads);
    d.wake().unwrap();
    d.stop().unwrap();
    d.initialize_control().unwrap();
    assert_eq!(d.f3a_capabilities().count(), 0);
    assert_eq!(h.borrow().memory[0x41], 1);
    d.initialize_f3a().unwrap();
    let fail = h.borrow().reads + 3;
    h.borrow_mut().fail_read_number = Some(fail);
    h.borrow_mut().memory[0x81] = 2;
    let poll = d.poll_input();
    assert!(matches!(poll.error, Some(Error::I2c(_))));
    assert!(poll.reports.is_empty());
    assert_eq!(poll.control.unwrap().interrupts, [2]);
}
