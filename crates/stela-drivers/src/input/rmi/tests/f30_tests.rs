//! Independent F30 variable control-bank and GPIO bit-vector peripheral.
use super::*;
fn install(h: &Rc<RefCell<Hardware>>, flags: u8, count: u8) -> Vec<(u8, u16, Vec<u8>)> {
    let mut h = h.borrow_mut();
    h.memory[0xe8] = 0;
    h.memory[0x1e9..0x1ef].copy_from_slice(&[0x10, 0x30, 0x40, 0x80, 2, 0x30]);
    h.windows.insert((0x110, 2), vec![flags, count | 0xe0]);
    let width = usize::from(count).div_ceil(8);
    let mut blocks = Vec::new();
    let mut image = Vec::new();
    let mut append = |number: u8, size: usize| {
        let address = 0x140 + image.len() as u16;
        let bytes: Vec<_> = (0..size)
            .map(|index| number.wrapping_mul(17).wrapping_add(index as u8))
            .collect();
        image.extend_from_slice(&bytes);
        blocks.push((number, address, bytes));
    };
    if flags & 8 != 0 && flags & 4 != 0 {
        append(0, width);
    }
    append(1, 1);
    if flags & 8 != 0 {
        append(2, width);
        append(3, width);
    }
    if flags & 4 != 0 {
        append(4, width);
        append(5, if flags & 1 != 0 { 6 } else { 2 });
    }
    if flags & (4 | 32) != 0 {
        append(6, usize::from(count));
    }
    if flags & 2 != 0 {
        append(7, usize::from(count));
    }
    if flags & 16 != 0 {
        append(8, width);
        append(9, 1);
    }
    if flags & 64 != 0 {
        append(10, 1);
    }
    h.windows.insert((0x140, image.len()), image);
    blocks
}
#[test]
fn f30_all_gpio_counts_and_optional_control_layouts_match_independent_register_banks() {
    for flags in (0..128).filter(|flags| flags & 8 != 0) {
        for count in 1..=31 {
            let h = hardware();
            let blocks = install(&h, flags, count);
            let mut d = control_device(&h);
            d.initialize_control().unwrap();
            d.initialize_f30().unwrap();
            assert_eq!(h.borrow().memory[0x41], 7);
            let cap = d.f30_capabilities().next().unwrap();
            assert_eq!(cap.gpio_count, count);
            assert_eq!(cap.query, [flags, count | 0xe0]);
            assert_eq!(
                cap.controls
                    .iter()
                    .map(|c| (c.number, c.address, c.bytes.clone()))
                    .collect::<Vec<_>>(),
                blocks
            );
            let direction = &blocks.iter().find(|block| block.0 == 2).unwrap().2;
            let data = &blocks.iter().find(|block| block.0 == 3).unwrap().2;
            let mut expected = 0;
            for index in 0..count {
                let bit = 1 << (index % 8);
                let byte = usize::from(index / 8);
                if direction[byte] & bit == 0 && data[byte] & bit != 0 {
                    expected |= 1 << index;
                }
            }
            assert_eq!(cap.input_buttons, expected);
        }
    }
}
#[test]
fn f30_all_level_bytes_use_active_low_input_pins_across_all_four_data_registers() {
    let h = hardware();
    let blocks = install(&h, 0x7f, 31);
    let length: usize = blocks.iter().map(|block| block.2.len()).sum();
    {
        let mut h = h.borrow_mut();
        let raw = h.windows.get_mut(&(0x140, length)).unwrap();
        let direction = usize::from(blocks.iter().find(|block| block.0 == 2).unwrap().1 - 0x140);
        raw[direction..direction + 4].fill(0);
        let data = usize::from(blocks.iter().find(|block| block.0 == 3).unwrap().1 - 0x140);
        raw[data..data + 4].fill(255);
    }
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f30().unwrap();
    assert_eq!(
        d.f30_capabilities().next().unwrap().input_buttons,
        0x7fff_ffff
    );
    for value in 0u8..=255 {
        let levels = vec![
            value,
            value.wrapping_add(39),
            value.wrapping_add(78),
            value.wrapping_add(117),
        ];
        h.borrow_mut().windows.insert((0x180, 4), levels.clone());
        h.borrow_mut().memory[0x81] = 4;
        let poll = d.poll_input();
        assert_eq!(poll.error, None);
        let FunctionReport::F30(frame) = &poll.reports[0] else {
            panic!("wrong function");
        };
        assert_eq!(frame.levels, levels);
        assert_eq!(frame.buttons.len(), 31);
        for button in &frame.buttons {
            assert_eq!(
                button.pressed,
                ((levels[usize::from(button.gpio_index / 8)] >> (button.gpio_index % 8)) & 1) == 0
            );
        }
    }
}
#[test]
fn f30_missing_gpio_empty_count_and_control_irq_read_errors_never_publish_an_engine() {
    for (flags, count, error) in [
        (
            4,
            8,
            Error::UnsupportedFormat {
                function: 0x30,
                format: 4,
            },
        ),
        (8, 0, Error::InvalidGpioCount(0)),
    ] {
        let h = hardware();
        install(&h, flags, count);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        assert_eq!(d.initialize_f30(), Err(error));
        assert_eq!(h.borrow().memory[0x41], 1);
        assert_eq!(d.f30_capabilities().count(), 0);
    }
    for address in [0x140, 0x41] {
        let h = hardware();
        install(&h, 0x7f, 31);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        h.borrow_mut().fail_address = Some(address);
        assert!(matches!(d.initialize_f30(), Err(Error::I2c(_))));
        assert_eq!(d.f30_capabilities().count(), 0);
        assert_eq!(d.control_state(), ControlState::Uncertain);
        let writes = h.borrow().writes.len();
        assert_eq!(d.initialize_f30(), Err(Error::NeedsReset));
        assert_eq!(h.borrow().writes.len(), writes);
    }
    for offset in 1..=4 {
        let h = hardware();
        install(&h, 0x7f, 31);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        let fail = h.borrow().reads + offset;
        h.borrow_mut().fail_read_number = Some(fail);
        assert!(matches!(d.initialize_f30(), Err(Error::I2c(_))));
        assert_eq!(d.f30_capabilities().count(), 0);
        assert_eq!(d.control_state(), ControlState::Uncertain);
    }
}
#[test]
fn f30_mixed_order_late_data_failures_and_sleep_reset_keep_attention_ownership() {
    let h = hardware();
    install(&h, 8, 31);
    super::f12_tests::install_f12(&h, 2);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f12(None).unwrap();
    d.initialize_f30().unwrap();
    assert_eq!(d.poll_control(), Err(Error::InputConsumerActive));
    assert_eq!(d.poll_f12().error, Some(Error::InputConsumerActive));
    h.borrow_mut().memory[0x81] = 0xa;
    let poll = d.poll_input();
    assert_eq!(poll.error, None);
    assert_eq!(poll.reports.len(), 2);
    assert!(matches!(poll.reports[0], FunctionReport::F30(_)));
    assert!(matches!(poll.reports[1], FunctionReport::F12(_)));
    let fail = h.borrow().reads + 4;
    h.borrow_mut().fail_read_number = Some(fail);
    h.borrow_mut().memory[0x81] = 0xa;
    let poll = d.poll_input();
    assert!(matches!(poll.error, Some(Error::I2c(_))));
    assert_eq!(poll.reports.len(), 1);
    assert!(matches!(poll.reports[0], FunctionReport::F30(_)));
    assert_eq!(poll.control.unwrap().interrupts, [0xa]);
    let h = hardware();
    install(&h, 8, 31);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f30().unwrap();
    d.sleep().unwrap();
    let reads = h.borrow().reads;
    assert_eq!(d.poll_input().error, Some(Error::NotActive));
    assert_eq!(h.borrow().reads, reads);
    d.wake().unwrap();
    d.stop().unwrap();
    d.initialize_control().unwrap();
    assert_eq!(d.f30_capabilities().count(), 0);
    assert_eq!(h.borrow().memory[0x41], 1);
    d.initialize_f30().unwrap();
    let fail = h.borrow().reads + 3;
    h.borrow_mut().fail_read_number = Some(fail);
    h.borrow_mut().memory[0x81] = 2;
    let poll = d.poll_input();
    assert!(matches!(poll.error, Some(Error::I2c(_))));
    assert!(poll.reports.is_empty());
    assert_eq!(poll.control.unwrap().interrupts, [2]);
}
