// SPDX-License-Identifier: GPL-2.0
use super::*;

#[test]
#[ignore = "requires a fresh pinned original Intel GPIO oracle trace"]
fn original_linux_gpio_encodings_and_pad_ownership() {
    let path = std::env::var("STELA_INTEL_GPIO_ORACLE").unwrap();
    let bytes = std::fs::read(path).unwrap();
    let text = core::str::from_utf8(&bytes).unwrap();
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some("INTEL_GPIO cc9de5d4b5ab6459f5774946aa3195ad51236fa8")
    );
    let mut count = 0;
    for line in lines {
        if line == "DONE 552" {
            break;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        let decimal = |index: usize| fields[index].parse::<u32>().unwrap();
        let word = |index: usize| u32::from_str_radix(fields[index], 16).unwrap();
        match fields[0] {
            "D" => {
                assert_eq!(fields.len(), 4);
                let (mut controller, state, _) = setup(&[0], 0x94);
                state.borrow_mut().words.insert((0, 0x1000), word(1));
                match decimal(2) {
                    0 => controller.direction_input(0),
                    1 => controller.direction_output(0, true),
                    2 => controller.high_impedance(0),
                    _ => panic!("unknown direction"),
                }
                .unwrap();
                assert_eq!(state.borrow().words[&(0, 0x1000)], word(3));
                controller.retire().unwrap();
            }
            "P" => {
                assert_eq!(fields.len(), 8);
                let (mut controller, state, _) =
                    setup(&[0], if decimal(1) == 0 { 0x91 } else { 0x94 });
                state.borrow_mut().words.insert((0, 0x1004), word(2));
                state.borrow_mut().trace.clear();
                let pull = match decimal(3) {
                    0 => Pull::Disabled,
                    1 => Pull::Up(decimal(4)),
                    2 => Pull::Down(decimal(4)),
                    _ => panic!("unknown pull"),
                };
                let result = controller.pull(0, pull);
                assert_eq!(
                    result,
                    if fields[5] == "0" {
                        Ok(())
                    } else {
                        Err(Error::InvalidPull)
                    }
                );
                assert_eq!(state.borrow().words[&(0, 0x1004)], word(6));
                assert_eq!(writes(&state).len(), decimal(7) as usize);
                controller.retire().unwrap();
            }
            "B" => {
                assert_eq!(fields.len(), 8);
                let (mut controller, state, _) =
                    setup(&[0], if decimal(1) == 0 { 0x91 } else { 0x94 });
                {
                    let mut state = state.borrow_mut();
                    state.words.insert((0, 0x1000), word(2));
                    state.words.insert((0, 0x1008), 0x8000_0020);
                    state.trace.clear();
                }
                let result = controller.debounce(0, decimal(3));
                let expected = match fields[4] {
                    "0" => Ok(()),
                    "-22" => Err(Error::InvalidDebounce),
                    "-524" => Err(Error::Unsupported),
                    _ => panic!("unknown debounce result"),
                };
                assert_eq!(result, expected, "{line}");
                assert_eq!(state.borrow().words[&(0, 0x1000)], word(5), "{line}");
                assert_eq!(state.borrow().words[&(0, 0x1008)], word(6), "{line}");
                assert_eq!(writes(&state).len(), decimal(7) as usize);
                controller.retire().unwrap();
            }
            "O" => {
                assert_eq!(fields.len(), 5);
                let revision = if decimal(1) == 0 { 0x94 } else { 0x110 };
                let pin = decimal(2) as u16;
                let (mut controller, state, _) = setup(&[pin], revision);
                let group = modern().communities[0]
                    .groups
                    .iter()
                    .find(|group| pin >= group.first && pin - group.first < group.count)
                    .unwrap();
                let offset = if revision >= 0x110 {
                    0x20 + usize::from(pin) * 4
                } else {
                    0x20 + usize::from(group.pad_own + (pin - group.first) / 8) * 4
                };
                state.borrow_mut().words.insert((0, offset), word(3));
                state.borrow_mut().trace.clear();
                assert_eq!(
                    controller.value(pin),
                    if decimal(4) != 0 {
                        Ok(false)
                    } else {
                        Err(Error::FirmwareOwner)
                    }
                );
                assert!(writes(&state).is_empty());
            }
            _ => panic!("unknown original-source row: {line}"),
        }
        count += 1;
    }
    assert_eq!(count, 552);
}
