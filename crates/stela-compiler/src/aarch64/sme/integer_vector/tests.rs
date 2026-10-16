use super::*;

#[test]
fn arithmetic_widths_groups_and_register_edges() {
    for encoding in &ARITHMETIC_ENCODINGS {
        let register_count = encoding.group.count();
        let clamp = matches!(encoding.kind, ArithmeticKind::Clamp(_));
        let right_shift = if clamp || !encoding.right_grouped {
            SINGLE_SOURCE_SHIFT
        } else {
            match encoding.group {
                Group::Pair => PAIR_SOURCE_SHIFT,
                Group::Quartet => QUARTET_SOURCE_SHIFT,
            }
        };
        let source_limit = if clamp {
            REGISTER_MASK
        } else if encoding.right_grouped {
            REGISTER_MASK / u32::from(register_count)
        } else {
            SINGLE_SOURCE_MASK
        };
        for size in 0..=SIZE_MASK {
            for destination in (0..VECTOR_REGISTER_COUNT).step_by(usize::from(register_count)) {
                for right in 0..=source_limit {
                    for lower in if clamp { 0..=REGISTER_MASK } else { 0..=0 } {
                        let word = encoding.opcode
                            | (size << SIZE_SHIFT)
                            | u32::from(destination)
                            | (right << right_shift)
                            | (lower << CLAMP_LOWER_SHIFT);
                        let operand = decode(word).unwrap().unwrap();
                        assert_eq!(
                            operand,
                            Operand::Arithmetic(Arithmetic {
                                kind: encoding.kind,
                                destination,
                                right: (right as u8)
                                    * if encoding.right_grouped {
                                        register_count
                                    } else {
                                        1
                                    },
                                lower: clamp.then_some(lower as u8),
                                group: encoding.group,
                                element: element(size),
                                right_grouped: encoding.right_grouped,
                            })
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn narrowing_all_destination_aliases_and_source_group_edges() {
    for encoding in &NARROW_ENCODINGS {
        let register_count = encoding.group.count();
        let source_shift = match encoding.group {
            Group::Pair => NARROW_PAIR_SOURCE_SHIFT,
            Group::Quartet => NARROW_QUARTET_SOURCE_SHIFT,
        };
        let source_limit = VECTOR_REGISTER_COUNT / register_count;
        for source in 0..source_limit {
            for destination in 0..VECTOR_REGISTER_COUNT {
                let word = encoding.opcode
                    | (u32::from(source) << source_shift)
                    | u32::from(destination)
                    | if encoding.rounded_shift && encoding.group == Group::Quartet {
                        1 << NARROW_SHIFT_SIZE_SHIFT
                    } else {
                        0
                    };
                let operand = decode(word).unwrap().unwrap();
                let Operand::Narrow(narrow) = operand else {
                    panic!("matched non-narrow operand");
                };
                assert_eq!(narrow.source, source * register_count);
                assert_eq!(narrow.destination, destination);
                assert_eq!(narrow.group, encoding.group);
                assert_eq!(
                    narrow.source_element.bytes(),
                    narrow.destination_element.bytes() * usize::from(register_count)
                );
                assert_eq!(narrow.interleaved, encoding.interleaved);
                assert_eq!(narrow.source_signedness, encoding.source_signedness);
                assert_eq!(
                    narrow.destination_signedness,
                    encoding.destination_signedness
                );
            }
        }
    }
}

#[test]
fn quartet_narrow_shift_size_and_full_width_rounding() {
    for encoding in NARROW_ENCODINGS
        .into_iter()
        .filter(|encoding| encoding.rounded_shift && encoding.group == Group::Quartet)
    {
        for size in 0..=SIZE_MASK {
            for immediate in 0..=QUARTET_SHIFT_IMMEDIATE_MASK {
                let word = (encoding.opcode & !(SIZE_MASK << NARROW_SHIFT_SIZE_SHIFT))
                    | (size << NARROW_SHIFT_SIZE_SHIFT)
                    | (immediate << NARROW_IMMEDIATE_SHIFT);
                if size == 0 {
                    assert_eq!(decode(word), Some(Err(())));
                    continue;
                }
                let Operand::Narrow(narrow) = decode(word).unwrap().unwrap() else {
                    panic!("matched non-narrow operand");
                };
                let (width, shift) = match size {
                    1 => (ElementSize::Byte, 32 - immediate),
                    2 => (ElementSize::Halfword, 64 - immediate),
                    3 => (ElementSize::Halfword, 32 - immediate),
                    _ => unreachable!(),
                };
                assert_eq!(narrow.destination_element, width);
                assert_eq!(u32::from(narrow.shift), shift);
            }
        }
    }
}

#[test]
fn pair_narrow_rounds_from_one_through_sixteen() {
    for encoding in NARROW_ENCODINGS
        .into_iter()
        .filter(|encoding| encoding.rounded_shift && encoding.group == Group::Pair)
    {
        for immediate in 0..=PAIR_SHIFT_IMMEDIATE_MASK {
            let Operand::Narrow(narrow) =
                decode(encoding.opcode | (immediate << NARROW_IMMEDIATE_SHIFT))
                    .unwrap()
                    .unwrap()
            else {
                panic!("matched non-narrow operand");
            };
            assert_eq!(narrow.source_element, ElementSize::Word);
            assert_eq!(narrow.destination_element, ElementSize::Halfword);
            assert_eq!(u32::from(narrow.shift), 16 - immediate);
        }
    }
}

#[test]
fn unrelated_words_do_not_enter_this_family() {
    for word in [0, 0xffff_ffff, 0xd503_201f, 0x9100_0400, 0x0420_0000] {
        assert_eq!(decode(word), None);
    }
}
