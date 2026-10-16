use super::*;

#[test]
fn immediate_size_allocations_and_boundaries() {
    for encoding in ENCODINGS {
        let predicated = matches!(encoding.format, Format::PredicatedImmediate);
        if !matches!(
            encoding.format,
            Format::PredicatedImmediate | Format::Immediate | Format::XorRotate
        ) {
            continue;
        }
        let (low_shift, immediate_shift) = if predicated {
            (PREDICATED_TSIZE_LOW_SHIFT, PREDICATED_IMMEDIATE_SHIFT)
        } else {
            (TSIZE_LOW_SHIFT, IMMEDIATE_SHIFT)
        };
        for tsize in 0_u32..16 {
            for immediate in 0..=IMMEDIATE_MASK {
                let word = encoding.value
                    | (tsize >> 2) << SIZE_SHIFT
                    | (tsize & SIZE_MASK) << low_shift
                    | immediate << immediate_shift
                    | REGISTER_MASK;
                let result = decode(word).expect("owned immediate encoding");
                if tsize == 0 {
                    assert_eq!(result, Err(()));
                    continue;
                }
                let operand = result.unwrap();
                let expected_bits =
                    usize::from(BYTE_BITS) << (u32::BITS - 1 - tsize.leading_zeros());
                assert_eq!(operand.element_size.bits(), expected_bits);
                assert_eq!(operand.destination, REGISTER_MASK as u8);
                let Count::Immediate(amount) = operand.count else {
                    panic!("immediate operand");
                };
                let left = matches!(
                    operand.kind,
                    Kind::LogicalLeft
                        | Kind::InsertLeft
                        | Kind::SaturatingSigned
                        | Kind::SaturatingUnsigned
                        | Kind::SaturatingSignedToUnsigned
                );
                assert!(
                    usize::from(amount) < expected_bits
                        || !left && usize::from(amount) == expected_bits
                );
                assert!(left || amount != 0);
            }
        }
    }
}

#[test]
fn register_forms_preserve_count_shape_and_aliases() {
    for encoding in ENCODINGS {
        if !matches!(
            encoding.format,
            Format::PredicatedElements | Format::PredicatedDoublewords | Format::Doublewords
        ) {
            continue;
        }
        let wide = matches!(
            encoding.format,
            Format::PredicatedDoublewords | Format::Doublewords
        );
        let unpredicated = matches!(encoding.format, Format::Doublewords);
        for size in 0..=SIZE_MASK {
            let count_shift = if unpredicated {
                WIDE_SOURCE_SHIFT
            } else {
                SOURCE_SHIFT
            };
            let word = encoding.value
                | size << SIZE_SHIFT
                | REGISTER_MASK << count_shift
                | REGISTER_MASK
                | if unpredicated {
                    0
                } else {
                    PREDICATE_MASK << PREDICATE_SHIFT
                };
            let result = decode(word).expect("owned register encoding");
            if wide && size == SIZE_MASK {
                assert_eq!(result, Err(()));
                continue;
            }
            let operand = result.unwrap();
            assert_eq!(operand.destination, REGISTER_MASK as u8);
            assert_eq!(
                operand.count,
                if wide {
                    Count::Doublewords(REGISTER_MASK as u8)
                } else {
                    Count::Elements(REGISTER_MASK as u8)
                }
            );
            assert_eq!(
                operand.predication,
                if unpredicated {
                    Predication::Unpredicated
                } else {
                    Predication::Merging(PREDICATE_MASK as u8)
                }
            );
        }
    }
}

#[test]
fn xor_rotate_retains_both_inputs_and_width_rotation() {
    let word = XAR_Z_ZZI | 1 << TSIZE_LOW_SHIFT | 9 << SOURCE_SHIFT | 31;
    let operand = decode(word).unwrap().unwrap();
    assert_eq!(operand.kind, Kind::XorRotate);
    assert_eq!(operand.element_size, ElementSize::Byte);
    assert_eq!(operand.source, 31);
    assert_eq!(operand.second_source, Some(9));
    assert_eq!(operand.count, Count::Immediate(BYTE_BITS));
}
