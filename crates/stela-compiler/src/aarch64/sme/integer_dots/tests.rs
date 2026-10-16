use super::*;

#[test]
fn canonical_forms_and_variable_size_decode() {
    for encoding in ENCODINGS {
        let operand = decode(encoding.value).expect("canonical form");
        assert_eq!(operand.terms, encoding.terms);
        assert_eq!(operand.groups, encoding.groups);
        assert_eq!(
            operand.accumulator.bits(),
            usize::from(encoding.accumulator_bits)
        );
        if encoding.dynamic_size {
            assert_eq!(
                decode(encoding.value | (1 << SIZE_SHIFT))
                    .unwrap()
                    .accumulator
                    .bits(),
                64
            );
        }
    }
}

#[test]
fn operand_extremes_match_encoded_group_and_index_fields() {
    for encoding in ENCODINGS {
        for size in 0..=u32::from(encoding.dynamic_size) {
            let word = encoding.value
                | (encoding.left_mask << encoding.left_shift)
                | (encoding.right_mask << encoding.right_shift)
                | (SELECTOR_MASK << SELECTOR_SHIFT)
                | OFFSET_MASK
                | (size << SIZE_SHIFT);
            let operand = decode(word).unwrap();
            assert_eq!(operand.left, encoding.left_mask as u8 * encoding.left_scale);
            assert_eq!(operand.selector, 11);
            assert_eq!(operand.offset, 7);
            assert!(operand.left_register(operand.groups - 1, operand.terms - 1) < 32);
            assert!(operand.right_register(operand.groups - 1) < 32);
            if let RightSource::Indexed { index, .. } = operand.right {
                assert_eq!(index, 0);
                let maximum_index = (VECTOR_SEGMENT_BITS / operand.accumulator.bits() - 1) as u8;
                assert_eq!(
                    decode(word | (u32::from(maximum_index) << INDEX_SHIFT))
                        .unwrap()
                        .right,
                    RightSource::Indexed {
                        register: operand.right_register(0),
                        index: maximum_index
                    }
                );
            }
        }
    }
}

#[test]
fn vector_first_source_wraps_but_vertical_transposes_registers() {
    let ordinary = decode(0xc120_1400 | (31 << 5)).unwrap();
    assert_eq!(ordinary.left_register(1, 0), 0);
    let vertical = decode(0xc150_8020).unwrap();
    assert_eq!(vertical.left_register(3, 2), 2);
    assert!(decode(0).is_none());
}
