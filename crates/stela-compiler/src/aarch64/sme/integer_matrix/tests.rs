use super::*;

mod outer;

#[test]
fn add_sub_group_roles_widths_and_complete_fields() {
    for (opcode, groups) in [
        (ADD_SUB_ACCUMULATE_PAIR, 2),
        (ADD_SUB_ACCUMULATE_QUAD, 4),
        (ADD_SUB_SINGLE_PAIR, 2),
        (ADD_SUB_SINGLE_QUAD, 4),
        (ADD_SUB_GROUP_PAIR, 2),
        (ADD_SUB_GROUP_QUAD, 4),
    ] {
        for subtract in [false, true] {
            for wide in [false, true] {
                for selector in 0..=ADD_SUB_SELECTOR_MASK {
                    for offset in 0..=ADD_SUB_OFFSET_MASK {
                        let word = opcode
                            | if subtract { ADD_SUB_SIGN_BIT } else { 0 }
                            | (u32::from(wide) << ADD_SUB_SIZE_SHIFT)
                            | (selector << ADD_SUB_SELECTOR_SHIFT)
                            | offset;
                        let operation = decode_add_sub(word).unwrap();
                        assert_eq!(operation.subtract, subtract);
                        assert_eq!(operation.groups, groups);
                        assert_eq!(operation.selector, 8 + selector as u8);
                        assert_eq!(operation.offset, offset as u8);
                        assert_eq!(
                            operation.element_size,
                            if wide {
                                ElementSize::Doubleword
                            } else {
                                ElementSize::Word
                            }
                        );
                        assert!(decode(word).unwrap().requires_sme2());
                        assert_eq!(decode(word).unwrap().requires_i16i64(), wide);
                    }
                }
            }
        }
    }
}

#[test]
fn vector_groups_wrap_only_for_unaligned_first_sources() {
    let operation = decode_add_sub(
        ADD_SUB_SINGLE_QUAD | (31 << ADD_SUB_LEFT_SHIFT) | (15 << ADD_SUB_SINGLE_SHIFT),
    )
    .unwrap();
    assert_eq!(
        operation.sources,
        AddSubSources::GroupSingle {
            left: 31,
            right: 15
        }
    );
    let operation = decode_add_sub(
        ADD_SUB_GROUP_QUAD
            | (ADD_SUB_QUAD_GROUP_MASK << ADD_SUB_QUAD_LEFT_SHIFT)
            | (ADD_SUB_QUAD_GROUP_MASK << ADD_SUB_QUAD_RIGHT_SHIFT),
    )
    .unwrap();
    assert_eq!(
        operation.sources,
        AddSubSources::GroupGroup {
            left: 28,
            right: 28
        }
    );
    let operation = decode_add_sub(
        ADD_SUB_ACCUMULATE_PAIR | (ADD_SUB_PAIR_GROUP_MASK << ADD_SUB_PAIR_LEFT_SHIFT),
    )
    .unwrap();
    assert_eq!(
        operation.sources,
        AddSubSources::AccumulatorGroup { right: 30 }
    );
}

#[test]
fn long_index_fields_and_source_signedness_are_independent() {
    let signed = decode_long(0xc1c0_1000 | (1 << 15) | (3 << 10)).unwrap();
    assert_eq!(signed.indexed_lane, Some(7));
    assert!(signed.signed_left && signed.signed_right);
    assert_eq!(signed.factor, 2);
    assert_eq!(signed.source_size, ElementSize::Halfword);
    assert_eq!(signed.accumulator_size, ElementSize::Word);
    let unsigned_signed = decode_long(0xc130_0004 | (31 << 5)).unwrap();
    assert!(!unsigned_signed.signed_left && unsigned_signed.signed_right);
    assert_eq!(unsigned_signed.source_left, 31);
    assert!(unsigned_signed.wrap_left);
    assert_eq!(unsigned_signed.factor, 4);
    assert_eq!(unsigned_signed.group_size, 4);
    let wide = decode_long(0xc120_0400 | (1 << 22)).unwrap();
    assert_eq!(wide.source_size, ElementSize::Halfword);
    assert_eq!(wide.accumulator_size, ElementSize::Doubleword);
    assert!(decode(0).is_none());
}
