use super::*;

#[test]
fn complete_allocated_width_direction_hint_address_and_tuple_combinations() {
    for loading in [false, true] {
        for non_temporal in [false, true] {
            for element in 0..=ELEMENT_MASK {
                for quad in [false, true] {
                    for immediate in [false, true] {
                        for first in (0..32).step_by(if quad { 4 } else { 2 }) {
                            for predicate in 0..=PREDICATE_MASK {
                                let word = CLASS_VALUE
                                    | if loading { 0 } else { STORE }
                                    | if non_temporal { NON_TEMPORAL } else { 0 }
                                    | (element << ELEMENT_SHIFT)
                                    | if quad { FOUR_REGISTERS } else { 0 }
                                    | if immediate { IMMEDIATE_ADDRESS } else { 0 }
                                    | (predicate << PREDICATE_SHIFT)
                                    | (REGISTER_MASK << BASE_SHIFT)
                                    | first;
                                let operand = decode(word).unwrap().unwrap();
                                assert_eq!(operand.loading, loading);
                                assert_eq!(operand.non_temporal, non_temporal);
                                assert_eq!(operand.element.bytes(), 1 << element);
                                assert_eq!(operand.registers, if quad { 4 } else { 2 });
                                assert_eq!(operand.first, first as u8);
                                assert_eq!(
                                    operand.predicate,
                                    FIRST_COUNTER_REGISTER + predicate as u8
                                );
                                assert_eq!(operand.address.base, Register::Sp);
                                assert_eq!(operand.tag_checked(), !immediate);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn signed_tuple_offsets_and_zero_register_offsets_remain_distinct() {
    for raw in 0..=IMMEDIATE_MASK {
        let operand = decode(CLASS_VALUE | IMMEDIATE_ADDRESS | (raw << OFFSET_SHIFT))
            .unwrap()
            .unwrap();
        assert_eq!(
            operand.address.offset,
            Offset::Immediate {
                value: i16::from(if raw >= IMMEDIATE_SIGN as u32 {
                    raw as i8 - IMMEDIATE_MODULUS
                } else {
                    raw as i8
                }),
                scale: Scale::VectorBytes {
                    multiply: 2,
                    divide: 1
                },
            }
        );
    }
    let operand = decode(CLASS_VALUE | (REGISTER_MASK << OFFSET_SHIFT))
        .unwrap()
        .unwrap();
    assert_eq!(
        operand.address.offset,
        Offset::Register {
            index: Register::Zero,
            shift: 0
        }
    );
}

#[test]
fn reserved_fields_are_explicit_and_other_classes_do_not_match() {
    assert_eq!(
        decode(CLASS_VALUE | FOUR_REGISTERS | QUAD_RESERVED),
        Some(Err(()))
    );
    assert_eq!(
        decode(CLASS_VALUE | IMMEDIATE_ADDRESS | IMMEDIATE_RESERVED),
        Some(Err(()))
    );
    for bit in 23..32 {
        assert_eq!(decode(CLASS_VALUE ^ (1 << bit)), None);
    }
}
