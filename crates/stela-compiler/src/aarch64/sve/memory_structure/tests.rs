use super::*;

const FORM_ROWS: [(u32, u8, ElementSize, bool); 30] = [
    (0xa420_e000, 2, ElementSize::Byte, true),
    (0xa420_c000, 2, ElementSize::Byte, false),
    (0xa4a0_e000, 2, ElementSize::Halfword, true),
    (0xa4a0_c000, 2, ElementSize::Halfword, false),
    (0xa520_e000, 2, ElementSize::Word, true),
    (0xa520_c000, 2, ElementSize::Word, false),
    (0xa5a0_e000, 2, ElementSize::Doubleword, true),
    (0xa5a0_c000, 2, ElementSize::Doubleword, false),
    (0xa490_e000, 2, ElementSize::Quadword, true),
    (0xa4a0_8000, 2, ElementSize::Quadword, false),
    (0xa440_e000, 3, ElementSize::Byte, true),
    (0xa440_c000, 3, ElementSize::Byte, false),
    (0xa4c0_e000, 3, ElementSize::Halfword, true),
    (0xa4c0_c000, 3, ElementSize::Halfword, false),
    (0xa540_e000, 3, ElementSize::Word, true),
    (0xa540_c000, 3, ElementSize::Word, false),
    (0xa5c0_e000, 3, ElementSize::Doubleword, true),
    (0xa5c0_c000, 3, ElementSize::Doubleword, false),
    (0xa510_e000, 3, ElementSize::Quadword, true),
    (0xa520_8000, 3, ElementSize::Quadword, false),
    (0xa460_e000, 4, ElementSize::Byte, true),
    (0xa460_c000, 4, ElementSize::Byte, false),
    (0xa4e0_e000, 4, ElementSize::Halfword, true),
    (0xa4e0_c000, 4, ElementSize::Halfword, false),
    (0xa560_e000, 4, ElementSize::Word, true),
    (0xa560_c000, 4, ElementSize::Word, false),
    (0xa5e0_e000, 4, ElementSize::Doubleword, true),
    (0xa5e0_c000, 4, ElementSize::Doubleword, false),
    (0xa590_e000, 4, ElementSize::Quadword, true),
    (0xa5a0_8000, 4, ElementSize::Quadword, false),
];

#[test]
fn all_forms_preserve_fields_and_tuple_wrap() {
    for (class, registers, width, immediate) in FORM_ROWS {
        for destination in 0..VECTOR_REGISTER_COUNT {
            for predicate in 0..=PREDICATE_MASK {
                let word = class
                    | REGISTER_FIELD_MASK << BASE_SHIFT
                    | predicate << PREDICATE_SHIFT
                    | u32::from(destination);
                let operand = decode(word).unwrap().unwrap();
                assert_eq!(operand.destination, destination);
                assert_eq!(operand.registers, registers);
                assert_eq!(operand.element, width);
                assert_eq!(operand.predicate, predicate as u8);
                assert_eq!(operand.address.base, register(REGISTER_FIELD_MASK, true));
                assert_eq!(
                    matches!(operand.address.offset, Offset::Immediate { .. }),
                    immediate
                );
                for index in 0..registers {
                    assert_eq!(
                        operand.destination_register(index),
                        (destination + index) % VECTOR_REGISTER_COUNT
                    );
                }
            }
        }
    }
}

#[test]
fn signed_immediates_and_reserved_index_registers() {
    for (class, _, _, immediate) in FORM_ROWS {
        if immediate {
            for raw in 0..=IMMEDIATE_FIELD_MASK {
                let operand = decode(class | raw << OFFSET_SHIFT).unwrap().unwrap();
                let expected = if raw < 1 << (IMMEDIATE_BITS - 1) {
                    raw as i8
                } else {
                    raw as i8 - (1 << IMMEDIATE_BITS)
                };
                assert_eq!(
                    operand.address.offset,
                    Offset::Immediate {
                        value: i16::from(expected),
                        scale: Scale::VectorBytes {
                            multiply: operand.registers,
                            divide: 1
                        }
                    }
                );
            }
        } else {
            assert_eq!(
                decode(class | REGISTER_FIELD_MASK << OFFSET_SHIFT),
                Some(Err(()))
            );
        }
    }
    assert_eq!(decode(IMMEDIATE_CLASS), None);
    assert_eq!(decode(REGISTER_CLASS), None);
    assert_eq!(decode(QUAD_IMMEDIATE_CLASS), None);
    assert_eq!(decode(QUAD_REGISTER_CLASS), None);
}
