use super::*;

#[test]
fn all_move_slices_and_vector_registers_decode() {
    for (opcode, element, slices) in [
        (PMOV_BYTE, ElementSize::Byte, 1),
        (PMOV_HALF, ElementSize::Halfword, 2),
        (PMOV_SINGLE, ElementSize::Word, 4),
        (PMOV_DOUBLE, ElementSize::Doubleword, 8),
    ] {
        for part in 0..slices {
            for source in 0..=VECTOR_MASK {
                let slice_bits = if element == ElementSize::Doubleword {
                    ((part & 3) << PMOV_IMMEDIATE_SHIFT) | ((part >> 2) << PMOV_DOUBLE_HIGH_SHIFT)
                } else {
                    part << PMOV_IMMEDIATE_SHIFT
                };
                assert_eq!(
                    decode(opcode | slice_bits | (source << SOURCE_SHIFT) | 15),
                    Some(Ok(Operand {
                        destination: 15,
                        kind: Kind::MoveVector {
                            element,
                            source: source as u8,
                            part: part as u8
                        }
                    }))
                );
            }
        }
    }
}

#[test]
fn all_permutation_element_groups_allow_operand_aliases() {
    for opcode in [ZIP1, ZIP2, TRN1, TRN2, UZP1, UZP2] {
        for size in 0..=SIZE_MASK {
            for register in 0..=PREDICATE_MASK {
                let word = opcode
                    | (size << SIZE_SHIFT)
                    | register
                    | (register << SOURCE_SHIFT)
                    | (register << RIGHT_SHIFT);
                assert!(matches!(decode(word), Some(Ok(Operand {
                    destination, kind: Kind::Permute { element, left, right, .. }
                })) if destination == register as u8 && left == destination && right == destination
                    && element.bytes() == 1 << size));
            }
        }
    }
}
