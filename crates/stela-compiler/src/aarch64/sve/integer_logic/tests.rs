use super::*;

mod prefix_requirement;

#[test]
fn destructive_and_constructive_register_roles_include_z31() {
    for destination in 0..=REGISTER_MASK {
        for source in 0..=REGISTER_MASK {
            let operand = decode(AND_PREDICATED | (source << SOURCE_SHIFT) | destination)
                .unwrap()
                .unwrap();
            assert_eq!(
                operand.kind,
                Kind::Binary {
                    operation: Boolean::And,
                    left: destination as u8,
                    right: source as u8,
                }
            );
            let operand =
                decode(BCAX | (source << RIGHT_SHIFT) | (31 << SOURCE_SHIFT) | destination)
                    .unwrap()
                    .unwrap();
            assert_eq!(
                operand.kind,
                Kind::Ternary {
                    operation: Ternary::BitClearXor,
                    right: source as u8,
                    mask: 31,
                }
            );
        }
    }
}

#[test]
fn copies_distinguish_full_predicate_range_sp_and_reserved_byte_shift() {
    for size in 0..=SIZE_MASK {
        for predicate in 0..=WIDE_PREDICATE_MASK {
            for shifted in [false, true] {
                let word = COPY_IMMEDIATE_ZERO
                    | (size << SIZE_SHIFT)
                    | (predicate << COPY_PREDICATE_SHIFT)
                    | (255 << SOURCE_SHIFT)
                    | if shifted { COPY_SHIFT_FLAG } else { 0 };
                let result = decode(word).unwrap();
                if size == 0 && shifted {
                    assert_eq!(result, Err(()));
                } else {
                    let operand = result.unwrap();
                    assert_eq!(operand.predication, Predication::Zeroing(predicate as u8));
                    assert_eq!(
                        operand.kind,
                        Kind::Copy(CopySource::Immediate(if shifted { -256 } else { -1 }))
                    );
                }
            }
        }
    }
    assert_eq!(
        decode(COPY_REGISTER | (31 << SOURCE_SHIFT))
            .unwrap()
            .unwrap()
            .kind,
        Kind::Copy(CopySource::General(Register::Sp))
    );
}

#[test]
fn reserved_logical_immediates_decline_and_zeroing_unary_is_outside_inventory() {
    for opcode in [AND_IMMEDIATE, ORR_IMMEDIATE, EOR_IMMEDIATE] {
        assert_eq!(decode(opcode | (63 << SOURCE_SHIFT)), Some(Err(())));
        assert!(decode(opcode).unwrap().is_ok());
    }
    assert_eq!(decode(NOT_PREDICATED ^ (1 << 20)), None);
    assert_eq!(decode(CNOT_PREDICATED ^ (1 << 20)), None);
}
