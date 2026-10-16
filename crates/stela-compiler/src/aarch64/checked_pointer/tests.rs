use super::*;

#[test]
fn offsets_preserve_sp_and_zero_roles_for_every_shift() {
    for opcode in [ADDPT, SUBPT] {
        for amount in 0..=AMOUNT_MASK {
            assert_eq!(
                decode(
                    opcode
                        | (REGISTER_MASK << SOURCE_SHIFT)
                        | (REGISTER_MASK << RIGHT_SHIFT)
                        | (amount << AMOUNT_SHIFT)
                        | REGISTER_MASK
                ),
                Some(Operand {
                    destination: Register::Sp,
                    kind: Kind::Offset {
                        base: Register::Sp,
                        offset: Register::Zero,
                        amount: amount as u8,
                        subtract: opcode == SUBPT,
                    },
                })
            );
        }
    }
}

#[test]
fn products_use_zero_for_every_register_31_role() {
    for opcode in [MADDPT, MSUBPT] {
        assert_eq!(
            decode(
                opcode
                    | (REGISTER_MASK << SOURCE_SHIFT)
                    | (REGISTER_MASK << RIGHT_SHIFT)
                    | (REGISTER_MASK << ACCUMULATOR_SHIFT)
                    | REGISTER_MASK
            ),
            Some(Operand {
                destination: Register::Zero,
                kind: Kind::Product {
                    left: Register::Zero,
                    right: Register::Zero,
                    base: Register::Zero,
                    subtract: opcode == MSUBPT,
                },
            })
        );
    }
}

#[test]
fn fixed_bits_reject_neighbours_unless_another_family_form_matches() {
    for (opcode, mask) in [
        (ADDPT, OFFSET_OPCODE_MASK),
        (SUBPT, OFFSET_OPCODE_MASK),
        (MADDPT, PRODUCT_OPCODE_MASK),
        (MSUBPT, PRODUCT_OPCODE_MASK),
    ] {
        for bit in 0..u32::BITS {
            if mask & (1 << bit) != 0 {
                let changed = opcode ^ (1 << bit);
                let belongs = [ADDPT, SUBPT].contains(&(changed & OFFSET_OPCODE_MASK))
                    || [MADDPT, MSUBPT].contains(&(changed & PRODUCT_OPCODE_MASK));
                assert_eq!(decode(changed).is_some(), belongs);
            }
        }
    }
}
