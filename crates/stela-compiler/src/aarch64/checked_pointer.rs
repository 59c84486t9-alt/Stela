//! FEAT_CPA checked pointer arithmetic: ADDPT, SUBPT, MADDPT and MSUBPT.
use super::{Register, register};

const OFFSET_OPCODE_MASK: u32 = 0xffe0_e000;
const PRODUCT_OPCODE_MASK: u32 = 0xffe0_8000;
const ADDPT: u32 = 0x9a00_2000;
const SUBPT: u32 = 0xda00_2000;
const MADDPT: u32 = 0x9b60_0000;
const MSUBPT: u32 = 0x9b60_8000;
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const ACCUMULATOR_SHIFT: u32 = 10;
const AMOUNT_SHIFT: u32 = 10;
const AMOUNT_MASK: u32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Offset {
        base: Register,
        offset: Register,
        amount: u8,
        subtract: bool,
    },
    Product {
        left: Register,
        right: Register,
        base: Register,
        subtract: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: Register,
    pub kind: Kind,
}

/// Recognizes the encoding only. The entry owner must separately prove FEAT_CPA.
pub fn decode(word: u32) -> Option<Operand> {
    let (kind, destination_sp) = match word & OFFSET_OPCODE_MASK {
        ADDPT | SUBPT => (
            Kind::Offset {
                base: register((word >> SOURCE_SHIFT) & REGISTER_MASK, true),
                offset: register((word >> RIGHT_SHIFT) & REGISTER_MASK, false),
                amount: ((word >> AMOUNT_SHIFT) & AMOUNT_MASK) as u8,
                subtract: word & OFFSET_OPCODE_MASK == SUBPT,
            },
            true,
        ),
        _ => match word & PRODUCT_OPCODE_MASK {
            MADDPT | MSUBPT => (
                Kind::Product {
                    left: register((word >> SOURCE_SHIFT) & REGISTER_MASK, false),
                    right: register((word >> RIGHT_SHIFT) & REGISTER_MASK, false),
                    base: register((word >> ACCUMULATOR_SHIFT) & REGISTER_MASK, false),
                    subtract: word & PRODUCT_OPCODE_MASK == MSUBPT,
                },
                false,
            ),
            _ => return None,
        },
    };
    Some(Operand {
        destination: register(word & REGISTER_MASK, destination_sp),
        kind,
    })
}

#[cfg(test)]
mod tests {
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
}
