use super::*;

#[test]
fn conditional_compare_widths_modes_conditions_fallbacks_and_fixed_bits() {
    for sf in 0..2 {
        for subtract in 0..2 {
            for immediate in 0..2 {
                let base = (sf << 31) | (subtract << 30) | (immediate << 11) | 0x3a400000;
                for condition in 0..16 {
                    for fallback in 0..16 {
                        let word = base | (31 << 16) | (condition << 12) | (31 << 5) | fallback;
                        assert_eq!(
                            decode_compare(word),
                            Some(CompareOperand {
                                width: if sf == 0 { Width::W32 } else { Width::X64 },
                                subtract: subtract != 0,
                                left: Register::Zero,
                                right: if immediate == 0 {
                                    CompareRight::Register(Register::Zero)
                                } else {
                                    CompareRight::Immediate(31)
                                },
                                condition: condition as u8,
                                fallback: fallback as u8,
                            })
                        );
                    }
                }
                for bit in 0..32 {
                    if 0x3fe00410 & (1 << bit) != 0 {
                        assert!(decode_compare(base ^ (1 << bit)).is_none());
                    }
                }
            }
        }
    }
}

#[test]
fn all_conditions_and_zero_registers_preserve_operand_roles() {
    for width in [Width::W32, Width::X64] {
        for (op, otherwise) in [
            Otherwise::Unchanged,
            Otherwise::Increment,
            Otherwise::Invert,
            Otherwise::Negate,
        ]
        .into_iter()
        .enumerate()
        {
            for condition in 0..16 {
                let word = 0x1a9f03ff
                    | (u32::from(width == Width::X64) << 31)
                    | (((op as u32) >> 1) << 30)
                    | (((op as u32) & 1) << 10)
                    | (condition << 12);
                assert_eq!(
                    decode(word),
                    Some(Operand {
                        width,
                        destination: Register::Zero,
                        left: Register::Zero,
                        right: Register::Zero,
                        condition: condition as u8,
                        otherwise
                    })
                );
            }
        }
    }
}

#[test]
fn fixed_encoding_bits_are_not_ignored() {
    for bit in 0..32 {
        if 0x3fe00800u32 & (1 << bit) != 0 {
            assert!(decode(0x9a820020 ^ (1 << bit)).is_none());
        }
    }
    assert!(decode(0x9a820020).is_some());
    assert!(decode(0xfa420000).is_none()); // conditional compare
    assert!(decode(0x9a020020).is_none()); // carry arithmetic
}
