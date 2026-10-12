//! Integer conditional selection. All register 31 operands name ZR, never SP.
use super::{Register, Width, register};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Otherwise {
    Unchanged,
    Increment,
    Invert,
    Negate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub width: Width,
    pub destination: Register,
    pub left: Register,
    pub right: Register,
    pub condition: u8,
    pub otherwise: Otherwise,
}

pub fn decode(word: u32) -> Option<Operand> {
    // sf/op vary; S, bit 21 and bit 11 are fixed. op2 is bit 10.
    if word & 0x3fe00800 != 0x1a800000 {
        return None;
    }
    Some(Operand {
        width: if word >> 31 == 0 {
            Width::W32
        } else {
            Width::X64
        },
        destination: register(word & 31, false),
        left: register((word >> 5) & 31, false),
        right: register((word >> 16) & 31, false),
        condition: ((word >> 12) & 15) as u8,
        otherwise: match ((word >> 29) & 2) | ((word >> 10) & 1) {
            0 => Otherwise::Unchanged,
            1 => Otherwise::Increment,
            2 => Otherwise::Invert,
            _ => Otherwise::Negate,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
