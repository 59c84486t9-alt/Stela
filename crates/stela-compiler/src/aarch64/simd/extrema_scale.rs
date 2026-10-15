//! AdvSIMD absolute extrema and integer power-of-two scaling (Arm A64 June 2026).
//!
//! FAMIN/MAX require AdvSIMD + FAMINMAX; FSCALE requires FP8. Decoding does
//! not establish guest feature availability or FP/AdvSIMD access permission.
use crate::aarch64::floating::{Format, absolute_minmax::AbsoluteMinMaxOperation};

use super::arithmetic::Shape;

const REGISTER_MASK: u32 = 31;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const VECTOR_Q: u32 = 1 << 30;
const DOUBLE_SIZE: u32 = 1 << 22;
const ORDINARY_MASK: u32 = 0xbfa0_fc00;
const HALF_MASK: u32 = 0xbfe0_fc00;
const FAMAX: u32 = 0x0ea0_dc00;
const FAMIN: u32 = 0x2ea0_dc00;
const FSCALE: u32 = 0x2ea0_fc00;
const HALF_FAMAX: u32 = 0x0ec0_1c00;
const HALF_FAMIN: u32 = 0x2ec0_1c00;
const HALF_FSCALE: u32 = 0x2ec0_3c00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Absolute(AbsoluteMinMaxOperation),
    Scale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub format: Format,
    pub shape: Shape,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
}

/// V31 is ordinary data in every position. Q=0 writes clear the upper 64 bits.
/// The one-double arrangement is reserved; scalar/pairwise neighbors decline.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    for (mask, half) in [(HALF_MASK, true), (ORDINARY_MASK, false)] {
        let kind = match (word & mask, half) {
            (HALF_FAMAX, true) | (FAMAX, false) => Kind::Absolute(AbsoluteMinMaxOperation::Maximum),
            (HALF_FAMIN, true) | (FAMIN, false) => Kind::Absolute(AbsoluteMinMaxOperation::Minimum),
            (HALF_FSCALE, true) | (FSCALE, false) => Kind::Scale,
            _ => continue,
        };
        let format = if half {
            Format::Half
        } else if word & DOUBLE_SIZE != 0 {
            Format::Double
        } else {
            Format::Single
        };
        let shape = if word & VECTOR_Q == 0 {
            Shape::Vector64
        } else {
            Shape::Vector128
        };
        if format == Format::Double && shape == Shape::Vector64 {
            return Some(Err(()));
        }
        return Some(Ok(Operand {
            kind,
            format,
            shape,
            destination: (word & REGISTER_MASK) as u8,
            left: ((word >> LEFT_SHIFT) & REGISTER_MASK) as u8,
            right: ((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8,
        }));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_allocated_arrangements_and_register_aliases_decode() {
        for (ordinary, half, kind) in [
            (
                FAMAX,
                HALF_FAMAX,
                Kind::Absolute(AbsoluteMinMaxOperation::Maximum),
            ),
            (
                FAMIN,
                HALF_FAMIN,
                Kind::Absolute(AbsoluteMinMaxOperation::Minimum),
            ),
            (FSCALE, HALF_FSCALE, Kind::Scale),
        ] {
            for (base, format) in [
                (ordinary, Format::Single),
                (ordinary | DOUBLE_SIZE, Format::Double),
                (half, Format::Half),
            ] {
                for (q, shape) in [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)] {
                    for (destination, left, right) in [
                        (0, 1, 2),
                        (0, 0, 2),
                        (0, 1, 0),
                        (0, 1, 1),
                        (0, 0, 0),
                        (31, 31, 31),
                        (31, 0, 30),
                        (28, 31, 0),
                    ] {
                        let word =
                            base | q | destination | (left << LEFT_SHIFT) | (right << RIGHT_SHIFT);
                        let expected = if format == Format::Double && shape == Shape::Vector64 {
                            Err(())
                        } else {
                            Ok(Operand {
                                kind,
                                format,
                                shape,
                                destination: destination as u8,
                                left: left as u8,
                                right: right as u8,
                            })
                        };
                        assert_eq!(decode(word), Some(expected), "{word:08x}");
                    }
                }
            }
        }
    }

    #[test]
    fn neighboring_families_and_unallocated_sizes_are_not_consumed() {
        for word in [
            0x0e20_dc00,
            0x2e20_dc00,
            0x0e40_1c00,
            0x2e40_1c00,
            0x0e20_f400,
            0x2e20_f400,
            0x1e20_4800,
            0x0e20_e400,
        ] {
            assert_eq!(decode(word), None, "{word:08x}");
        }
    }
}
