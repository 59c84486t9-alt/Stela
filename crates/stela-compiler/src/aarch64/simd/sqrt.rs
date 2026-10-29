//! Scalar and AdvSIMD FSQRT.
use crate::aarch64::Unsupported;
use crate::aarch64::floating::Format;

use super::arithmetic::Shape;

const SCALAR_MASK: u32 = 0xff3f_fc00;
const SCALAR_FSQRT: u32 = 0x1e21_c000;
const VECTOR_MASK: u32 = 0xbfbf_fc00;
const VECTOR_FSQRT: u32 = 0x2ea1_f800;
const VECTOR_HALF_MASK: u32 = 0xbfff_fc00;
const VECTOR_HALF_FSQRT: u32 = 0x2ef9_f800;
const FORMAT_SHIFT: u32 = 22;
const FORMAT_MASK: u32 = 3;
const FORMAT_SINGLE: u32 = 0;
const FORMAT_DOUBLE: u32 = 1;
const FORMAT_HALF: u32 = 3;
const VECTOR_Q: u32 = 1 << 30;
const VECTOR_DOUBLE: u32 = 1 << 22;
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub format: Format,
    pub shape: Shape,
    pub destination: u8,
    pub source: u8,
}

/// None denotes another family; Err denotes reserved scalar ftype or vector1D.
/// Every register field denotes ordinary V data, including V31.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    let (format, shape) = if word & SCALAR_MASK == SCALAR_FSQRT {
        let format = match (word >> FORMAT_SHIFT) & FORMAT_MASK {
            FORMAT_SINGLE => Format::Single,
            FORMAT_DOUBLE => Format::Double,
            FORMAT_HALF => Format::Half,
            _ => return Some(Err(Unsupported)),
        };
        (format, Shape::Scalar)
    } else {
        let format = if word & VECTOR_HALF_MASK == VECTOR_HALF_FSQRT {
            Format::Half
        } else if word & VECTOR_MASK == VECTOR_FSQRT {
            if word & VECTOR_DOUBLE == 0 {
                Format::Single
            } else {
                Format::Double
            }
        } else {
            return None;
        };
        let shape = if word & VECTOR_Q == 0 {
            Shape::Vector64
        } else {
            Shape::Vector128
        };
        if format == Format::Double && shape == Shape::Vector64 {
            return Some(Err(Unsupported));
        }
        (format, shape)
    };
    Some(Ok(Operand {
        format,
        shape,
        destination: (word & REGISTER_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_eight_arrangements_cover_every_register_pair_and_alias() {
        const ARRANGEMENTS: [(u32, Format, Shape); 8] = [
            (SCALAR_FSQRT, Format::Single, Shape::Scalar),
            (
                SCALAR_FSQRT | (FORMAT_DOUBLE << FORMAT_SHIFT),
                Format::Double,
                Shape::Scalar,
            ),
            (
                SCALAR_FSQRT | (FORMAT_HALF << FORMAT_SHIFT),
                Format::Half,
                Shape::Scalar,
            ),
            (VECTOR_FSQRT, Format::Single, Shape::Vector64),
            (VECTOR_FSQRT | VECTOR_Q, Format::Single, Shape::Vector128),
            (
                VECTOR_FSQRT | VECTOR_DOUBLE | VECTOR_Q,
                Format::Double,
                Shape::Vector128,
            ),
            (VECTOR_HALF_FSQRT, Format::Half, Shape::Vector64),
            (VECTOR_HALF_FSQRT | VECTOR_Q, Format::Half, Shape::Vector128),
        ];
        for (encoding, format, shape) in ARRANGEMENTS {
            for destination in 0..=REGISTER_MASK {
                for source in 0..=REGISTER_MASK {
                    let word = encoding | destination | (source << SOURCE_SHIFT);
                    assert_eq!(
                        decode(word),
                        Some(Ok(Operand {
                            format,
                            shape,
                            destination: destination as u8,
                            source: source as u8,
                        })),
                        "word={word:08x}"
                    );
                }
            }
        }
    }

    #[test]
    fn reserved_scalar_format_and_vector_one_double_decline_for_all_registers() {
        const FORMAT_RESERVED: u32 = 2;
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                let registers = destination | (source << SOURCE_SHIFT);
                assert_eq!(
                    decode(SCALAR_FSQRT | (FORMAT_RESERVED << FORMAT_SHIFT) | registers),
                    Some(Err(Unsupported))
                );
                assert_eq!(
                    decode(VECTOR_FSQRT | VECTOR_DOUBLE | registers),
                    Some(Err(Unsupported))
                );
            }
        }
    }

    #[test]
    fn fixed_bit_changes_do_not_keep_sqrt_semantics() {
        for (encoding, mask) in [
            (SCALAR_FSQRT, SCALAR_MASK),
            (VECTOR_FSQRT, VECTOR_MASK),
            (VECTOR_HALF_FSQRT, VECTOR_HALF_MASK),
        ] {
            for bit in 0..u32::BITS {
                if mask & (1 << bit) != 0 {
                    assert_eq!(decode(encoding ^ (1 << bit)), None);
                }
            }
        }
    }

    #[test]
    fn allocated_rounding_comparison_and_estimate_neighbors_stay_separate() {
        // Neighboring forms: scalar and vector FRINT64X, scalar FRINTN, FRSQRTE,
        // FRECPE, FCMP, FCVT and MOVI.
        const NEIGHBORS: [u32; 8] = [
            0x1e29_c000,
            0x2e21_f800,
            0x1e24_4000,
            0x2ea1_d800,
            0x0ea1_d800,
            0x1e20_2000,
            0x1e22_c000,
            0x6f00_e400,
        ];
        for word in NEIGHBORS {
            assert_eq!(decode(word), None, "word={word:08x}");
        }
    }
}
