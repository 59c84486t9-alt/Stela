//! Scalar and AdvSIMD FRINT*.
use crate::aarch64::Unsupported;
use crate::aarch64::floating::{Format, rounding::RoundingOperation};

use super::arithmetic::Shape;

const SCALAR_MASK: u32 = 0xff3f_fc00;
const SCALAR_FRINTN: u32 = 0x1e24_4000;
const SCALAR_FRINTA: u32 = 0x1e26_4000;
const SCALAR_FRINTP: u32 = 0x1e24_c000;
const SCALAR_FRINTM: u32 = 0x1e25_4000;
const SCALAR_FRINTZ: u32 = 0x1e25_c000;
const SCALAR_FRINTI: u32 = 0x1e27_c000;
const SCALAR_FRINTX: u32 = 0x1e27_4000;
const SCALAR_FRINT32Z: u32 = 0x1e28_4000;
const SCALAR_FRINT32X: u32 = 0x1e28_c000;
const SCALAR_FRINT64Z: u32 = 0x1e29_4000;
const SCALAR_FRINT64X: u32 = 0x1e29_c000;

const VECTOR_MASK: u32 = 0xbfbf_fc00;
const VECTOR_HALF_MASK: u32 = 0xbfff_fc00;
const VECTOR_HALF_ADJUSTMENT: u32 = 0x0058_0000;
const VECTOR_FRINTN: u32 = 0x0e21_8800;
const VECTOR_FRINTA: u32 = 0x2e21_8800;
const VECTOR_FRINTP: u32 = 0x0ea1_8800;
const VECTOR_FRINTM: u32 = 0x0e21_9800;
const VECTOR_FRINTZ: u32 = 0x0ea1_9800;
const VECTOR_FRINTI: u32 = 0x2ea1_9800;
const VECTOR_FRINTX: u32 = 0x2e21_9800;
const VECTOR_FRINT32Z: u32 = 0x0e21_e800;
const VECTOR_FRINT32X: u32 = 0x2e21_e800;
const VECTOR_FRINT64Z: u32 = 0x0e21_f800;
const VECTOR_FRINT64X: u32 = 0x2e21_f800;

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
    pub operation: RoundingOperation,
    pub format: Format,
    pub shape: Shape,
    pub destination: u8,
    pub source: u8,
}

fn scalar_operation(opcode: u32) -> Option<RoundingOperation> {
    Some(match opcode {
        SCALAR_FRINTN => RoundingOperation::NearestEven,
        SCALAR_FRINTA => RoundingOperation::NearestAway,
        SCALAR_FRINTP => RoundingOperation::TowardPositive,
        SCALAR_FRINTM => RoundingOperation::TowardNegative,
        SCALAR_FRINTZ => RoundingOperation::TowardZero,
        SCALAR_FRINTI => RoundingOperation::Current,
        SCALAR_FRINTX => RoundingOperation::CurrentExact,
        SCALAR_FRINT32Z => RoundingOperation::Signed32Zero,
        SCALAR_FRINT32X => RoundingOperation::Signed32Current,
        SCALAR_FRINT64Z => RoundingOperation::Signed64Zero,
        SCALAR_FRINT64X => RoundingOperation::Signed64Current,
        _ => return None,
    })
}

fn vector_operation(opcode: u32) -> Option<RoundingOperation> {
    Some(match opcode {
        VECTOR_FRINTN => RoundingOperation::NearestEven,
        VECTOR_FRINTA => RoundingOperation::NearestAway,
        VECTOR_FRINTP => RoundingOperation::TowardPositive,
        VECTOR_FRINTM => RoundingOperation::TowardNegative,
        VECTOR_FRINTZ => RoundingOperation::TowardZero,
        VECTOR_FRINTI => RoundingOperation::Current,
        VECTOR_FRINTX => RoundingOperation::CurrentExact,
        VECTOR_FRINT32Z => RoundingOperation::Signed32Zero,
        VECTOR_FRINT32X => RoundingOperation::Signed32Current,
        VECTOR_FRINT64Z => RoundingOperation::Signed64Zero,
        VECTOR_FRINT64X => RoundingOperation::Signed64Current,
        _ => return None,
    })
}

/// None denotes another family; Err denotes reserved scalar ftype, bounded H
/// or vector1D. Every register field denotes ordinary V data, including V31.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    let (operation, format, shape) = if let Some(operation) = scalar_operation(word & SCALAR_MASK) {
        let format = match (word >> FORMAT_SHIFT) & FORMAT_MASK {
            FORMAT_SINGLE => Format::Single,
            FORMAT_DOUBLE => Format::Double,
            FORMAT_HALF if operation.signed_width().is_none() => Format::Half,
            _ => return Some(Err(Unsupported)),
        };
        (operation, format, Shape::Scalar)
    } else {
        let (operation, format) = if let Some(operation) = vector_operation(word & VECTOR_MASK) {
            (
                operation,
                if word & VECTOR_DOUBLE == 0 {
                    Format::Single
                } else {
                    Format::Double
                },
            )
        } else {
            let operation = vector_operation((word & VECTOR_HALF_MASK) ^ VECTOR_HALF_ADJUSTMENT)?;
            if operation.signed_width().is_some() {
                return None;
            }
            (operation, Format::Half)
        };
        let shape = if word & VECTOR_Q == 0 {
            Shape::Vector64
        } else {
            Shape::Vector128
        };
        if format == Format::Double && shape == Shape::Vector64 {
            return Some(Err(Unsupported));
        }
        (operation, format, shape)
    };
    Some(Ok(Operand {
        operation,
        format,
        shape,
        destination: (word & REGISTER_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATIONS: [(u32, u32, RoundingOperation); 11] = [
        (SCALAR_FRINTN, VECTOR_FRINTN, RoundingOperation::NearestEven),
        (SCALAR_FRINTA, VECTOR_FRINTA, RoundingOperation::NearestAway),
        (
            SCALAR_FRINTP,
            VECTOR_FRINTP,
            RoundingOperation::TowardPositive,
        ),
        (
            SCALAR_FRINTM,
            VECTOR_FRINTM,
            RoundingOperation::TowardNegative,
        ),
        (SCALAR_FRINTZ, VECTOR_FRINTZ, RoundingOperation::TowardZero),
        (SCALAR_FRINTI, VECTOR_FRINTI, RoundingOperation::Current),
        (
            SCALAR_FRINTX,
            VECTOR_FRINTX,
            RoundingOperation::CurrentExact,
        ),
        (
            SCALAR_FRINT32Z,
            VECTOR_FRINT32Z,
            RoundingOperation::Signed32Zero,
        ),
        (
            SCALAR_FRINT32X,
            VECTOR_FRINT32X,
            RoundingOperation::Signed32Current,
        ),
        (
            SCALAR_FRINT64Z,
            VECTOR_FRINT64Z,
            RoundingOperation::Signed64Zero,
        ),
        (
            SCALAR_FRINT64X,
            VECTOR_FRINT64X,
            RoundingOperation::Signed64Current,
        ),
    ];

    fn check_registers(word: u32, operation: RoundingOperation, format: Format, shape: Shape) {
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                let word = word | destination | (source << SOURCE_SHIFT);
                assert_eq!(
                    decode(word),
                    Some(Ok(Operand {
                        operation,
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

    #[test]
    fn scalar_operation_formats_and_all_register_aliases_are_explicit() {
        let mut arrangements = 0;
        for (scalar, _, operation) in OPERATIONS {
            for (field, format) in [
                (FORMAT_SINGLE, Format::Single),
                (FORMAT_DOUBLE, Format::Double),
                (FORMAT_HALF, Format::Half),
            ] {
                if format == Format::Half && operation.signed_width().is_some() {
                    assert_eq!(
                        decode(scalar | (field << FORMAT_SHIFT)),
                        Some(Err(Unsupported))
                    );
                    continue;
                }
                check_registers(
                    scalar | (field << FORMAT_SHIFT),
                    operation,
                    format,
                    Shape::Scalar,
                );
                arrangements += 1;
            }
        }
        assert_eq!(arrangements, 29);
    }

    #[test]
    fn vector_operation_shapes_and_all_register_aliases_are_explicit() {
        let mut arrangements = 0;
        for (_, vector, operation) in OPERATIONS {
            for (adjustment, format) in [
                (0, Format::Single),
                (VECTOR_DOUBLE, Format::Double),
                (VECTOR_HALF_ADJUSTMENT, Format::Half),
            ] {
                for (q, shape) in [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)] {
                    let word = (vector ^ adjustment) | q;
                    if format == Format::Half && operation.signed_width().is_some() {
                        assert_eq!(decode(word), None);
                        continue;
                    }
                    if format == Format::Double && shape == Shape::Vector64 {
                        assert_eq!(decode(word), Some(Err(Unsupported)));
                        continue;
                    }
                    check_registers(word, operation, format, shape);
                    arrangements += 1;
                }
            }
        }
        assert_eq!(arrangements, 47);
    }

    #[test]
    fn reserved_fields_decline_for_every_register_pair() {
        const RESERVED_FORMAT: u32 = 2;
        for (scalar, vector, operation) in OPERATIONS {
            for destination in 0..=REGISTER_MASK {
                for source in 0..=REGISTER_MASK {
                    let registers = destination | (source << SOURCE_SHIFT);
                    assert_eq!(
                        decode(scalar | (RESERVED_FORMAT << FORMAT_SHIFT) | registers),
                        Some(Err(Unsupported))
                    );
                    assert_eq!(
                        decode(vector | VECTOR_DOUBLE | registers),
                        Some(Err(Unsupported))
                    );
                    if operation.signed_width().is_some() {
                        assert_eq!(
                            decode(scalar | (FORMAT_HALF << FORMAT_SHIFT) | registers),
                            Some(Err(Unsupported))
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn allocated_neighbors_remain_owned_by_their_existing_families() {
        // Neighboring forms: FSQRT, FCVT, FCMP, FMAX, scalar FMOV, FCVTNS, vector
        // FRECPE/FCVTN/FCMEQ and the modified-immediate class.
        const NEIGHBORS: [u32; 10] = [
            0x1e21_c000,
            0x1e22_c000,
            0x1e20_2000,
            0x1e20_4800,
            0x1e20_4000,
            0x1e20_0000,
            0x0ea1_d800,
            0x0e21_6800,
            0x0e20_e400,
            0x6f00_e400,
        ];
        for word in NEIGHBORS {
            assert_eq!(decode(word), None, "word={word:08x}");
        }
    }
}
