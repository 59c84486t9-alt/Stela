//! Scalar, vector, indexed and pairwise FP arithmetic (Arm A64 2026-06).
use crate::aarch64::floating::{BinaryOperation, Format};

const SCALAR_MASK: u32 = 0xff20_fc00;
const FADD: u32 = 0x1e20_2800;
const FSUB: u32 = 0x1e20_3800;
const FMUL: u32 = 0x1e20_0800;
const FDIV: u32 = 0x1e20_1800;
const FNMUL: u32 = 0x1e20_8800;
const VECTOR_MASK: u32 = 0xbfa0_fc00;
const VECTOR_FADD: u32 = 0x0e20_d400;
const VECTOR_FSUB: u32 = 0x0ea0_d400;
const VECTOR_FMUL: u32 = 0x2e20_dc00;
const VECTOR_FDIV: u32 = 0x2e20_fc00;
const VECTOR_FABD: u32 = 0x2ea0_d400;
const VECTOR_FMULX: u32 = 0x0e20_dc00;
const VECTOR_FADDP: u32 = 0x2e20_d400;
const VECTOR_HALF_MASK: u32 = 0xbfe0_fc00;
const VECTOR_HALF_FADD: u32 = 0x0e40_1400;
const VECTOR_HALF_FSUB: u32 = 0x0ec0_1400;
const VECTOR_HALF_FMUL: u32 = 0x2e40_1c00;
const VECTOR_HALF_FDIV: u32 = 0x2e40_3c00;
const VECTOR_HALF_FABD: u32 = 0x2ec0_1400;
const VECTOR_HALF_FMULX: u32 = 0x0e40_1c00;
const VECTOR_HALF_FADDP: u32 = 0x2e40_1400;
const SIMD_SCALAR_MASK: u32 = 0xffa0_fc00;
const SIMD_SCALAR_HALF_MASK: u32 = 0xffe0_fc00;
const SCALAR_FABD: u32 = 0x7ea0_d400;
const SCALAR_FMULX: u32 = 0x5e20_dc00;
const SCALAR_HALF_FABD: u32 = 0x7ec0_1400;
const SCALAR_HALF_FMULX: u32 = 0x5e40_1c00;
const PAIR_SCALAR_MASK: u32 = 0xffbf_fc00;
const SCALAR_FADDP: u32 = 0x7e30_d800;
const SCALAR_HALF_FADDP: u32 = 0x5e30_d800;
// These masks combine FMUL and FMULX; bit29 selects extended multiplication.
const INDEXED_SCALAR_HALF_MASK: u32 = 0xdfc0_f400;
const INDEXED_SCALAR_HALF: u32 = 0x5f00_9000;
const INDEXED_SCALAR_MASK: u32 = 0xdf80_f400;
const INDEXED_SCALAR: u32 = 0x5f80_9000;
const INDEXED_VECTOR_HALF_MASK: u32 = 0x9fc0_f400;
const INDEXED_VECTOR_HALF: u32 = 0x0f00_9000;
const INDEXED_VECTOR_MASK: u32 = 0x9f80_f400;
const INDEXED_VECTOR: u32 = 0x0f80_9000;
const INDEXED_EXTENDED_MULTIPLY: u32 = 1 << 29;
const INDEX_H_SHIFT: u32 = 11;
const INDEX_L_SHIFT: u32 = 21;
const INDEX_M_SHIFT: u32 = 20;
const INDEX_BIT_MASK: u32 = 1;
const HALF_LANE_HIGH_SHIFT: u32 = 2;
const HALF_LANE_LOW_SHIFT: u32 = 1;
const SINGLE_LANE_HIGH_SHIFT: u32 = 1;
const INDEXED_HALF_REGISTER_MASK: u32 = 15;
const VECTOR_Q: u32 = 1 << 30;
const VECTOR_DOUBLE: u32 = 1 << 22;
const VECTOR64_BITS: u32 = 64;
const VECTOR128_BITS: u32 = 128;
const FORMAT_SHIFT: u32 = 22;
const FORMAT_MASK: u32 = 3;
const FORMAT_SINGLE: u32 = 0;
const FORMAT_DOUBLE: u32 = 1;
const FORMAT_HALF: u32 = 3;
const REGISTER_MASK: u32 = 31;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Scalar,
    Vector64,
    Vector128,
}

impl Shape {
    pub const fn lane_count(self, format: Format) -> u32 {
        match self {
            Self::Scalar => 1,
            Self::Vector64 => VECTOR64_BITS / format.bits(),
            Self::Vector128 => VECTOR128_BITS / format.bits(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inputs {
    Elementwise {
        left: u8,
        right: u8,
    },
    Indexed {
        left: u8,
        right: u8,
        right_lane: u8,
    },
    Pairwise {
        left: u8,
        right: u8,
    },
    /// Reads exactly two lanes: 32 source bits for Half, 64 for Single, 128 for Double.
    PairwiseScalar {
        source: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub operation: BinaryOperation,
    pub format: Format,
    pub shape: Shape,
    pub destination: u8,
    pub inputs: Inputs,
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

fn elementwise(word: u32) -> Inputs {
    Inputs::Elementwise {
        left: register(word, LEFT_SHIFT),
        right: register(word, RIGHT_SHIFT),
    }
}

fn vector_shape(word: u32) -> Shape {
    if word & VECTOR_Q == 0 {
        Shape::Vector64
    } else {
        Shape::Vector128
    }
}

/// None is another family; Err is reserved scalar ftype, vector1D, Half scalar
/// pair size or indexed Double/L. All ordinary V0–V31 roles are data; indexed
/// Half Vm permits only V0–V15 and all eight source indices, including under Q=0.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    decode_scalar(word)
        .or_else(|| decode_vector(word))
        .or_else(|| decode_simd_scalar(word))
        .or_else(|| decode_pairwise_scalar(word))
        .or_else(|| decode_indexed(word))
}

fn decode_scalar(word: u32) -> Option<Result<Operand, ()>> {
    let operation = match word & SCALAR_MASK {
        FADD => BinaryOperation::Add,
        FSUB => BinaryOperation::Subtract,
        FMUL => BinaryOperation::Multiply,
        FDIV => BinaryOperation::Divide,
        FNMUL => BinaryOperation::NegatedMultiply,
        _ => return None,
    };
    let format = match (word >> FORMAT_SHIFT) & FORMAT_MASK {
        FORMAT_SINGLE => Format::Single,
        FORMAT_DOUBLE => Format::Double,
        FORMAT_HALF => Format::Half,
        _ => return Some(Err(())),
    };
    Some(Ok(Operand {
        operation,
        format,
        shape: Shape::Scalar,
        destination: register(word, 0),
        inputs: elementwise(word),
    }))
}

fn decode_vector(word: u32) -> Option<Result<Operand, ()>> {
    let (operation, half, pairwise) = match word & VECTOR_HALF_MASK {
        VECTOR_HALF_FADD => (BinaryOperation::Add, true, false),
        VECTOR_HALF_FSUB => (BinaryOperation::Subtract, true, false),
        VECTOR_HALF_FMUL => (BinaryOperation::Multiply, true, false),
        VECTOR_HALF_FDIV => (BinaryOperation::Divide, true, false),
        VECTOR_HALF_FABD => (BinaryOperation::AbsoluteDifference, true, false),
        VECTOR_HALF_FMULX => (BinaryOperation::MultiplyExtended, true, false),
        VECTOR_HALF_FADDP => (BinaryOperation::Add, true, true),
        _ => match word & VECTOR_MASK {
            VECTOR_FADD => (BinaryOperation::Add, false, false),
            VECTOR_FSUB => (BinaryOperation::Subtract, false, false),
            VECTOR_FMUL => (BinaryOperation::Multiply, false, false),
            VECTOR_FDIV => (BinaryOperation::Divide, false, false),
            VECTOR_FABD => (BinaryOperation::AbsoluteDifference, false, false),
            VECTOR_FMULX => (BinaryOperation::MultiplyExtended, false, false),
            VECTOR_FADDP => (BinaryOperation::Add, false, true),
            _ => return None,
        },
    };
    let shape = vector_shape(word);
    let format = if half {
        Format::Half
    } else if word & VECTOR_DOUBLE != 0 {
        Format::Double
    } else {
        Format::Single
    };
    if format == Format::Double && shape == Shape::Vector64 {
        return Some(Err(()));
    }
    Some(Ok(Operand {
        operation,
        format,
        shape,
        destination: register(word, 0),
        inputs: if pairwise {
            Inputs::Pairwise {
                left: register(word, LEFT_SHIFT),
                right: register(word, RIGHT_SHIFT),
            }
        } else {
            elementwise(word)
        },
    }))
}

fn decode_simd_scalar(word: u32) -> Option<Result<Operand, ()>> {
    let (operation, half) = match word & SIMD_SCALAR_HALF_MASK {
        SCALAR_HALF_FABD => (BinaryOperation::AbsoluteDifference, true),
        SCALAR_HALF_FMULX => (BinaryOperation::MultiplyExtended, true),
        _ => match word & SIMD_SCALAR_MASK {
            SCALAR_FABD => (BinaryOperation::AbsoluteDifference, false),
            SCALAR_FMULX => (BinaryOperation::MultiplyExtended, false),
            _ => return None,
        },
    };
    let format = if half {
        Format::Half
    } else if word & VECTOR_DOUBLE != 0 {
        Format::Double
    } else {
        Format::Single
    };
    Some(Ok(Operand {
        operation,
        format,
        shape: Shape::Scalar,
        destination: register(word, 0),
        inputs: elementwise(word),
    }))
}

fn decode_pairwise_scalar(word: u32) -> Option<Result<Operand, ()>> {
    let format = match word & PAIR_SCALAR_MASK {
        SCALAR_FADDP => {
            if word & VECTOR_DOUBLE == 0 {
                Format::Single
            } else {
                Format::Double
            }
        }
        SCALAR_HALF_FADDP => {
            if word & VECTOR_DOUBLE != 0 {
                return Some(Err(()));
            }
            Format::Half
        }
        _ => return None,
    };
    Some(Ok(Operand {
        operation: BinaryOperation::Add,
        format,
        shape: Shape::Scalar,
        destination: register(word, 0),
        inputs: Inputs::PairwiseScalar {
            source: register(word, LEFT_SHIFT),
        },
    }))
}

fn decode_indexed(word: u32) -> Option<Result<Operand, ()>> {
    let (half, shape) = if word & INDEXED_SCALAR_HALF_MASK == INDEXED_SCALAR_HALF {
        (true, Shape::Scalar)
    } else if word & INDEXED_SCALAR_MASK == INDEXED_SCALAR {
        (false, Shape::Scalar)
    } else if word & INDEXED_VECTOR_HALF_MASK == INDEXED_VECTOR_HALF {
        (true, vector_shape(word))
    } else if word & INDEXED_VECTOR_MASK == INDEXED_VECTOR {
        (false, vector_shape(word))
    } else {
        return None;
    };
    let high = (word >> INDEX_H_SHIFT) & INDEX_BIT_MASK;
    let low = (word >> INDEX_L_SHIFT) & INDEX_BIT_MASK;
    let middle = (word >> INDEX_M_SHIFT) & INDEX_BIT_MASK;
    let (format, right, right_lane) = if half {
        (
            Format::Half,
            ((word >> RIGHT_SHIFT) & INDEXED_HALF_REGISTER_MASK) as u8,
            (high << HALF_LANE_HIGH_SHIFT) | (low << HALF_LANE_LOW_SHIFT) | middle,
        )
    } else if word & VECTOR_DOUBLE == 0 {
        (
            Format::Single,
            register(word, RIGHT_SHIFT),
            (high << SINGLE_LANE_HIGH_SHIFT) | low,
        )
    } else {
        if low != 0 || shape == Shape::Vector64 {
            return Some(Err(()));
        }
        (Format::Double, register(word, RIGHT_SHIFT), high)
    };
    Some(Ok(Operand {
        operation: if word & INDEXED_EXTENDED_MULTIPLY == 0 {
            BinaryOperation::Multiply
        } else {
            BinaryOperation::MultiplyExtended
        },
        format,
        shape,
        destination: register(word, 0),
        inputs: Inputs::Indexed {
            left: register(word, LEFT_SHIFT),
            right,
            right_lane: right_lane as u8,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORMAT_RESERVED: u32 = 2;
    const SCALAR_OPERATION_FIELD_MASK: u32 = 0xb000;
    const VECTOR_OPERATION_FIELD_MASK: u32 = 0x2080_2800;
    const SCALAR_OPERATIONS: [(u32, BinaryOperation); 5] = [
        (FADD, BinaryOperation::Add),
        (FSUB, BinaryOperation::Subtract),
        (FMUL, BinaryOperation::Multiply),
        (FDIV, BinaryOperation::Divide),
        (FNMUL, BinaryOperation::NegatedMultiply),
    ];
    const ORIGINAL_VECTOR_OPERATIONS: [(u32, u32, BinaryOperation); 4] = [
        (VECTOR_FADD, VECTOR_HALF_FADD, BinaryOperation::Add),
        (VECTOR_FSUB, VECTOR_HALF_FSUB, BinaryOperation::Subtract),
        (VECTOR_FMUL, VECTOR_HALF_FMUL, BinaryOperation::Multiply),
        (VECTOR_FDIV, VECTOR_HALF_FDIV, BinaryOperation::Divide),
    ];
    const NEW_VECTOR_OPERATIONS: [(u32, u32, BinaryOperation); 3] = [
        (
            VECTOR_FABD,
            VECTOR_HALF_FABD,
            BinaryOperation::AbsoluteDifference,
        ),
        (
            VECTOR_FMULX,
            VECTOR_HALF_FMULX,
            BinaryOperation::MultiplyExtended,
        ),
        (VECTOR_FADDP, VECTOR_HALF_FADDP, BinaryOperation::Add),
    ];

    fn instruction(operation: u32, format: u32, destination: u32, left: u32, right: u32) -> u32 {
        operation
            | (format << FORMAT_SHIFT)
            | (left << LEFT_SHIFT)
            | (right << RIGHT_SHIFT)
            | destination
    }

    #[test]
    fn every_scalar_operation_format_and_register_combination_is_explicit() {
        for (encoding, operation) in SCALAR_OPERATIONS {
            for format_field in 0..=FORMAT_MASK {
                let format = match format_field {
                    FORMAT_SINGLE => Some(Format::Single),
                    FORMAT_DOUBLE => Some(Format::Double),
                    FORMAT_HALF => Some(Format::Half),
                    FORMAT_RESERVED => None,
                    _ => unreachable!(),
                };
                for destination in 0..=REGISTER_MASK {
                    for left in 0..=REGISTER_MASK {
                        for right in 0..=REGISTER_MASK {
                            let expected = format.map_or(Err(()), |format| {
                                Ok(Operand {
                                    operation,
                                    format,
                                    shape: Shape::Scalar,
                                    destination: destination as u8,
                                    inputs: Inputs::Elementwise {
                                        left: left as u8,
                                        right: right as u8,
                                    },
                                })
                            });
                            assert_eq!(
                                decode(instruction(
                                    encoding,
                                    format_field,
                                    destination,
                                    left,
                                    right
                                )),
                                Some(expected)
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn all_vector_elementwise_and_pairwise_shapes_cover_every_alias() {
        for (ordinary, half, operation) in ORIGINAL_VECTOR_OPERATIONS
            .into_iter()
            .chain(NEW_VECTOR_OPERATIONS)
        {
            for (encoding, format, size) in [
                (ordinary, Format::Single, 0),
                (ordinary, Format::Double, VECTOR_DOUBLE),
                (half, Format::Half, 0),
            ] {
                for (q, shape) in [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)] {
                    for destination in 0..=REGISTER_MASK {
                        for left in 0..=REGISTER_MASK {
                            for right in 0..=REGISTER_MASK {
                                let word = encoding
                                    | size
                                    | q
                                    | (left << LEFT_SHIFT)
                                    | (right << RIGHT_SHIFT)
                                    | destination;
                                let expected =
                                    if format == Format::Double && shape == Shape::Vector64 {
                                        Err(())
                                    } else {
                                        let inputs = if ordinary == VECTOR_FADDP {
                                            Inputs::Pairwise {
                                                left: left as u8,
                                                right: right as u8,
                                            }
                                        } else {
                                            Inputs::Elementwise {
                                                left: left as u8,
                                                right: right as u8,
                                            }
                                        };
                                        Ok(Operand {
                                            operation,
                                            format,
                                            shape,
                                            destination: destination as u8,
                                            inputs,
                                        })
                                    };
                                assert_eq!(decode(word), Some(expected), "word={word:08x}");
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn advsimd_scalar_extended_multiply_and_absolute_difference_have_ordinary_v31() {
        for (ordinary, half, operation) in [
            (
                SCALAR_FABD,
                SCALAR_HALF_FABD,
                BinaryOperation::AbsoluteDifference,
            ),
            (
                SCALAR_FMULX,
                SCALAR_HALF_FMULX,
                BinaryOperation::MultiplyExtended,
            ),
        ] {
            for (encoding, format) in [
                (ordinary, Format::Single),
                (ordinary | VECTOR_DOUBLE, Format::Double),
                (half, Format::Half),
            ] {
                for destination in 0..=REGISTER_MASK {
                    for left in 0..=REGISTER_MASK {
                        for right in 0..=REGISTER_MASK {
                            let word = encoding
                                | destination
                                | (left << LEFT_SHIFT)
                                | (right << RIGHT_SHIFT);
                            assert_eq!(
                                decode(word),
                                Some(Ok(Operand {
                                    operation,
                                    format,
                                    shape: Shape::Scalar,
                                    destination: destination as u8,
                                    inputs: Inputs::Elementwise {
                                        left: left as u8,
                                        right: right as u8
                                    },
                                })),
                                "word={word:08x}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn scalar_pairwise_uses_one_source_and_exactly_two_lanes() {
        for (encoding, format) in [
            (SCALAR_HALF_FADDP, Format::Half),
            (SCALAR_FADDP, Format::Single),
            (SCALAR_FADDP | VECTOR_DOUBLE, Format::Double),
        ] {
            for destination in 0..=REGISTER_MASK {
                for source in 0..=REGISTER_MASK {
                    let word = encoding | destination | (source << LEFT_SHIFT);
                    assert_eq!(
                        decode(word),
                        Some(Ok(Operand {
                            operation: BinaryOperation::Add,
                            format,
                            shape: Shape::Scalar,
                            destination: destination as u8,
                            inputs: Inputs::PairwiseScalar {
                                source: source as u8
                            },
                        }))
                    );
                    assert_eq!(
                        decode(
                            SCALAR_HALF_FADDP
                                | VECTOR_DOUBLE
                                | destination
                                | (source << LEFT_SHIFT)
                        ),
                        Some(Err(()))
                    );
                }
            }
        }
        for format in [Format::Half, Format::Single, Format::Double] {
            assert_eq!(Shape::Scalar.lane_count(format), 1);
        }
        assert_eq!(2 * Format::Half.bits(), 32);
    }

    fn indexed_word(base: u32, format: Format, lane: u32, right: u32) -> u32 {
        let fields = match format {
            Format::Half => {
                ((lane >> HALF_LANE_HIGH_SHIFT) << INDEX_H_SHIFT)
                    | (((lane >> HALF_LANE_LOW_SHIFT) & INDEX_BIT_MASK) << INDEX_L_SHIFT)
                    | ((lane & INDEX_BIT_MASK) << INDEX_M_SHIFT)
            }
            Format::Single => {
                ((lane >> SINGLE_LANE_HIGH_SHIFT) << INDEX_H_SHIFT)
                    | ((lane & INDEX_BIT_MASK) << INDEX_L_SHIFT)
            }
            Format::Double => VECTOR_DOUBLE | (lane << INDEX_H_SHIFT),
        };
        base | fields | (right << RIGHT_SHIFT)
    }

    #[test]
    fn indexed_multiply_all_widths_indices_registers_and_aliases_are_explicit() {
        let mut index_variants = 0;
        for (extended, operation) in [
            (0, BinaryOperation::Multiply),
            (INDEXED_EXTENDED_MULTIPLY, BinaryOperation::MultiplyExtended),
        ] {
            for format in [Format::Half, Format::Single, Format::Double] {
                for (shape, ordinary, half) in [
                    (Shape::Scalar, INDEXED_SCALAR, INDEXED_SCALAR_HALF),
                    (Shape::Vector64, INDEXED_VECTOR, INDEXED_VECTOR_HALF),
                    (
                        Shape::Vector128,
                        INDEXED_VECTOR | VECTOR_Q,
                        INDEXED_VECTOR_HALF | VECTOR_Q,
                    ),
                ] {
                    if format == Format::Double && shape == Shape::Vector64 {
                        continue;
                    }
                    let base = (if format == Format::Half {
                        half
                    } else {
                        ordinary
                    }) | extended;
                    let right_limit = if format == Format::Half {
                        INDEXED_HALF_REGISTER_MASK
                    } else {
                        REGISTER_MASK
                    };
                    for lane in 0..VECTOR128_BITS / format.bits() {
                        for destination in 0..=REGISTER_MASK {
                            for left in 0..=REGISTER_MASK {
                                for right in 0..=right_limit {
                                    let word = indexed_word(base, format, lane, right)
                                        | destination
                                        | (left << LEFT_SHIFT);
                                    assert_eq!(
                                        decode(word),
                                        Some(Ok(Operand {
                                            operation,
                                            format,
                                            shape,
                                            destination: destination as u8,
                                            inputs: Inputs::Indexed {
                                                left: left as u8,
                                                right: right as u8,
                                                right_lane: lane as u8
                                            },
                                        })),
                                        "word={word:08x}"
                                    );
                                }
                            }
                        }
                        index_variants += 1;
                    }
                }
            }
        }
        assert_eq!(index_variants, 80);
    }

    #[test]
    fn indexed_double_l_and_one_double_remain_reserved() {
        for extended in [0, INDEXED_EXTENDED_MULTIPLY] {
            for base in [INDEXED_SCALAR, INDEXED_VECTOR, INDEXED_VECTOR | VECTOR_Q] {
                for high in [0, 1 << INDEX_H_SHIFT] {
                    for right in 0..=REGISTER_MASK {
                        for destination in 0..=REGISTER_MASK {
                            for left in 0..=REGISTER_MASK {
                                let word = base
                                    | extended
                                    | VECTOR_DOUBLE
                                    | high
                                    | (right << RIGHT_SHIFT)
                                    | destination
                                    | (left << LEFT_SHIFT);
                                assert_eq!(decode(word | (1 << INDEX_L_SHIFT)), Some(Err(())));
                                if base == INDEXED_VECTOR {
                                    assert_eq!(decode(word), Some(Err(())));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn half_index_m_is_a_lane_bit_and_q0_can_select_the_upper_source_half() {
        for extended in [0, INDEXED_EXTENDED_MULTIPLY] {
            let word = indexed_word(INDEXED_VECTOR_HALF | extended, Format::Half, 7, 15)
                | REGISTER_MASK
                | (REGISTER_MASK << LEFT_SHIFT);
            assert_eq!(
                decode(word),
                Some(Ok(Operand {
                    operation: if extended == 0 {
                        BinaryOperation::Multiply
                    } else {
                        BinaryOperation::MultiplyExtended
                    },
                    format: Format::Half,
                    shape: Shape::Vector64,
                    destination: 31,
                    inputs: Inputs::Indexed {
                        left: 31,
                        right: 15,
                        right_lane: 7
                    },
                }))
            );
            let word = indexed_word(INDEXED_VECTOR | extended, Format::Single, 3, 31);
            assert!(matches!(
                decode(word),
                Some(Ok(Operand {
                    inputs: Inputs::Indexed {
                        right: 31,
                        right_lane: 3,
                        ..
                    },
                    shape: Shape::Vector64,
                    ..
                }))
            ));
        }
    }

    #[test]
    fn lane_counts_follow_allocated_scalar_and_vector_shapes() {
        for format in [Format::Half, Format::Single, Format::Double] {
            assert_eq!(Shape::Scalar.lane_count(format), 1);
        }
        for (shape, format, lanes) in [
            (Shape::Vector64, Format::Half, 4),
            (Shape::Vector128, Format::Half, 8),
            (Shape::Vector64, Format::Single, 2),
            (Shape::Vector128, Format::Single, 4),
            (Shape::Vector128, Format::Double, 2),
        ] {
            assert_eq!(shape.lane_count(format), lanes);
        }
    }

    #[test]
    fn old_fixed_bit_neighbors_still_decline_outside_assigned_operation_fields() {
        let fixed_mask = SCALAR_MASK & !SCALAR_OPERATION_FIELD_MASK;
        for (encoding, _) in SCALAR_OPERATIONS {
            for format in 0..=FORMAT_MASK {
                let word = instruction(
                    encoding,
                    format,
                    REGISTER_MASK,
                    REGISTER_MASK,
                    REGISTER_MASK,
                );
                for bit in 0..u32::BITS {
                    let changed = 1 << bit;
                    if fixed_mask & changed != 0 {
                        assert_eq!(decode(word ^ changed), None);
                    }
                }
            }
        }
        for (ordinary, half, _) in ORIGINAL_VECTOR_OPERATIONS {
            for (encoding, mask) in [(ordinary, VECTOR_MASK), (half, VECTOR_HALF_MASK)] {
                let fixed_mask = mask & !VECTOR_OPERATION_FIELD_MASK;
                for q in [0, VECTOR_Q] {
                    let word = encoding
                        | q
                        | (REGISTER_MASK << LEFT_SHIFT)
                        | (REGISTER_MASK << RIGHT_SHIFT)
                        | REGISTER_MASK;
                    for bit in 0..u32::BITS {
                        let changed = 1 << bit;
                        if fixed_mask & changed != 0 {
                            assert_eq!(decode(word ^ changed), None);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn allocated_other_families_do_not_gain_arithmetic_semantics() {
        const SCALAR_NEIGHBORS: [u32; 7] = [
            0x1e20_4800,
            0x1e20_5800,
            0x1e20_6800,
            0x1e20_7800,
            0x1e20_0c00,
            0x1e20_2000,
            0x1f00_0000,
        ];
        for neighbor in SCALAR_NEIGHBORS {
            for format in 0..=FORMAT_MASK {
                assert_eq!(
                    decode(instruction(
                        neighbor,
                        format,
                        REGISTER_MASK,
                        REGISTER_MASK,
                        REGISTER_MASK
                    )),
                    None
                );
            }
        }
        const VECTOR_NEIGHBORS: [u32; 12] = [
            0x0e20_cc00,
            0x0ea0_cc00,
            0x0e20_f400,
            0x0ea0_f400,
            0x0e20_e400,
            0x2e20_e400,
            0x0e20_8400,
            0x2e20_8400,
            0x0e20_fc00,
            0x0ea0_fc00,
            0x0f80_1000,
            0x6f00_e400,
        ];
        for neighbor in VECTOR_NEIGHBORS {
            for q in [0, VECTOR_Q] {
                for size in [0, VECTOR_DOUBLE] {
                    assert_eq!(
                        decode(
                            neighbor
                                | q
                                | size
                                | (REGISTER_MASK << LEFT_SHIFT)
                                | (REGISTER_MASK << RIGHT_SHIFT)
                                | REGISTER_MASK
                        ),
                        None
                    );
                }
            }
        }
    }
}
