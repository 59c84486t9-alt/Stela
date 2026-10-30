//! FP min/max: scalar, vector, pairwise and across-lane forms.
use super::scalar_format;
use crate::aarch64::Unsupported;
use crate::aarch64::floating::{Format, minmax::MinMaxOperation};

use super::arithmetic::Shape;

const REGISTER_MASK: u32 = 31;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const VECTOR_Q: u32 = 1 << 30;
const SIMD_DOUBLE: u32 = 1 << 22;
const VECTOR_PAIRWISE: u32 = 1 << 29;
const HALF_REGISTER_ADJUSTMENT: u32 = 0x0060c000;
const HALF_PAIR_ADJUSTMENT: u32 = 1 << 29;

const SCALAR_MASK: u32 = 0xff20fc00;
const SCALAR_FMAX: u32 = 0x1e204800;
const SCALAR_FMIN: u32 = 0x1e205800;
const SCALAR_FMAXNM: u32 = 0x1e206800;
const SCALAR_FMINNM: u32 = 0x1e207800;
const VECTOR_MASK: u32 = 0x9fa0fc00;
const VECTOR_HALF_MASK: u32 = 0x9fe0fc00;
const VECTOR_FMAX: u32 = 0x0e20f400;
const VECTOR_FMIN: u32 = 0x0ea0f400;
const VECTOR_FMAXNM: u32 = 0x0e20c400;
const VECTOR_FMINNM: u32 = 0x0ea0c400;
const PAIR_SCALAR_MASK: u32 = 0xffbffc00;
const PAIR_FMAX: u32 = 0x7e30f800;
const PAIR_FMIN: u32 = 0x7eb0f800;
const PAIR_FMAXNM: u32 = 0x7e30c800;
const PAIR_FMINNM: u32 = 0x7eb0c800;
const REDUCTION_MASK: u32 = 0xbfbffc00;
const REDUCTION_HALF_MASK: u32 = 0xbffffc00;
const REDUCTION_FMAX: u32 = 0x2e30f800;
const REDUCTION_FMIN: u32 = 0x2eb0f800;
const REDUCTION_FMAXNM: u32 = 0x2e30c800;
const REDUCTION_FMINNM: u32 = 0x2eb0c800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryMode {
    Elementwise,
    Pairwise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Binary {
        operation: MinMaxOperation,
        format: Format,
        shape: Shape,
        mode: BinaryMode,
        destination: u8,
        left: u8,
        right: u8,
    },
    PairwiseScalar {
        operation: MinMaxOperation,
        format: Format,
        destination: u8,
        source: u8,
    },
    Reduction {
        operation: MinMaxOperation,
        format: Format,
        shape: Shape,
        destination: u8,
        source: u8,
    },
}

impl Operand {
    pub const fn format(self) -> Format {
        match self {
            Self::Binary { format, .. }
            | Self::PairwiseScalar { format, .. }
            | Self::Reduction { format, .. } => format,
        }
    }

    pub const fn operation(self) -> MinMaxOperation {
        match self {
            Self::Binary { operation, .. }
            | Self::PairwiseScalar { operation, .. }
            | Self::Reduction { operation, .. } => operation,
        }
    }

    pub const fn destination(self) -> u8 {
        match self {
            Self::Binary { destination, .. }
            | Self::PairwiseScalar { destination, .. }
            | Self::Reduction { destination, .. } => destination,
        }
    }
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

fn vector_shape(word: u32) -> Shape {
    if word & VECTOR_Q == 0 {
        Shape::Vector64
    } else {
        Shape::Vector128
    }
}

/// None denotes another family; Err denotes reserved scalar ftype, vector1D,
/// half scalar-pair size or ordinary reduction size/Q. Registers denote V31
/// normally; pairwise scalar H consumes only the source's first two H lanes.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    decode_scalar(word)
        .or_else(|| decode_vector(word))
        .or_else(|| decode_pairwise_scalar(word))
        .or_else(|| decode_reduction(word))
}

fn decode_scalar(word: u32) -> Option<Result<Operand, Unsupported>> {
    let operation = match word & SCALAR_MASK {
        SCALAR_FMAX => MinMaxOperation::Maximum,
        SCALAR_FMIN => MinMaxOperation::Minimum,
        SCALAR_FMAXNM => MinMaxOperation::MaximumNumber,
        SCALAR_FMINNM => MinMaxOperation::MinimumNumber,
        _ => return None,
    };
    Some(scalar_format(word).map(|format| Operand::Binary {
        operation,
        format,
        shape: Shape::Scalar,
        mode: BinaryMode::Elementwise,
        destination: register(word, 0),
        left: register(word, LEFT_SHIFT),
        right: register(word, RIGHT_SHIFT),
    }))
}

fn vector_operation(opcode: u32) -> Option<MinMaxOperation> {
    Some(match opcode {
        VECTOR_FMAX => MinMaxOperation::Maximum,
        VECTOR_FMIN => MinMaxOperation::Minimum,
        VECTOR_FMAXNM => MinMaxOperation::MaximumNumber,
        VECTOR_FMINNM => MinMaxOperation::MinimumNumber,
        _ => return None,
    })
}

fn decode_vector(word: u32) -> Option<Result<Operand, Unsupported>> {
    for (mask, adjustment, half) in [
        (VECTOR_MASK, 0, false),
        (VECTOR_HALF_MASK, HALF_REGISTER_ADJUSTMENT, true),
    ] {
        let Some(operation) = vector_operation((word & mask) ^ adjustment) else {
            continue;
        };
        let format = if half {
            Format::Half
        } else if word & SIMD_DOUBLE != 0 {
            Format::Double
        } else {
            Format::Single
        };
        let shape = vector_shape(word);
        if format == Format::Double && shape == Shape::Vector64 {
            return Some(Err(Unsupported));
        }
        return Some(Ok(Operand::Binary {
            operation,
            format,
            shape,
            mode: if word & VECTOR_PAIRWISE == 0 {
                BinaryMode::Elementwise
            } else {
                BinaryMode::Pairwise
            },
            destination: register(word, 0),
            left: register(word, LEFT_SHIFT),
            right: register(word, RIGHT_SHIFT),
        }));
    }
    None
}

fn pair_operation(opcode: u32) -> Option<MinMaxOperation> {
    Some(match opcode {
        PAIR_FMAX => MinMaxOperation::Maximum,
        PAIR_FMIN => MinMaxOperation::Minimum,
        PAIR_FMAXNM => MinMaxOperation::MaximumNumber,
        PAIR_FMINNM => MinMaxOperation::MinimumNumber,
        _ => return None,
    })
}

fn decode_pairwise_scalar(word: u32) -> Option<Result<Operand, Unsupported>> {
    for (adjustment, half) in [(0, false), (HALF_PAIR_ADJUSTMENT, true)] {
        let Some(operation) = pair_operation((word & PAIR_SCALAR_MASK) ^ adjustment) else {
            continue;
        };
        if half && word & SIMD_DOUBLE != 0 {
            return Some(Err(Unsupported));
        }
        let format = if half {
            Format::Half
        } else if word & SIMD_DOUBLE != 0 {
            Format::Double
        } else {
            Format::Single
        };
        return Some(Ok(Operand::PairwiseScalar {
            operation,
            format,
            destination: register(word, 0),
            source: register(word, LEFT_SHIFT),
        }));
    }
    None
}

fn reduction_operation(opcode: u32) -> Option<MinMaxOperation> {
    Some(match opcode {
        REDUCTION_FMAX => MinMaxOperation::Maximum,
        REDUCTION_FMIN => MinMaxOperation::Minimum,
        REDUCTION_FMAXNM => MinMaxOperation::MaximumNumber,
        REDUCTION_FMINNM => MinMaxOperation::MinimumNumber,
        _ => return None,
    })
}

fn decode_reduction(word: u32) -> Option<Result<Operand, Unsupported>> {
    for (mask, adjustment, half) in [
        (REDUCTION_MASK, 0, false),
        (REDUCTION_HALF_MASK, HALF_PAIR_ADJUSTMENT, true),
    ] {
        let Some(operation) = reduction_operation((word & mask) ^ adjustment) else {
            continue;
        };
        if !half && (word & SIMD_DOUBLE != 0 || word & VECTOR_Q == 0) {
            return Some(Err(Unsupported));
        }
        return Some(Ok(Operand::Reduction {
            operation,
            format: if half { Format::Half } else { Format::Single },
            shape: vector_shape(word),
            destination: register(word, 0),
            source: register(word, LEFT_SHIFT),
        }));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::simd::{FORMAT_DOUBLE, FORMAT_HALF, FORMAT_SHIFT, FORMAT_SINGLE};

    const SCALAR_OPERATIONS: [(u32, MinMaxOperation); 4] = [
        (SCALAR_FMAX, MinMaxOperation::Maximum),
        (SCALAR_FMIN, MinMaxOperation::Minimum),
        (SCALAR_FMAXNM, MinMaxOperation::MaximumNumber),
        (SCALAR_FMINNM, MinMaxOperation::MinimumNumber),
    ];
    const VECTOR_OPERATIONS: [(u32, MinMaxOperation); 4] = [
        (VECTOR_FMAX, MinMaxOperation::Maximum),
        (VECTOR_FMIN, MinMaxOperation::Minimum),
        (VECTOR_FMAXNM, MinMaxOperation::MaximumNumber),
        (VECTOR_FMINNM, MinMaxOperation::MinimumNumber),
    ];
    const PAIR_OPERATIONS: [(u32, MinMaxOperation); 4] = [
        (PAIR_FMAX, MinMaxOperation::Maximum),
        (PAIR_FMIN, MinMaxOperation::Minimum),
        (PAIR_FMAXNM, MinMaxOperation::MaximumNumber),
        (PAIR_FMINNM, MinMaxOperation::MinimumNumber),
    ];
    const REDUCTION_OPERATIONS: [(u32, MinMaxOperation); 4] = [
        (REDUCTION_FMAX, MinMaxOperation::Maximum),
        (REDUCTION_FMIN, MinMaxOperation::Minimum),
        (REDUCTION_FMAXNM, MinMaxOperation::MaximumNumber),
        (REDUCTION_FMINNM, MinMaxOperation::MinimumNumber),
    ];

    fn check_registers(word: u32, expected: Operand) {
        for destination in 0..=REGISTER_MASK {
            for left in 0..=REGISTER_MASK {
                let right_limit = if matches!(expected, Operand::Binary { .. }) {
                    REGISTER_MASK
                } else {
                    0
                };
                for right in 0..=right_limit {
                    let word = word | destination | (left << LEFT_SHIFT) | (right << RIGHT_SHIFT);
                    let operand = match expected {
                        Operand::Binary {
                            operation,
                            format,
                            shape,
                            mode,
                            ..
                        } => Operand::Binary {
                            operation,
                            format,
                            shape,
                            mode,
                            destination: destination as u8,
                            left: left as u8,
                            right: right as u8,
                        },
                        Operand::PairwiseScalar {
                            operation, format, ..
                        } => Operand::PairwiseScalar {
                            operation,
                            format,
                            destination: destination as u8,
                            source: left as u8,
                        },
                        Operand::Reduction {
                            operation,
                            format,
                            shape,
                            ..
                        } => Operand::Reduction {
                            operation,
                            format,
                            shape,
                            destination: destination as u8,
                            source: left as u8,
                        },
                    };
                    assert_eq!(decode(word), Some(Ok(operand)), "word={word:08x}");
                    assert_eq!(operand.operation(), expected.operation());
                    assert_eq!(operand.format(), expected.format());
                    assert_eq!(operand.destination(), destination as u8);
                }
            }
        }
    }

    #[test]
    fn binary_minmax_decoding_covers_every_form() {
        let mut arrangements = 0;
        for (opcode, operation) in SCALAR_OPERATIONS {
            for (field, format) in [
                (FORMAT_SINGLE, Format::Single),
                (FORMAT_DOUBLE, Format::Double),
                (FORMAT_HALF, Format::Half),
            ] {
                check_registers(
                    opcode | (field << FORMAT_SHIFT),
                    Operand::Binary {
                        operation,
                        format,
                        shape: Shape::Scalar,
                        mode: BinaryMode::Elementwise,
                        destination: 0,
                        left: 0,
                        right: 0,
                    },
                );
                arrangements += 1;
            }
        }
        for (opcode, operation) in VECTOR_OPERATIONS {
            for (pairwise, mode) in [
                (0, BinaryMode::Elementwise),
                (VECTOR_PAIRWISE, BinaryMode::Pairwise),
            ] {
                for format in [Format::Half, Format::Single, Format::Double] {
                    let size = match format {
                        Format::Half => HALF_REGISTER_ADJUSTMENT,
                        Format::Single => 0,
                        Format::Double => SIMD_DOUBLE,
                    };
                    for (q, shape) in [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)] {
                        if format == Format::Double && shape == Shape::Vector64 {
                            continue;
                        }
                        check_registers(
                            (opcode ^ size) | pairwise | q,
                            Operand::Binary {
                                operation,
                                format,
                                shape,
                                mode,
                                destination: 0,
                                left: 0,
                                right: 0,
                            },
                        );
                        arrangements += 1;
                    }
                }
            }
        }
        assert_eq!(arrangements, 52);
    }

    #[test]
    fn scalar_pairwise_distinguishes_two_half_inputs_from_vector64() {
        let mut arrangements = 0;
        for (opcode, operation) in PAIR_OPERATIONS {
            for (adjustment, format) in [
                (HALF_PAIR_ADJUSTMENT, Format::Half),
                (0, Format::Single),
                (SIMD_DOUBLE, Format::Double),
            ] {
                check_registers(
                    opcode ^ adjustment,
                    Operand::PairwiseScalar {
                        operation,
                        format,
                        destination: 0,
                        source: 0,
                    },
                );
                arrangements += 1;
            }
        }
        assert_eq!(arrangements, 12);
    }

    #[test]
    fn reductions_allow_four_or_eight_half_and_exactly_four_single() {
        let mut arrangements = 0;
        for (opcode, operation) in REDUCTION_OPERATIONS {
            for (adjustment, q, format, shape) in [
                (HALF_PAIR_ADJUSTMENT, 0, Format::Half, Shape::Vector64),
                (
                    HALF_PAIR_ADJUSTMENT,
                    VECTOR_Q,
                    Format::Half,
                    Shape::Vector128,
                ),
                (0, VECTOR_Q, Format::Single, Shape::Vector128),
            ] {
                check_registers(
                    (opcode ^ adjustment) | q,
                    Operand::Reduction {
                        operation,
                        format,
                        shape,
                        destination: 0,
                        source: 0,
                    },
                );
                arrangements += 1;
            }
        }
        assert_eq!(arrangements, 12);
    }

    #[test]
    fn reserved_formats_one_double_half_pair_size_and_reduction_sizes_decline() {
        const RESERVED_FORMAT: u32 = 2;
        for (opcode, _) in SCALAR_OPERATIONS {
            assert_eq!(
                decode(opcode | (RESERVED_FORMAT << FORMAT_SHIFT)),
                Some(Err(Unsupported))
            );
        }
        for (opcode, _) in VECTOR_OPERATIONS {
            for pairwise in [0, VECTOR_PAIRWISE] {
                assert_eq!(
                    decode(opcode | SIMD_DOUBLE | pairwise),
                    Some(Err(Unsupported))
                );
            }
        }
        for (opcode, _) in PAIR_OPERATIONS {
            assert_eq!(
                decode((opcode ^ HALF_PAIR_ADJUSTMENT) | SIMD_DOUBLE),
                Some(Err(Unsupported))
            );
        }
        for (opcode, _) in REDUCTION_OPERATIONS {
            assert_eq!(decode(opcode), Some(Err(Unsupported)));
            for q in [0, VECTOR_Q] {
                assert_eq!(decode(opcode | SIMD_DOUBLE | q), Some(Err(Unsupported)));
            }
        }
    }

    #[test]
    fn allocated_comparison_conversion_and_absolute_minmax_neighbors_stay_separate() {
        // Neighboring forms: FAMIN/FAMAX vector classes, scalar FCMP, AdvSIMD
        // FCMEQ, FCVTN and MOVI.
        const NEIGHBORS: [u32; 8] = [
            0x0ea0dc00, 0x2ea0dc00, 0x0ec01c00, 0x2ec01c00, 0x1e202000, 0x0e20e400, 0x0e216800,
            0x6f00e400,
        ];
        for word in NEIGHBORS {
            assert_eq!(decode(word), None, "word={word:08x}");
        }
    }
}
