//! FP min/max: scalar, vector, pairwise and across-lane forms.
use crate::aarch64::floating::{Format, minmax::MinMaxOperation};

use super::arithmetic::Shape;

const REGISTER_MASK: u32 = 31;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const FORMAT_SHIFT: u32 = 22;
const FORMAT_MASK: u32 = 3;
const FORMAT_SINGLE: u32 = 0;
const FORMAT_DOUBLE: u32 = 1;
const FORMAT_HALF: u32 = 3;
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

fn scalar_format(word: u32) -> Result<Format, ()> {
    match (word >> FORMAT_SHIFT) & FORMAT_MASK {
        FORMAT_SINGLE => Ok(Format::Single),
        FORMAT_DOUBLE => Ok(Format::Double),
        FORMAT_HALF => Ok(Format::Half),
        _ => Err(()),
    }
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
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    decode_scalar(word)
        .or_else(|| decode_vector(word))
        .or_else(|| decode_pairwise_scalar(word))
        .or_else(|| decode_reduction(word))
}

fn decode_scalar(word: u32) -> Option<Result<Operand, ()>> {
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

fn decode_vector(word: u32) -> Option<Result<Operand, ()>> {
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
            return Some(Err(()));
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

fn decode_pairwise_scalar(word: u32) -> Option<Result<Operand, ()>> {
    for (adjustment, half) in [(0, false), (HALF_PAIR_ADJUSTMENT, true)] {
        let Some(operation) = pair_operation((word & PAIR_SCALAR_MASK) ^ adjustment) else {
            continue;
        };
        if half && word & SIMD_DOUBLE != 0 {
            return Some(Err(()));
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

fn decode_reduction(word: u32) -> Option<Result<Operand, ()>> {
    for (mask, adjustment, half) in [
        (REDUCTION_MASK, 0, false),
        (REDUCTION_HALF_MASK, HALF_PAIR_ADJUSTMENT, true),
    ] {
        let Some(operation) = reduction_operation((word & mask) ^ adjustment) else {
            continue;
        };
        if !half && (word & SIMD_DOUBLE != 0 || word & VECTOR_Q == 0) {
            return Some(Err(()));
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
mod tests;
