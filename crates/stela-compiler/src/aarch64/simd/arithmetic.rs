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
mod tests;
