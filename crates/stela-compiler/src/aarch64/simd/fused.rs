//! Fused scalar and AdvSIMD multiply-add forms from the pinned Arm 2026-06 reference.
use crate::aarch64::floating::{Format, fused::FusedOperation};

use super::arithmetic::Shape;

const SCALAR_MASK: u32 = 0xff208000;
const FMADD: u32 = 0x1f000000;
const FMSUB: u32 = 0x1f008000;
const FNMADD: u32 = 0x1f200000;
const FNMSUB: u32 = 0x1f208000;
const VECTOR_MASK: u32 = 0xbfa0fc00;
const VECTOR_FMLA: u32 = 0x0e20cc00;
const VECTOR_FMLS: u32 = 0x0ea0cc00;
const VECTOR_HALF_MASK: u32 = 0xbfe0fc00;
const VECTOR_HALF_FMLA: u32 = 0x0e400c00;
const VECTOR_HALF_FMLS: u32 = 0x0ec00c00;
const INDEXED_SCALAR_HALF_MASK: u32 = 0xffc0b400;
const INDEXED_SCALAR_HALF: u32 = 0x5f001000;
const INDEXED_SCALAR_MASK: u32 = 0xff80b400;
const INDEXED_SCALAR: u32 = 0x5f801000;
const INDEXED_VECTOR_HALF_MASK: u32 = 0xbfc0b400;
const INDEXED_VECTOR_HALF: u32 = 0x0f001000;
const INDEXED_VECTOR_MASK: u32 = 0xbf80b400;
const INDEXED_VECTOR: u32 = 0x0f801000;
const INDEXED_SUBTRACT: u32 = 1 << 14;
const VECTOR_Q: u32 = 1 << 30;
const VECTOR_DOUBLE: u32 = 1 << 22;
const FORMAT_SHIFT: u32 = 22;
const FORMAT_MASK: u32 = 3;
const FORMAT_SINGLE: u32 = 0;
const FORMAT_DOUBLE: u32 = 1;
const FORMAT_HALF: u32 = 3;
const REGISTER_MASK: u32 = 31;
const INDEXED_HALF_REGISTER_MASK: u32 = 15;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const ADDEND_SHIFT: u32 = 10;
const RIGHT_SHIFT: u32 = 16;
const INDEX_H_SHIFT: u32 = 11;
const INDEX_L_SHIFT: u32 = 21;
const INDEX_M_SHIFT: u32 = 20;
const INDEX_BIT_MASK: u32 = 1;
const HALF_LANE_HIGH_SHIFT: u32 = 2;
const HALF_LANE_LOW_SHIFT: u32 = 1;
const SINGLE_LANE_HIGH_SHIFT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub operation: FusedOperation,
    pub format: Format,
    pub shape: Shape,
    pub destination: u8,
    pub addend: u8,
    pub left: u8,
    pub right: u8,
    pub right_lane: Option<u8>,
}

/// None is another family; Err is reserved scalar ftype, vector 1D or indexed D/L.
/// Register fields denote ordinary V registers; indexed H permits only V0–V15.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    decode_scalar(word)
        .or_else(|| decode_vector(word))
        .or_else(|| decode_indexed(word))
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

fn decode_scalar(word: u32) -> Option<Result<Operand, ()>> {
    let operation = match word & SCALAR_MASK {
        FMADD => FusedOperation::Add,
        FMSUB => FusedOperation::Subtract,
        FNMADD => FusedOperation::NegatedAdd,
        FNMSUB => FusedOperation::NegatedSubtract,
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
        destination: register(word, DESTINATION_SHIFT),
        addend: register(word, ADDEND_SHIFT),
        left: register(word, LEFT_SHIFT),
        right: register(word, RIGHT_SHIFT),
        right_lane: None,
    }))
}

fn decode_vector(word: u32) -> Option<Result<Operand, ()>> {
    let half_operation = match word & VECTOR_HALF_MASK {
        VECTOR_HALF_FMLA => Some(FusedOperation::Add),
        VECTOR_HALF_FMLS => Some(FusedOperation::Subtract),
        _ => None,
    };
    let shape = vector_shape(word);
    let (operation, format) = if let Some(operation) = half_operation {
        (operation, Format::Half)
    } else {
        let operation = match word & VECTOR_MASK {
            VECTOR_FMLA => FusedOperation::Add,
            VECTOR_FMLS => FusedOperation::Subtract,
            _ => return None,
        };
        let format = if word & VECTOR_DOUBLE == 0 {
            Format::Single
        } else {
            if shape == Shape::Vector64 {
                return Some(Err(()));
            }
            Format::Double
        };
        (operation, format)
    };
    let destination = register(word, DESTINATION_SHIFT);
    Some(Ok(Operand {
        operation,
        format,
        shape,
        destination,
        addend: destination,
        left: register(word, LEFT_SHIFT),
        right: register(word, RIGHT_SHIFT),
        right_lane: None,
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
    let (format, right, lane) = if half {
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
    let operation = if word & INDEXED_SUBTRACT == 0 {
        FusedOperation::Add
    } else {
        FusedOperation::Subtract
    };
    let destination = register(word, DESTINATION_SHIFT);
    Some(Ok(Operand {
        operation,
        format,
        shape,
        destination,
        addend: destination,
        left: register(word, LEFT_SHIFT),
        right,
        right_lane: Some(lane as u8),
    }))
}

#[cfg(test)]
mod tests;
