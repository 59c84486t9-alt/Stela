//! Scalar and AdvSIMD integral rounding from the pinned Arm A64 2026-06 reference.
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
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let (operation, format, shape) = if let Some(operation) = scalar_operation(word & SCALAR_MASK) {
        let format = match (word >> FORMAT_SHIFT) & FORMAT_MASK {
            FORMAT_SINGLE => Format::Single,
            FORMAT_DOUBLE => Format::Double,
            FORMAT_HALF if operation.signed_width().is_none() => Format::Half,
            _ => return Some(Err(())),
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
            return Some(Err(()));
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
mod tests;
