//! Scalar and AdvSIMD FSQRT from the pinned Arm A64 2026-06 reference.
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
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let (format, shape) = if word & SCALAR_MASK == SCALAR_FSQRT {
        let format = match (word >> FORMAT_SHIFT) & FORMAT_MASK {
            FORMAT_SINGLE => Format::Single,
            FORMAT_DOUBLE => Format::Double,
            FORMAT_HALF => Format::Half,
            _ => return Some(Err(())),
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
            return Some(Err(()));
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
mod tests;
