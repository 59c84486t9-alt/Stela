//! Fused reciprocal refinement steps from the pinned Arm A64 2026-06 reference.
use crate::aarch64::floating::Format;

use super::arithmetic::Shape;

const SCALAR_MASK: u32 = 0xffa0_fc00;
const VECTOR_MASK: u32 = 0xbfa0_fc00;
const SCALAR_HALF_MASK: u32 = 0xffe0_fc00;
const VECTOR_HALF_MASK: u32 = 0xbfe0_fc00;
const SCALAR_PREFIX: u32 = 0x5000_0000;
const HALF_ADJUSTMENT: u32 = 0x0060_c000;
const FRECPS: u32 = 0x0e20_fc00;
const FRSQRTS: u32 = 0x0ea0_fc00;
const VECTOR_Q: u32 = 1 << 30;
const DOUBLE_SIZE: u32 = 1 << 22;
const REGISTER_MASK: u32 = 31;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Reciprocal,
    ReciprocalSquareRoot,
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

fn kind(opcode: u32) -> Option<Kind> {
    Some(match opcode {
        FRECPS => Kind::Reciprocal,
        FRSQRTS => Kind::ReciprocalSquareRoot,
        _ => return None,
    })
}

/// None denotes another family; Err denotes reserved vector1D. Every register
/// field is ordinary V data, including V31 and all source/destination aliases.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    for (mask, adjustment, scalar, half) in [
        (SCALAR_MASK, SCALAR_PREFIX, true, false),
        (VECTOR_MASK, 0, false, false),
        (
            SCALAR_HALF_MASK,
            SCALAR_PREFIX | HALF_ADJUSTMENT,
            true,
            true,
        ),
        (VECTOR_HALF_MASK, HALF_ADJUSTMENT, false, true),
    ] {
        let Some(kind) = kind((word & mask) ^ adjustment) else {
            continue;
        };
        let format = if half {
            Format::Half
        } else if word & DOUBLE_SIZE != 0 {
            Format::Double
        } else {
            Format::Single
        };
        let shape = if scalar {
            Shape::Scalar
        } else if word & VECTOR_Q == 0 {
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
mod tests;
