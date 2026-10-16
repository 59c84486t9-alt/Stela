//! Reciprocal, reciprocal-square-root and exponent estimates (Arm A64 2026-06).
use crate::aarch64::floating::Format;

use super::arithmetic::Shape;

const SCALAR_MASK: u32 = 0xffbf_fc00;
const VECTOR_MASK: u32 = 0xbfbf_fc00;
const SCALAR_HALF_MASK: u32 = 0xffff_fc00;
const VECTOR_HALF_MASK: u32 = 0xbfff_fc00;
const SCALAR_PREFIX: u32 = 0x5000_0000;
const HALF_ADJUSTMENT: u32 = 0x0058_0000;
// Normalized floating class opcodes; FRECPX is admitted only with scalar prefix.
const FRECPE: u32 = 0x0ea1_d800;
const FRSQRTE: u32 = 0x2ea1_d800;
const FRECPX: u32 = 0x0ea1_f800;
const URECPE: u32 = 0x0ea1_c800;
const URSQRTE: u32 = 0x2ea1_c800;
const VECTOR_Q: u32 = 1 << 30;
const DOUBLE_SIZE: u32 = 1 << 22;
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Reciprocal,
    ReciprocalSquareRoot,
    ReciprocalExponent,
    UnsignedReciprocal,
    UnsignedReciprocalSquareRoot,
}

impl Kind {
    pub const fn is_unsigned(self) -> bool {
        matches!(
            self,
            Self::UnsignedReciprocal | Self::UnsignedReciprocalSquareRoot
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    /// Unsigned kinds use Single solely to identify their 32-bit integer lanes.
    pub format: Format,
    pub shape: Shape,
    pub destination: u8,
    pub source: u8,
}

fn floating_kind(opcode: u32) -> Option<Kind> {
    Some(match opcode {
        FRECPE => Kind::Reciprocal,
        FRSQRTE => Kind::ReciprocalSquareRoot,
        FRECPX => Kind::ReciprocalExponent,
        _ => return None,
    })
}

fn vector_shape(word: u32) -> Shape {
    if word & VECTOR_Q == 0 {
        Shape::Vector64
    } else {
        Shape::Vector128
    }
}

/// None denotes another family; Err denotes floating vector1D or unsigned sz1.
/// FRECPX is scalar only. All registers, including V31, are ordinary vector data.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let unsigned = match word & VECTOR_MASK {
        URECPE => Some(Kind::UnsignedReciprocal),
        URSQRTE => Some(Kind::UnsignedReciprocalSquareRoot),
        _ => None,
    };
    if let Some(kind) = unsigned {
        if word & DOUBLE_SIZE != 0 {
            return Some(Err(()));
        }
        return Some(Ok(operand(word, kind, Format::Single, vector_shape(word))));
    }
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
        let Some(kind) = floating_kind((word & mask) ^ adjustment) else {
            continue;
        };
        if kind == Kind::ReciprocalExponent && !scalar {
            continue;
        }
        let format = if half {
            Format::Half
        } else if word & DOUBLE_SIZE != 0 {
            Format::Double
        } else {
            Format::Single
        };
        let shape = if scalar {
            Shape::Scalar
        } else {
            vector_shape(word)
        };
        if format == Format::Double && shape == Shape::Vector64 {
            return Some(Err(()));
        }
        return Some(Ok(operand(word, kind, format, shape)));
    }
    None
}

fn operand(word: u32, kind: Kind, format: Format, shape: Shape) -> Operand {
    Operand {
        kind,
        format,
        shape,
        destination: (word & REGISTER_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
    }
}

#[cfg(test)]
mod tests;
