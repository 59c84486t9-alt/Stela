//! AdvSIMD FAMIN/FAMAX (FEAT_FAMINMAX) and FSCALE (FEAT_FP8).
use crate::aarch64::floating::{Format, absolute_minmax::AbsoluteMinMaxOperation};

use super::arithmetic::Shape;

const REGISTER_MASK: u32 = 31;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const VECTOR_Q: u32 = 1 << 30;
const DOUBLE_SIZE: u32 = 1 << 22;
const ORDINARY_MASK: u32 = 0xbfa0_fc00;
const HALF_MASK: u32 = 0xbfe0_fc00;
const FAMAX: u32 = 0x0ea0_dc00;
const FAMIN: u32 = 0x2ea0_dc00;
const FSCALE: u32 = 0x2ea0_fc00;
const HALF_FAMAX: u32 = 0x0ec0_1c00;
const HALF_FAMIN: u32 = 0x2ec0_1c00;
const HALF_FSCALE: u32 = 0x2ec0_3c00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Absolute(AbsoluteMinMaxOperation),
    Scale,
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

/// V31 is ordinary data in every position. Q=0 writes clear the upper 64 bits.
/// The one-double arrangement is reserved; scalar/pairwise neighbors decline.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    for (mask, half) in [(HALF_MASK, true), (ORDINARY_MASK, false)] {
        let kind = match (word & mask, half) {
            (HALF_FAMAX, true) | (FAMAX, false) => Kind::Absolute(AbsoluteMinMaxOperation::Maximum),
            (HALF_FAMIN, true) | (FAMIN, false) => Kind::Absolute(AbsoluteMinMaxOperation::Minimum),
            (HALF_FSCALE, true) | (FSCALE, false) => Kind::Scale,
            _ => continue,
        };
        let format = if half {
            Format::Half
        } else if word & DOUBLE_SIZE != 0 {
            Format::Double
        } else {
            Format::Single
        };
        let shape = if word & VECTOR_Q == 0 {
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
