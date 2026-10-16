//! FMLAL and FMLSL (half to single).
use crate::aarch64::floating::{Format, widening::WideningOperation};

use super::arithmetic::Shape;

const VECTOR_MASK: u32 = 0xbfe0_fc00;
const VECTOR_FMLAL: u32 = 0x0e20_ec00;
const VECTOR_FMLAL2: u32 = 0x2e20_cc00;
const VECTOR_FMLSL: u32 = 0x0ea0_ec00;
const VECTOR_FMLSL2: u32 = 0x2ea0_cc00;
const INDEXED_MASK: u32 = 0xbfc0_f400;
const INDEXED_FMLAL: u32 = 0x0f80_0000;
const INDEXED_FMLAL2: u32 = 0x2f80_8000;
const INDEXED_FMLSL: u32 = 0x0f80_4000;
const INDEXED_FMLSL2: u32 = 0x2f80_c000;
const VECTOR_Q: u32 = 1 << 30;
const REGISTER_MASK: u32 = 31;
const INDEXED_REGISTER_MASK: u32 = 15;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const INDEX_H_SHIFT: u32 = 11;
const INDEX_L_SHIFT: u32 = 21;
const INDEX_M_SHIFT: u32 = 20;
const INDEX_BIT_MASK: u32 = 1;
const HALF_LANE_HIGH_SHIFT: u32 = 2;
const HALF_LANE_LOW_SHIFT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Lower,
    Upper,
}

impl Part {
    /// The source part is relative to the active vector width: upper Q0 uses
    /// H2/H3, while upper Q1 uses H4..H7. Scalar FHM forms are not allocated.
    pub const fn source_lane_offset(self, shape: Shape) -> u32 {
        match shape {
            Shape::Scalar => panic!("widening FP16 requires a vector shape"),
            Shape::Vector64 | Shape::Vector128 => match self {
                Self::Lower => 0,
                Self::Upper => shape.lane_count(Format::Single),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub operation: WideningOperation,
    pub shape: Shape,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
    pub right_lane: Option<u8>,
    pub part: Part,
}

/// Exact fixed bits keep sz=1 and adjacent FP8/SME forms outside this family.
/// All registers are ordinary V registers; indexed Vm is limited to V0..V15.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let (operation, part) = match word & VECTOR_MASK {
        VECTOR_FMLAL => (WideningOperation::Add, Part::Lower),
        VECTOR_FMLAL2 => (WideningOperation::Add, Part::Upper),
        VECTOR_FMLSL => (WideningOperation::Subtract, Part::Lower),
        VECTOR_FMLSL2 => (WideningOperation::Subtract, Part::Upper),
        _ => return decode_indexed(word),
    };
    Some(Ok(operand(
        word,
        operation,
        part,
        register(word, RIGHT_SHIFT),
        None,
    )))
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

fn operand(
    word: u32,
    operation: WideningOperation,
    part: Part,
    right: u8,
    right_lane: Option<u8>,
) -> Operand {
    Operand {
        operation,
        shape: if word & VECTOR_Q == 0 {
            Shape::Vector64
        } else {
            Shape::Vector128
        },
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        right,
        right_lane,
        part,
    }
}

fn decode_indexed(word: u32) -> Option<Result<Operand, ()>> {
    let (operation, part) = match word & INDEXED_MASK {
        INDEXED_FMLAL => (WideningOperation::Add, Part::Lower),
        INDEXED_FMLAL2 => (WideningOperation::Add, Part::Upper),
        INDEXED_FMLSL => (WideningOperation::Subtract, Part::Lower),
        INDEXED_FMLSL2 => (WideningOperation::Subtract, Part::Upper),
        _ => return None,
    };
    let high = (word >> INDEX_H_SHIFT) & INDEX_BIT_MASK;
    let low = (word >> INDEX_L_SHIFT) & INDEX_BIT_MASK;
    let middle = (word >> INDEX_M_SHIFT) & INDEX_BIT_MASK;
    let right = ((word >> RIGHT_SHIFT) & INDEXED_REGISTER_MASK) as u8;
    let lane = (high << HALF_LANE_HIGH_SHIFT) | (low << HALF_LANE_LOW_SHIFT) | middle;
    Some(Ok(operand(word, operation, part, right, Some(lane as u8))))
}

#[cfg(test)]
mod tests;
