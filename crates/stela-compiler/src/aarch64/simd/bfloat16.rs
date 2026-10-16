//! AdvSIMD BF16: BFCVT, BFCVTN, BFDOT, BFMMLA and BFMLAL.
use super::arithmetic::Shape;

const SCALAR_MASK: u32 = 0xffff_fc00;
const BFCVT: u32 = 0x1e63_4000;
const NARROW_MASK: u32 = 0xbfff_fc00;
const BFCVTN: u32 = 0x0ea1_6800;
const VECTOR_MASK: u32 = 0xbfe0_fc00;
const VECTOR_BFDOT: u32 = 0x2e40_fc00;
const VECTOR_BFMLAL: u32 = 0x2ec0_fc00;
const INDEXED_MASK: u32 = 0xbfc0_f400;
const INDEXED_BFDOT: u32 = 0x0f40_f000;
const INDEXED_BFMLAL: u32 = 0x0fc0_f000;
const MATRIX_MASK: u32 = 0xffe0_fc00;
const BFMMLA: u32 = 0x6e40_ec00;
const VECTOR_Q: u32 = 1 << 30;
const REGISTER_MASK: u32 = 31;
const INDEXED_MULTIPLY_REGISTER_MASK: u32 = 15;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const INDEX_H_SHIFT: u32 = 11;
const INDEX_L_SHIFT: u32 = 21;
const INDEX_M_SHIFT: u32 = 20;
const INDEX_BIT_MASK: u32 = 1;
const PAIR_INDEX_HIGH_SHIFT: u32 = 1;
const HALF_LANE_HIGH_SHIFT: u32 = 2;
const HALF_LANE_LOW_SHIFT: u32 = 1;
const SOURCE_PAIR_LANES: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionMode {
    Scalar,
    Narrow { upper: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConversionOperand {
    pub mode: ConversionMode,
    pub destination: u8,
    pub source: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotSource {
    Vector(u8),
    Indexed { register: u8, index: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DotOperand {
    pub shape: Shape,
    pub destination: u8,
    pub left: u8,
    pub right: DotSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    Even,
    Odd,
}

impl Parity {
    /// BFMLAL selects the even or odd source lane of each destination pair.
    pub const fn source_lane(self, destination_lane: u32) -> u32 {
        destination_lane * SOURCE_PAIR_LANES
            + match self {
                Self::Even => 0,
                Self::Odd => 1,
            }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiplySource {
    Vector(u8),
    Indexed { register: u8, index: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiplyOperand {
    pub parity: Parity,
    pub destination: u8,
    pub left: u8,
    pub right: MultiplySource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatrixOperand {
    pub destination: u8,
    pub left: u8,
    pub right: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Conversion(ConversionOperand),
    Dot(DotOperand),
    MultiplyAdd(MultiplyOperand),
    Matrix(MatrixOperand),
}

/// The masks match only this family's formats. Indexed multiplies accept only
/// V0-V15.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    decode_conversion(word)
        .or_else(|| decode_dot(word))
        .or_else(|| decode_multiply(word))
        .or_else(|| decode_matrix(word))
        .map(Ok)
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

fn decode_conversion(word: u32) -> Option<Operand> {
    let mode = if word & SCALAR_MASK == BFCVT {
        ConversionMode::Scalar
    } else if word & NARROW_MASK == BFCVTN {
        ConversionMode::Narrow {
            upper: word & VECTOR_Q != 0,
        }
    } else {
        return None;
    };
    Some(Operand::Conversion(ConversionOperand {
        mode,
        destination: register(word, DESTINATION_SHIFT),
        source: register(word, LEFT_SHIFT),
    }))
}

fn decode_dot(word: u32) -> Option<Operand> {
    let right = if word & VECTOR_MASK == VECTOR_BFDOT {
        DotSource::Vector(register(word, RIGHT_SHIFT))
    } else if word & INDEXED_MASK == INDEXED_BFDOT {
        let high = (word >> INDEX_H_SHIFT) & INDEX_BIT_MASK;
        let low = (word >> INDEX_L_SHIFT) & INDEX_BIT_MASK;
        DotSource::Indexed {
            register: register(word, RIGHT_SHIFT),
            index: ((high << PAIR_INDEX_HIGH_SHIFT) | low) as u8,
        }
    } else {
        return None;
    };
    Some(Operand::Dot(DotOperand {
        shape: vector_shape(word),
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        right,
    }))
}

fn decode_multiply(word: u32) -> Option<Operand> {
    let right = if word & VECTOR_MASK == VECTOR_BFMLAL {
        MultiplySource::Vector(register(word, RIGHT_SHIFT))
    } else if word & INDEXED_MASK == INDEXED_BFMLAL {
        let high = (word >> INDEX_H_SHIFT) & INDEX_BIT_MASK;
        let low = (word >> INDEX_L_SHIFT) & INDEX_BIT_MASK;
        let middle = (word >> INDEX_M_SHIFT) & INDEX_BIT_MASK;
        MultiplySource::Indexed {
            register: ((word >> RIGHT_SHIFT) & INDEXED_MULTIPLY_REGISTER_MASK) as u8,
            index: ((high << HALF_LANE_HIGH_SHIFT) | (low << HALF_LANE_LOW_SHIFT) | middle) as u8,
        }
    } else {
        return None;
    };
    Some(Operand::MultiplyAdd(MultiplyOperand {
        parity: if word & VECTOR_Q == 0 {
            Parity::Even
        } else {
            Parity::Odd
        },
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        right,
    }))
}

fn decode_matrix(word: u32) -> Option<Operand> {
    if word & MATRIX_MASK != BFMMLA {
        return None;
    }
    Some(Operand::Matrix(MatrixOperand {
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        right: register(word, RIGHT_SHIFT),
    }))
}

#[cfg(test)]
mod tests;
