//! SVE BF16 arithmetic, dot products and widening multiply-add. Non-widening
//! arithmetic rounds to BF16 and reports exceptions. Predicated forms merge.

use crate::aarch64::sve::dot::{RightOperand, VectorPart};

const REGISTER_MASK: u32 = 31;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const INDEX_HIGH_SHIFT: u32 = 19;
const INDEX_HIGH_MASK: u32 = 3;
const HALF_INDEX_LOW_SHIFT: u32 = 11;
const HALF_INDEX_HIGH_SHIFT: u32 = 22;
const INDEX_BIT_MASK: u32 = 1;
const INDEXED_REGISTER_MASK: u32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperation {
    Add,
    Subtract,
    Multiply,
    Maximum,
    MaximumNumber,
    Minimum,
    MinimumNumber,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Binary(BinaryOperation),
    Clamp,
    MultiplyAdd { subtract: bool },
    Dot,
    MultiplyLong { subtract: bool, part: VectorPart },
}

impl Kind {
    pub const fn output_bits(self) -> u32 {
        match self {
            Self::Dot | Self::MultiplyLong { .. } => 32,
            Self::Binary(_) | Self::Clamp | Self::MultiplyAdd { .. } => 16,
        }
    }

    /// These forms require B16B16; streaming execution additionally needs SME2.
    /// Classic BF16 dot/long-add and SME2 long-subtract have separate predicates.
    pub const fn is_b16b16(self) -> bool {
        matches!(
            self,
            Self::Binary(_) | Self::Clamp | Self::MultiplyAdd { .. }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub left: u8,
    pub right: RightOperand,
    pub predicate: Option<u8>,
}

#[derive(Clone, Copy)]
enum SourceShape {
    Vector,
    PredicatedBinary,
    PredicatedMultiplyAdd,
    IndexedPair,
    IndexedHalf,
    IndexedLong,
}

#[derive(Clone, Copy)]
struct Encoding {
    mask: u32,
    value: u32,
    kind: Kind,
    source: SourceShape,
}

const ENCODINGS: &[Encoding] = &[
    Encoding {
        mask: 0xffffe000,
        value: 0x65008000,
        kind: Kind::Binary(BinaryOperation::Add),
        source: SourceShape::PredicatedBinary,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x65000000,
        kind: Kind::Binary(BinaryOperation::Add),
        source: SourceShape::Vector,
    },
    Encoding {
        mask: 0xffffe000,
        value: 0x65018000,
        kind: Kind::Binary(BinaryOperation::Subtract),
        source: SourceShape::PredicatedBinary,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x65000400,
        kind: Kind::Binary(BinaryOperation::Subtract),
        source: SourceShape::Vector,
    },
    Encoding {
        mask: 0xffffe000,
        value: 0x65028000,
        kind: Kind::Binary(BinaryOperation::Multiply),
        source: SourceShape::PredicatedBinary,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x65000800,
        kind: Kind::Binary(BinaryOperation::Multiply),
        source: SourceShape::Vector,
    },
    Encoding {
        mask: 0xffa0fc00,
        value: 0x64202800,
        kind: Kind::Binary(BinaryOperation::Multiply),
        source: SourceShape::IndexedHalf,
    },
    Encoding {
        mask: 0xffffe000,
        value: 0x65068000,
        kind: Kind::Binary(BinaryOperation::Maximum),
        source: SourceShape::PredicatedBinary,
    },
    Encoding {
        mask: 0xffffe000,
        value: 0x65048000,
        kind: Kind::Binary(BinaryOperation::MaximumNumber),
        source: SourceShape::PredicatedBinary,
    },
    Encoding {
        mask: 0xffffe000,
        value: 0x65078000,
        kind: Kind::Binary(BinaryOperation::Minimum),
        source: SourceShape::PredicatedBinary,
    },
    Encoding {
        mask: 0xffffe000,
        value: 0x65058000,
        kind: Kind::Binary(BinaryOperation::MinimumNumber),
        source: SourceShape::PredicatedBinary,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64202400,
        kind: Kind::Clamp,
        source: SourceShape::Vector,
    },
    Encoding {
        mask: 0xffe0e000,
        value: 0x65200000,
        kind: Kind::MultiplyAdd { subtract: false },
        source: SourceShape::PredicatedMultiplyAdd,
    },
    Encoding {
        mask: 0xffe0e000,
        value: 0x65202000,
        kind: Kind::MultiplyAdd { subtract: true },
        source: SourceShape::PredicatedMultiplyAdd,
    },
    Encoding {
        mask: 0xffa0fc00,
        value: 0x64200800,
        kind: Kind::MultiplyAdd { subtract: false },
        source: SourceShape::IndexedHalf,
    },
    Encoding {
        mask: 0xffa0fc00,
        value: 0x64200c00,
        kind: Kind::MultiplyAdd { subtract: true },
        source: SourceShape::IndexedHalf,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64608000,
        kind: Kind::Dot,
        source: SourceShape::Vector,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64604000,
        kind: Kind::Dot,
        source: SourceShape::IndexedPair,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64e08000,
        kind: Kind::MultiplyLong {
            subtract: false,
            part: VectorPart::Bottom,
        },
        source: SourceShape::Vector,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64e08400,
        kind: Kind::MultiplyLong {
            subtract: false,
            part: VectorPart::Top,
        },
        source: SourceShape::Vector,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64e0a000,
        kind: Kind::MultiplyLong {
            subtract: true,
            part: VectorPart::Bottom,
        },
        source: SourceShape::Vector,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64e0a400,
        kind: Kind::MultiplyLong {
            subtract: true,
            part: VectorPart::Top,
        },
        source: SourceShape::Vector,
    },
    Encoding {
        mask: 0xffe0f400,
        value: 0x64e04000,
        kind: Kind::MultiplyLong {
            subtract: false,
            part: VectorPart::Bottom,
        },
        source: SourceShape::IndexedLong,
    },
    Encoding {
        mask: 0xffe0f400,
        value: 0x64e04400,
        kind: Kind::MultiplyLong {
            subtract: false,
            part: VectorPart::Top,
        },
        source: SourceShape::IndexedLong,
    },
    Encoding {
        mask: 0xffe0f400,
        value: 0x64e06000,
        kind: Kind::MultiplyLong {
            subtract: true,
            part: VectorPart::Bottom,
        },
        source: SourceShape::IndexedLong,
    },
    Encoding {
        mask: 0xffe0f400,
        value: 0x64e06400,
        kind: Kind::MultiplyLong {
            subtract: true,
            part: VectorPart::Top,
        },
        source: SourceShape::IndexedLong,
    },
];

/// Exact fixed-bit forms contain no additional reserved register/index values.
/// The enclosing decoder validates guest feature availability and streaming mode.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let encoding = ENCODINGS
        .iter()
        .find(|encoding| word & encoding.mask == encoding.value)?;
    let destination = register(word, DESTINATION_SHIFT);
    let left = if matches!(encoding.source, SourceShape::PredicatedBinary) {
        destination
    } else {
        register(word, LEFT_SHIFT)
    };
    let right = match encoding.source {
        SourceShape::Vector | SourceShape::PredicatedMultiplyAdd => {
            RightOperand::Vector(register(word, RIGHT_SHIFT))
        }
        SourceShape::PredicatedBinary => RightOperand::Vector(register(word, LEFT_SHIFT)),
        SourceShape::IndexedPair => RightOperand::Indexed {
            register: indexed_register(word),
            index: ((word >> INDEX_HIGH_SHIFT) & INDEX_HIGH_MASK) as u8,
        },
        SourceShape::IndexedHalf => RightOperand::Indexed {
            register: indexed_register(word),
            index: ((((word >> HALF_INDEX_HIGH_SHIFT) & INDEX_BIT_MASK) << 2)
                | ((word >> INDEX_HIGH_SHIFT) & INDEX_HIGH_MASK)) as u8,
        },
        SourceShape::IndexedLong => RightOperand::Indexed {
            register: indexed_register(word),
            index: ((((word >> INDEX_HIGH_SHIFT) & INDEX_HIGH_MASK) << 1)
                | ((word >> HALF_INDEX_LOW_SHIFT) & INDEX_BIT_MASK)) as u8,
        },
    };
    let predicate = if matches!(
        encoding.source,
        SourceShape::PredicatedBinary | SourceShape::PredicatedMultiplyAdd
    ) {
        Some(((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8)
    } else {
        None
    };
    Some(Ok(Operand {
        kind: encoding.kind,
        destination,
        left,
        right,
        predicate,
    }))
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

fn indexed_register(word: u32) -> u8 {
    ((word >> RIGHT_SHIFT) & INDEXED_REGISTER_MASK) as u8
}

#[cfg(test)]
mod tests;
