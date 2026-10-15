//! Streaming BF dot and widening Single accumulation allocations.

use crate::aarch64::sve::dot::{RightOperand, VectorPart};

const REGISTER_MASK: u32 = 31;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const INDEX_HIGH_SHIFT: u32 = 19;
const INDEX_HIGH_MASK: u32 = 3;
const HALF_INDEX_LOW_SHIFT: u32 = 11;
const INDEX_BIT_MASK: u32 = 1;
const INDEXED_REGISTER_MASK: u32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dot,
    MultiplyLong { subtract: bool, part: VectorPart },
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
    IndexedPair,
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
    let left = register(word, LEFT_SHIFT);
    let right = match encoding.source {
        SourceShape::Vector => RightOperand::Vector(register(word, RIGHT_SHIFT)),
        SourceShape::IndexedPair => RightOperand::Indexed {
            register: indexed_register(word),
            index: ((word >> INDEX_HIGH_SHIFT) & INDEX_HIGH_MASK) as u8,
        },
        SourceShape::IndexedLong => RightOperand::Indexed {
            register: indexed_register(word),
            index: ((((word >> INDEX_HIGH_SHIFT) & INDEX_HIGH_MASK) << 1)
                | ((word >> HALF_INDEX_LOW_SHIFT) & INDEX_BIT_MASK)) as u8,
        },
    };
    let predicate = None;
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
mod tests {
    use super::*;

    #[test]
    fn classic_dot_and_long_indices_preserve_original_fields() {
        for index in 0..8 {
            let word = 0x64e04000
                | ((index >> 1) << INDEX_HIGH_SHIFT)
                | ((index & INDEX_BIT_MASK) << HALF_INDEX_LOW_SHIFT)
                | (7 << RIGHT_SHIFT)
                | (30 << LEFT_SHIFT)
                | 31;
            let operand = decode(word).unwrap().unwrap();
            assert_eq!(operand.destination, 31);
            assert_eq!(operand.left, 30);
            assert_eq!(
                operand.right,
                RightOperand::Indexed {
                    register: 7,
                    index: index as u8
                }
            );
            assert_eq!(operand.predicate, None);
        }
        for index in 0..4 {
            let operand = decode(0x64604000 | (index << INDEX_HIGH_SHIFT) | (7 << RIGHT_SHIFT))
                .unwrap()
                .unwrap();
            assert_eq!(operand.kind, Kind::Dot);
            assert_eq!(
                operand.right,
                RightOperand::Indexed {
                    register: 7,
                    index: index as u8
                }
            );
        }
    }

    #[test]
    fn separately_owned_true_bfloat_and_conversion_allocations_decline() {
        for word in [
            0x65008000, 0x65000000, 0x65018000, 0x65000400, 0x65028000, 0x65000800, 0x64202800,
            0x65068000, 0x65048000, 0x65078000, 0x65058000, 0x64202400, 0x65200000, 0x65202000,
            0x64200800, 0x64200c00, 0x658aa000,
        ] {
            assert_eq!(decode(word), None);
        }
    }
}
