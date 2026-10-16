//! SVE integer and complex dot products, half-precision FDOT and widening
//! multiply-add. Indexed sources select within each 128-bit segment.

use crate::aarch64::scalable::ElementSize;

const REGISTER_MASK: u32 = 31;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const ROTATION_SHIFT: u32 = 10;
const ROTATION_MASK: u32 = 3;
const WORD_INDEX_SHIFT: u32 = 19;
const WORD_INDEX_MASK: u32 = 3;
const DOUBLE_INDEX_SHIFT: u32 = 20;
const DOUBLE_INDEX_MASK: u32 = 1;
const HALF_INDEX_LOW_SHIFT: u32 = 11;
const HALF_INDEX_LOW_MASK: u32 = 1;
const INDEXED_WORD_REGISTER_MASK: u32 = 7;
const INDEXED_DOUBLE_REGISTER_MASK: u32 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signedness {
    Signed,
    Unsigned,
    UnsignedSigned,
    SignedUnsigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Products {
    Two,
    Four,
}

impl Products {
    pub const fn count(self) -> u32 {
        match self {
            Self::Two => 2,
            Self::Four => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorPart {
    Bottom,
    Top,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RightOperand {
    Vector(u8),
    Indexed { register: u8, index: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    Zero,
    Ninety,
    OneEighty,
    TwoSeventy,
}

impl Rotation {
    /// CDOT's integer component selection is distinct from FCMLA's rotation.
    pub const fn component_selection(self) -> (u8, u8, bool) {
        match self {
            Self::Zero => (0, 1, true),
            Self::Ninety => (1, 0, false),
            Self::OneEighty => (0, 1, false),
            Self::TwoSeventy => (1, 0, true),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Integer {
        signedness: Signedness,
        products: Products,
    },
    Complex {
        rotation: Rotation,
    },
    HalfDot,
    HalfMultiplyLong {
        subtract: bool,
        part: VectorPart,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub element_size: ElementSize,
    pub destination: u8,
    pub left: u8,
    pub right: RightOperand,
}

impl Operand {
    /// Mixed signedness dot products need the guest I8MM extension in addition
    /// to streaming SVE through SME. Host SSSE3 selection is independent.
    pub const fn requires_i8mm(self) -> bool {
        matches!(
            self.kind,
            Kind::Integer {
                signedness: Signedness::UnsignedSigned | Signedness::SignedUnsigned,
                ..
            }
        )
    }
}

#[derive(Clone, Copy)]
enum SourceShape {
    Vector,
    IndexedWord,
    IndexedDoubleWord,
    IndexedHalf,
}

#[derive(Clone, Copy)]
enum SizeShape {
    Word,
    DoubleWord,
    Variable,
}

#[derive(Clone, Copy)]
struct Encoding {
    mask: u32,
    value: u32,
    kind: Kind,
    source: SourceShape,
    size: SizeShape,
}

const fn integer(signedness: Signedness, products: Products) -> Kind {
    Kind::Integer {
        signedness,
        products,
    }
}

// Fixed bits are the canonical Arm A64 2026-06 forms. In particular, the
// SME2 two-product forms have 32-bit outputs and 16-bit multiplicands; the
// separate SVE2p3 byte-to-Half forms are not selected by the Apple inventory.
const ENCODINGS: &[Encoding] = &[
    Encoding {
        mask: 0xffa0fc00,
        value: 0x44800000,
        kind: integer(Signedness::Signed, Products::Four),
        source: SourceShape::Vector,
        size: SizeShape::Variable,
    },
    Encoding {
        mask: 0xffa0fc00,
        value: 0x44800400,
        kind: integer(Signedness::Unsigned, Products::Four),
        source: SourceShape::Vector,
        size: SizeShape::Variable,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x44a00000,
        kind: integer(Signedness::Signed, Products::Four),
        source: SourceShape::IndexedWord,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x44a00400,
        kind: integer(Signedness::Unsigned, Products::Four),
        source: SourceShape::IndexedWord,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x44e00000,
        kind: integer(Signedness::Signed, Products::Four),
        source: SourceShape::IndexedDoubleWord,
        size: SizeShape::DoubleWord,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x44e00400,
        kind: integer(Signedness::Unsigned, Products::Four),
        source: SourceShape::IndexedDoubleWord,
        size: SizeShape::DoubleWord,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x44807800,
        kind: integer(Signedness::UnsignedSigned, Products::Four),
        source: SourceShape::Vector,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x44a01800,
        kind: integer(Signedness::UnsignedSigned, Products::Four),
        source: SourceShape::IndexedWord,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x44a01c00,
        kind: integer(Signedness::SignedUnsigned, Products::Four),
        source: SourceShape::IndexedWord,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x4400c800,
        kind: integer(Signedness::Signed, Products::Two),
        source: SourceShape::Vector,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x4400cc00,
        kind: integer(Signedness::Unsigned, Products::Two),
        source: SourceShape::Vector,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x4480c800,
        kind: integer(Signedness::Signed, Products::Two),
        source: SourceShape::IndexedWord,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x4480cc00,
        kind: integer(Signedness::Unsigned, Products::Two),
        source: SourceShape::IndexedWord,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xff20f000,
        value: 0x44001000,
        kind: Kind::Complex {
            rotation: Rotation::Zero,
        },
        source: SourceShape::Vector,
        size: SizeShape::Variable,
    },
    Encoding {
        mask: 0xffe0f000,
        value: 0x44a04000,
        kind: Kind::Complex {
            rotation: Rotation::Zero,
        },
        source: SourceShape::IndexedWord,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0f000,
        value: 0x44e04000,
        kind: Kind::Complex {
            rotation: Rotation::Zero,
        },
        source: SourceShape::IndexedDoubleWord,
        size: SizeShape::DoubleWord,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64208000,
        kind: Kind::HalfDot,
        source: SourceShape::Vector,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64204000,
        kind: Kind::HalfDot,
        source: SourceShape::IndexedWord,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64a08000,
        kind: Kind::HalfMultiplyLong {
            subtract: false,
            part: VectorPart::Bottom,
        },
        source: SourceShape::Vector,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64a08400,
        kind: Kind::HalfMultiplyLong {
            subtract: false,
            part: VectorPart::Top,
        },
        source: SourceShape::Vector,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64a0a000,
        kind: Kind::HalfMultiplyLong {
            subtract: true,
            part: VectorPart::Bottom,
        },
        source: SourceShape::Vector,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0fc00,
        value: 0x64a0a400,
        kind: Kind::HalfMultiplyLong {
            subtract: true,
            part: VectorPart::Top,
        },
        source: SourceShape::Vector,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0f400,
        value: 0x64a04000,
        kind: Kind::HalfMultiplyLong {
            subtract: false,
            part: VectorPart::Bottom,
        },
        source: SourceShape::IndexedHalf,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0f400,
        value: 0x64a04400,
        kind: Kind::HalfMultiplyLong {
            subtract: false,
            part: VectorPart::Top,
        },
        source: SourceShape::IndexedHalf,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0f400,
        value: 0x64a06000,
        kind: Kind::HalfMultiplyLong {
            subtract: true,
            part: VectorPart::Bottom,
        },
        source: SourceShape::IndexedHalf,
        size: SizeShape::Word,
    },
    Encoding {
        mask: 0xffe0f400,
        value: 0x64a06400,
        kind: Kind::HalfMultiplyLong {
            subtract: true,
            part: VectorPart::Top,
        },
        source: SourceShape::IndexedHalf,
        size: SizeShape::Word,
    },
];

/// Feature and execution-mode validation belongs to the enclosing SVE profile.
/// These instructions have no predicate operand; every output lane is active.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let encoding = ENCODINGS
        .iter()
        .find(|encoding| word & encoding.mask == encoding.value)?;
    let element_size = match encoding.size {
        SizeShape::Word => ElementSize::Word,
        SizeShape::DoubleWord => ElementSize::Doubleword,
        SizeShape::Variable => match (word >> SIZE_SHIFT) & SIZE_MASK {
            2 => ElementSize::Word,
            3 => ElementSize::Doubleword,
            _ => return Some(Err(())),
        },
    };
    let kind = if let Kind::Complex { .. } = encoding.kind {
        let rotation = match (word >> ROTATION_SHIFT) & ROTATION_MASK {
            0 => Rotation::Zero,
            1 => Rotation::Ninety,
            2 => Rotation::OneEighty,
            3 => Rotation::TwoSeventy,
            _ => unreachable!(),
        };
        Kind::Complex { rotation }
    } else {
        encoding.kind
    };
    let right = match encoding.source {
        SourceShape::Vector => RightOperand::Vector(register(word, RIGHT_SHIFT)),
        SourceShape::IndexedWord => RightOperand::Indexed {
            register: ((word >> RIGHT_SHIFT) & INDEXED_WORD_REGISTER_MASK) as u8,
            index: ((word >> WORD_INDEX_SHIFT) & WORD_INDEX_MASK) as u8,
        },
        SourceShape::IndexedDoubleWord => RightOperand::Indexed {
            register: ((word >> RIGHT_SHIFT) & INDEXED_DOUBLE_REGISTER_MASK) as u8,
            index: ((word >> DOUBLE_INDEX_SHIFT) & DOUBLE_INDEX_MASK) as u8,
        },
        SourceShape::IndexedHalf => RightOperand::Indexed {
            register: ((word >> RIGHT_SHIFT) & INDEXED_WORD_REGISTER_MASK) as u8,
            index: ((((word >> WORD_INDEX_SHIFT) & WORD_INDEX_MASK) << 1)
                | ((word >> HALF_INDEX_LOW_SHIFT) & HALF_INDEX_LOW_MASK)) as u8,
        },
    };
    Some(Ok(Operand {
        kind,
        element_size,
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        right,
    }))
}

/// Integer-only admission shares allocation checks with the numerical decoder.
/// Half dot and widening arithmetic remain separate numerical operations.
#[allow(clippy::result_unit_err)]
pub fn decode_integer(word: u32) -> Option<Result<Operand, ()>> {
    match decode(word)? {
        Ok(operand) if matches!(operand.kind, Kind::Integer { .. } | Kind::Complex { .. }) => {
            Some(Ok(operand))
        }
        Err(()) => Some(Err(())),
        Ok(_) => None,
    }
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

#[cfg(test)]
mod tests;
