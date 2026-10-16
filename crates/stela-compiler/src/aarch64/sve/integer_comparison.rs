//! SVE integer comparisons into predicates (CMP*).
use crate::aarch64::scalable::ElementSize;

const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const SOURCE_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const UNSIGNED_IMMEDIATE_SHIFT: u32 = 14;
const GOVERNING_SHIFT: u32 = 10;
const Z_REGISTER_MASK: u32 = 31;
const P_REGISTER_MASK: u32 = 15;
const GOVERNING_REGISTER_MASK: u32 = 7;
const SIGNED_IMMEDIATE_MASK: u32 = 31;
const UNSIGNED_IMMEDIATE_MASK: u32 = 127;
const SIGNED_IMMEDIATE_SIGN: i16 = 16;
const SIGNED_IMMEDIATE_MODULUS: i16 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    Equal,
    NotEqual,
    GreaterEqual,
    Greater,
    LessEqual,
    Less,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Right {
    Immediate(i16),
    Vector(u8),
    WideVector(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub relation: Relation,
    pub unsigned: bool,
    pub element_size: ElementSize,
    pub destination: u8,
    pub governing: u8,
    pub left: u8,
    pub right: Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    Immediate,
    Vector,
    WideVector,
}
struct Encoding {
    mask: u32,
    value: u32,
    relation: Relation,
    unsigned: bool,
    source: SourceKind,
}
const ENCODINGS: [Encoding; 26] = [
    Encoding {
        mask: 0xff20e010,
        value: 0x25008000,
        relation: Relation::Equal,
        unsigned: false,
        source: SourceKind::Immediate,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x24002000,
        relation: Relation::Equal,
        unsigned: false,
        source: SourceKind::WideVector,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x2400a000,
        relation: Relation::Equal,
        unsigned: false,
        source: SourceKind::Vector,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x25000000,
        relation: Relation::GreaterEqual,
        unsigned: false,
        source: SourceKind::Immediate,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x24004000,
        relation: Relation::GreaterEqual,
        unsigned: false,
        source: SourceKind::WideVector,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x24008000,
        relation: Relation::GreaterEqual,
        unsigned: false,
        source: SourceKind::Vector,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x25000010,
        relation: Relation::Greater,
        unsigned: false,
        source: SourceKind::Immediate,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x24004010,
        relation: Relation::Greater,
        unsigned: false,
        source: SourceKind::WideVector,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x24008010,
        relation: Relation::Greater,
        unsigned: false,
        source: SourceKind::Vector,
    },
    Encoding {
        mask: 0xff202010,
        value: 0x24200010,
        relation: Relation::Greater,
        unsigned: true,
        source: SourceKind::Immediate,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x2400c010,
        relation: Relation::Greater,
        unsigned: true,
        source: SourceKind::WideVector,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x24000010,
        relation: Relation::Greater,
        unsigned: true,
        source: SourceKind::Vector,
    },
    Encoding {
        mask: 0xff202010,
        value: 0x24200000,
        relation: Relation::GreaterEqual,
        unsigned: true,
        source: SourceKind::Immediate,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x2400c000,
        relation: Relation::GreaterEqual,
        unsigned: true,
        source: SourceKind::WideVector,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x24000000,
        relation: Relation::GreaterEqual,
        unsigned: true,
        source: SourceKind::Vector,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x25002010,
        relation: Relation::LessEqual,
        unsigned: false,
        source: SourceKind::Immediate,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x24006010,
        relation: Relation::LessEqual,
        unsigned: false,
        source: SourceKind::WideVector,
    },
    Encoding {
        mask: 0xff202010,
        value: 0x24202000,
        relation: Relation::Less,
        unsigned: true,
        source: SourceKind::Immediate,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x2400e000,
        relation: Relation::Less,
        unsigned: true,
        source: SourceKind::WideVector,
    },
    Encoding {
        mask: 0xff202010,
        value: 0x24202010,
        relation: Relation::LessEqual,
        unsigned: true,
        source: SourceKind::Immediate,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x2400e010,
        relation: Relation::LessEqual,
        unsigned: true,
        source: SourceKind::WideVector,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x25002000,
        relation: Relation::Less,
        unsigned: false,
        source: SourceKind::Immediate,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x24006000,
        relation: Relation::Less,
        unsigned: false,
        source: SourceKind::WideVector,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x25008010,
        relation: Relation::NotEqual,
        unsigned: false,
        source: SourceKind::Immediate,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x24002010,
        relation: Relation::NotEqual,
        unsigned: false,
        source: SourceKind::WideVector,
    },
    Encoding {
        mask: 0xff20e010,
        value: 0x2400a010,
        relation: Relation::NotEqual,
        unsigned: false,
        source: SourceKind::Vector,
    },
];

pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let encoding = ENCODINGS
        .iter()
        .find(|entry| word & entry.mask == entry.value)?;
    let element_bytes = 1 << ((word >> SIZE_SHIFT) & SIZE_MASK);
    if encoding.source == SourceKind::WideVector && element_bytes == 8 {
        return Some(Err(()));
    }
    let right = match encoding.source {
        SourceKind::Immediate => {
            let immediate = if encoding.unsigned {
                ((word >> UNSIGNED_IMMEDIATE_SHIFT) & UNSIGNED_IMMEDIATE_MASK) as i16
            } else {
                let bits = ((word >> RIGHT_SHIFT) & SIGNED_IMMEDIATE_MASK) as i16;
                if bits & SIGNED_IMMEDIATE_SIGN != 0 {
                    bits - SIGNED_IMMEDIATE_MODULUS
                } else {
                    bits
                }
            };
            Right::Immediate(immediate)
        }
        SourceKind::Vector => Right::Vector(((word >> RIGHT_SHIFT) & Z_REGISTER_MASK) as u8),
        SourceKind::WideVector => {
            Right::WideVector(((word >> RIGHT_SHIFT) & Z_REGISTER_MASK) as u8)
        }
    };
    Some(Ok(Operand {
        relation: encoding.relation,
        unsigned: encoding.unsigned,
        element_size: ElementSize::from_bytes(element_bytes as usize)
            .expect("two-bit SVE element size"),
        destination: (word & P_REGISTER_MASK) as u8,
        governing: ((word >> GOVERNING_SHIFT) & GOVERNING_REGISTER_MASK) as u8,
        left: ((word >> SOURCE_SHIFT) & Z_REGISTER_MASK) as u8,
        right,
    }))
}

#[cfg(test)]
mod tests;
