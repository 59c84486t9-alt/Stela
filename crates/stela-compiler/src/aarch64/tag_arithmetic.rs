//! Register-only allocation-tag arithmetic for the declared MTE guest profile.
use super::{Register, register};

const OFFSET_OPCODE_MASK: u32 = 0xffc0_0000;
const REGISTER_OPCODE_MASK: u32 = 0xffe0_fc00;
const ADDG: u32 = 0x9180_0000;
const SUBG: u32 = 0xd180_0000;
const SUBP: u32 = 0x9ac0_0000;
const SUBPS: u32 = 0xbac0_0000;
const GMI: u32 = 0x9ac0_1400;
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const ADDRESS_IMMEDIATE_MASK: u32 = 63;
const ADDRESS_GRANULE_SHIFT: u32 = 4;
const TAG_IMMEDIATE_SHIFT: u32 = 10;
const TAG_MASK: u32 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Offset {
        source: Register,
        subtract: bool,
        address_offset: u16,
        tag_offset: u8,
    },
    Difference {
        left: Register,
        right: Register,
        flags: bool,
    },
    Mask {
        address: Register,
        mask: Register,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: Register,
    pub kind: Kind,
}

pub fn decode(word: u32) -> Option<Operand> {
    let source = register((word >> SOURCE_SHIFT) & REGISTER_MASK, true);
    let kind = match word & OFFSET_OPCODE_MASK {
        ADDG | SUBG => Kind::Offset {
            source,
            subtract: word & OFFSET_OPCODE_MASK == SUBG,
            address_offset: (((word >> RIGHT_SHIFT) & ADDRESS_IMMEDIATE_MASK)
                << ADDRESS_GRANULE_SHIFT) as u16,
            tag_offset: ((word >> TAG_IMMEDIATE_SHIFT) & TAG_MASK) as u8,
        },
        _ => match word & REGISTER_OPCODE_MASK {
            SUBP | SUBPS => Kind::Difference {
                left: source,
                right: register((word >> RIGHT_SHIFT) & REGISTER_MASK, true),
                flags: word & REGISTER_OPCODE_MASK == SUBPS,
            },
            GMI => Kind::Mask {
                address: source,
                mask: register((word >> RIGHT_SHIFT) & REGISTER_MASK, false),
            },
            _ => return None,
        },
    };
    Some(Operand {
        destination: register(word & REGISTER_MASK, matches!(kind, Kind::Offset { .. })),
        kind,
    })
}

#[cfg(test)]
mod tests;
