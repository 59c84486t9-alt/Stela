//! SME streaming-length address arithmetic. Mode/feature checks belong to the caller.
use crate::aarch64::{Register, register};

const ADD_LENGTH_MASK: u32 = 0xffe0_f800;
const READ_LENGTH_MASK: u32 = 0xffff_f800;
const ADDSPL: u32 = 0x0460_5800;
const ADDSVL: u32 = 0x0420_5800;
const RDSVL: u32 = 0x04bf_5800;
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 16;
const IMMEDIATE_SHIFT: u32 = 5;
const IMMEDIATE_BITS: u32 = 6;
const IMMEDIATE_MASK: u32 = (1 << IMMEDIATE_BITS) - 1;
const IMMEDIATE_SIGN: u32 = 1 << (IMMEDIATE_BITS - 1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scale {
    Predicate,
    Vector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Add { source: Register, scale: Scale },
    Read,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: Register,
    pub immediate: i8,
    pub kind: Kind,
}

pub fn decode(word: u32) -> Option<Operand> {
    let kind = match word & ADD_LENGTH_MASK {
        ADDSPL => Kind::Add {
            source: register((word >> SOURCE_SHIFT) & REGISTER_MASK, true),
            scale: Scale::Predicate,
        },
        ADDSVL => Kind::Add {
            source: register((word >> SOURCE_SHIFT) & REGISTER_MASK, true),
            scale: Scale::Vector,
        },
        _ if word & READ_LENGTH_MASK == RDSVL => Kind::Read,
        _ => return None,
    };
    let immediate = (word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK;
    Some(Operand {
        destination: register(word & REGISTER_MASK, matches!(kind, Kind::Add { .. })),
        immediate: ((immediate ^ IMMEDIATE_SIGN) as i32 - IMMEDIATE_SIGN as i32) as i8,
        kind,
    })
}

#[cfg(test)]
mod tests;
