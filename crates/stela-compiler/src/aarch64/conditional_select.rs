//! Integer conditional selection. All register 31 operands name ZR, never SP.
use super::{Register, Width, register};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Otherwise {
    Unchanged,
    Increment,
    Invert,
    Negate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub width: Width,
    pub destination: Register,
    pub left: Register,
    pub right: Register,
    pub condition: u8,
    pub otherwise: Otherwise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareRight {
    Register(Register),
    Immediate(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompareOperand {
    pub width: Width,
    pub subtract: bool,
    pub left: Register,
    pub right: CompareRight,
    pub condition: u8,
    pub fallback: u8,
}

pub fn decode_compare(word: u32) -> Option<CompareOperand> {
    if word & 0x3fe00410 != 0x3a400000 {
        return None;
    }
    Some(CompareOperand {
        width: if word >> 31 == 0 {
            Width::W32
        } else {
            Width::X64
        },
        subtract: word & (1 << 30) != 0,
        left: register((word >> 5) & 31, false),
        right: if word & (1 << 11) != 0 {
            CompareRight::Immediate(((word >> 16) & 31) as u8)
        } else {
            CompareRight::Register(register((word >> 16) & 31, false))
        },
        condition: ((word >> 12) & 15) as u8,
        fallback: (word & 15) as u8,
    })
}

pub fn decode(word: u32) -> Option<Operand> {
    // sf/op vary; S, bit 21 and bit 11 are fixed. op2 is bit 10.
    if word & 0x3fe00800 != 0x1a800000 {
        return None;
    }
    Some(Operand {
        width: if word >> 31 == 0 {
            Width::W32
        } else {
            Width::X64
        },
        destination: register(word & 31, false),
        left: register((word >> 5) & 31, false),
        right: register((word >> 16) & 31, false),
        condition: ((word >> 12) & 15) as u8,
        otherwise: match ((word >> 29) & 2) | ((word >> 10) & 1) {
            0 => Otherwise::Unchanged,
            1 => Otherwise::Increment,
            2 => Otherwise::Invert,
            _ => Otherwise::Negate,
        },
    })
}

#[cfg(test)]
mod tests;
