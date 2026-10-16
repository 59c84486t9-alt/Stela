//! FEAT_CSSC SMAX/SMIN/UMAX/UMIN, register and immediate forms.
use super::{Register, Width, register};

const REGISTER_OPCODE_MASK: u32 = 0x7fe0_fc00;
const IMMEDIATE_OPCODE_MASK: u32 = 0x7ffc_0000;
const WIDTH_BIT: u32 = 1 << 31;
const REGISTER_MASK: u32 = 31;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const IMMEDIATE_SHIFT: u32 = 10;
const IMMEDIATE_MASK: u32 = u8::MAX as u32;
const SIGNED_MAXIMUM_REGISTER: u32 = 0x1ac0_6000;
const SIGNED_MINIMUM_REGISTER: u32 = 0x1ac0_6800;
const UNSIGNED_MAXIMUM_REGISTER: u32 = 0x1ac0_6400;
const UNSIGNED_MINIMUM_REGISTER: u32 = 0x1ac0_6c00;
const SIGNED_MAXIMUM_IMMEDIATE: u32 = 0x11c0_0000;
const SIGNED_MINIMUM_IMMEDIATE: u32 = 0x11c8_0000;
const UNSIGNED_MAXIMUM_IMMEDIATE: u32 = 0x11c4_0000;
const UNSIGNED_MINIMUM_IMMEDIATE: u32 = 0x11cc_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    SignedMinimum,
    SignedMaximum,
    UnsignedMinimum,
    UnsignedMaximum,
}

impl Kind {
    pub fn signed(self) -> bool {
        matches!(self, Self::SignedMinimum | Self::SignedMaximum)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Right {
    Register(Register),
    Immediate(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub width: Width,
    pub destination: Register,
    pub left: Register,
    pub right: Right,
}

pub fn decode(word: u32) -> Option<Operand> {
    let register_kind = match word & REGISTER_OPCODE_MASK {
        SIGNED_MINIMUM_REGISTER => Some(Kind::SignedMinimum),
        SIGNED_MAXIMUM_REGISTER => Some(Kind::SignedMaximum),
        UNSIGNED_MINIMUM_REGISTER => Some(Kind::UnsignedMinimum),
        UNSIGNED_MAXIMUM_REGISTER => Some(Kind::UnsignedMaximum),
        _ => None,
    };
    let (kind, right) = if let Some(kind) = register_kind {
        (
            kind,
            Right::Register(register((word >> RIGHT_SHIFT) & REGISTER_MASK, false)),
        )
    } else {
        let kind = match word & IMMEDIATE_OPCODE_MASK {
            SIGNED_MINIMUM_IMMEDIATE => Kind::SignedMinimum,
            SIGNED_MAXIMUM_IMMEDIATE => Kind::SignedMaximum,
            UNSIGNED_MINIMUM_IMMEDIATE => Kind::UnsignedMinimum,
            UNSIGNED_MAXIMUM_IMMEDIATE => Kind::UnsignedMaximum,
            _ => return None,
        };
        (
            kind,
            Right::Immediate(((word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK) as u8),
        )
    };
    Some(Operand {
        kind,
        width: if word & WIDTH_BIT == 0 {
            Width::W32
        } else {
            Width::X64
        },
        destination: register(word & REGISTER_MASK, false),
        left: register((word >> LEFT_SHIFT) & REGISTER_MASK, false),
        right,
    })
}

#[cfg(test)]
mod tests;
