//! SIMD/FP register-offset loads and stores.
use super::super::{Register, register, register_offset::IndexExtend};

const REGISTER_OFFSET_MASK: u32 = 0x3f20_0c00;
const REGISTER_OFFSET_CLASS: u32 = 0x3c20_0800;
const SIZE_SHIFT: u32 = 30;
const OPCODE_SHIFT: u32 = 22;
const OPCODE_MASK: u32 = 3;
const Q_OPCODE_BIT: u32 = 2;
const LOAD_OPCODE_BIT: u32 = 1;
const Q_SCALE: u8 = 4;
const EXTENSION_SHIFT: u32 = 13;
const EXTENSION_MASK: u32 = 7;
const SCALED_OFFSET_BIT: u32 = 1 << 12;
const REGISTER_MASK: u32 = 31;
const BASE_SHIFT: u32 = 5;
const INDEX_SHIFT: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub load: bool,
    pub bytes: u8,
    pub vector: u8,
    pub base: Register,
    pub index: Register,
    pub extend: IndexExtend,
    pub shift: u8,
}

/// None is a different class; Err is an undefined size or index extension.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if word & REGISTER_OFFSET_MASK != REGISTER_OFFSET_CLASS {
        return None;
    }
    let size = (word >> SIZE_SHIFT) as u8;
    let opcode = (word >> OPCODE_SHIFT) & OPCODE_MASK;
    let scale = if opcode & Q_OPCODE_BIT != 0 {
        if size != 0 {
            return Some(Err(()));
        }
        Q_SCALE
    } else {
        size
    };
    let Some(extend) = IndexExtend::decode((word >> EXTENSION_SHIFT) & EXTENSION_MASK) else {
        return Some(Err(()));
    };
    Some(Ok(Operand {
        load: opcode & LOAD_OPCODE_BIT != 0,
        bytes: 1 << scale,
        vector: (word & REGISTER_MASK) as u8,
        base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
        index: register((word >> INDEX_SHIFT) & REGISTER_MASK, false),
        extend,
        shift: if word & SCALED_OFFSET_BIT == 0 {
            0
        } else {
            scale
        },
    }))
}

#[cfg(test)]
mod tests;
