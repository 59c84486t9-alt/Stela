//! Scalar unprivileged integer transfers, retaining their access intent.
//!
//! Native lowering currently supports EL0 direct private Normal RAM only.
//! Guest privilege overrides, MMU permissions and CPA checks require a separate
//! execution profile; they must not be inferred from the ordinary-RAM mapping.
use super::{MemoryTransfer, Register, Width, register};

const CLASS_MASK: u32 = 0x3f20_0c00;
const UNPRIVILEGED_CLASS: u32 = 0x3800_0800;
const SIZE_SHIFT: u32 = 30;
const OPCODE_SHIFT: u32 = 22;
const OPCODE_MASK: u32 = 3;
const STORE_OPCODE: u32 = 0;
const UNSIGNED_LOAD_OPCODE: u32 = 1;
const SIGNED_LOAD_X_OPCODE: u32 = 2;
const SIGNED_LOAD_W_OPCODE: u32 = 3;
const DOUBLEWORD_SIZE: u32 = 3;
const WORD_SIZE: u32 = 2;
const IMMEDIATE_SHIFT: u32 = 12;
const IMMEDIATE_BITS: u32 = 9;
const IMMEDIATE_MASK: u32 = (1 << IMMEDIATE_BITS) - 1;
const SIGN_EXTENSION_SHIFT: u32 = i32::BITS - IMMEDIATE_BITS;
const BASE_SHIFT: u32 = 5;
const REGISTER_MASK: u32 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub transfer: MemoryTransfer,
    pub bytes: u8,
    pub data: Register,
    pub base: Register,
    pub displacement: i32,
}

/// None denotes another encoding class; Err denotes a reserved size/opcode.
/// This class has neither writeback nor register-overlap restrictions.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if word & CLASS_MASK != UNPRIVILEGED_CLASS {
        return None;
    }
    let size = word >> SIZE_SHIFT;
    let transfer = match (word >> OPCODE_SHIFT) & OPCODE_MASK {
        STORE_OPCODE => MemoryTransfer::Store,
        UNSIGNED_LOAD_OPCODE => MemoryTransfer::Load {
            signed: false,
            width: if size == DOUBLEWORD_SIZE {
                Width::X64
            } else {
                Width::W32
            },
        },
        SIGNED_LOAD_X_OPCODE if size < DOUBLEWORD_SIZE => MemoryTransfer::Load {
            signed: true,
            width: Width::X64,
        },
        SIGNED_LOAD_W_OPCODE if size < WORD_SIZE => MemoryTransfer::Load {
            signed: true,
            width: Width::W32,
        },
        _ => return Some(Err(())),
    };
    let immediate = ((word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK) as i32;
    Some(Ok(Operand {
        transfer,
        bytes: 1 << size,
        data: register(word & REGISTER_MASK, false),
        base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
        displacement: (immediate << SIGN_EXTENSION_SHIFT) >> SIGN_EXTENSION_SHIFT,
    }))
}

#[cfg(test)]
mod tests;
