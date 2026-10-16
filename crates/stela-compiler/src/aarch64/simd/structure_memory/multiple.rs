//! LD1-4 and ST1-4 (multiple structures).
use super::{Direction, Layout, Operand, decode_addressing};

const CLASS_MASK: u32 = 0xbf20_0000;
const CLASS: u32 = 0x0c00_0000;
const Q_BIT: u32 = 1 << 30;
const LOAD_BIT: u32 = 1 << 22;
const POST_INDEX_BIT: u32 = 1 << 23;
const INDEX_MASK: u32 = 31 << 16;
const OPCODE_SHIFT: u32 = 12;
const OPCODE_MASK: u32 = 15;
const SIZE_SHIFT: u32 = 10;
const SIZE_MASK: u32 = 3;
const VECTOR_MASK: u32 = 31;
const FOUR_STRUCTURES: u32 = 0b0000;
const FOUR_REGISTERS: u32 = 0b0010;
const THREE_STRUCTURES: u32 = 0b0100;
const THREE_REGISTERS: u32 = 0b0110;
const ONE_REGISTER: u32 = 0b0111;
const TWO_STRUCTURES: u32 = 0b1000;
const TWO_REGISTERS: u32 = 0b1010;

/// None denotes a different instruction class; Err denotes a reserved encoding.
pub(super) fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if word & CLASS_MASK != CLASS {
        return None;
    }
    if word & POST_INDEX_BIT == 0 && word & INDEX_MASK != 0 {
        return Some(Err(()));
    }
    let (repetitions, structures) = match (word >> OPCODE_SHIFT) & OPCODE_MASK {
        FOUR_STRUCTURES => (1, 4),
        FOUR_REGISTERS => (4, 1),
        THREE_STRUCTURES => (1, 3),
        THREE_REGISTERS => (3, 1),
        ONE_REGISTER => (1, 1),
        TWO_STRUCTURES => (1, 2),
        TWO_REGISTERS => (2, 1),
        _ => return Some(Err(())),
    };
    let size = (word >> SIZE_SHIFT) & SIZE_MASK;
    let vector_bytes = if word & Q_BIT == 0 { 8 } else { 16 };
    if structures != 1 && vector_bytes == 8 && size == SIZE_MASK {
        return Some(Err(()));
    }
    let (base, post_index) = decode_addressing(word);
    Some(Ok(Operand {
        direction: if word & LOAD_BIT == 0 {
            Direction::Store
        } else {
            Direction::Load
        },
        first_vector: (word & VECTOR_MASK) as u8,
        base,
        element_bytes: 1 << size,
        layout: Layout::Multiple {
            repetitions,
            structures,
            vector_bytes,
        },
        post_index,
    }))
}

#[cfg(test)]
mod tests;
