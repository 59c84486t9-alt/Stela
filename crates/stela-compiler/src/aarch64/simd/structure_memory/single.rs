//! LD1-4 and ST1-4 (single lane) and LD1R-4R (replicate).
use super::{Direction, Layout, Operand, decode_addressing};

const SINGLE_STRUCTURE_MASK: u32 = 0xbf00_0000;
const SINGLE_STRUCTURE_CLASS: u32 = 0x0d00_0000;
const POST_INDEX_BIT: u32 = 1 << 23;
const LOAD_BIT: u32 = 1 << 22;
const STRUCTURE_LOW_BIT_SHIFT: u32 = 21;
const OFFSET_REGISTER_MASK: u32 = 31 << 16;
const OPCODE_SHIFT: u32 = 13;
const OPCODE_MASK: u32 = 7;
const LANE_BIT_SHIFT: u32 = 12;
const SIZE_SHIFT: u32 = 10;
const SIZE_MASK: u32 = 3;
const Q_SHIFT: u32 = 30;
const VECTOR_MASK: u32 = 31;
const BYTE_SCALE: u8 = 0;
const HALFWORD_SCALE: u8 = 1;
const WORD_SCALE: u8 = 2;
const DOUBLEWORD_SCALE: u8 = 3;
const LOW_VECTOR_BYTES: u8 = 8;

/// None denotes a different class; Err denotes a reserved single structure.
#[allow(clippy::result_unit_err)]
pub(super) fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if word & SINGLE_STRUCTURE_MASK != SINGLE_STRUCTURE_CLASS {
        return None;
    }
    if word & POST_INDEX_BIT == 0 && word & OFFSET_REGISTER_MASK != 0 {
        return Some(Err(()));
    }
    let opcode = ((word >> OPCODE_SHIFT) & OPCODE_MASK) as u8;
    let structures = ((opcode & 1) << 1) + ((word >> STRUCTURE_LOW_BIT_SHIFT) & 1) as u8 + 1;
    let q = ((word >> Q_SHIFT) & 1) as u8;
    let lane_bit = ((word >> LANE_BIT_SHIFT) & 1) as u8;
    let size = ((word >> SIZE_SHIFT) & SIZE_MASK) as u8;
    let direction = if word & LOAD_BIT == 0 {
        Direction::Store
    } else {
        Direction::Load
    };
    let (scale, layout) = match opcode >> 1 {
        BYTE_SCALE => (
            BYTE_SCALE,
            Layout::Lane {
                structures,
                index: (q << 3) | (lane_bit << 2) | size,
            },
        ),
        HALFWORD_SCALE if size & 1 == 0 => (
            HALFWORD_SCALE,
            Layout::Lane {
                structures,
                index: (q << 2) | (lane_bit << 1) | (size >> 1),
            },
        ),
        WORD_SCALE if size == 0 => (
            WORD_SCALE,
            Layout::Lane {
                structures,
                index: (q << 1) | lane_bit,
            },
        ),
        WORD_SCALE if size == 1 && lane_bit == 0 => (
            DOUBLEWORD_SCALE,
            Layout::Lane {
                structures,
                index: q,
            },
        ),
        DOUBLEWORD_SCALE if direction == Direction::Load && lane_bit == 0 => (
            size,
            Layout::Replicate {
                structures,
                vector_bytes: LOW_VECTOR_BYTES << q,
            },
        ),
        _ => return Some(Err(())),
    };
    let (base, post_index) = decode_addressing(word);
    Some(Ok(Operand {
        direction,
        first_vector: (word & VECTOR_MASK) as u8,
        base,
        element_bytes: 1 << scale,
        layout,
        post_index,
    }))
}

#[cfg(test)]
mod tests;
