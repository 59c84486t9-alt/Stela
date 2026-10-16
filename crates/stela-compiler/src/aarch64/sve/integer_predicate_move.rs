//! PMOV between predicates and vector bitmaps.
use crate::aarch64::scalable::ElementSize;

const DESTINATION_MASK: u32 = 31;
const PREDICATE_SHIFT: u32 = 5;
const PREDICATE_MASK: u32 = 15;
const PORTION_LOW_SHIFT: u32 = 17;
const PORTION_HIGH_SHIFT: u32 = 22;
const BYTE_MASK: u32 = 0xffff_fe00;
const BYTE: u32 = 0x052b_3800;
const HALFWORD_MASK: u32 = 0xfffd_fe00;
const HALFWORD: u32 = 0x052d_3800;
const WORD_MASK: u32 = 0xfff9_fe00;
const WORD: u32 = 0x0569_3800;
const DOUBLEWORD_MASK: u32 = 0xffb9_fe00;
const DOUBLEWORD: u32 = 0x05a9_3800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: u8,
    pub predicate: u8,
    pub element_size: ElementSize,
    /// Zero clears the whole destination; other indices replace one bit portion.
    pub portion: u8,
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let (element_size, portion) = if word & BYTE_MASK == BYTE {
        (ElementSize::Byte, 0)
    } else if word & HALFWORD_MASK == HALFWORD {
        (ElementSize::Halfword, (word >> PORTION_LOW_SHIFT) & 1)
    } else if word & WORD_MASK == WORD {
        (ElementSize::Word, (word >> PORTION_LOW_SHIFT) & 3)
    } else if word & DOUBLEWORD_MASK == DOUBLEWORD {
        (
            ElementSize::Doubleword,
            ((word >> PORTION_HIGH_SHIFT) & 1) << 2 | ((word >> PORTION_LOW_SHIFT) & 3),
        )
    } else {
        return None;
    };
    Some(Ok(Operand {
        destination: (word & DESTINATION_MASK) as u8,
        predicate: ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8,
        element_size,
        portion: portion as u8,
    }))
}

#[cfg(test)]
mod tests;
