//! SVE predicated bit operations: CLS, CLZ, CNT, RBIT and REVB/REVH/REVW.
use crate::aarch64::scalable::{ElementSize, Predication};

const OPCODE_MASK: u32 = 0xff3f_e000;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 0b11;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 0b111;
const SOURCE_SHIFT: u32 = 5;
const REGISTER_MASK: u32 = 0b1_1111;
const CLS: u32 = 0x0418_a000;
const CLZ: u32 = 0x0419_a000;
const CNT: u32 = 0x041a_a000;
const RBIT: u32 = 0x0527_8000;
const REVB: u32 = 0x0524_8000;
const REVH: u32 = 0x0525_8000;
const REVW: u32 = 0x0526_8000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    LeadingSignBits,
    LeadingZeros,
    PopulationCount,
    ReverseBits,
    ReverseGroups { group_size: ElementSize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub source: u8,
    pub element_size: ElementSize,
    pub predication: Predication,
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    use ElementSize::{Byte, Halfword, Word};
    use Kind::{LeadingSignBits, LeadingZeros, PopulationCount, ReverseBits, ReverseGroups};
    let kind = match word & OPCODE_MASK {
        CLS => LeadingSignBits,
        CLZ => LeadingZeros,
        CNT => PopulationCount,
        RBIT => ReverseBits,
        REVB => ReverseGroups { group_size: Byte },
        REVH => ReverseGroups {
            group_size: Halfword,
        },
        REVW => ReverseGroups { group_size: Word },
        _ => return None,
    };
    let bytes = 1usize << ((word >> SIZE_SHIFT) & SIZE_MASK);
    let Some(element_size) = ElementSize::from_bytes(bytes) else {
        return Some(Err(()));
    };
    if let ReverseGroups { group_size } = kind
        && element_size <= group_size
    {
        return Some(Err(()));
    }
    Some(Ok(Operand {
        kind,
        destination: (word & REGISTER_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
        element_size,
        predication: Predication::Merging(((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8),
    }))
}

#[cfg(test)]
mod tests;
