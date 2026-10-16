//! SVE predicated FRINT*.
use crate::aarch64::floating::{Format, rounding::RoundingOperation};

const OPCODE_MASK: u32 = 0xff3f_e000;
const FRINTN: u32 = 0x6500_a000;
const FRINTP: u32 = 0x6501_a000;
const FRINTM: u32 = 0x6502_a000;
const FRINTZ: u32 = 0x6503_a000;
const FRINTA: u32 = 0x6504_a000;
const FRINTX: u32 = 0x6506_a000;
const FRINTI: u32 = 0x6507_a000;
const REGISTER_MASK: u32 = 31;
const GOVERNING_MASK: u32 = 7;
const SOURCE_SHIFT: u32 = 5;
const GOVERNING_SHIFT: u32 = 10;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub operation: RoundingOperation,
    pub format: Format,
    pub destination: u8,
    pub governing: u8,
    pub source: u8,
}

/// Merging forms only. The FEAT_SVE2p2 zeroing forms and the bounded FRINT
/// forms are not decoded.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let operation = match word & OPCODE_MASK {
        FRINTN => RoundingOperation::NearestEven,
        FRINTP => RoundingOperation::TowardPositive,
        FRINTM => RoundingOperation::TowardNegative,
        FRINTZ => RoundingOperation::TowardZero,
        FRINTA => RoundingOperation::NearestAway,
        FRINTX => RoundingOperation::CurrentExact,
        FRINTI => RoundingOperation::Current,
        _ => return None,
    };
    let format = match (word >> SIZE_SHIFT) & SIZE_MASK {
        1 => Format::Half,
        2 => Format::Single,
        3 => Format::Double,
        _ => return Some(Err(())),
    };
    Some(Ok(Operand {
        operation,
        format,
        destination: (word & REGISTER_MASK) as u8,
        governing: ((word >> GOVERNING_SHIFT) & GOVERNING_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests;
