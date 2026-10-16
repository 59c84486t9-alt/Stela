//! Predicated SVE floating sign operations; inactive destination lanes merge.
//! Encoding facts: Arm ISA_A64_xml_A_profile-2026-06, FABS/FNEG vector forms.

use crate::aarch64::floating::Format;

const OPCODE_MASK: u32 = 0xff3f_e000;
const ABSOLUTE_OPCODE: u32 = 0x041c_a000;
const NEGATE_OPCODE: u32 = 0x041d_a000;
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const HALF_SIZE: u32 = 1;
const SINGLE_SIZE: u32 = 2;
const DOUBLE_SIZE: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Absolute,
    Negate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub format: Format,
    pub destination: u8,
    pub source: u8,
    pub predicate: u8,
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let kind = match word & OPCODE_MASK {
        ABSOLUTE_OPCODE => Kind::Absolute,
        NEGATE_OPCODE => Kind::Negate,
        _ => return None,
    };
    let format = match (word >> SIZE_SHIFT) & SIZE_MASK {
        HALF_SIZE => Format::Half,
        SINGLE_SIZE => Format::Single,
        DOUBLE_SIZE => Format::Double,
        _ => return Some(Err(())),
    };
    Some(Ok(Operand {
        kind,
        format,
        destination: (word & REGISTER_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
        predicate: ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests;
