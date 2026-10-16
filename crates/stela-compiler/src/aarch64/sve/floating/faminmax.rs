//! SVE predicated FAMIN and FAMAX.
use crate::aarch64::floating::{Format, absolute_minmax::AbsoluteMinMaxOperation};

const FORM_MASK: u32 = 0xff3f_e000;
const FAMAX: u32 = 0x650e_8000;
const FAMIN: u32 = 0x650f_8000;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const RIGHT_SHIFT: u32 = 5;
const GOVERNING_SHIFT: u32 = 10;
const REGISTER_MASK: u32 = 31;
const GOVERNING_MASK: u32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub operation: AbsoluteMinMaxOperation,
    pub format: Format,
    /// The first source is also the merging destination.
    pub destination: u8,
    pub governing: u8,
    pub right: u8,
}

/// Decode only canonical allocated forms; size00 remains explicitly reserved.
/// Guest feature and streaming access checks belong to profile admission.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let operation = match word & FORM_MASK {
        FAMAX => AbsoluteMinMaxOperation::Maximum,
        FAMIN => AbsoluteMinMaxOperation::Minimum,
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
        right: ((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests;
