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

/// Size 00 is reserved.
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
mod tests {
    use super::*;

    #[test]
    fn all_widths_predicates_aliases_and_fixed_bits() {
        for (opcode, operation) in [
            (FAMAX, AbsoluteMinMaxOperation::Maximum),
            (FAMIN, AbsoluteMinMaxOperation::Minimum),
        ] {
            assert_eq!(decode(opcode), Some(Err(())));
            for (size, format) in [(1, Format::Half), (2, Format::Single), (3, Format::Double)] {
                for governing in 0..=GOVERNING_MASK {
                    for destination in 0..=REGISTER_MASK {
                        for right in [0, destination, REGISTER_MASK] {
                            let word = opcode
                                | (size << SIZE_SHIFT)
                                | (governing << GOVERNING_SHIFT)
                                | (right << RIGHT_SHIFT)
                                | destination;
                            assert_eq!(
                                decode(word),
                                Some(Ok(Operand {
                                    operation,
                                    format,
                                    destination: destination as u8,
                                    governing: governing as u8,
                                    right: right as u8,
                                }))
                            );
                        }
                    }
                }
            }
            for bit in 0..32 {
                if FORM_MASK & (1 << bit) != 0 && bit != 16 {
                    assert_eq!(decode(opcode ^ (1 << bit)), None);
                }
            }
        }
    }
}
