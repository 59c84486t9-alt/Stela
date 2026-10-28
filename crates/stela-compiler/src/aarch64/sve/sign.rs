//! SVE predicated FABS and FNEG.
use crate::aarch64::Unsupported;

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

pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    let kind = match word & OPCODE_MASK {
        ABSOLUTE_OPCODE => Kind::Absolute,
        NEGATE_OPCODE => Kind::Negate,
        _ => return None,
    };
    let format = match (word >> SIZE_SHIFT) & SIZE_MASK {
        HALF_SIZE => Format::Half,
        SINGLE_SIZE => Format::Single,
        DOUBLE_SIZE => Format::Double,
        _ => return Some(Err(Unsupported)),
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
mod tests {
    use super::*;

    #[test]
    fn widths_aliases_and_reserved_size_are_distinct() {
        for opcode in [ABSOLUTE_OPCODE, NEGATE_OPCODE] {
            for (size, format) in [
                (HALF_SIZE, Format::Half),
                (SINGLE_SIZE, Format::Single),
                (DOUBLE_SIZE, Format::Double),
            ] {
                let word = opcode
                    | (size << SIZE_SHIFT)
                    | (31 << SOURCE_SHIFT)
                    | (7 << PREDICATE_SHIFT)
                    | 31;
                let operand = decode(word).unwrap().unwrap();
                assert_eq!(operand.format, format);
                assert_eq!(
                    (operand.source, operand.destination, operand.predicate),
                    (31, 31, 7)
                );
            }
            assert_eq!(decode(opcode), Some(Err(Unsupported)));
        }
        assert_eq!(decode(0x6580_8000), None);
    }
}
