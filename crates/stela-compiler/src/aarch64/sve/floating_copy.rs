//! Bitwise SVE floating immediate construction; Arm A64 2026-06.
//! FCPY merges inactive lanes; FDUP fills every lane. FP controls/status are unchanged.

use crate::aarch64::floating::Format;

const REGISTER_MASK: u32 = 31;
const FCPY_MASK: u32 = 0xff30_e000;
const FCPY: u32 = 0x0510_c000;
const FDUP_MASK: u32 = 0xff3f_e000;
const FDUP: u32 = 0x2539_c000;
const COPY_GOVERNING_SHIFT: u32 = 16;
const COPY_GOVERNING_MASK: u32 = 15;
const IMMEDIATE_SHIFT: u32 = 5;
const IMMEDIATE_MASK: u32 = 255;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const IMMEDIATE_SIGN_SHIFT: u32 = 7;
const IMMEDIATE_EXPONENT_REPEAT_SHIFT: u32 = 6;
const IMMEDIATE_EXPONENT_LOW_SHIFT: u32 = 4;
const IMMEDIATE_EXPONENT_LOW_BITS: u32 = 2;
const IMMEDIATE_FRACTION_BITS: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub format: Format,
    pub value: u64,
    pub destination: u8,
    /// FCPY admits P0..P15; FDUP is unpredicated. Neither changes FPSR or
    /// consults numerical exception enables, rounding, AHP, DN or flushing.
    pub governing: Option<u8>,
}

fn expand_immediate(format: Format, immediate: u8) -> u64 {
    let fraction_bits = format.fraction_bits();
    let exponent_bits = format.bits() - fraction_bits - 1;
    let immediate = u32::from(immediate);
    let repeated = (immediate >> IMMEDIATE_EXPONENT_REPEAT_SHIFT) & 1;
    let exponent = ((repeated ^ 1) << (exponent_bits - 1))
        | ((((1 << (exponent_bits - 3)) - 1) * repeated) << IMMEDIATE_EXPONENT_LOW_BITS)
        | ((immediate >> IMMEDIATE_EXPONENT_LOW_SHIFT) & ((1 << IMMEDIATE_EXPONENT_LOW_BITS) - 1));
    let fraction = immediate & ((1 << IMMEDIATE_FRACTION_BITS) - 1);
    (u64::from(immediate >> IMMEDIATE_SIGN_SHIFT) << (format.bits() - 1))
        | (u64::from(exponent) << fraction_bits)
        | (u64::from(fraction) << (fraction_bits - IMMEDIATE_FRACTION_BITS))
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let governing = if word & FCPY_MASK == FCPY {
        Some(((word >> COPY_GOVERNING_SHIFT) & COPY_GOVERNING_MASK) as u8)
    } else if word & FDUP_MASK == FDUP {
        None
    } else {
        return None;
    };
    let format = match (word >> SIZE_SHIFT) & SIZE_MASK {
        1 => Format::Half,
        2 => Format::Single,
        3 => Format::Double,
        _ => return Some(Err(())),
    };
    Some(Ok(Operand {
        format,
        value: expand_immediate(format, ((word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK) as u8),
        destination: (word & REGISTER_MASK) as u8,
        governing,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediate_full_range_and_high_predicate_fields() {
        for (size, format) in [(1, Format::Half), (2, Format::Single), (3, Format::Double)] {
            for immediate in 0..=IMMEDIATE_MASK {
                for governing in 0..=COPY_GOVERNING_MASK {
                    let word = FCPY
                        | (size << SIZE_SHIFT)
                        | (governing << COPY_GOVERNING_SHIFT)
                        | (immediate << IMMEDIATE_SHIFT)
                        | REGISTER_MASK;
                    let operand = decode(word).unwrap().unwrap();
                    assert_eq!(operand.format, format);
                    assert_eq!(operand.value, expand_immediate(format, immediate as u8));
                    assert_eq!(operand.governing, Some(governing as u8));
                }
                let word = FDUP | (size << SIZE_SHIFT) | (immediate << IMMEDIATE_SHIFT);
                assert_eq!(decode(word).unwrap().unwrap().governing, None);
            }
        }
        assert_eq!(decode(FCPY), Some(Err(())));
        assert_eq!(decode(FDUP), Some(Err(())));
        // VFP imm8 0x70 is exactly +1.0 in every destination format.
        assert_eq!(expand_immediate(Format::Half, 0x70), 0x3c00);
        assert_eq!(expand_immediate(Format::Single, 0x70), 0x3f80_0000);
        assert_eq!(
            expand_immediate(Format::Double, 0x70),
            0x3ff0_0000_0000_0000
        );
    }
}
