//! Exact Half-to-integer conversion on the small source significand.
use super::{Class, Format, INEXACT, INVALID, IntegerFormat, IntegerRounding, Operand, Outcome};

const FRACTION_BITS: u32 = Format::Half.fraction_bits();
const EXPONENT_BIAS: i32 = Format::Half.exponent_bias() as i32;
const SUBNORMAL_SHIFT: i32 = 1 - EXPONENT_BIAS - FRACTION_BITS as i32;

/// The caller has checked controls, unpacked/flushed once and handled NaNs.
/// A Half significand needs at most eleven bits. Scaling and rounding therefore
/// need only bounded integer shifts, even for the full public u8 scale range.
pub(super) fn to_integer(
    operand: Operand,
    integer: IntegerFormat,
    frac_bits: u8,
    rounding: IntegerRounding,
    exceptions: u32,
) -> Outcome {
    debug_assert!(!operand.class.nan());
    let limit = if integer.signed {
        (1u64 << (integer.width.bits() - 1)) - u64::from(!operand.negative)
    } else if operand.negative {
        0
    } else {
        integer.width.mask()
    };
    let saturated = || Outcome {
        bits: limit,
        exceptions: exceptions | INVALID,
    };
    if operand.class == Class::Infinity {
        return saturated();
    }
    if operand.class == Class::Zero {
        return Outcome {
            bits: 0,
            exceptions,
        };
    }

    let exponent = (operand.bits & Format::Half.exponent_mask()) >> FRACTION_BITS;
    let fraction = operand.bits & Format::Half.fraction_mask();
    let significand = fraction | if exponent == 0 { 0 } else { 1 << FRACTION_BITS };
    let shift = if exponent == 0 {
        SUBNORMAL_SHIFT
    } else {
        exponent as i32 - EXPONENT_BIAS - FRACTION_BITS as i32
    } + i32::from(frac_bits);
    let (magnitude, inexact) = if shift >= 0 {
        let shift = shift as u32;
        // Nonzero significand and a <=64-bit limit: compare before shifting,
        // both to detect saturation exactly and to prevent oversized shifts.
        if shift >= u64::BITS || significand > limit >> shift {
            return saturated();
        }
        (significand << shift, false)
    } else {
        let discarded = (-shift) as u32;
        // The smallest Half exponent gives -24 before nonnegative scaling.
        debug_assert!(discarded <= (-SUBNORMAL_SHIFT) as u32);
        let quotient = significand >> discarded;
        let remainder = significand & ((1u64 << discarded) - 1);
        let halfway = 1u64 << (discarded - 1);
        let increment = match rounding {
            IntegerRounding::NearestEven => {
                remainder > halfway || remainder == halfway && quotient & 1 != 0
            }
            IntegerRounding::NearestAway => remainder >= halfway,
            IntegerRounding::TowardPositive => !operand.negative && remainder != 0,
            IntegerRounding::TowardNegative => operand.negative && remainder != 0,
            IntegerRounding::TowardZero => false,
        };
        (quotient + u64::from(increment), remainder != 0)
    };
    // Check the rounded magnitude: negative unsigned inputs rounding to zero
    // are valid. Invalid conversion suppresses this operation's fresh IXC.
    if magnitude > limit {
        return saturated();
    }
    Outcome {
        bits: if operand.negative {
            magnitude.wrapping_neg() & integer.width.mask()
        } else {
            magnitude
        },
        exceptions: exceptions | if inexact { INEXACT } else { 0 },
    }
}

#[cfg(test)]
mod tests {
    use super::super::{IntegerWidth, control, to_integer_ieee};
    use super::*;
    use crate::aarch64::floating::{
        self, FPCR_AH, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_FZ16,
        FPCR_ROUNDING_SHIFT, UnsupportedControl,
    };
    use alloc::vec::Vec;

    const ROUNDINGS: [IntegerRounding; 5] = [
        IntegerRounding::NearestEven,
        IntegerRounding::NearestAway,
        IntegerRounding::TowardPositive,
        IntegerRounding::TowardNegative,
        IntegerRounding::TowardZero,
    ];
    const WIDTHS: [IntegerWidth; 3] = [
        IntegerWidth::Bits16,
        IntegerWidth::Bits32,
        IntegerWidth::Bits64,
    ];

    fn reference(
        integer: IntegerFormat,
        frac_bits: u8,
        rounding: IntegerRounding,
        fpcr: u32,
        bits: u64,
    ) -> Result<Outcome, UnsupportedControl> {
        let control = control(fpcr)?;
        let mut exceptions = 0;
        let operand = floating::unpack(Format::Half, bits, control, &mut exceptions);
        if operand.class.nan() {
            return Ok(Outcome {
                bits: 0,
                exceptions: exceptions | INVALID,
            });
        }
        Ok(to_integer_ieee(
            Format::Half,
            integer,
            frac_bits,
            rounding,
            operand.bits,
            exceptions,
        ))
    }

    fn compare(
        integer: IntegerFormat,
        frac_bits: u8,
        rounding: IntegerRounding,
        fpcr: u32,
        bits: u64,
    ) {
        assert_eq!(
            super::super::to_integer(Format::Half, integer, frac_bits, rounding, fpcr, bits),
            reference(integer, frac_bits, rounding, fpcr, bits),
            "{integer:?} scale={frac_bits} {rounding:?} FPCR={fpcr:#x} bits={bits:#x}"
        );
    }

    fn compare_encodings(encodings: impl Iterator<Item = u16> + Clone) {
        for width in WIDTHS {
            for signed in [false, true] {
                for rounding in ROUNDINGS {
                    for frac_bits in [0, 1, 15, 16, 31, 32, 63, 64, 87, 255] {
                        for fpcr in [0, FPCR_FZ16] {
                            for bits in encodings.clone() {
                                compare(
                                    IntegerFormat { width, signed },
                                    frac_bits,
                                    rounding,
                                    fpcr,
                                    u64::from(bits) | 0xfedc_ba98_7654_0000,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn sampled_half_conversions_match_quad() {
        let mut samples = Vec::new();
        for sign in [0u16, 0x8000] {
            for exponent in 0..32u16 {
                for fraction in [0, 1, 0x1ff, 0x200, 0x201, 0x3fe, 0x3ff] {
                    samples.push(sign | (exponent << FRACTION_BITS) | fraction);
                }
            }
        }
        let mut state = 0x41c6_4e6du32;
        for _ in 0..512 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            samples.push(state as u16);
        }
        samples.sort_unstable();
        samples.dedup();
        compare_encodings(samples.iter().copied());
    }

    #[test]
    #[ignore = "oracle: exhaustive"]
    fn all_half_conversions_match_quad() {
        compare_encodings(0..=u16::MAX);
    }

    #[test]
    fn controls_and_every_scale_preserve_half_integer_semantics() {
        for bits in [
            0, 0x8000, 1, 0x8001, 0x03ff, 0x0400, 0x3800, 0xb800, 0x3c00, 0x3e00, 0x4100, 0x7bff,
            0xfbff, 0x7c00, 0xfc00, 0x7c01, 0x7e01,
        ] {
            for fpcr in [
                FPCR_AH,
                FPCR_AHP,
                FPCR_FZ,
                FPCR_FIZ,
                FPCR_DN,
                FPCR_AH | FPCR_AHP | FPCR_FZ | FPCR_FIZ | FPCR_DN,
                FPCR_AH | FPCR_FZ16,
                3 << FPCR_ROUNDING_SHIFT,
            ] {
                for width in WIDTHS {
                    for signed in [false, true] {
                        for rounding in ROUNDINGS {
                            for frac_bits in 0..=u8::MAX {
                                compare(
                                    IntegerFormat { width, signed },
                                    frac_bits,
                                    rounding,
                                    fpcr,
                                    bits,
                                );
                            }
                        }
                    }
                }
            }
        }
        for bit in 0..u32::BITS {
            let enable = (1u32 << bit) & FPCR_EXCEPTION_ENABLE_MASK;
            if enable == 0 {
                continue;
            }
            for fpcr in [enable, enable | FPCR_AH] {
                for bits in [0, 1, 0x3c00, 0x7c01, 0xfc00] {
                    compare(
                        IntegerFormat {
                            width: IntegerWidth::Bits64,
                            signed: false,
                        },
                        255,
                        IntegerRounding::NearestAway,
                        fpcr,
                        bits,
                    );
                }
            }
        }
    }

    #[test]
    fn fresh_status_preserves_the_incoming_exception_accumulator() {
        let inherited = floating::INPUT_DENORMAL;
        let integer = IntegerFormat {
            width: IntegerWidth::Bits16,
            signed: false,
        };
        for (bits, result, fresh) in [
            (0, 0, 0),
            (0x3800, 1, INEXACT),
            (0xb800, 0, INVALID),
            (0x7c00, u64::from(u16::MAX), INVALID),
        ] {
            let mut unpacked_status = 0;
            let operand = floating::unpack(
                Format::Half,
                bits,
                control(0).unwrap(),
                &mut unpacked_status,
            );
            assert_eq!(unpacked_status, 0);
            assert_eq!(
                to_integer(operand, integer, 0, IntegerRounding::NearestAway, inherited),
                Outcome {
                    bits: result,
                    exceptions: inherited | fresh
                }
            );
        }
    }
}
