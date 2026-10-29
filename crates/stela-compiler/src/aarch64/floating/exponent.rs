//! Integer exponent extraction and exact power-of-two scaling for SVE lanes.
use super::{
    Class, Control, Format, INVALID, Outcome, UnsupportedControl, nan, precision,
    process_denormals, unpack, widen,
};
use rustc_apfloat::{
    Float,
    ieee::{Double, Half, Single},
};

/// Extract the signed integer exponent, with integer extrema for special inputs.
/// The caller owns active-lane selection, effective FPCR and sticky status.
pub fn logb(format: Format, fpcr: u32, bits: u64) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let mut exceptions = 0;
    let operand = unpack(format, bits, control, &mut exceptions);
    let minimum_integer = format.sign_mask();
    let result = match operand.class {
        Class::Zero | Class::QuietNaN | Class::SignalingNaN => {
            exceptions |= INVALID;
            return Ok(Outcome {
                bits: minimum_integer,
                exceptions,
            });
        }
        Class::Infinity => {
            return Ok(Outcome {
                bits: minimum_integer - 1,
                exceptions,
            });
        }
        Class::Normal => {
            let exponent = (operand.bits & format.exponent_mask()) >> format.fraction_bits();
            exponent as i64 - i64::from(format.exponent_bias())
        }
        Class::Denormal => {
            let fraction = operand.bits & format.fraction_mask();
            i64::from(fraction.ilog2()) + 1
                - i64::from(format.exponent_bias())
                - i64::from(format.fraction_bits())
        }
    };
    process_denormals(format, control, operand, operand, &mut exceptions);
    let lane_mask = format.sign_mask() | (format.sign_mask() - 1);
    Ok(Outcome {
        bits: result as u64 & lane_mask,
        exceptions,
    })
}

/// Scale a floating lane by a signed integer lane with one architectural rounding.
/// Clamp the exponent adjustment before widening and avoid intermediate H/S/D
/// powers of two, whose underflow or overflow would change the result and status.
pub fn scale(
    format: Format,
    fpcr: u32,
    bits: u64,
    scale_bits: u64,
) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let mut exceptions = 0;
    let operand = unpack(format, bits, control, &mut exceptions);
    // Repeating the same unpacked operand applies the shared unary NaN behavior
    // without introducing another classification or changing NaN priority.
    if let Some(bits) = nan(format, operand, operand, control, &mut exceptions) {
        return Ok(Outcome { bits, exceptions });
    }
    match operand.class {
        Class::Zero | Class::Infinity => {
            return Ok(Outcome {
                bits: operand.bits,
                exceptions,
            });
        }
        Class::Normal | Class::Denormal => {}
        Class::QuietNaN | Class::SignalingNaN => unreachable!("NaNs handled before finite scaling"),
    }
    let sign_extension_shift = u64::BITS - format.bits();
    let signed_scale = ((scale_bits << sign_extension_shift) as i64) >> sign_extension_shift;
    let exponent = ((bits & format.exponent_mask()) >> format.fraction_bits()) as i64;
    let fraction_precision = i64::from(format.fraction_bits()) + 1;
    let maximum_exponent_field = (format.exponent_mask() >> format.fraction_bits()) as i64;
    let minimum_scale = -fraction_precision - exponent;
    let maximum_scale = maximum_exponent_field + fraction_precision - exponent;
    let clamped_scale = signed_scale.clamp(minimum_scale, maximum_scale) as i32;
    let value = match format {
        Format::Half => widen(Half::from_bits(u128::from(operand.bits))),
        Format::Single => widen(Single::from_bits(u128::from(operand.bits))),
        Format::Double => widen(Double::from_bits(u128::from(operand.bits))),
    };
    // FPClampScale bounds every H/S/D result well inside Quad's exponent range;
    // widening and exponent adjustment therefore keep the exact significand.
    let scaled = value.scalbn(clamped_scale);
    debug_assert!(scaled.is_finite() && !scaled.is_zero());
    debug_assert!(scaled.scalbn(-clamped_scale).bitwise_eq(value));
    let mut result = precision::round_ieee(scaled, format, control, control.round(), true, false);
    process_denormals(format, control, operand, operand, &mut exceptions);
    result.exceptions |= exceptions;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::floating::{
        EXCEPTIONS, FPCR_AH, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FIZ, FPCR_FZ,
        FPCR_FZ16, FPCR_NEP, FPCR_ROUNDING_SHIFT, INEXACT, INPUT_DENORMAL, OVERFLOW,
        ROUND_NEGATIVE, ROUND_POSITIVE, ROUND_ZERO, UNDERFLOW,
    };

    const FORMATS: [Format; 3] = [Format::Half, Format::Single, Format::Double];
    const SINGLE_ONE: u64 = 0x3f80_0000;
    const SINGLE_MAXIMUM: u64 = 0x7f7f_ffff;
    const SINGLE_MINIMUM_NORMAL: u64 = 0x0080_0000;
    const SINGLE_HALF_MINIMUM_NORMAL: u64 = 0x0040_0000;
    const SINGLE_NEGATIVE_ZERO: u64 = 0x8000_0000;
    const HALF_IGNORED_HIGH_BITS: u64 = 0xdead_beef_abcd_0000;
    const SINGLE_IGNORED_HIGH_BITS: u64 = 0xdead_beef_0000_0000;
    const NO_EXCEPTIONS: u32 = 0;

    fn outcome(bits: u64, exceptions: u32) -> Result<Outcome, UnsupportedControl> {
        Ok(Outcome { bits, exceptions })
    }

    fn integer_lane(format: Format, value: i64) -> u64 {
        value as u64 & (format.sign_mask() | (format.sign_mask() - 1))
    }

    fn one(format: Format) -> u64 {
        u64::from(format.exponent_bias()) << format.fraction_bits()
    }

    #[test]
    fn logb_special_values_use_integer_extrema_and_invalid() {
        for format in FORMATS {
            for sign in [0, format.sign_mask()] {
                for value in [
                    0,
                    format.infinity(false) | 1,
                    format.infinity(false) | format.quiet_bit(),
                ] {
                    for fpcr in [0, FPCR_AH, FPCR_DN, FPCR_AH | FPCR_DN] {
                        assert_eq!(
                            logb(format, fpcr, sign | value),
                            outcome(format.sign_mask(), INVALID)
                        );
                    }
                }
                assert_eq!(
                    logb(format, 0, sign | format.infinity(false)),
                    outcome(format.sign_mask() - 1, NO_EXCEPTIONS)
                );
            }
        }
    }

    #[test]
    fn logb_covers_every_normal_exponent_and_subnormal_leading_bit() {
        for format in FORMATS {
            let maximum_exponent = format.exponent_mask() >> format.fraction_bits();
            for exponent in 1..maximum_exponent {
                let expected =
                    integer_lane(format, exponent as i64 - i64::from(format.exponent_bias()));
                for fraction in [0, format.fraction_mask()] {
                    for sign in [0, format.sign_mask()] {
                        let bits = sign | exponent << format.fraction_bits() | fraction;
                        assert_eq!(logb(format, 0, bits), outcome(expected, NO_EXCEPTIONS));
                    }
                }
            }
            for leading_bit in 0..format.fraction_bits() {
                let expected = integer_lane(
                    format,
                    i64::from(leading_bit) + 1
                        - i64::from(format.exponent_bias())
                        - i64::from(format.fraction_bits()),
                );
                for sign in [0, format.sign_mask()] {
                    let bits = sign | 1 << leading_bit;
                    assert_eq!(logb(format, 0, bits), outcome(expected, NO_EXCEPTIONS));
                    assert_eq!(
                        logb(format, FPCR_AH, bits),
                        outcome(
                            expected,
                            if format == Format::Half {
                                0
                            } else {
                                INPUT_DENORMAL
                            }
                        )
                    );
                }
            }
        }
    }

    #[test]
    fn input_flush_and_ignored_controls_follow_arithmetic_unpack() {
        assert_eq!(
            logb(Format::Half, FPCR_FZ16, 1),
            outcome(Format::Half.sign_mask(), INVALID)
        );
        assert_eq!(
            scale(Format::Half, FPCR_FZ16, 1, 1),
            outcome(0, NO_EXCEPTIONS)
        );
        for format in [Format::Single, Format::Double] {
            assert_eq!(
                logb(format, FPCR_FZ, 1),
                outcome(format.sign_mask(), INVALID | INPUT_DENORMAL)
            );
            assert_eq!(
                logb(format, FPCR_FIZ, 1),
                outcome(format.sign_mask(), INVALID)
            );
            assert_eq!(scale(format, FPCR_FZ, 1, 1), outcome(0, INPUT_DENORMAL));
            assert_eq!(scale(format, FPCR_FIZ, 1, 1), outcome(0, NO_EXCEPTIONS));
        }
        for format in FORMATS {
            assert_eq!(
                logb(format, FPCR_AHP | FPCR_NEP, one(format)),
                outcome(0, NO_EXCEPTIONS)
            );
            assert_eq!(
                scale(format, FPCR_AHP | FPCR_NEP, one(format), 0),
                outcome(one(format), NO_EXCEPTIONS)
            );
        }
    }

    #[test]
    fn scale_preserves_signed_specials_and_processes_nan_once() {
        for format in FORMATS {
            for sign in [0, format.sign_mask()] {
                for value in [0, format.infinity(false)] {
                    assert_eq!(
                        scale(format, 0, sign | value, format.sign_mask()),
                        outcome(sign | value, NO_EXCEPTIONS)
                    );
                }
                let signaling = sign | format.infinity(false) | 1;
                let quiet = signaling | format.quiet_bit();
                for fpcr in [0, FPCR_AH] {
                    assert_eq!(scale(format, fpcr, signaling, 1), outcome(quiet, INVALID));
                    assert_eq!(scale(format, fpcr, quiet, 1), outcome(quiet, NO_EXCEPTIONS));
                }
                assert_eq!(
                    scale(format, FPCR_DN, quiet, 1),
                    outcome(format.infinity(false) | format.quiet_bit(), NO_EXCEPTIONS)
                );
                assert_eq!(
                    scale(format, FPCR_AH | FPCR_DN, signaling, 1),
                    outcome(format.infinity(true) | format.quiet_bit(), INVALID)
                );
            }
        }
    }

    #[test]
    fn scale_signed_lane_extrema_clamp_before_exact_quad_adjustment() {
        for format in FORMATS {
            let positive_one = one(format);
            let positive_two = positive_one + (1 << format.fraction_bits());
            assert_eq!(
                scale(format, 0, positive_one, 1),
                outcome(positive_two, NO_EXCEPTIONS)
            );
            assert_eq!(
                scale(format, 0, positive_two, integer_lane(format, -1)),
                outcome(positive_one, NO_EXCEPTIONS)
            );
            assert_eq!(
                scale(format, 0, positive_one, format.sign_mask()),
                outcome(0, UNDERFLOW | INEXACT)
            );
            assert_eq!(
                scale(format, 0, positive_one, format.sign_mask() - 1),
                outcome(format.infinity(false), OVERFLOW | INEXACT)
            );
            assert_eq!(
                scale(format, 0, positive_one, 0),
                outcome(positive_one, NO_EXCEPTIONS)
            );
        }
    }

    #[test]
    fn scale_rounding_and_tininess_match_architectural_boundaries() {
        let negative_one = integer_lane(Format::Single, -1);
        assert_eq!(
            scale(Format::Single, 0, 1, negative_one),
            outcome(0, UNDERFLOW | INEXACT)
        );
        assert_eq!(
            scale(
                Format::Single,
                ROUND_POSITIVE << FPCR_ROUNDING_SHIFT,
                1,
                negative_one
            ),
            outcome(1, UNDERFLOW | INEXACT)
        );
        assert_eq!(
            scale(
                Format::Single,
                ROUND_NEGATIVE << FPCR_ROUNDING_SHIFT,
                SINGLE_NEGATIVE_ZERO | 1,
                negative_one
            ),
            outcome(SINGLE_NEGATIVE_ZERO | 1, UNDERFLOW | INEXACT)
        );
        assert_eq!(
            scale(Format::Single, 0, SINGLE_MINIMUM_NORMAL, negative_one),
            outcome(SINGLE_HALF_MINIMUM_NORMAL, NO_EXCEPTIONS)
        );
        assert_eq!(
            scale(Format::Single, FPCR_FZ, SINGLE_MINIMUM_NORMAL, negative_one),
            outcome(0, UNDERFLOW)
        );
        assert_eq!(
            scale(
                Format::Single,
                FPCR_AH | FPCR_FZ,
                SINGLE_MINIMUM_NORMAL,
                negative_one
            ),
            outcome(0, UNDERFLOW | INEXACT)
        );
        assert_eq!(
            scale(Format::Single, 0, SINGLE_MAXIMUM, 1),
            outcome(Format::Single.infinity(false), OVERFLOW | INEXACT)
        );
        assert_eq!(
            scale(
                Format::Single,
                ROUND_ZERO << FPCR_ROUNDING_SHIFT,
                SINGLE_MAXIMUM,
                1
            ),
            outcome(SINGLE_MAXIMUM, OVERFLOW | INEXACT)
        );
        let normalize_smallest_subnormal =
            u64::from(Format::Single.exponent_bias() + Format::Single.fraction_bits() - 1);
        assert_eq!(
            scale(Format::Single, FPCR_AH, 1, normalize_smallest_subnormal),
            outcome(SINGLE_ONE, INPUT_DENORMAL)
        );
    }

    #[test]
    fn narrow_operands_ignore_poisoned_high_bits_before_sign_extension() {
        for (format, poison) in [
            (Format::Half, HALF_IGNORED_HIGH_BITS),
            (Format::Single, SINGLE_IGNORED_HIGH_BITS),
        ] {
            assert_eq!(
                logb(format, 0, poison | one(format)),
                outcome(0, NO_EXCEPTIONS)
            );
            assert_eq!(
                scale(format, 0, poison | one(format), poison),
                outcome(one(format), NO_EXCEPTIONS)
            );
            assert_eq!(
                scale(format, 0, poison | one(format), poison | format.sign_mask()),
                outcome(0, UNDERFLOW | INEXACT)
            );
        }
    }

    #[test]
    fn retained_exception_enables_refuse_without_successful_outcomes() {
        for format in FORMATS {
            for bit in 0..u32::BITS {
                let exception = 1 << bit;
                if exception & EXCEPTIONS == 0 {
                    continue;
                }
                let fpcr = exception << FPCR_EXCEPTION_ENABLE_SHIFT;
                let expected = Err(UnsupportedControl {
                    enabled_exceptions: exception,
                });
                assert_eq!(logb(format, fpcr, one(format)), expected);
                assert_eq!(scale(format, fpcr, one(format), 0), expected);
            }
        }
    }
}
