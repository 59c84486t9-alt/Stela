//! Conversions between floating-point formats, with one rounding.
use super::{
    Class, Control, EXCEPTIONS, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FZ16, Format,
    INPUT_DENORMAL, INVALID, Outcome, UnsupportedControl, rounded_outcome, unpack, widen,
};
use rustc_apfloat::{
    Float, FloatConvert, Round, Status, StatusAnd,
    ieee::{Double, Half, Quad, Single},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecisionRounding {
    Fpcr,
    ToOdd,
}

const HALF_EXPONENT_STEP: u64 = 1 << 10;
const HALF_MAX_ALTERNATIVE: u64 = 0x7fff;
const HALF_UPPER_BINADES: u128 = 1 << 15;
const HALF_IEEE_OVERFLOW: u128 = 1 << 16;
const HALF_TO_SINGLE_BIAS: u64 = 112;

fn convert<F: Float>(value: Quad, round: Round, odd: bool) -> StatusAnd<F>
where
    Quad: FloatConvert<F>,
{
    let mut loses_info = false;
    let mut result: StatusAnd<F> = value.convert_r(round, &mut loses_info);
    // Arm rounds toward zero, then jams the retained significand's low bit.
    // This includes zero/subnormal results; toward-zero overflow is finite.
    if odd && result.status.contains(Status::INEXACT) {
        result.value = F::from_bits(result.value.to_bits() | 1);
    }
    result
}

fn round_format<F: Float + FloatConvert<Quad>>(
    value: Quad,
    destination: Format,
    control: Control,
    round: Round,
    odd: bool,
) -> Outcome
where
    Quad: FloatConvert<F>,
{
    let result = convert::<F>(value, round, odd);
    let minimum = F::smallest_normalized();
    let tiny = if !control.alternative() {
        !value.is_zero() && value.abs() < widen(minimum)
    } else if result.value.abs() < minimum {
        !value.is_zero()
    } else if result.value.abs() == minimum && result.status.contains(Status::INEXACT) {
        // Scaling an exact source by two avoids constrained subnormal rounding
        // when testing Arm's unconstrained, precision-only rounded tininess.
        convert::<F>(value.scalbn(1), round, odd).value.abs() < minimum.scalbn(1)
    } else {
        false
    };
    // APFloat can omit OFC when rounding to largest finite toward zero.
    let overflow = result.status.contains(Status::OVERFLOW)
        || result.value.abs().bitwise_eq(F::largest())
            && result.status.contains(Status::INEXACT)
            && value.abs() >= Quad::from_u128(1).value.scalbn(F::MAX_EXP + 1);
    rounded_outcome(destination, control, result, tiny, overflow)
}

/// Round an exact finite Quad value to IEEE H/S/D. Integer conversions share
/// this primitive but retain their own unpacking, scaling and AHP policy.
pub(super) fn round_ieee(
    value: Quad,
    destination: Format,
    control: Control,
    round: Round,
    flush_half: bool,
    odd: bool,
) -> Outcome {
    let control = if flush_half {
        control
    } else {
        Control(control.0 & !FPCR_FZ16)
    };
    match destination {
        Format::Half => round_format::<Half>(value, destination, control, round, odd),
        Format::Single => round_format::<Single>(value, destination, control, round, odd),
        Format::Double => round_format::<Double>(value, destination, control, round, odd),
    }
}

fn round_alternative_half(value: Quad, control: Control, round: Round) -> Outcome {
    if value.abs() < Quad::from_u128(HALF_UPPER_BINADES).value {
        return round_ieee(value, Format::Half, control, round, false, false);
    }
    // Alternative half has one extra finite exponent. Halving maps its two
    // highest binades exactly onto IEEE half's highest two finite binades.
    let scaled = value.scalbn(-1);
    let result = convert::<Half>(scaled, round, false);
    if result.status.contains(Status::OVERFLOW)
        || scaled.abs() >= Quad::from_u128(HALF_IEEE_OVERFLOW).value
    {
        return Outcome {
            bits: HALF_MAX_ALTERNATIVE
                | if value.is_negative() {
                    Format::Half.sign_mask()
                } else {
                    0
                },
            exceptions: INVALID,
        };
    }
    Outcome {
        bits: result.value.to_bits() as u64 + HALF_EXPONENT_STEP,
        exceptions: if result.status.contains(Status::INEXACT) {
            super::INEXACT
        } else {
            0
        },
    }
}

fn finite_source(source: Format, bits: u64, alternative_half: bool) -> Quad {
    if source == Format::Half && alternative_half {
        let exponent = (bits & source.exponent_mask()) >> source.fraction_bits();
        if exponent != 0 {
            let single = (bits & source.sign_mask()) << (Format::Single.bits() - source.bits())
                | (exponent + HALF_TO_SINGLE_BIAS) << Format::Single.fraction_bits()
                | (bits & source.fraction_mask())
                    << (Format::Single.fraction_bits() - source.fraction_bits());
            return widen(Single::from_bits(u128::from(single)));
        }
    }
    match source {
        Format::Half => widen(Half::from_bits(u128::from(bits))),
        Format::Single => widen(Single::from_bits(u128::from(bits))),
        Format::Double => widen(Double::from_bits(u128::from(bits))),
    }
}

fn resize_nan(source: Format, destination: Format, bits: u64) -> u64 {
    let payload = bits & (source.quiet_bit() - 1);
    let payload = if destination.fraction_bits() >= source.fraction_bits() {
        payload << (destination.fraction_bits() - source.fraction_bits())
    } else {
        payload >> (source.fraction_bits() - destination.fraction_bits())
    };
    destination.infinity(bits & source.sign_mask() != 0) | destination.quiet_bit() | payload
}

/// Evaluate one conversion lane without state or host floating-point effects.
/// FZ16 is ignored; AHP controls half representation. Scalar merging and vector
/// destination-half insertion remain caller responsibilities.
pub fn evaluate(
    source: Format,
    destination: Format,
    rounding: PrecisionRounding,
    fpcr: u32,
    bits: u64,
) -> Result<Outcome, UnsupportedControl> {
    let enabled_exceptions = (fpcr >> FPCR_EXCEPTION_ENABLE_SHIFT) & EXCEPTIONS;
    if enabled_exceptions != 0 {
        return Err(UnsupportedControl { enabled_exceptions });
    }
    let control = Control(fpcr & !FPCR_FZ16);
    let alternative_half = control.0 & FPCR_AHP != 0;
    let mut exceptions = 0;
    let mut operand = unpack(source, bits, control, &mut exceptions);
    if source == Format::Half && alternative_half && operand.class != Class::Zero {
        // In alternative half, the IEEE infinity/NaN exponent is finite.
        if operand.bits & source.exponent_mask() == source.exponent_mask() {
            operand.class = Class::Normal;
        }
    }
    let sign = if operand.negative {
        destination.sign_mask()
    } else {
        0
    };
    let alternative_destination = destination == Format::Half && alternative_half;
    let result = if operand.class.nan() {
        if operand.class == Class::SignalingNaN || alternative_destination {
            exceptions |= INVALID;
        }
        Outcome {
            bits: if alternative_destination {
                sign
            } else if control.0 & FPCR_DN != 0 {
                control.default_nan(destination)
            } else {
                resize_nan(source, destination, operand.bits)
            },
            exceptions: 0,
        }
    } else if operand.class == Class::Infinity {
        if alternative_destination {
            exceptions |= INVALID;
        }
        Outcome {
            bits: if alternative_destination {
                sign | HALF_MAX_ALTERNATIVE
            } else {
                destination.infinity(operand.negative)
            },
            exceptions: 0,
        }
    } else if operand.class == Class::Zero {
        Outcome {
            bits: sign,
            exceptions: 0,
        }
    } else {
        let value = finite_source(source, operand.bits, alternative_half);
        let odd = rounding == PrecisionRounding::ToOdd;
        let round = if odd {
            Round::TowardZero
        } else {
            control.round()
        };
        let result = if alternative_destination {
            round_alternative_half(value, control, round)
        } else {
            round_ieee(value, destination, control, round, false, odd)
        };
        if control.alternative() && source != Format::Half && operand.class == Class::Denormal {
            exceptions |= INPUT_DENORMAL;
        }
        result
    };
    Ok(Outcome {
        bits: result.bits,
        exceptions: result.exceptions | exceptions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::floating::{
        FPCR_AH, FPCR_FIZ, FPCR_FZ, FPCR_ROUNDING_SHIFT, INEXACT, OVERFLOW, ROUND_ZERO, UNDERFLOW,
    };

    fn result(source: Format, destination: Format, fpcr: u32, bits: u64) -> Outcome {
        evaluate(source, destination, PrecisionRounding::Fpcr, fpcr, bits).unwrap()
    }

    #[test]
    fn half_conversion_ignores_flush_and_observes_alternative_exponent() {
        assert_eq!(
            result(Format::Half, Format::Single, FPCR_FZ16 | FPCR_FIZ, 1),
            Outcome {
                bits: 0x33800000,
                exceptions: 0
            }
        );
        for (half, single) in [
            (0x7c00, 0x47800000),
            (0x7fff, 0x47ffe000),
            (0xfc01, 0xc7802000),
        ] {
            assert_eq!(
                result(Format::Half, Format::Single, FPCR_AHP | FPCR_DN, half),
                Outcome {
                    bits: single,
                    exceptions: 0
                }
            );
        }
        assert_eq!(
            result(Format::Single, Format::Half, FPCR_FZ16, 0x33800000),
            Outcome {
                bits: 1,
                exceptions: 0
            }
        );
    }

    #[test]
    fn alternative_half_overflow_distinguishes_rounded_exponent_from_inexact_maximum() {
        for sign in [0, Format::Single.sign_mask()] {
            let half_sign = if sign == 0 {
                0
            } else {
                Format::Half.sign_mask()
            };
            // 131040 is halfway between alternative-half maximum and 131072.
            assert_eq!(
                result(Format::Single, Format::Half, FPCR_AHP, 0x47fff000 | sign),
                Outcome {
                    bits: HALF_MAX_ALTERNATIVE | half_sign,
                    exceptions: INVALID
                }
            );
            assert_eq!(
                result(
                    Format::Single,
                    Format::Half,
                    FPCR_AHP | (ROUND_ZERO << FPCR_ROUNDING_SHIFT),
                    0x47fff000 | sign
                ),
                Outcome {
                    bits: HALF_MAX_ALTERNATIVE | half_sign,
                    exceptions: INEXACT
                }
            );
            assert_eq!(
                result(
                    Format::Single,
                    Format::Half,
                    FPCR_AHP | (ROUND_ZERO << FPCR_ROUNDING_SHIFT),
                    0x48000000 | sign
                ),
                Outcome {
                    bits: HALF_MAX_ALTERNATIVE | half_sign,
                    exceptions: INVALID
                }
            );
        }
    }

    #[test]
    fn alternative_half_nan_and_infinity_have_signed_non_ieee_results() {
        for controls in [FPCR_AHP, FPCR_AHP | FPCR_DN | FPCR_AH] {
            for (source, expected) in [
                (0x7fc00001, 0),
                (0xff800001, 0x8000),
                (0x7f800000, 0x7fff),
                (0xff800000, 0xffff),
            ] {
                assert_eq!(
                    result(Format::Single, Format::Half, controls, source),
                    Outcome {
                        bits: expected,
                        exceptions: INVALID
                    }
                );
            }
        }
    }

    #[test]
    fn nan_payloads_resize_from_the_most_significant_end() {
        assert_eq!(
            result(Format::Double, Format::Half, 0, 0xfff123456789abcd),
            Outcome {
                bits: 0xfe48,
                exceptions: INVALID
            }
        );
        assert_eq!(
            result(Format::Half, Format::Double, 0, 0xfe48),
            Outcome {
                bits: 0xfff9200000000000,
                exceptions: 0
            }
        );
        assert_eq!(
            result(Format::Half, Format::Single, FPCR_DN | FPCR_AH, 0x7e01),
            Outcome {
                bits: 0xffc00000,
                exceptions: 0
            }
        );
    }

    #[test]
    fn source_denormal_controls_apply_even_to_exact_widening() {
        for (control, bits, exceptions) in [
            (0, 0x36a0000000000000, 0),
            (FPCR_AH | FPCR_FZ, 0x36a0000000000000, INPUT_DENORMAL),
            (FPCR_FIZ, 0, 0),
            (FPCR_FIZ | FPCR_FZ, 0, INPUT_DENORMAL),
        ] {
            assert_eq!(
                result(Format::Single, Format::Double, control, 1),
                Outcome { bits, exceptions }
            );
        }
    }

    #[test]
    fn output_tininess_and_flush_follow_before_or_unconstrained_rounding() {
        // Exact Double is just below Single minimum normal, but rounds to it.
        let source = 0x380ffffff8000000;
        for (control, bits, exceptions) in [
            (0, 0x00800000, UNDERFLOW | INEXACT),
            (FPCR_AH, 0x00800000, INEXACT),
            (FPCR_FZ, 0, UNDERFLOW),
            (FPCR_AH | FPCR_FZ, 0x00800000, INEXACT),
        ] {
            assert_eq!(
                result(Format::Double, Format::Single, control, source),
                Outcome { bits, exceptions }
            );
        }
    }

    #[test]
    fn round_to_odd_jams_each_inexact_result_and_repairs_clamped_overflow() {
        for (source, bits, exceptions) in [
            (0x3ff0000010000000, 0x3f800001, INEXACT),
            (0x3ff0000020000000, 0x3f800001, 0),
            (1, 1, UNDERFLOW | INEXACT),
            (0x7fefffffffffffff, 0x7f7fffff, OVERFLOW | INEXACT),
        ] {
            for rounding in 0..4 {
                assert_eq!(
                    evaluate(
                        Format::Double,
                        Format::Single,
                        PrecisionRounding::ToOdd,
                        rounding << FPCR_ROUNDING_SHIFT,
                        source
                    )
                    .unwrap(),
                    Outcome { bits, exceptions }
                );
            }
        }
    }

    #[test]
    fn retained_exception_enables_decline_before_special_cases() {
        for exception in [
            INVALID,
            super::super::DIVIDE_BY_ZERO,
            OVERFLOW,
            UNDERFLOW,
            INEXACT,
            INPUT_DENORMAL,
            EXCEPTIONS,
        ] {
            assert_eq!(
                evaluate(
                    Format::Double,
                    Format::Half,
                    PrecisionRounding::Fpcr,
                    exception << FPCR_EXCEPTION_ENABLE_SHIFT,
                    0
                ),
                Err(UnsupportedControl {
                    enabled_exceptions: exception
                })
            );
        }
    }
}
