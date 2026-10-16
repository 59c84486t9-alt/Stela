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
