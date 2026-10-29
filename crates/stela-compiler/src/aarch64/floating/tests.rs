use super::*;

fn result(format: Format, operation: BinaryOperation, fpcr: u32, left: u64, right: u64) -> Outcome {
    evaluate(format, operation, fpcr, left, right).unwrap()
}

#[test]
fn negated_multiply_changes_the_rounded_result_under_every_direction() {
    for format in [Format::Half, Format::Single, Format::Double] {
        let one = u64::from(format.exponent_bias()) << format.fraction_bits();
        for ah in [0, FPCR_AH] {
            for round in [
                ROUND_NEAREST_EVEN,
                ROUND_POSITIVE,
                ROUND_NEGATIVE,
                ROUND_ZERO,
            ] {
                assert_eq!(
                    result(
                        format,
                        BinaryOperation::NegatedMultiply,
                        ah | (round << FPCR_ROUNDING_SHIFT),
                        one + 1,
                        one + 1,
                    ),
                    Outcome {
                        bits: format.sign_mask()
                            | (one + if round == ROUND_POSITIVE { 3 } else { 2 }),
                        exceptions: INEXACT,
                    }
                );
            }
        }
    }
}

#[test]
fn absolute_difference_rounds_the_negative_difference_before_clearing_sign() {
    for format in [Format::Half, Format::Single, Format::Double] {
        let one = u64::from(format.exponent_bias()) << format.fraction_bits();
        let minimum_normal = 1 << format.fraction_bits();
        for ah in [0, FPCR_AH] {
            for round in [
                ROUND_NEAREST_EVEN,
                ROUND_POSITIVE,
                ROUND_NEGATIVE,
                ROUND_ZERO,
            ] {
                assert_eq!(
                    result(
                        format,
                        BinaryOperation::AbsoluteDifference,
                        ah | (round << FPCR_ROUNDING_SHIFT),
                        minimum_normal,
                        one,
                    ),
                    Outcome {
                        bits: one - u64::from(matches!(round, ROUND_POSITIVE | ROUND_ZERO)),
                        exceptions: INEXACT,
                    }
                );
            }
        }
    }
}

#[test]
fn post_arithmetic_sign_transforms_keep_ah_nan_signs_and_fresh_invalid() {
    for format in [Format::Half, Format::Single, Format::Double] {
        let one = u64::from(format.exponent_bias()) << format.fraction_bits();
        let signaling = format.sign_mask() | format.exponent_mask() | 1;
        for operation in [
            BinaryOperation::NegatedMultiply,
            BinaryOperation::AbsoluteDifference,
        ] {
            for ah in [0, FPCR_AH] {
                assert_eq!(
                    result(format, operation, ah, signaling, one),
                    Outcome {
                        bits: (signaling | format.quiet_bit())
                            ^ if ah == 0 { format.sign_mask() } else { 0 },
                        exceptions: INVALID,
                    }
                );
            }
        }
    }
}

#[test]
fn extended_multiply_zero_times_infinity_returns_signed_two_without_invalid() {
    for format in [Format::Half, Format::Single, Format::Double] {
        let two = u64::from(format.exponent_bias() + 1) << format.fraction_bits();
        for ah in [0, FPCR_AH] {
            for zero_negative in [false, true] {
                for infinity_negative in [false, true] {
                    let zero = if zero_negative { format.sign_mask() } else { 0 };
                    let infinity = format.infinity(infinity_negative);
                    for (left, right) in [(zero, infinity), (infinity, zero)] {
                        assert_eq!(
                            result(format, BinaryOperation::MultiplyExtended, ah, left, right),
                            Outcome {
                                bits: two
                                    | if zero_negative ^ infinity_negative {
                                        format.sign_mask()
                                    } else {
                                        0
                                    },
                                exceptions: 0,
                            }
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn extended_multiply_flush_and_nan_shortcuts_keep_denormal_status_order() {
    for format in [Format::Single, Format::Double] {
        let two = u64::from(format.exponent_bias() + 1) << format.fraction_bits();
        let infinity = format.infinity(false);
        for (control, expected, exceptions) in [
            (0, infinity, 0),
            (FPCR_FZ, two, INPUT_DENORMAL),
            (FPCR_FIZ, two, 0),
            (FPCR_AH, infinity, INPUT_DENORMAL),
            (FPCR_AH | FPCR_FIZ, two, 0),
        ] {
            assert_eq!(
                result(
                    format,
                    BinaryOperation::MultiplyExtended,
                    control,
                    1,
                    infinity
                ),
                Outcome {
                    bits: expected,
                    exceptions
                }
            );
        }
        let quiet = infinity | format.quiet_bit() | 1;
        assert_eq!(
            result(format, BinaryOperation::MultiplyExtended, FPCR_AH, 1, quiet),
            Outcome {
                bits: quiet,
                exceptions: 0
            }
        );
    }
}

#[test]
fn enabled_exceptions_decline_before_any_numerical_effect() {
    for exception in [
        INVALID,
        DIVIDE_BY_ZERO,
        OVERFLOW,
        UNDERFLOW,
        INEXACT,
        INPUT_DENORMAL,
        EXCEPTIONS,
    ] {
        for operation in [
            BinaryOperation::Divide,
            BinaryOperation::NegatedMultiply,
            BinaryOperation::AbsoluteDifference,
            BinaryOperation::MultiplyExtended,
        ] {
            for ah in [0, FPCR_AH] {
                assert_eq!(
                    evaluate(
                        Format::Double,
                        operation,
                        ah | (exception << FPCR_EXCEPTION_ENABLE_SHIFT),
                        0,
                        0
                    ),
                    Err(UnsupportedControl {
                        enabled_exceptions: exception
                    })
                );
            }
        }
    }
}

#[test]
fn signaling_priority_and_alternative_nan_selection_preserve_payloads() {
    let quiet = 0x7fc00123;
    let signaling = 0xff800456;
    for operation in [
        BinaryOperation::Add,
        BinaryOperation::Subtract,
        BinaryOperation::Multiply,
        BinaryOperation::Divide,
    ] {
        assert_eq!(
            result(Format::Single, operation, 0, quiet, signaling),
            Outcome {
                bits: 0xffc00456,
                exceptions: INVALID
            }
        );
        assert_eq!(
            result(Format::Single, operation, FPCR_AH, quiet, signaling),
            Outcome {
                bits: quiet,
                exceptions: INVALID
            }
        );
        assert_eq!(
            result(
                Format::Single,
                operation,
                FPCR_AH | FPCR_DN,
                quiet,
                signaling
            ),
            Outcome {
                bits: 0xffc00000,
                exceptions: INVALID
            }
        );
    }
}

#[test]
fn input_denormal_order_is_distinct_from_host_denormal_status() {
    assert_eq!(
        result(Format::Single, BinaryOperation::Add, FPCR_FZ, 1, 0x7fc00123),
        Outcome {
            bits: 0x7fc00123,
            exceptions: INPUT_DENORMAL
        }
    );
    assert_eq!(
        result(
            Format::Single,
            BinaryOperation::Add,
            FPCR_AH | FPCR_FZ,
            1,
            0x7fc00123
        ),
        Outcome {
            bits: 0x7fc00123,
            exceptions: 0
        }
    );
    assert_eq!(
        result(Format::Single, BinaryOperation::Divide, FPCR_AH, 1, 0),
        Outcome {
            bits: 0x7f800000,
            exceptions: DIVIDE_BY_ZERO
        }
    );
    assert_eq!(
        result(
            Format::Single,
            BinaryOperation::Multiply,
            FPCR_AH,
            1,
            0x3f800000
        ),
        Outcome {
            bits: 1,
            exceptions: INPUT_DENORMAL
        }
    );
    assert_eq!(
        result(Format::Single, BinaryOperation::Divide, FPCR_FIZ, 1, 0),
        Outcome {
            bits: 0x7fc00000,
            exceptions: INVALID
        }
    );
    assert_eq!(
        result(
            Format::Single,
            BinaryOperation::Divide,
            FPCR_FIZ | FPCR_FZ,
            1,
            0
        ),
        Outcome {
            bits: 0x7fc00000,
            exceptions: INVALID | INPUT_DENORMAL
        }
    );
}

#[test]
fn exact_tiny_output_flushes_with_architectural_inexact_policy() {
    for (format, minimum, half) in [
        (Format::Half, 0x0400, 0x3800),
        (Format::Single, 0x00800000, 0x3f000000),
        (Format::Double, 0x0010000000000000, 0x3fe0000000000000),
    ] {
        let flush = if format == Format::Half {
            FPCR_FZ16
        } else {
            FPCR_FZ
        };
        assert_eq!(
            result(format, BinaryOperation::Multiply, 0, minimum, half),
            Outcome {
                bits: minimum / 2,
                exceptions: 0
            }
        );
        assert_eq!(
            result(format, BinaryOperation::Multiply, flush, minimum, half),
            Outcome {
                bits: 0,
                exceptions: UNDERFLOW
            }
        );
        assert_eq!(
            result(
                format,
                BinaryOperation::Multiply,
                flush | FPCR_AH,
                minimum,
                half
            ),
            Outcome {
                bits: 0,
                exceptions: UNDERFLOW | INEXACT
            }
        );
    }
}

#[test]
fn unconstrained_rounding_differs_at_minimum_normal_boundary() {
    // (1+2^-23)*(1-2^-23)*2^-126 = minimum_normal - 2^-172.
    // The stored result is normal in both modes; exact-value tininess and
    // precision-only rounded tininess nevertheless have different outcomes.
    let left = 0x00800001;
    let right = 0x3f7ffffe;
    assert_eq!(
        result(Format::Single, BinaryOperation::Multiply, 0, left, right),
        Outcome {
            bits: 0x00800000,
            exceptions: UNDERFLOW | INEXACT
        }
    );
    assert_eq!(
        result(
            Format::Single,
            BinaryOperation::Multiply,
            FPCR_AH,
            left,
            right
        ),
        Outcome {
            bits: 0x00800000,
            exceptions: INEXACT
        }
    );
    assert_eq!(
        result(
            Format::Single,
            BinaryOperation::Multiply,
            FPCR_FZ,
            left,
            right
        ),
        Outcome {
            bits: 0,
            exceptions: UNDERFLOW
        }
    );
    assert_eq!(
        result(
            Format::Single,
            BinaryOperation::Multiply,
            FPCR_FZ | FPCR_AH,
            left,
            right
        ),
        Outcome {
            bits: 0x00800000,
            exceptions: INEXACT
        }
    );
}

#[test]
fn exact_cancellation_skips_scaling_and_obeys_zero_sign() {
    let maximum = 0x7fefffffffffffff;
    for rounding in 0..4 {
        let fpcr = FPCR_AH | (rounding << FPCR_ROUNDING_SHIFT);
        let expected = Outcome {
            bits: if rounding == ROUND_NEGATIVE {
                1 << 63
            } else {
                0
            },
            exceptions: 0,
        };
        assert_eq!(
            result(
                Format::Double,
                BinaryOperation::Subtract,
                fpcr,
                maximum,
                maximum
            ),
            expected
        );
    }
}

#[test]
fn clamped_overflow_raises_overflow_without_confusing_inexact_maximum() {
    for format in [Format::Half, Format::Single, Format::Double] {
        let maximum = format.exponent_mask() - 1;
        for negative in [false, true] {
            let sign = if negative { format.sign_mask() } else { 0 };
            for rounding in [
                ROUND_NEAREST_EVEN,
                ROUND_POSITIVE,
                ROUND_NEGATIVE,
                ROUND_ZERO,
            ] {
                let fpcr = rounding << FPCR_ROUNDING_SHIFT;
                let infinite = rounding == ROUND_NEAREST_EVEN
                    || rounding == ROUND_POSITIVE && !negative
                    || rounding == ROUND_NEGATIVE && negative;
                assert_eq!(
                    result(
                        format,
                        BinaryOperation::Add,
                        fpcr,
                        maximum | sign,
                        maximum | sign
                    ),
                    Outcome {
                        bits: if infinite {
                            format.infinity(negative)
                        } else {
                            maximum | sign
                        },
                        exceptions: OVERFLOW | INEXACT
                    }
                );
                // A tiny increment beyond largest finite is inexact, but its
                // exact exponent has not reached the overflow threshold.
                if !infinite || rounding == ROUND_NEAREST_EVEN {
                    assert_eq!(
                        result(format, BinaryOperation::Add, fpcr, maximum | sign, 1 | sign),
                        Outcome {
                            bits: maximum | sign,
                            exceptions: INEXACT
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn lane_width_and_irrelevant_arithmetic_controls_do_not_leak() {
    const AHP: u32 = 1 << 26;
    const NEP: u32 = 1 << 2;
    for (format, one, expected) in [
        (Format::Half, 0x3c00, 0x4000),
        (Format::Single, 0x3f800000, 0x40000000),
    ] {
        let poison = !((1u64 << format.bits()) - 1);
        assert_eq!(
            result(
                format,
                BinaryOperation::Add,
                AHP | NEP,
                one | poison,
                one | poison
            ),
            Outcome {
                bits: expected,
                exceptions: 0
            }
        );
    }
}
