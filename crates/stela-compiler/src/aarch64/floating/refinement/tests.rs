use super::*;
use crate::aarch64::floating::{
    EXCEPTIONS, FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FZ16, INEXACT, INPUT_DENORMAL,
    INVALID, OVERFLOW, UNDERFLOW,
};

const FORMATS: [Format; 3] = [Format::Half, Format::Single, Format::Double];
const KINDS: [Kind; 2] = [Kind::Reciprocal, Kind::ReciprocalSquareRoot];

fn power(format: Format, exponent: i32) -> u64 {
    ((format.exponent_bias() as i32 + exponent) as u64) << format.fraction_bits()
}

#[test]
fn halving_precedes_target_overflow_and_preserves_distant_inexact_bits() {
    for (format, input, expected) in [
        (Format::Half, 0x5c00, 0xf800),
        (Format::Single, 0x5f80_0000, 0xff00_0000),
        (Format::Double, 0x5ff0_0000_0000_0000, 0xffe0_0000_0000_0000),
    ] {
        assert_eq!(
            evaluate(Kind::ReciprocalSquareRoot, format, 0, input, input),
            Ok(Outcome {
                bits: expected,
                exceptions: INEXACT
            })
        );
        for mode in 0..4 {
            assert_eq!(
                evaluate(
                    Kind::ReciprocalSquareRoot,
                    format,
                    FPCR_AH | (mode << FPCR_ROUNDING_SHIFT),
                    input,
                    input
                ),
                Ok(Outcome {
                    bits: expected,
                    exceptions: 0
                })
            );
        }
    }
    for format in FORMATS {
        let one = power(format, 0);
        for kind in KINDS {
            for mode in 0..4 {
                assert_eq!(
                    evaluate(kind, format, mode << FPCR_ROUNDING_SHIFT, one + 1, one - 2),
                    Ok(Outcome {
                        bits: one + u64::from(mode == super::super::ROUND_POSITIVE),
                        exceptions: INEXACT
                    })
                );
            }
        }
    }
}

#[test]
fn exact_cancellation_zero_sign_follows_effective_rounding() {
    for format in FORMATS {
        for kind in KINDS {
            let right = match kind {
                Kind::Reciprocal => power(format, 1),
                Kind::ReciprocalSquareRoot => power(format, 1) | 1 << (format.fraction_bits() - 1),
            };
            for mode in 0..4 {
                for ah in [0, FPCR_AH] {
                    assert_eq!(
                        evaluate(
                            kind,
                            format,
                            ah | mode << FPCR_ROUNDING_SHIFT,
                            power(format, 0),
                            right
                        ),
                        Ok(Outcome {
                            bits: if ah == 0 && mode == super::super::ROUND_NEGATIVE {
                                format.sign_mask()
                            } else {
                                0
                            },
                            exceptions: 0
                        })
                    );
                }
            }
        }
    }
}

#[test]
fn half_exact_subnormal_flush_has_underflow_only_and_ah_suppresses_it() {
    for (kind, left, right, expected) in [
        (Kind::Reciprocal, 0x3c01, 0x3ffe, 0x0020),
        (Kind::ReciprocalSquareRoot, 0x3c02, 0x41fd, 0x0060),
    ] {
        for ah in [0, FPCR_AH] {
            for flush in [0, FPCR_FZ16] {
                assert_eq!(
                    evaluate(kind, Format::Half, ah | flush, left, right),
                    Ok(Outcome {
                        bits: if flush == 0 { expected } else { 0 },
                        exceptions: if flush != 0 && ah == 0 { UNDERFLOW } else { 0 }
                    })
                );
            }
        }
    }
}

#[test]
fn invalid_product_returns_constant_and_other_infinities_negate_product_sign() {
    for format in FORMATS {
        for kind in KINDS {
            let constant = match kind {
                Kind::Reciprocal => power(format, 1),
                Kind::ReciprocalSquareRoot => power(format, 0) | 1 << (format.fraction_bits() - 1),
            };
            for left_negative in [false, true] {
                for right_negative in [false, true] {
                    let zero = if left_negative { format.sign_mask() } else { 0 };
                    let infinity = format.infinity(right_negative);
                    for (left, right) in [(zero, infinity), (infinity, zero)] {
                        assert_eq!(
                            evaluate(kind, format, 0, left, right),
                            Ok(Outcome {
                                bits: constant,
                                exceptions: 0
                            })
                        );
                    }
                    assert_eq!(
                        evaluate(kind, format, 0, power(format, 0) | zero, infinity),
                        Ok(Outcome {
                            bits: format.infinity(!(left_negative ^ right_negative)),
                            exceptions: 0
                        })
                    );
                }
            }
        }
    }
}

#[test]
fn nan_sign_and_priority_precede_suppression_and_default_selection() {
    for format in FORMATS {
        let first = format.infinity(false) | format.quiet_bit() | 3;
        let second = format.infinity(false) | 5;
        for kind in KINDS {
            assert_eq!(
                evaluate(kind, format, 0, first, second),
                Ok(Outcome {
                    bits: second | format.quiet_bit(),
                    exceptions: INVALID
                })
            );
            assert_eq!(
                evaluate(kind, format, FPCR_AH, first, second),
                Ok(Outcome {
                    bits: first,
                    exceptions: 0
                })
            );
            assert_eq!(
                evaluate(kind, format, 0, second, power(format, 0)),
                Ok(Outcome {
                    bits: second | format.sign_mask() | format.quiet_bit(),
                    exceptions: INVALID
                })
            );
            assert_eq!(
                evaluate(kind, format, FPCR_AH | FPCR_DN, second, first),
                Ok(Outcome {
                    bits: Control(FPCR_AH).default_nan(format),
                    exceptions: 0
                })
            );
        }
    }
}

#[test]
fn effective_denormal_flush_uses_half_control_independently() {
    for format in FORMATS {
        for kind in KINDS {
            let infinity = format.infinity(false);
            let constant = evaluate(kind, format, 0, 0, infinity).unwrap().bits;
            let flush = if format == Format::Half {
                FPCR_FZ16
            } else {
                FPCR_FZ
            };
            assert_eq!(
                evaluate(kind, format, 0, 1, infinity),
                Ok(Outcome {
                    bits: format.infinity(true),
                    exceptions: 0
                })
            );
            assert_eq!(
                evaluate(kind, format, flush, 1, infinity),
                Ok(Outcome {
                    bits: constant,
                    exceptions: if format == Format::Half {
                        0
                    } else {
                        INPUT_DENORMAL
                    }
                })
            );
            assert_eq!(
                evaluate(kind, format, FPCR_AH, 1, infinity),
                Ok(Outcome {
                    bits: if format == Format::Half {
                        format.infinity(true)
                    } else {
                        constant
                    },
                    exceptions: 0
                })
            );
        }
    }
}

#[test]
fn ah_accepts_all_retained_enables_without_fresh_status() {
    for format in FORMATS {
        for kind in KINDS {
            for enabled in [
                INVALID,
                super::super::DIVIDE_BY_ZERO,
                OVERFLOW,
                UNDERFLOW,
                INEXACT,
                INPUT_DENORMAL,
                EXCEPTIONS,
            ] {
                let fpcr = enabled << FPCR_EXCEPTION_ENABLE_SHIFT;
                assert_eq!(
                    evaluate(kind, format, fpcr, 0, 0),
                    Err(UnsupportedControl {
                        enabled_exceptions: enabled
                    })
                );
                assert_eq!(
                    evaluate(kind, format, FPCR_AH | fpcr, format.infinity(false) | 1, 0)
                        .unwrap()
                        .exceptions,
                    0
                );
            }
        }
    }
}
