//! FRECPS and FRSQRTS fused steps, including the halving before rounding.
use super::{
    Class, Control, FPCR_FIZ, FPCR_FZ, FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT, Format, Outcome,
    UnsupportedControl, nan, negate, precision, unpack, widen,
};
use crate::aarch64::simd::refinement::Kind;
use rustc_apfloat::{
    Float, Round, Status,
    ieee::{Double, Half, Quad, Single},
};

const RECIPROCAL_ADDEND: u128 = 2;
const RECIPROCAL_SQUARE_ROOT_ADDEND: u128 = 3;
const HALVE_EXPONENT: i32 = -1;
const ODD_SIGNIFICAND_BIT: u128 = 1;

fn wide(format: Format, bits: u64) -> Quad {
    let bits = u128::from(bits);
    match format {
        Format::Half => widen(Half::from_bits(bits)),
        Format::Single => widen(Single::from_bits(bits)),
        Format::Double => widen(Double::from_bits(bits)),
    }
}

fn finite(format: Format, kind: Kind, control: Control, left: u64, right: u64) -> Outcome {
    let addend = Quad::from_u128(match kind {
        Kind::Reciprocal => RECIPROCAL_ADDEND,
        Kind::ReciprocalSquareRoot => RECIPROCAL_SQUARE_ROOT_ADDEND,
    })
    .value;
    // Every H/S/D product is exact in Quad and fits its exponent range. Adding
    // the constant can lose distant bits. Round-to-odd preserves their side of
    // all H/S/D rounding boundaries (at least 59 additional precision bits).
    let intermediate = wide(format, left).mul_add_r(wide(format, right), addend, Round::TowardZero);
    let mut value = intermediate.value;
    if intermediate.status.contains(Status::INEXACT) {
        value = Quad::from_bits(value.to_bits() | ODD_SIGNIFICAND_BIT);
    }
    if kind == Kind::ReciprocalSquareRoot {
        value = value.scalbn(HALVE_EXPONENT);
    }
    if value.is_zero() {
        return Outcome {
            bits: if control.round() == Round::TowardNegative {
                format.sign_mask()
            } else {
                0
            },
            exceptions: 0,
        };
    }
    // A jammed Quad cannot be exact in a <=53-bit target, so final conversion
    // supplies IXC. Do not OR wide IXC into the AH0 tiny-flush UFC-only result.
    precision::round_ieee(value, format, control, control.round(), true, false)
}

/// Returns fresh status only. FPCR.AH suppresses all exceptions; with AH clear,
/// enabled traps are refused.
pub fn evaluate(
    kind: Kind,
    format: Format,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<Outcome, UnsupportedControl> {
    let original = Control(fpcr);
    let left = negate(format, left, original);
    let control = if original.alternative() {
        Control((fpcr | FPCR_FIZ | FPCR_FZ) & !(FPCR_ROUNDING_MASK << FPCR_ROUNDING_SHIFT))
    } else {
        Control::checked(fpcr)?
    };
    let mut exceptions = 0;
    let left = unpack(format, left, control, &mut exceptions);
    let right = unpack(format, right, control, &mut exceptions);
    let mut result = if let Some(bits) = nan(format, left, right, control, &mut exceptions) {
        Outcome {
            bits,
            exceptions: 0,
        }
    } else if left.class == Class::Infinity && right.class == Class::Zero
        || left.class == Class::Zero && right.class == Class::Infinity
    {
        Outcome {
            bits: match kind {
                Kind::Reciprocal => u64::from(format.exponent_bias() + 1) << format.fraction_bits(),
                Kind::ReciprocalSquareRoot => {
                    u64::from(format.exponent_bias()) << format.fraction_bits()
                        | 1 << (format.fraction_bits() - 1)
                }
            },
            exceptions: 0,
        }
    } else if left.class == Class::Infinity || right.class == Class::Infinity {
        Outcome {
            bits: format.infinity(left.negative ^ right.negative),
            exceptions: 0,
        }
    } else {
        finite(format, kind, control, left.bits, right.bits)
    };
    result.exceptions = if original.alternative() {
        0
    } else {
        result.exceptions | exceptions
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::floating::{
        EXCEPTIONS, FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FZ16, INEXACT,
        INPUT_DENORMAL, INVALID, OVERFLOW, UNDERFLOW,
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
                    Kind::ReciprocalSquareRoot => {
                        power(format, 1) | 1 << (format.fraction_bits() - 1)
                    }
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
                    Kind::ReciprocalSquareRoot => {
                        power(format, 0) | 1 << (format.fraction_bits() - 1)
                    }
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
    fn nan_operands_take_priority_over_default_selection() {
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
    fn ah_accepts_all_kept_enables_without_fresh_status() {
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
}
