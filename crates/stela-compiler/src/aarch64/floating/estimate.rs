//! Deterministic standard-precision estimates in the RPRES-disabled A64 profile.
//! AFP controls are supported; this does not assert a closed Apple hardware profile.
pub mod precision;

use super::{
    Class, Control, DIVIDE_BY_ZERO, FPCR_FIZ, FPCR_FZ, FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT,
    Format, INEXACT, OVERFLOW, Outcome, UNDERFLOW, UnsupportedControl, nan, unpack,
};
use crate::aarch64::simd::estimate::Kind;
use rustc_apfloat::Round;

const ESTIMATE_FRACTION_BITS: u32 = 8;
const ESTIMATE_UNIT: u64 = 1 << ESTIMATE_FRACTION_BITS;
const RECIPROCAL_NUMERATOR: u64 = 1 << 19;
const RECIPROCAL_SQRT_NUMERATOR: u64 = 1 << 28;
const UNSIGNED_WIDTH: u32 = 32;
const UNSIGNED_TABLE_SHIFT: u32 = UNSIGNED_WIDTH - ESTIMATE_FRACTION_BITS - 1;
const UNSIGNED_RECIPROCAL_MINIMUM: u64 = 1 << (UNSIGNED_WIDTH - 1);
const UNSIGNED_RECIPROCAL_SQRT_MINIMUM: u64 = 1 << (UNSIGNED_WIDTH - 2);

fn reciprocal_table(scaled: u64) -> u64 {
    debug_assert!((ESTIMATE_UNIT..ESTIMATE_UNIT * 2).contains(&scaled));
    let midpoint = scaled * 2 + 1;
    (RECIPROCAL_NUMERATOR / midpoint).div_ceil(2)
}

fn reciprocal_sqrt_table(scaled: u64) -> u64 {
    debug_assert!((ESTIMATE_UNIT / 2..ESTIMATE_UNIT * 2).contains(&scaled));
    let midpoint = if scaled < ESTIMATE_UNIT {
        scaled * 2 + 1
    } else {
        ((scaled & !1) + 1) * 2
    };
    // The source loop chooses the largest b with midpoint*b*b < numerator.
    // Subtracting one before division retains that strict inequality exactly.
    let bound = ((RECIPROCAL_SQRT_NUMERATOR - 1) / midpoint).isqrt();
    bound.div_ceil(2)
}

fn unsigned(kind: Kind, bits: u64) -> Outcome {
    let bits = u64::from(bits as u32);
    let minimum = if kind == Kind::UnsignedReciprocal {
        UNSIGNED_RECIPROCAL_MINIMUM
    } else {
        UNSIGNED_RECIPROCAL_SQRT_MINIMUM
    };
    let bits = if bits < minimum {
        u64::from(u32::MAX)
    } else {
        let scaled = bits >> UNSIGNED_TABLE_SHIFT;
        let estimate = if kind == Kind::UnsignedReciprocal {
            reciprocal_table(scaled)
        } else {
            reciprocal_sqrt_table(scaled)
        };
        estimate << UNSIGNED_TABLE_SHIFT
    };
    Outcome {
        bits,
        exceptions: 0,
    }
}

fn reciprocal(format: Format, control: Control, bits: u64, exceptions: &mut u32) -> u64 {
    let fraction_bits = format.fraction_bits();
    let fraction_mask = format.fraction_mask();
    let sign = bits & format.sign_mask();
    let mut fraction = bits & fraction_mask;
    let mut exponent = ((bits & format.exponent_mask()) >> fraction_bits) as i32;
    let reciprocal_exponent_base = format.exponent_bias() as i32 * 2 - 1;

    // The overflow threshold is one quarter of minimum normal in every format.
    if exponent == 0 && fraction < 1 << (fraction_bits - 2) {
        *exceptions |= OVERFLOW | INEXACT;
        let infinity = match control.round() {
            Round::NearestTiesToEven | Round::NearestTiesToAway => true,
            Round::TowardPositive => sign == 0,
            Round::TowardNegative => sign != 0,
            Round::TowardZero => false,
        };
        return sign
            | if infinity {
                format.exponent_mask()
            } else {
                format.exponent_mask() - 1
            };
    }
    if control.flush_output(format) && exponent >= reciprocal_exponent_base {
        // Estimate output flushing directly sets UFC, without IXC.
        *exceptions |= UNDERFLOW;
        return sign;
    }

    if exponent == 0 {
        if fraction & (1 << (fraction_bits - 1)) == 0 {
            exponent = -1;
            fraction = (fraction << 2) & fraction_mask;
        } else {
            fraction = (fraction << 1) & fraction_mask;
        }
    }
    let scaled = ESTIMATE_UNIT | (fraction >> (fraction_bits - ESTIMATE_FRACTION_BITS));
    let estimate = reciprocal_table(scaled);
    let exponent = reciprocal_exponent_base - exponent;
    let significand = estimate << (fraction_bits - ESTIMATE_FRACTION_BITS);
    if exponent <= 0 {
        sign | (significand >> (1 - exponent))
    } else {
        sign | ((exponent as u64) << fraction_bits) | (significand & fraction_mask)
    }
}

fn reciprocal_sqrt(format: Format, bits: u64) -> u64 {
    let fraction_bits = format.fraction_bits();
    let mut fraction = bits & format.fraction_mask();
    let mut exponent = ((bits & format.exponent_mask()) >> fraction_bits) as i32;
    if exponent == 0 {
        let normalization = fraction_bits - fraction.ilog2();
        fraction = (fraction << normalization) & format.fraction_mask();
        exponent = 1 - normalization as i32;
    }
    let scaled = if exponent.rem_euclid(2) == 0 {
        ESTIMATE_UNIT | (fraction >> (fraction_bits - ESTIMATE_FRACTION_BITS))
    } else {
        (ESTIMATE_UNIT / 2) | (fraction >> (fraction_bits - ESTIMATE_FRACTION_BITS + 1))
    };
    let estimate = reciprocal_sqrt_table(scaled);
    let exponent = (format.exponent_bias() as i32 * 3 - 1 - exponent).div_euclid(2);
    ((exponent as u64) << fraction_bits)
        | ((estimate - ESTIMATE_UNIT) << (fraction_bits - ESTIMATE_FRACTION_BITS))
}

fn reciprocal_exponent(format: Format, bits: u64) -> u64 {
    let exponent = bits & format.exponent_mask();
    let result_exponent = if exponent == 0 {
        format.exponent_mask() - (1 << format.fraction_bits())
    } else {
        format.exponent_mask() ^ exponent
    };
    (bits & format.sign_mask()) | result_exponent
}

/// Evaluate one lane; callers own scalar merging, active lanes and sticky commit.
/// Unsigned kinds always interpret low32 bits and ignore format/FPCR entirely.
/// AH floating kinds suppress all exception effects and accept retained enables.
pub fn evaluate(
    kind: Kind,
    format: Format,
    fpcr: u32,
    bits: u64,
) -> Result<Outcome, UnsupportedControl> {
    if kind.is_unsigned() {
        return Ok(unsigned(kind, bits));
    }
    let alternative = Control(fpcr).alternative();
    let control = if alternative {
        let mut effective = fpcr | FPCR_FIZ | FPCR_FZ;
        if kind == Kind::Reciprocal {
            effective &= !(FPCR_ROUNDING_MASK << FPCR_ROUNDING_SHIFT);
        }
        Control(effective)
    } else {
        Control::checked(fpcr)?
    };
    let mut exceptions = 0;
    let operand = unpack(format, bits, control, &mut exceptions);
    let bits = if let Some(bits) = nan(format, operand, operand, control, &mut exceptions) {
        bits
    } else {
        match kind {
            Kind::ReciprocalExponent => reciprocal_exponent(format, bits),
            Kind::Reciprocal if operand.class == Class::Infinity => {
                operand.bits & format.sign_mask()
            }
            Kind::Reciprocal | Kind::ReciprocalSquareRoot if operand.class == Class::Zero => {
                exceptions |= DIVIDE_BY_ZERO;
                format.infinity(operand.negative)
            }
            Kind::Reciprocal => reciprocal(format, control, operand.bits, &mut exceptions),
            Kind::ReciprocalSquareRoot if operand.negative => {
                exceptions |= super::INVALID;
                control.default_nan(format)
            }
            Kind::ReciprocalSquareRoot if operand.class == Class::Infinity => 0,
            Kind::ReciprocalSquareRoot => reciprocal_sqrt(format, operand.bits),
            Kind::UnsignedReciprocal | Kind::UnsignedReciprocalSquareRoot => {
                unreachable!("unsigned handled before FP controls")
            }
        }
    };
    // fpexc=false in all AH estimate helpers, including direct output UFC writes.
    Ok(Outcome {
        bits,
        exceptions: if alternative { 0 } else { exceptions },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::floating::{
        EXCEPTIONS, FPCR_AH, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FZ16,
        INPUT_DENORMAL, INVALID, ROUND_NEGATIVE, ROUND_POSITIVE, ROUND_ZERO,
    };

    const FORMATS: [Format; 3] = [Format::Half, Format::Single, Format::Double];
    const FLOATING_KINDS: [Kind; 3] = [
        Kind::Reciprocal,
        Kind::ReciprocalSquareRoot,
        Kind::ReciprocalExponent,
    ];

    fn result(kind: Kind, format: Format, fpcr: u32, bits: u64) -> Outcome {
        evaluate(kind, format, fpcr, bits).unwrap()
    }

    fn one(format: Format) -> u64 {
        u64::from(format.exponent_bias()) << format.fraction_bits()
    }

    #[test]
    fn table_endpoints_and_sqrt_interval_split_have_fixed_architectural_values() {
        assert_eq!(reciprocal_table(256), 511);
        assert_eq!(reciprocal_table(511), 256);
        assert_eq!(reciprocal_sqrt_table(128), 511);
        assert_eq!(reciprocal_sqrt_table(255), 362);
        assert_eq!(reciprocal_sqrt_table(256), 361);
        assert_eq!(reciprocal_sqrt_table(511), 256);
        // Independent source-loop oracle checks every finite table input,
        // distinct from the integer-square-root implementation.
        for scaled in ESTIMATE_UNIT / 2..ESTIMATE_UNIT * 2 {
            let midpoint = if scaled < ESTIMATE_UNIT {
                scaled * 2 + 1
            } else {
                ((scaled >> 1) * 2 + 1) * 2
            };
            let mut bound = 512;
            while midpoint * (bound + 1) * (bound + 1) < RECIPROCAL_SQRT_NUMERATOR {
                bound += 1;
            }
            assert_eq!(reciprocal_sqrt_table(scaled), bound.div_ceil(2));
        }
    }

    #[test]
    fn standard_precision_one_estimates_are_deterministic_and_not_exact_reciprocals() {
        for (format, expected) in [
            (Format::Half, 0x3bfc),
            (Format::Single, 0x3f7f8000),
            (Format::Double, 0x3feff00000000000),
        ] {
            for kind in [Kind::Reciprocal, Kind::ReciprocalSquareRoot] {
                for mode in 0..4 {
                    assert_eq!(
                        result(kind, format, mode << FPCR_ROUNDING_SHIFT, one(format)),
                        Outcome {
                            bits: expected,
                            exceptions: 0
                        }
                    );
                }
            }
            assert_eq!(
                result(Kind::ReciprocalExponent, format, 0, one(format)),
                Outcome {
                    bits: one(format) + (1 << format.fraction_bits()),
                    exceptions: 0
                }
            );
        }
    }

    #[test]
    fn zero_infinity_and_negative_domains_have_operation_specific_results() {
        for format in FORMATS {
            for negative in [false, true] {
                let sign = if negative { format.sign_mask() } else { 0 };
                for kind in [Kind::Reciprocal, Kind::ReciprocalSquareRoot] {
                    assert_eq!(
                        result(kind, format, 0, sign),
                        Outcome {
                            bits: format.infinity(negative),
                            exceptions: DIVIDE_BY_ZERO
                        }
                    );
                }
                assert_eq!(
                    result(Kind::Reciprocal, format, 0, format.infinity(negative)),
                    Outcome {
                        bits: sign,
                        exceptions: 0
                    }
                );
                assert_eq!(
                    result(
                        Kind::ReciprocalExponent,
                        format,
                        0,
                        format.infinity(negative)
                    ),
                    Outcome {
                        bits: sign,
                        exceptions: 0
                    }
                );
                assert_eq!(
                    result(
                        Kind::ReciprocalSquareRoot,
                        format,
                        0,
                        format.infinity(negative)
                    ),
                    Outcome {
                        bits: if negative {
                            Control(0).default_nan(format)
                        } else {
                            0
                        },
                        exceptions: if negative { INVALID } else { 0 }
                    }
                );
            }
        }
    }

    #[test]
    fn ah_suppresses_all_status_and_accepts_retained_enables_without_forcing_fz16() {
        let enables = EXCEPTIONS << FPCR_EXCEPTION_ENABLE_SHIFT;
        for format in FORMATS {
            for kind in FLOATING_KINDS {
                for bits in [
                    0,
                    format.infinity(false) | 1,
                    format.sign_mask() | one(format),
                    1,
                    format.exponent_mask() - 1,
                ] {
                    assert_eq!(result(kind, format, FPCR_AH | enables, bits).exceptions, 0);
                }
            }
        }
        assert_eq!(
            result(Kind::Reciprocal, Format::Half, FPCR_AH | enables, 1),
            Outcome {
                bits: 0x7c00,
                exceptions: 0
            }
        );
        assert_eq!(
            result(
                Kind::ReciprocalSquareRoot,
                Format::Half,
                FPCR_AH | enables,
                1
            ),
            Outcome {
                bits: 0x6bfc,
                exceptions: 0
            }
        );
        assert_eq!(
            result(
                Kind::ReciprocalSquareRoot,
                Format::Half,
                FPCR_AH | FPCR_FZ16 | enables,
                1
            ),
            Outcome {
                bits: 0x7c00,
                exceptions: 0
            }
        );
        for format in [Format::Single, Format::Double] {
            for kind in [Kind::Reciprocal, Kind::ReciprocalSquareRoot] {
                assert_eq!(
                    result(kind, format, FPCR_AH | enables, 1),
                    Outcome {
                        bits: format.infinity(false),
                        exceptions: 0
                    }
                );
            }
        }
    }

    #[test]
    fn nan_payload_quieting_and_default_sign_do_not_inherit_ordinary_ah_exceptions() {
        for format in FORMATS {
            for kind in FLOATING_KINDS {
                for ah in [0, FPCR_AH] {
                    for dn in [0, FPCR_DN] {
                        let control = ah | dn | FPCR_AHP;
                        let signaling = format.infinity(true) | 1;
                        assert_eq!(
                            result(kind, format, control, signaling),
                            Outcome {
                                bits: if dn == 0 {
                                    signaling | format.quiet_bit()
                                } else {
                                    Control(control).default_nan(format)
                                },
                                exceptions: if ah == 0 { INVALID } else { 0 }
                            }
                        );
                        let quiet = signaling | format.quiet_bit();
                        assert_eq!(result(kind, format, control, quiet).exceptions, 0);
                    }
                }
            }
        }
    }

    #[test]
    fn reciprocal_overflow_threshold_and_rounding_follow_explicit_source_branches() {
        for format in FORMATS {
            let threshold = 1 << (format.fraction_bits() - 2);
            let finite_boundary = (format.exponent_mask() - 1)
                & !((1 << (format.fraction_bits() - ESTIMATE_FRACTION_BITS)) - 1);
            assert_eq!(
                result(Kind::Reciprocal, format, 0, threshold),
                Outcome {
                    bits: finite_boundary,
                    exceptions: 0
                }
            );
            for negative in [false, true] {
                let sign = if negative { format.sign_mask() } else { 0 };
                for mode in 0..4 {
                    let infinity = mode == 0
                        || mode == ROUND_POSITIVE && !negative
                        || mode == ROUND_NEGATIVE && negative;
                    assert_eq!(
                        result(
                            Kind::Reciprocal,
                            format,
                            mode << FPCR_ROUNDING_SHIFT,
                            sign | (threshold - 1)
                        ),
                        Outcome {
                            bits: sign
                                | if infinity {
                                    format.exponent_mask()
                                } else {
                                    format.exponent_mask() - 1
                                },
                            exceptions: OVERFLOW | INEXACT
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn reciprocal_output_flush_sets_underflow_without_inexact_and_ah_suppresses_it() {
        for format in FORMATS {
            let boundary = (u64::from(format.exponent_bias()) * 2 - 1) << format.fraction_bits();
            let flush = if format == Format::Half {
                FPCR_FZ16
            } else {
                FPCR_FZ
            };
            for sign in [0, format.sign_mask()] {
                assert_eq!(
                    result(Kind::Reciprocal, format, flush, boundary | sign),
                    Outcome {
                        bits: sign,
                        exceptions: UNDERFLOW
                    }
                );
                assert_eq!(
                    result(Kind::Reciprocal, format, FPCR_AH | flush, boundary | sign),
                    Outcome {
                        bits: sign,
                        exceptions: 0
                    }
                );
                assert_ne!(
                    result(Kind::Reciprocal, format, 0, boundary | sign).bits & !format.sign_mask(),
                    0
                );
            }
        }
    }

    #[test]
    fn reciprocal_exponent_uses_original_exponent_even_after_input_flush() {
        for format in FORMATS {
            let maximum_exponent = format.exponent_mask() - (1 << format.fraction_bits());
            for fraction in [0, 1, format.fraction_mask()] {
                for sign in [0, format.sign_mask()] {
                    for control in [0, FPCR_FIZ, FPCR_FZ, FPCR_AH, FPCR_FZ16] {
                        let expected_status =
                            if format != Format::Half && control == FPCR_FZ && fraction != 0 {
                                INPUT_DENORMAL
                            } else {
                                0
                            };
                        assert_eq!(
                            result(Kind::ReciprocalExponent, format, control, sign | fraction),
                            Outcome {
                                bits: sign | maximum_exponent,
                                exceptions: expected_status
                            }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn unsigned_domains_ignore_every_raw_control_and_preserve_status() {
        for (kind, boundary) in [
            (Kind::UnsignedReciprocal, 0x80000000),
            (Kind::UnsignedReciprocalSquareRoot, 0x40000000),
        ] {
            for fpcr in [0, u32::MAX, EXCEPTIONS << FPCR_EXCEPTION_ENABLE_SHIFT] {
                assert_eq!(
                    result(kind, Format::Single, fpcr, boundary - 1),
                    Outcome {
                        bits: 0xffffffff,
                        exceptions: 0
                    }
                );
                assert_eq!(
                    result(kind, Format::Single, fpcr, boundary),
                    Outcome {
                        bits: 0xff800000,
                        exceptions: 0
                    }
                );
                assert_eq!(
                    result(kind, Format::Single, fpcr, 0xffffffffffffffff),
                    Outcome {
                        bits: 0x80000000,
                        exceptions: 0
                    }
                );
            }
            let first = boundary >> UNSIGNED_TABLE_SHIFT;
            for scaled in first..ESTIMATE_UNIT * 2 {
                let clean = result(kind, Format::Single, 0, scaled << UNSIGNED_TABLE_SHIFT);
                let poisoned = result(
                    kind,
                    Format::Half,
                    u32::MAX,
                    (scaled << UNSIGNED_TABLE_SHIFT)
                        | ((1 << UNSIGNED_TABLE_SHIFT) - 1)
                        | (u64::MAX << UNSIGNED_WIDTH),
                );
                assert_eq!(clean, poisoned);
            }
        }
    }

    #[test]
    fn ah_zero_floating_kinds_retain_explicit_enable_refusals() {
        for exception in [
            INVALID,
            DIVIDE_BY_ZERO,
            OVERFLOW,
            UNDERFLOW,
            INEXACT,
            INPUT_DENORMAL,
            EXCEPTIONS,
        ] {
            for kind in FLOATING_KINDS {
                assert_eq!(
                    evaluate(
                        kind,
                        Format::Single,
                        exception << FPCR_EXCEPTION_ENABLE_SHIFT,
                        0
                    ),
                    Err(UnsupportedControl {
                        enabled_exceptions: exception
                    })
                );
            }
        }
        assert_eq!(
            result(
                Kind::Reciprocal,
                Format::Half,
                FPCR_AH | (ROUND_ZERO << FPCR_ROUNDING_SHIFT),
                1
            )
            .bits,
            0x7c00
        );
    }
}
