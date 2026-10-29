use super::*;
use crate::aarch64::floating::{
    EXCEPTIONS, FPCR_AH, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FZ16, INPUT_DENORMAL,
    INVALID, ROUND_NEGATIVE, ROUND_POSITIVE, ROUND_ZERO,
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
