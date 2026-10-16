//! FSQRT computed from an integer radicand and remainder.
use super::{
    Class, Control, Format, INEXACT, INVALID, Outcome, UnsupportedControl, nan, process_denormals,
    unpack,
};
use rustc_apfloat::Round;

fn positive_finite(format: Format, rounding: Round, bits: u64) -> Outcome {
    let fraction_bits = format.fraction_bits();
    let hidden_bit = 1u64 << fraction_bits;
    let bias = format.exponent_bias() as i32;
    let encoded_exponent = ((bits & format.exponent_mask()) >> fraction_bits) as i32;
    let mut significand = bits & format.fraction_mask();
    let exponent = if encoded_exponent == 0 {
        let normalization = fraction_bits - significand.ilog2();
        significand <<= normalization;
        1 - bias - normalization as i32
    } else {
        significand |= hidden_bit;
        encoded_exponent - bias
    };

    // x = significand * 2^(exponent-fraction_bits). Scaling its root to the
    // destination significand gives this integer radicand, at most 106 bits.
    // Euclidean parity/division are required for negative odd exponents.
    let radicand = u128::from(significand) << (fraction_bits + exponent.rem_euclid(2) as u32);
    let mut root = radicand.isqrt();
    let remainder = radicand - root * root;
    let increment = match rounding {
        // (root+1/2)^2 = root^2+root+1/4. An integer radicand cannot tie.
        Round::NearestTiesToEven | Round::NearestTiesToAway => remainder > root,
        Round::TowardPositive => remainder != 0,
        Round::TowardNegative | Round::TowardZero => false,
    };
    root += u128::from(increment);
    let mut result_exponent = exponent.div_euclid(2);
    if root == u128::from(hidden_bit) << 1 {
        root >>= 1;
        result_exponent += 1;
    }
    debug_assert!((u128::from(hidden_bit)..u128::from(hidden_bit) << 1).contains(&root));
    let bits =
        ((result_exponent + bias) as u64) << fraction_bits | (root as u64 & format.fraction_mask());
    Outcome {
        bits,
        exceptions: if remainder == 0 { 0 } else { INEXACT },
    }
}

/// Fresh status only. Scalar merging, active lanes and sticky FPSR belong to
/// the caller. AHP is ignored; input controls and early-branch IDC follow FPSqrt.
pub fn evaluate(format: Format, fpcr: u32, bits: u64) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let mut exceptions = 0;
    let operand = unpack(format, bits, control, &mut exceptions);
    let bits = if let Some(bits) = nan(format, operand, operand, control, &mut exceptions) {
        bits
    } else if operand.class == Class::Zero || operand.class == Class::Infinity && !operand.negative
    {
        operand.bits
    } else if operand.negative {
        exceptions |= INVALID;
        control.default_nan(format)
    } else {
        let result = positive_finite(format, control.round(), operand.bits);
        exceptions |= result.exceptions;
        // Negative invalid inputs and all other early returns skip this check.
        process_denormals(format, control, operand, operand, &mut exceptions);
        result.bits
    };
    Ok(Outcome { bits, exceptions })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::floating::{
        EXCEPTIONS, FPCR_AH, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FIZ, FPCR_FZ,
        FPCR_FZ16, FPCR_NEP, FPCR_ROUNDING_SHIFT, INPUT_DENORMAL, ROUND_NEGATIVE, ROUND_POSITIVE,
        ROUND_ZERO,
    };
    use rustc_apfloat::{
        Float, FloatConvert, StatusAnd,
        ieee::{Double, Half},
    };

    const FORMATS: [Format; 3] = [Format::Half, Format::Single, Format::Double];
    const EXACT_SUBNORMAL_ROOTS: [(Format, u64, u64); 3] = [
        (Format::Half, 0x0001, 0x0c00),
        (Format::Single, 0x0000_0002, 0x1a80_0000),
        (Format::Double, 0x0000_0000_0000_0001, 0x1e60_0000_0000_0000),
    ];

    fn result(format: Format, fpcr: u32, bits: u64) -> Outcome {
        evaluate(format, fpcr, bits).unwrap()
    }

    fn power_of_two(format: Format, exponent: i32) -> u64 {
        let fraction = format.fraction_bits();
        let bias = format.exponent_bias() as i32;
        ((bias + exponent) as u64) << fraction
    }

    #[test]
    fn exact_powers_signed_zeros_and_positive_infinity_preserve_exact_status() {
        for format in FORMATS {
            for rounding in 0..4 {
                let fpcr = rounding << FPCR_ROUNDING_SHIFT;
                for bits in [0, format.sign_mask(), format.infinity(false)] {
                    assert_eq!(
                        result(format, fpcr, bits),
                        Outcome {
                            bits,
                            exceptions: 0
                        }
                    );
                }
                for exponent in [-12, -6, -2, 0, 2, 8, 14] {
                    assert_eq!(
                        result(format, fpcr, power_of_two(format, exponent)),
                        Outcome {
                            bits: power_of_two(format, exponent / 2),
                            exceptions: 0
                        }
                    );
                }
            }
        }
        for (format, input, expected) in EXACT_SUBNORMAL_ROOTS {
            assert_eq!(
                result(format, 0, input),
                Outcome {
                    bits: expected,
                    exceptions: 0
                }
            );
        }
    }

    #[test]
    fn irrational_roots_round_in_all_directions_without_double_rounding() {
        for (format, nearest, floor, ceiling) in [
            (Format::Half, 0x3da8, 0x3da8, 0x3da9),
            (Format::Single, 0x3fb5_04f3, 0x3fb5_04f3, 0x3fb5_04f4),
            (
                Format::Double,
                0x3ff6_a09e_667f_3bcd,
                0x3ff6_a09e_667f_3bcc,
                0x3ff6_a09e_667f_3bcd,
            ),
        ] {
            for (mode, expected) in [
                (0, nearest),
                (ROUND_POSITIVE, ceiling),
                (ROUND_NEGATIVE, floor),
                (ROUND_ZERO, floor),
            ] {
                assert_eq!(
                    result(format, mode << FPCR_ROUNDING_SHIFT, power_of_two(format, 1)),
                    Outcome {
                        bits: expected,
                        exceptions: INEXACT
                    }
                );
            }
        }
    }

    #[test]
    fn just_below_four_distinguishes_nearest_floor_and_positive_carry() {
        for format in FORMATS {
            let input = power_of_two(format, 2) - 1;
            let two = power_of_two(format, 1);
            for mode in 0..4 {
                assert_eq!(
                    result(format, mode << FPCR_ROUNDING_SHIFT, input),
                    Outcome {
                        bits: if mode == ROUND_POSITIVE { two } else { two - 1 },
                        exceptions: INEXACT
                    }
                );
            }
        }
    }

    #[test]
    fn unary_nan_payload_default_sign_and_negative_invalid_order_are_preserved() {
        for format in FORMATS {
            for ah in [0, FPCR_AH] {
                for dn in [0, FPCR_DN] {
                    let fpcr = ah | dn;
                    for negative in [false, true] {
                        for signaling in [false, true] {
                            let input = format.infinity(negative)
                                | 1
                                | if signaling { 0 } else { format.quiet_bit() };
                            let expected = if dn != 0 {
                                Control(fpcr).default_nan(format)
                            } else {
                                input | format.quiet_bit()
                            };
                            assert_eq!(
                                result(format, fpcr, input),
                                Outcome {
                                    bits: expected,
                                    exceptions: if signaling { INVALID } else { 0 }
                                }
                            );
                        }
                    }
                    for magnitude in [power_of_two(format, 0), format.infinity(false), 1] {
                        assert_eq!(
                            result(format, fpcr, magnitude | format.sign_mask()),
                            Outcome {
                                bits: Control(fpcr).default_nan(format),
                                exceptions: INVALID
                            }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn denormal_input_flush_and_positive_only_post_status_have_distinct_ordering() {
        for (format, input, root) in EXACT_SUBNORMAL_ROOTS {
            for negative in [false, true] {
                let sign = if negative { format.sign_mask() } else { 0 };
                if format == Format::Half {
                    assert_eq!(
                        result(format, FPCR_FZ16 | FPCR_AHP, input | sign),
                        Outcome {
                            bits: sign,
                            exceptions: 0
                        }
                    );
                    assert_eq!(
                        result(format, FPCR_FIZ | FPCR_FZ | FPCR_AHP, input),
                        Outcome {
                            bits: root,
                            exceptions: 0
                        }
                    );
                    continue;
                }
                for (control, status) in [
                    (FPCR_FZ, INPUT_DENORMAL),
                    (FPCR_FIZ, 0),
                    (FPCR_FZ | FPCR_FIZ, INPUT_DENORMAL),
                    (FPCR_AH | FPCR_FIZ, 0),
                ] {
                    assert_eq!(
                        result(format, control, input | sign),
                        Outcome {
                            bits: sign,
                            exceptions: status
                        }
                    );
                }
                assert_eq!(
                    result(format, FPCR_AH | FPCR_FZ, input | sign),
                    Outcome {
                        bits: if negative {
                            Control(FPCR_AH).default_nan(format)
                        } else {
                            root
                        },
                        exceptions: if negative { INVALID } else { INPUT_DENORMAL }
                    }
                );
            }
        }
    }

    #[test]
    fn every_retained_exception_enable_refuses_even_early_return_values() {
        for format in FORMATS {
            for bit in 0..u32::BITS {
                let status = 1 << bit;
                if EXCEPTIONS & status == 0 {
                    continue;
                }
                for input in [
                    0,
                    format.sign_mask(),
                    format.infinity(false),
                    format.infinity(false) | 1,
                    power_of_two(format, 0),
                ] {
                    assert_eq!(
                        evaluate(format, status << FPCR_EXCEPTION_ENABLE_SHIFT, input),
                        Err(UnsupportedControl {
                            enabled_exceptions: status
                        })
                    );
                }
            }
        }
    }

    #[test]
    fn all_positive_finite_half_values_match_independent_double_sqrt_and_packing() {
        // Host double sqrt is correctly rounded and far from any half-precision
        // midpoint, and dyadic separation keeps it from reaching a half endpoint
        // unless the root is exact, so it is an exact reference here.
        for input in 0..Format::Half.infinity(false) {
            let mut loses = false;
            let wide: StatusAnd<Double> =
                Half::from_bits(u128::from(input)).convert_r(Round::NearestTiesToEven, &mut loses);
            assert!(!loses);
            let value = f64::from_bits(wide.value.to_bits() as u64);
            let square_root = Double::from_bits(u128::from(value.sqrt().to_bits()));
            for mode in 0..4 {
                let fpcr = mode << FPCR_ROUNDING_SHIFT;
                let rounding = Control(fpcr).round();
                let packed: StatusAnd<Half> = square_root.convert_r(rounding, &mut loses);
                let expanded: StatusAnd<Double> =
                    packed.value.convert_r(Round::NearestTiesToEven, &mut loses);
                let rounded = f64::from_bits(expanded.value.to_bits() as u64);
                let expected = Outcome {
                    bits: packed.value.to_bits() as u64,
                    exceptions: if rounded * rounded == value {
                        0
                    } else {
                        INEXACT
                    },
                };
                assert_eq!(
                    result(Format::Half, fpcr, input),
                    expected,
                    "input={input:04x}, mode={mode}"
                );
                assert_eq!(
                    result(Format::Half, fpcr | FPCR_AHP | FPCR_NEP, input),
                    expected
                );
            }
        }
    }
}
