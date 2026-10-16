use super::super::BFLOAT16_FRACTION_BITS;
use super::*;
use crate::aarch64::floating::{FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK};

const SINGLE_ONE: u32 = 0x3f800000;
const SINGLE_MINIMUM: u32 = 0x00800000;
const SINGLE_MAXIMUM: u32 = 0x7f7fffff;
const SINGLE_DEFAULT_NAN: u32 = 0x7fc00000;
const BFLOAT16_ONE: u16 = 0x3f80;
const BFLOAT16_HALF: u16 = 0x3f00;
const BFLOAT16_TWO: u16 = 0x4000;
const BFLOAT16_MINIMUM: u16 = 0x0080;
const BFLOAT16_MAXIMUM: u16 = 0x7f7f;
const BFLOAT16_SIGN: u16 = 0x8000;

fn single_power(exponent: i32) -> u32 {
    ((exponent + Format::Single.exponent_bias() as i32) as u32) << Format::Single.fraction_bits()
}

/// Independent integer BFRound for an exact signed integer times 2^scale.
fn round_scaled(value: i128, scale: i32) -> u32 {
    if value == 0 {
        return 0;
    }
    let sign = if value < 0 { SINGLE_SIGN } else { 0 };
    let magnitude = value.unsigned_abs();
    let leading = u128::BITS - 1 - magnitude.leading_zeros();
    let exponent = leading as i32 + scale;
    let bias = Format::Single.exponent_bias() as i32;
    if exponent < 1 - bias {
        return sign;
    }
    if exponent > bias {
        return sign | SINGLE_EXPONENT;
    }
    let fraction_bits = Format::Single.fraction_bits();
    let mantissa = if leading > fraction_bits {
        let discarded = leading - fraction_bits;
        let sticky = magnitude & ((1u128 << discarded) - 1) != 0;
        (magnitude >> discarded) | u128::from(sticky)
    } else {
        magnitude << (fraction_bits - leading)
    };
    sign | (((exponent + bias) as u32) << fraction_bits) | (mantissa as u32 & SINGLE_FRACTION)
}

#[test]
fn exact_bfloat_products_follow_integer_exponent_boundaries() {
    let fractions = [0, 1, 63, 127];
    let exponents = [1, 2, 63, 126, 127, 128, 190, 253, 254];
    for left_exponent in exponents {
        for right_exponent in exponents {
            for left_fraction in fractions {
                for right_fraction in fractions {
                    for left_negative in [false, true] {
                        for right_negative in [false, true] {
                            let left = ((left_exponent << BFLOAT16_FRACTION_BITS) | left_fraction)
                                as u16
                                | if left_negative { BFLOAT16_SIGN } else { 0 };
                            let right = ((right_exponent << BFLOAT16_FRACTION_BITS)
                                | right_fraction) as u16
                                | if right_negative { BFLOAT16_SIGN } else { 0 };
                            let product = i128::from((1 << BFLOAT16_FRACTION_BITS) + left_fraction)
                                * i128::from((1 << BFLOAT16_FRACTION_BITS) + right_fraction);
                            let value = if left_negative ^ right_negative {
                                -product
                            } else {
                                product
                            };
                            let scale = left_exponent + right_exponent
                                - 2 * (Format::Single.exponent_bias() + BFLOAT16_FRACTION_BITS)
                                    as i32;
                            assert_eq!(multiply(0, left, right), round_scaled(value, scale));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn fixed_odd_additions_preserve_sticky_across_double_rtz() {
    let fraction_bits = Format::Single.fraction_bits();
    let mantissas = [
        1u32 << fraction_bits,
        (1 << fraction_bits) + 1,
        (1 << (fraction_bits + 1)) - 1,
    ];
    for exponent in [-125, -32, 0, 64, 126, 127] {
        for gap in [0, 1, 2, 23, 24, 25, 52, 53, 54, 80] {
            let lower = exponent - gap;
            if lower < 1 - Format::Single.exponent_bias() as i32 {
                continue;
            }
            for left_mantissa in mantissas {
                for right_mantissa in mantissas {
                    for left_negative in [false, true] {
                        for right_negative in [false, true] {
                            let left = single_power(exponent)
                                | (left_mantissa & SINGLE_FRACTION)
                                | if left_negative { SINGLE_SIGN } else { 0 };
                            let right = single_power(lower)
                                | (right_mantissa & SINGLE_FRACTION)
                                | if right_negative { SINGLE_SIGN } else { 0 };
                            let left_integer = i128::from(left_mantissa) << gap;
                            let right_integer = i128::from(right_mantissa);
                            let exact = if left_negative {
                                -left_integer
                            } else {
                                left_integer
                            } + if right_negative {
                                -right_integer
                            } else {
                                right_integer
                            };
                            assert_eq!(
                                add(0, left, right),
                                round_scaled(exact, lower - fraction_bits as i32)
                            );
                        }
                    }
                }
            }
        }
    }
    assert_eq!(add(0, SINGLE_ONE, single_power(-100)), SINGLE_ONE | 1);
    assert_eq!(
        add(
            0,
            SINGLE_ONE | SINGLE_SIGN,
            single_power(-100) | SINGLE_SIGN
        ),
        SINGLE_ONE | SINGLE_SIGN | 1
    );
}

#[test]
fn special_values_flushing_and_signed_zeros_are_fixed() {
    for fpcr in [0, FPCR_AH, u32::MAX, FPCR_EXCEPTION_ENABLE_MASK] {
        let nan = SINGLE_DEFAULT_NAN | if fpcr & FPCR_AH != 0 { SINGLE_SIGN } else { 0 };
        for bf_nan in [0x7f81, 0x7fc0, 0xff81, 0xffc0] {
            assert_eq!(multiply(fpcr, bf_nan, BFLOAT16_ONE), nan);
        }
        assert_eq!(multiply(fpcr, 0x7f80, 1), nan);
        assert_eq!(
            add(fpcr, SINGLE_EXPONENT, SINGLE_EXPONENT | SINGLE_SIGN),
            nan
        );
        assert_eq!(add(fpcr, 0x7f800001, SINGLE_ONE), nan);
        assert_eq!(add(fpcr, SINGLE_SIGN, SINGLE_SIGN), SINGLE_SIGN);
        assert_eq!(add(fpcr, 0x80000001, SINGLE_SIGN), SINGLE_SIGN);
        assert_eq!(add(fpcr, SINGLE_SIGN, 0), 0);
        assert_eq!(add(fpcr, SINGLE_ONE, SINGLE_ONE | SINGLE_SIGN), 0);
        assert_eq!(multiply(fpcr, BFLOAT16_MINIMUM, BFLOAT16_HALF), 0);
        assert_eq!(
            multiply(fpcr, BFLOAT16_MINIMUM | BFLOAT16_SIGN, BFLOAT16_HALF),
            SINGLE_SIGN
        );
        assert_eq!(
            multiply(fpcr, BFLOAT16_MAXIMUM, BFLOAT16_TWO),
            SINGLE_EXPONENT
        );
        assert_eq!(add(fpcr, SINGLE_MAXIMUM, single_power(103)), SINGLE_MAXIMUM);
        assert_eq!(
            add(fpcr, SINGLE_MAXIMUM, single_power(104)),
            SINGLE_EXPONENT
        );
        assert_eq!(
            add(fpcr, SINGLE_MINIMUM + 1, SINGLE_MINIMUM | SINGLE_SIGN),
            0
        );
        assert_eq!(
            add(fpcr, SINGLE_MINIMUM, (SINGLE_MINIMUM + 1) | SINGLE_SIGN),
            SINGLE_SIGN
        );
    }
}

#[test]
fn dot_retains_separately_flushed_and_overflowed_stages() {
    assert_eq!(dot_add(0, 0, [BFLOAT16_MINIMUM; 2], [BFLOAT16_HALF; 2]), 0);
    // Opposite overflowing products become opposite infinities before their
    // pair addition; cancellation of exact real products is not fused.
    assert_eq!(
        dot_add(
            0,
            0,
            [BFLOAT16_MAXIMUM; 2],
            [BFLOAT16_TWO, BFLOAT16_TWO | BFLOAT16_SIGN]
        ),
        SINGLE_DEFAULT_NAN
    );
    assert_eq!(
        dot_add(
            FPCR_AH,
            0,
            [BFLOAT16_MAXIMUM; 2],
            [BFLOAT16_TWO, BFLOAT16_TWO | BFLOAT16_SIGN]
        ),
        SINGLE_DEFAULT_NAN | SINGLE_SIGN
    );
    assert_eq!(
        dot_add(
            u32::MAX,
            SINGLE_ONE,
            [BFLOAT16_ONE; 2],
            [BFLOAT16_ONE, BFLOAT16_ONE | BFLOAT16_SIGN]
        ),
        SINGLE_ONE
    );
}
