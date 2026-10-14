//! Classic BF16 dot stages: fixed flushing, separately rounded Single products
//! and additions, and no architectural exception or trap effects.
use super::super::{Control, Format};
use super::widen;
use rustc_apfloat::{
    Float, FloatConvert, Round, Status, StatusAnd,
    ieee::{Double, Single},
};

const SINGLE_SIGN: u32 = Format::Single.sign_mask() as u32;
const SINGLE_EXPONENT: u32 = Format::Single.exponent_mask() as u32;
const SINGLE_FRACTION: u32 = Format::Single.fraction_mask() as u32;
const SINGLE_MINIMUM_AS_DOUBLE: u128 =
    ((Format::Double.exponent_bias() - Format::Single.exponent_bias() + 1) as u128)
        << Format::Double.fraction_bits();
const SINGLE_OVERFLOW_AS_DOUBLE: u128 =
    ((Format::Double.exponent_bias() + Format::Single.exponent_bias() + 1) as u128)
        << Format::Double.fraction_bits();
const ODD_SIGNIFICAND_BIT: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum OperandClass {
    Zero,
    Finite,
    Infinity,
    NaN,
}

#[derive(Clone, Copy)]
struct Operand {
    bits: u32,
    class: OperandClass,
}

impl Operand {
    fn unpack(bits: u32) -> Self {
        let exponent = bits & SINGLE_EXPONENT;
        let class = if exponent == 0 {
            OperandClass::Zero
        } else if exponent != SINGLE_EXPONENT {
            OperandClass::Finite
        } else if bits & SINGLE_FRACTION == 0 {
            OperandClass::Infinity
        } else {
            // BFUnpack has no signaling NaN class, including Single addends.
            OperandClass::NaN
        };
        Self {
            bits: if class == OperandClass::Zero {
                bits & SINGLE_SIGN
            } else {
                bits
            },
            class,
        }
    }

    fn sign(self) -> u32 {
        self.bits & SINGLE_SIGN
    }
}

fn default_nan(fpcr: u32) -> u32 {
    Control(fpcr).default_nan(Format::Single) as u32
}

fn widen_single(bits: u32) -> Double {
    let mut loses_info = false;
    let result: StatusAnd<Double> =
        Single::from_bits(u128::from(bits)).convert_r(Round::TowardZero, &mut loses_info);
    debug_assert_eq!(result.status, Status::OK);
    debug_assert!(!loses_info);
    result.value
}

/// Double products are exact. A Double addition can discard distant Single
/// low bits; preserve that RTZ sticky bit through the second RTZ conversion.
/// Every Single boundary, including min-normal and 2^128, is exact in Double,
/// so the first RTZ cannot cross any boundary before the final odd-bit jam.
fn round_odd(result: StatusAnd<Double>) -> u32 {
    debug_assert!(result.value.is_finite() && !result.value.is_zero());
    let sign = if result.value.is_negative() {
        SINGLE_SIGN
    } else {
        0
    };
    let magnitude = result.value.abs().to_bits();
    // BFRound classifies the exact exponent before rounding. In particular,
    // neither tiny sticky values nor finite values above max-Single jam to
    // a subnormal or infinity merely because APFloat reports target overflow.
    if magnitude < SINGLE_MINIMUM_AS_DOUBLE {
        return sign;
    }
    if magnitude >= SINGLE_OVERFLOW_AS_DOUBLE {
        return sign | SINGLE_EXPONENT;
    }
    let mut loses_info = false;
    let converted: StatusAnd<Single> = result.value.convert_r(Round::TowardZero, &mut loses_info);
    let bits = converted.value.to_bits() as u32;
    if result.status.contains(Status::INEXACT) || converted.status.contains(Status::INEXACT) {
        bits | ODD_SIGNIFICAND_BIT
    } else {
        bits
    }
}

fn multiply(fpcr: u32, left: u16, right: u16) -> u32 {
    let left = Operand::unpack(widen(left));
    let right = Operand::unpack(widen(right));
    if left.class == OperandClass::NaN || right.class == OperandClass::NaN {
        return default_nan(fpcr);
    }
    let sign = left.sign() ^ right.sign();
    if (left.class == OperandClass::Infinity && right.class == OperandClass::Zero)
        || (left.class == OperandClass::Zero && right.class == OperandClass::Infinity)
    {
        return default_nan(fpcr);
    }
    if left.class == OperandClass::Infinity || right.class == OperandClass::Infinity {
        return sign | SINGLE_EXPONENT;
    }
    if left.class == OperandClass::Zero || right.class == OperandClass::Zero {
        return sign;
    }
    // Two eight-bit BF significands need at most sixteen exact product bits;
    // their exponent range is far inside normal Double without host FP use.
    let result = widen_single(left.bits).mul_r(widen_single(right.bits), Round::TowardZero);
    debug_assert_eq!(result.status, Status::OK);
    round_odd(result)
}

fn add(fpcr: u32, left: u32, right: u32) -> u32 {
    let left = Operand::unpack(left);
    let right = Operand::unpack(right);
    if left.class == OperandClass::NaN || right.class == OperandClass::NaN {
        return default_nan(fpcr);
    }
    if left.class == OperandClass::Infinity
        && right.class == OperandClass::Infinity
        && left.sign() != right.sign()
    {
        return default_nan(fpcr);
    }
    if left.class == OperandClass::Infinity {
        return left.bits;
    }
    if right.class == OperandClass::Infinity {
        return right.bits;
    }
    if left.class == OperandClass::Zero
        && right.class == OperandClass::Zero
        && left.sign() == right.sign()
    {
        return left.sign();
    }
    let result = widen_single(left.bits).add_r(widen_single(right.bits), Round::TowardZero);
    if result.value.is_zero() {
        // Opposite zeros and exact finite cancellation produce positive zero.
        0
    } else {
        round_odd(result)
    }
}

/// EBF16 is absent from the declared profile. Each classic stage rounds
/// independently; only AH's default-NaN sign is read from the supplied FPCR.
pub fn dot_add(fpcr: u32, addend: u32, left: [u16; 2], right: [u16; 2]) -> u32 {
    let first = multiply(fpcr, left[0], right[0]);
    let second = multiply(fpcr, left[1], right[1]);
    let pair = add(fpcr, first, second);
    add(fpcr, addend, pair)
}

#[cfg(test)]
mod tests {
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
        ((exponent + Format::Single.exponent_bias() as i32) as u32)
            << Format::Single.fraction_bits()
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
                                let left = ((left_exponent << BFLOAT16_FRACTION_BITS)
                                    | left_fraction)
                                    as u16
                                    | if left_negative { BFLOAT16_SIGN } else { 0 };
                                let right = ((right_exponent << BFLOAT16_FRACTION_BITS)
                                    | right_fraction)
                                    as u16
                                    | if right_negative { BFLOAT16_SIGN } else { 0 };
                                let product =
                                    i128::from((1 << BFLOAT16_FRACTION_BITS) + left_fraction)
                                        * i128::from(
                                            (1 << BFLOAT16_FRACTION_BITS) + right_fraction,
                                        );
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
}
