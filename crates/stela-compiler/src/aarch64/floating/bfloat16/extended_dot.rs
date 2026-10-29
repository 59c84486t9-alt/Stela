//! FEAT_EBF16 BFDOT: one rounded two-product sum, then a separate single add.
//! Default NaNs and no exceptions.
use super::super::{
    BinaryOperation, Class, Control, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, Format,
    Operand, Outcome, unpack,
};
use super::widen;
use rustc_apfloat::{
    Float, FloatConvert, Round, Status, StatusAnd,
    ieee::{Double, Single},
};

const ROUND_ODD_STICKY: u128 = 1;

fn widen_single(bits: u64) -> Double {
    let mut loses_info = false;
    let converted: StatusAnd<Double> = Single::from_bits(u128::from(bits)).convert(&mut loses_info);
    debug_assert_eq!(converted.status, Status::OK);
    debug_assert!(!loses_info);
    converted.value
}

fn finite_product((left, right): (Operand, Operand)) -> Double {
    let product = widen_single(left.bits).mul_r(widen_single(right.bits), Round::TowardZero);
    // BF16 operands have at most eight significant bits. Every finite product
    // is exact in Double and lies between 2^-266 and 2^256 in magnitude.
    debug_assert_eq!(product.status, Status::OK);
    product.value
}

fn round_sum(sum: StatusAnd<Double>, control: Control) -> u64 {
    if sum.value.is_zero() {
        // Same-signed zero products are handled before arithmetic. Cancellation
        // and opposite-signed zeros use the requested rounding mode's zero sign.
        return if control.round() == Round::TowardNegative {
            Format::Single.sign_mask()
        } else {
            0
        };
    }
    // The exact sum can span 523 bits. Truncating to Double and jamming its low
    // significand bit records every discarded bit without pretending that sum
    // was exact. Double's 53 bits exceed Single's 24 by more than two, so every
    // Single value, midpoint and exponent boundary remains distinguishable.
    // Cancellation is exact when the two products overlap closely enough to
    // cancel, and every nonzero sum remains normal Double (at least 2^-266).
    let sticky = u128::from(sum.status.contains(Status::INEXACT)) * ROUND_ODD_STICKY;
    let surrogate = Double::from_bits(sum.value.to_bits() | sticky);
    let mut loses_info = false;
    let converted: StatusAnd<Single> = surrogate.convert_r(control.round(), &mut loses_info);
    if control.flush_output(Format::Single) {
        let minimum = widen_single(Single::smallest_normalized().to_bits() as u64);
        let tiny = if control.alternative() {
            // AH tests the result of unconstrained rounding. Scaling by two
            // makes the threshold normal Single before the same final rounding.
            let scaled: StatusAnd<Single> = surrogate
                .scalbn(1)
                .convert_r(control.round(), &mut loses_info);
            widen_single(scaled.value.abs().to_bits() as u64) < minimum.scalbn(1)
        } else {
            surrogate.abs() < minimum
        };
        if tiny {
            return if surrogate.is_negative() {
                Format::Single.sign_mask()
            } else {
                0
            };
        }
    }
    converted.value.to_bits() as u64
}

fn product_sum(control: Control, left: [u16; 2], right: [u16; 2]) -> u64 {
    let mut discarded_exceptions = 0;
    let operands = [left[0], left[1], right[0], right[1]].map(|bits| {
        unpack(
            Format::Single,
            u64::from(widen(bits)),
            control,
            &mut discarded_exceptions,
        )
    });
    // DN is forced by BFDotAdd. Consequently the four-input signaling-first
    // priority cannot affect output payload, sign or suppressed status.
    if operands.iter().any(|operand| operand.class.nan()) {
        return control.default_nan(Format::Single);
    }
    let pairs = [(operands[0], operands[2]), (operands[1], operands[3])];
    let negative = pairs.map(|(left, right)| left.negative ^ right.negative);
    let infinite =
        pairs.map(|(left, right)| left.class == Class::Infinity || right.class == Class::Infinity);
    let zero = pairs.map(|(left, right)| left.class == Class::Zero || right.class == Class::Zero);
    let invalid_product = pairs.iter().any(|(left, right)| {
        left.class == Class::Infinity && right.class == Class::Zero
            || left.class == Class::Zero && right.class == Class::Infinity
    });
    if invalid_product || infinite[0] && infinite[1] && negative[0] != negative[1] {
        control.default_nan(Format::Single)
    } else if infinite[0] || infinite[1] {
        Format::Single.infinity(if infinite[0] {
            negative[0]
        } else {
            negative[1]
        })
    } else if zero[0] && zero[1] && negative[0] == negative[1] {
        if negative[0] {
            Format::Single.sign_mask()
        } else {
            0
        }
    } else {
        round_sum(
            finite_product(pairs[0]).add_r(finite_product(pairs[1]), Round::TowardZero),
            control,
        )
    }
}

/// The caller selects enhanced behavior from its immutable EBF16 feature and
/// FPCR.EBF. This kernel always evaluates that selected behavior; raw EBF does
/// not override the caller's advertised numerical feature profile.
pub fn evaluate(fpcr: u32, addend: u32, left: [u16; 2], right: [u16; 2]) -> Outcome {
    let control = Control((fpcr | FPCR_DN) & !(FPCR_EXCEPTION_ENABLE_MASK | FPCR_AHP));
    let product = product_sum(control, left, right);
    let mut result = super::super::evaluate(
        Format::Single,
        BinaryOperation::Add,
        control.0,
        u64::from(addend),
        product,
    )
    .expect("enhanced BF16 dot suppresses exception enables");
    result.exceptions = 0;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::floating::{FPCR_AH, FPCR_FIZ, FPCR_FZ, FPCR_ROUNDING_SHIFT};

    const BFLOAT16_ONE: u16 = 0x3f80;
    const BFLOAT16_MINIMUM: u16 = 1;
    const BFLOAT16_MAXIMUM: u16 = 0x7f7f;
    const BFLOAT16_SIGN: u16 = 0x8000;
    const SINGLE_ONE: u32 = 0x3f80_0000;
    const SINGLE_SIGN: u32 = 0x8000_0000;
    const SINGLE_MINIMUM_NORMAL: u32 = 0x0080_0000;

    fn outcome(bits: u32) -> Outcome {
        Outcome {
            bits: u64::from(bits),
            exceptions: 0,
        }
    }

    #[test]
    fn enhanced_dot_fuses_product_sum_before_the_separate_add() {
        // The classic recipe flushes each half-minimum product independently.
        assert_eq!(
            evaluate(0, 0, [0x0080; 2], [0x3f00; 2]),
            outcome(SINGLE_MINIMUM_NORMAL)
        );
        // The two exact overflowing real products cancel before any rounding.
        assert_eq!(
            evaluate(0, 0, [BFLOAT16_MAXIMUM; 2], [0x4000, 0xc000]),
            outcome(0)
        );
        // A midpoint rounds before adding -1: this is not one three-term FMA.
        for (rounding, expected) in [(0, 0), (1, 0x3400_0000), (2, SINGLE_SIGN), (3, 0)] {
            assert_eq!(
                evaluate(
                    rounding << FPCR_ROUNDING_SHIFT,
                    SINGLE_ONE | SINGLE_SIGN,
                    [BFLOAT16_ONE, 0x3380],
                    [BFLOAT16_ONE; 2]
                ),
                outcome(expected)
            );
        }
    }

    #[test]
    fn remote_products_keep_sticky_below_double_precision() {
        for (tiny_sign, expected) in [
            (0, [SINGLE_ONE, SINGLE_ONE + 1, SINGLE_ONE, SINGLE_ONE]),
            (
                BFLOAT16_SIGN,
                [SINGLE_ONE, SINGLE_ONE, SINGLE_ONE - 1, SINGLE_ONE - 1],
            ),
        ] {
            for (rounding, expected) in expected.into_iter().enumerate() {
                assert_eq!(
                    evaluate(
                        (rounding as u32) << FPCR_ROUNDING_SHIFT,
                        0,
                        [BFLOAT16_ONE, BFLOAT16_MINIMUM | tiny_sign],
                        [BFLOAT16_ONE, BFLOAT16_MINIMUM]
                    ),
                    outcome(expected)
                );
            }
        }
    }

    #[test]
    fn alternative_flush_uses_unconstrained_rounding_at_minimum_normal() {
        // 2^-126 - 2^-151 is the unconstrained precision-24 midpoint below
        // minimum normal. AH0 flushes first; AH1 first rounds precision-24.
        let left = [0x2000, 0x9a00];
        let right = [0x2000, 0x1980];
        assert_eq!(evaluate(FPCR_FZ, 0, left, right), outcome(0));
        assert_eq!(
            evaluate(FPCR_AH | FPCR_FZ, 0, left, right),
            outcome(SINGLE_MINIMUM_NORMAL)
        );
        assert_eq!(
            evaluate(FPCR_AH | FPCR_FZ | 2 << FPCR_ROUNDING_SHIFT, 0, left, right),
            outcome(0)
        );
        // FIZ flushes BF16 sources independently, including with AH set.
        assert_eq!(
            evaluate(
                FPCR_AH | FPCR_FIZ,
                0,
                [0x0080, 0x8001],
                [BFLOAT16_ONE, 0x3700]
            ),
            outcome(SINGLE_MINIMUM_NORMAL)
        );
    }

    #[test]
    fn enhanced_mode_forces_default_nans_and_suppresses_kept_enables() {
        for ah in [0, FPCR_AH] {
            let expected_nan = 0x7fc0_0000 | if ah == 0 { 0 } else { SINGLE_SIGN };
            for left in [
                [0x7f81, BFLOAT16_ONE],
                [0x7fc1, BFLOAT16_ONE],
                [0x7f80, BFLOAT16_ONE],
            ] {
                let right = if left[0] == 0x7f80 {
                    [0, BFLOAT16_ONE]
                } else {
                    [BFLOAT16_ONE; 2]
                };
                assert_eq!(
                    evaluate(ah | FPCR_EXCEPTION_ENABLE_MASK, 0, left, right),
                    outcome(expected_nan)
                );
            }
            assert_eq!(
                evaluate(
                    ah | FPCR_EXCEPTION_ENABLE_MASK,
                    0x7f80_0011,
                    [BFLOAT16_ONE; 2],
                    [BFLOAT16_ONE; 2]
                ),
                outcome(expected_nan)
            );
        }
    }
}
