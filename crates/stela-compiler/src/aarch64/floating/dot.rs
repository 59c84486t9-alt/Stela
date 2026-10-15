//! Half two-product dot with one Single rounding, followed by a separate add.
//! This is FPDotAdd, not a three-term fused operation. Callers supply effective
//! FPCR controls, preserve raw storage and own lane selection/sticky FPSR.
use super::{
    BinaryOperation, Class, Control, FPCR_AHP, FPCR_DN, Format, INVALID, Operand, Outcome,
    UnsupportedControl, rounded_outcome, unpack,
};
use rustc_apfloat::{
    Float, FloatConvert, Status, StatusAnd,
    ieee::{Half, Quad, Single},
};

const HALF_TO_SINGLE_FRACTION_SHIFT: u32 =
    Format::Single.fraction_bits() - Format::Half.fraction_bits();
const HALF_TO_SINGLE_SIGN_SHIFT: u32 = Format::Single.bits() - Format::Half.bits();

fn nan(operands: &[Operand; 4], control: Control) -> Option<Outcome> {
    // FPProcessNaNs4 has signaling-first source order even under AFP.AH.
    let selected = operands
        .iter()
        .find(|operand| operand.class == Class::SignalingNaN)
        .or_else(|| {
            operands
                .iter()
                .find(|operand| operand.class == Class::QuietNaN)
        })?;
    let exceptions = if selected.class == Class::SignalingNaN {
        INVALID
    } else {
        0
    };
    let bits = if control.0 & FPCR_DN != 0 {
        control.default_nan(Format::Single)
    } else {
        let sign = (selected.bits & Format::Half.sign_mask()) << HALF_TO_SINGLE_SIGN_SHIFT;
        let payload =
            (selected.bits & Format::Half.fraction_mask()) << HALF_TO_SINGLE_FRACTION_SHIFT;
        sign | Format::Single.exponent_mask() | Format::Single.quiet_bit() | payload
    };
    Some(Outcome { bits, exceptions })
}

fn widen_half(bits: u64) -> Quad {
    let mut loses_info = false;
    let result: StatusAnd<Quad> = Half::from_bits(u128::from(bits)).convert(&mut loses_info);
    debug_assert!(!loses_info && result.status == Status::OK);
    result.value
}

fn product_sum(fpcr: u32, left: [u16; 2], right: [u16; 2]) -> Result<Outcome, UnsupportedControl> {
    // FPDot ignores AHP for its Half inputs, independently of the final FPAdd.
    let control = Control::checked(fpcr & !FPCR_AHP)?;
    let mut exceptions = 0;
    let operands = [left[0], left[1], right[0], right[1]]
        .map(|bits| unpack(Format::Half, u64::from(bits), control, &mut exceptions));
    if let Some(mut result) = nan(&operands, control) {
        result.exceptions |= exceptions;
        return Ok(result);
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
    let invalid_sum = infinite[0] && infinite[1] && negative[0] != negative[1];
    let mut result = if invalid_product || invalid_sum {
        Outcome {
            bits: control.default_nan(Format::Single),
            exceptions: INVALID,
        }
    } else if infinite[0] || infinite[1] {
        Outcome {
            bits: Format::Single.infinity(if infinite[0] {
                negative[0]
            } else {
                negative[1]
            }),
            exceptions: 0,
        }
    } else if zero[0] && zero[1] && negative[0] == negative[1] {
        Outcome {
            bits: if negative[0] {
                Format::Single.sign_mask()
            } else {
                0
            },
            exceptions: 0,
        }
    } else {
        // Finite Half products are integer multiples of 2^-48 below 2^32.
        // Their exact two-term sum requires at most 81 significant bits, so
        // binary128's 113-bit precision contains both products and their sum.
        // A nonzero sum is normal Single and cannot overflow Single. Only the
        // final conversion rounds, with guest RC (including exact-zero sign).
        let product = |(left, right): (Operand, Operand)| {
            let result = widen_half(left.bits).mul_r(widen_half(right.bits), control.round());
            debug_assert_eq!(result.status, Status::OK);
            result.value
        };
        let sum = product(pairs[0]).add_r(product(pairs[1]), control.round());
        debug_assert_eq!(sum.status, Status::OK);
        let mut loses_info = false;
        let single: StatusAnd<Single> = sum.value.convert_r(control.round(), &mut loses_info);
        rounded_outcome(Format::Single, control, single, false, false)
    };
    result.exceptions |= exceptions;
    Ok(result)
}

/// Evaluate one FDOT accumulator lane, preserving both architectural roundings.
pub fn evaluate(
    fpcr: u32,
    addend: u32,
    left: [u16; 2],
    right: [u16; 2],
) -> Result<Outcome, UnsupportedControl> {
    let product = product_sum(fpcr, left, right)?;
    let mut result = super::evaluate(
        Format::Single,
        BinaryOperation::Add,
        fpcr,
        u64::from(addend),
        product.bits,
    )?;
    result.exceptions |= product.exceptions;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::floating::{
        FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FZ16, FPCR_ROUNDING_SHIFT, INEXACT,
    };

    const HALF_ONE: u16 = 0x3c00;
    const HALF_NEGATIVE_ZERO: u16 = 0x8000;
    const HALF_INFINITY: u16 = 0x7c00;
    const HALF_MINIMUM_SUBNORMAL: u16 = 1;
    const SINGLE_ONE: u32 = 0x3f80_0000;
    const SINGLE_SIGN: u32 = 0x8000_0000;

    #[test]
    fn first_rounding_is_observable_before_accumulator_add() {
        for ah in [0, FPCR_AH] {
            for (round, expected) in [(0, 0), (1, 0x3400_0000), (2, SINGLE_SIGN), (3, 0)] {
                assert_eq!(
                    evaluate(
                        ah | round << FPCR_ROUNDING_SHIFT,
                        SINGLE_ONE | SINGLE_SIGN,
                        [HALF_ONE, HALF_MINIMUM_SUBNORMAL],
                        [HALF_ONE, HALF_ONE]
                    ),
                    Ok(Outcome {
                        bits: u64::from(expected),
                        exceptions: INEXACT
                    })
                );
            }
        }
    }

    #[test]
    fn half_subnormal_product_stays_normal_single_and_ah_does_not_flush_half() {
        for ah in [0, FPCR_AH] {
            assert_eq!(
                evaluate(
                    ah,
                    0,
                    [HALF_MINIMUM_SUBNORMAL, 0],
                    [HALF_MINIMUM_SUBNORMAL, 0]
                ),
                Ok(Outcome {
                    bits: 0x2780_0000,
                    exceptions: 0
                })
            );
            assert_eq!(
                evaluate(
                    ah | FPCR_FZ16,
                    0,
                    [HALF_MINIMUM_SUBNORMAL, 0],
                    [HALF_MINIMUM_SUBNORMAL, 0]
                ),
                Ok(Outcome {
                    bits: 0,
                    exceptions: 0
                })
            );
        }
    }

    #[test]
    fn nan_priority_is_signaling_first_even_under_alternative_mode() {
        for ah in [0, FPCR_AH] {
            assert_eq!(
                evaluate(ah, 0, [0x7e11, 0x7c22], [HALF_ONE, HALF_ONE]),
                Ok(Outcome {
                    bits: 0x7fc4_4000,
                    exceptions: INVALID
                })
            );
            let default = if ah == 0 { 0x7fc0_0000 } else { 0xffc0_0000 };
            assert_eq!(
                evaluate(ah | FPCR_DN, 0, [0x7e11, 0x7c22], [HALF_ONE, HALF_ONE]),
                Ok(Outcome {
                    bits: default,
                    exceptions: INVALID
                })
            );
        }
    }

    #[test]
    fn invalid_products_and_opposite_infinities_are_explicit() {
        for (left, right) in [
            ([HALF_INFINITY, HALF_ONE], [0, HALF_ONE]),
            (
                [HALF_INFINITY, HALF_INFINITY],
                [HALF_ONE, HALF_ONE | 0x8000],
            ),
        ] {
            assert_eq!(
                evaluate(0, 0, left, right),
                Ok(Outcome {
                    bits: 0x7fc0_0000,
                    exceptions: INVALID
                })
            );
        }
        assert!(evaluate(FPCR_EXCEPTION_ENABLE_MASK, 0, [0, 0], [0, 0]).is_err());
    }

    #[test]
    fn same_signed_zero_products_and_ignored_ahp_are_preserved() {
        assert_eq!(
            evaluate(
                0,
                SINGLE_SIGN,
                [HALF_NEGATIVE_ZERO, HALF_NEGATIVE_ZERO],
                [HALF_ONE, HALF_ONE]
            ),
            Ok(Outcome {
                bits: u64::from(SINGLE_SIGN),
                exceptions: 0
            })
        );
        assert_eq!(
            evaluate(FPCR_AHP, 0, [HALF_INFINITY, 0], [HALF_ONE, 0]),
            Ok(Outcome {
                bits: 0x7f80_0000,
                exceptions: 0
            })
        );
    }
}
