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
