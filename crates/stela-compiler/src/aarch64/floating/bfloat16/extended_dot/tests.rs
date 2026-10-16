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
fn enhanced_mode_forces_default_nans_and_suppresses_retained_enables() {
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
