use super::*;
use floating::{
    EXCEPTIONS, FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FIZ, FPCR_FZ,
    FPCR_ROUNDING_SHIFT, INEXACT, INVALID, OVERFLOW, UNDERFLOW,
};

const ONE: u16 = 0x3f80;
const NEGATIVE_ONE: u16 = 0xbf80;
const TWO: u16 = 0x4000;
const POSITIVE_ZERO: u16 = 0;
const NEGATIVE_ZERO: u16 = 0x8000;
const INFINITY: u16 = 0x7f80;
const MAXIMUM: u16 = 0x7f7f;
const MINIMUM: u16 = 0x0080;
const HALF: u16 = 0x3f00;
const QUIET_NAN: u16 = 0x7fc1;
const SIGNALING_NAN: u16 = 0x7f81;

fn outcome(bits: u16, exceptions: u32) -> Result<Outcome, UnsupportedControl> {
    Ok(Outcome {
        bits: u64::from(bits),
        exceptions,
    })
}

#[test]
fn binary_rounds_directly_at_bfloat_precision_in_all_modes() {
    for (rounding, product) in [0x3f80, 0x3f80, 0x3f7f, 0x3f7f].into_iter().enumerate() {
        let fpcr = (rounding as u32) << FPCR_ROUNDING_SHIFT;
        assert_eq!(
            binary(BfloatBinaryOperation::Add, fpcr, ONE, ONE),
            outcome(TWO, 0)
        );
        assert_eq!(
            binary(BfloatBinaryOperation::Subtract, fpcr, ONE, ONE),
            outcome(
                if rounding == 2 {
                    NEGATIVE_ZERO
                } else {
                    POSITIVE_ZERO
                },
                0
            )
        );
        assert_eq!(
            binary(BfloatBinaryOperation::Multiply, fpcr, 0x3f81, 0x3f7e),
            outcome(product, INEXACT)
        );
    }
}

#[test]
fn fused_target_precision_avoids_single_double_rounding() {
    assert_eq!(fused(0, 0xb080, 0x3fc0, 0x3f81), outcome(0x3fc1, INEXACT));
    assert_eq!(fused(0, NEGATIVE_ONE, 0x3f81, 0x3f7e), outcome(0xb880, 0));
}

#[test]
fn alternative_tininess_uses_unconstrained_bfloat_rounding() {
    const NEGATIVE_MINIMUM_SUBNORMAL: u16 = 0x8001;
    const QUARTER: u16 = 0x3e80;
    assert_eq!(
        fused(0, MINIMUM, NEGATIVE_MINIMUM_SUBNORMAL, QUARTER),
        outcome(MINIMUM, UNDERFLOW | INEXACT)
    );
    assert_eq!(
        fused(
            FPCR_AH | FPCR_FZ,
            MINIMUM,
            NEGATIVE_MINIMUM_SUBNORMAL,
            QUARTER
        ),
        outcome(MINIMUM, INPUT_DENORMAL | INEXACT)
    );
    assert_eq!(
        fused(FPCR_AH | FPCR_FZ, 0, MINIMUM, ONE - 1),
        outcome(0, UNDERFLOW | INEXACT)
    );
}

#[test]
fn input_flush_and_alternative_late_denormal_status_are_distinct() {
    for (fpcr, bits, exceptions) in [
        (0, 1, 0),
        (FPCR_FIZ, 0, 0),
        (FPCR_FZ, 0, INPUT_DENORMAL),
        (FPCR_AH, 1, INPUT_DENORMAL),
        (FPCR_AH | FPCR_FIZ, 0, 0),
    ] {
        assert_eq!(
            binary(BfloatBinaryOperation::Multiply, fpcr, 1, ONE),
            outcome(bits, exceptions)
        );
    }
    assert_eq!(
        binary(BfloatBinaryOperation::Multiply, FPCR_FZ, MINIMUM, HALF),
        outcome(0, UNDERFLOW)
    );
    assert_eq!(
        binary(
            BfloatBinaryOperation::Multiply,
            FPCR_AH | FPCR_FZ,
            MINIMUM,
            HALF
        ),
        outcome(0, UNDERFLOW | INEXACT)
    );
}

#[test]
fn directed_overflow_and_nan_priority_use_arm_policy() {
    assert_eq!(
        binary(BfloatBinaryOperation::Multiply, 0, MAXIMUM, TWO),
        outcome(INFINITY, OVERFLOW | INEXACT)
    );
    assert_eq!(
        binary(
            BfloatBinaryOperation::Multiply,
            3 << FPCR_ROUNDING_SHIFT,
            MAXIMUM,
            TWO
        ),
        outcome(MAXIMUM, OVERFLOW | INEXACT)
    );
    assert_eq!(fused(0, QUIET_NAN, 0, INFINITY), outcome(0x7fc0, INVALID));
    assert_eq!(
        fused(FPCR_AH, QUIET_NAN, 0, INFINITY),
        outcome(QUIET_NAN, 0)
    );
    assert_eq!(
        fused(FPCR_AH | FPCR_DN, QUIET_NAN, 0, INFINITY),
        outcome(0xffc0, 0)
    );
}

#[test]
fn minmax_alternative_number_policy_and_clamp_preserve_status() {
    assert_eq!(
        minmax(MinMaxOperation::Maximum, FPCR_AH, QUIET_NAN, ONE),
        outcome(ONE, INVALID)
    );
    assert_eq!(
        minmax(MinMaxOperation::Minimum, FPCR_AH, ONE, SIGNALING_NAN),
        outcome(SIGNALING_NAN, INVALID)
    );
    assert_eq!(
        minmax(MinMaxOperation::MaximumNumber, FPCR_AH, QUIET_NAN, ONE),
        outcome(ONE, 0)
    );
    assert_eq!(
        minmax(
            MinMaxOperation::MinimumNumber,
            FPCR_AH,
            QUIET_NAN,
            SIGNALING_NAN
        ),
        outcome(QUIET_NAN, INVALID)
    );
    assert_eq!(clamp(0, POSITIVE_ZERO, ONE, TWO), outcome(ONE, 0));
    assert_eq!(clamp(0, SIGNALING_NAN, ONE, TWO), outcome(TWO, INVALID));
}

#[test]
fn negate_honors_alternative_nan_sign_without_quieting() {
    assert_eq!(negate(0, SIGNALING_NAN), SIGNALING_NAN | NEGATIVE_ZERO);
    assert_eq!(negate(FPCR_AH, SIGNALING_NAN), SIGNALING_NAN);
    assert_eq!(negate(FPCR_AH, INFINITY), INFINITY | NEGATIVE_ZERO);
    assert_eq!(negate(FPCR_AH, 1), 1 | NEGATIVE_ZERO);
}

#[test]
fn retained_enables_require_caller_execution_profile_handling() {
    let fpcr = EXCEPTIONS << FPCR_EXCEPTION_ENABLE_SHIFT;
    let expected = Err(UnsupportedControl {
        enabled_exceptions: EXCEPTIONS,
    });
    assert_eq!(binary(BfloatBinaryOperation::Add, fpcr, ONE, ONE), expected);
    assert_eq!(fused(fpcr, ONE, ONE, ONE), expected);
    assert_eq!(minmax(MinMaxOperation::Minimum, fpcr, ONE, ONE), expected);
    assert_eq!(clamp(fpcr, ONE, ONE, ONE), expected);
}
