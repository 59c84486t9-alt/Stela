use super::*;
use crate::aarch64::floating::{
    DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_AHP, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FIZ, FPCR_FZ,
    FPCR_FZ16, FPCR_NEP, FPCR_ROUNDING_SHIFT, INEXACT, OVERFLOW, UNDERFLOW,
};

const HALF_ONE: u16 = 0x3c00;
const HALF_INFINITY: u16 = 0x7c00;
const HALF_MINIMUM_SUBNORMAL: u16 = 1;
const SINGLE_ONE: u32 = 0x3f80_0000;
const SINGLE_INFINITY: u32 = 0x7f80_0000;
const SINGLE_SIGN: u32 = 0x8000_0000;
const SINGLE_QUIET: u32 = 0x0040_0000;
const SINGLE_MINIMUM_SUBNORMAL: u32 = 1;
const ROUND_NEAREST: u32 = 0;
const ROUND_POSITIVE: u32 = 1;
const ROUND_NEGATIVE: u32 = 2;
const ROUND_ZERO: u32 = 3;
const ROUNDINGS: [u32; 4] = [ROUND_NEAREST, ROUND_POSITIVE, ROUND_NEGATIVE, ROUND_ZERO];

fn outcome(bits: u32, exceptions: u32) -> Result<Outcome, UnsupportedControl> {
    Ok(Outcome {
        bits: u64::from(bits),
        exceptions,
    })
}

#[test]
fn half_product_cancellation_preserves_exact_single_residual() {
    // (1+2^-10)*(1-2^-10) = 1-2^-20, exactly in Single.
    const LEFT: u16 = 0x3c01;
    const RIGHT: u16 = 0x3bfe;
    const RESIDUAL: u32 = 0x3580_0000;
    for ah in [0, FPCR_AH] {
        for round in ROUNDINGS {
            let fpcr = ah | round << FPCR_ROUNDING_SHIFT;
            assert_eq!(
                evaluate(
                    WideningOperation::Add,
                    fpcr,
                    SINGLE_ONE | SINGLE_SIGN,
                    LEFT,
                    RIGHT
                ),
                outcome(RESIDUAL | SINGLE_SIGN, 0)
            );
            assert_eq!(
                evaluate(WideningOperation::Subtract, fpcr, SINGLE_ONE, LEFT, RIGHT),
                outcome(RESIDUAL, 0)
            );
        }
    }
}

#[test]
fn single_midpoints_use_fpcr_even_under_alternative_mode() {
    for ah in [0, FPCR_AH] {
        for round in ROUNDINGS {
            let fpcr = ah | round << FPCR_ROUNDING_SHIFT;
            assert_eq!(
                evaluate(
                    WideningOperation::Add,
                    fpcr,
                    SINGLE_ONE,
                    HALF_MINIMUM_SUBNORMAL,
                    HALF_ONE
                ),
                outcome(SINGLE_ONE + u32::from(round == ROUND_POSITIVE), INEXACT)
            );
            assert_eq!(
                evaluate(
                    WideningOperation::Subtract,
                    fpcr,
                    SINGLE_ONE | SINGLE_SIGN,
                    HALF_MINIMUM_SUBNORMAL,
                    HALF_ONE
                ),
                outcome(
                    (SINGLE_ONE + u32::from(round == ROUND_NEGATIVE)) | SINGLE_SIGN,
                    INEXACT
                )
            );
        }
    }
}

#[test]
fn half_denormals_observe_only_fz16_and_never_raise_idc() {
    const SINGLE_HALF_MINIMUM: u32 = 0x3380_0000; // 2^-24.
    for ah in [0, FPCR_AH] {
        for controls in [0, FPCR_FIZ, FPCR_FZ, FPCR_FIZ | FPCR_FZ] {
            for fz16 in [0, FPCR_FZ16] {
                assert_eq!(
                    evaluate(
                        WideningOperation::Add,
                        ah | controls | fz16,
                        0,
                        HALF_MINIMUM_SUBNORMAL,
                        HALF_ONE
                    ),
                    outcome(if fz16 == 0 { SINGLE_HALF_MINIMUM } else { 0 }, 0)
                );
            }
        }
    }
}

#[test]
fn accumulator_denormal_flushing_and_late_idc_are_distinct() {
    for sign in [0, SINGLE_SIGN] {
        for (fpcr, magnitude, exceptions) in [
            (0, SINGLE_MINIMUM_SUBNORMAL, 0),
            (FPCR_FIZ, 0, 0),
            (FPCR_FZ, 0, INPUT_DENORMAL),
            (FPCR_FIZ | FPCR_FZ, 0, INPUT_DENORMAL),
            (FPCR_AH, SINGLE_MINIMUM_SUBNORMAL, INPUT_DENORMAL),
            (FPCR_AH | FPCR_FIZ, 0, 0),
            (FPCR_AH | FPCR_FZ, 0, UNDERFLOW | INEXACT | INPUT_DENORMAL),
            (FPCR_AH | FPCR_FIZ | FPCR_FZ, 0, 0),
        ] {
            // Same-sign zero product preserves a flushed accumulator sign.
            let left = if sign == 0 {
                0
            } else {
                Format::Half.sign_mask() as u16
            };
            assert_eq!(
                evaluate(
                    WideningOperation::Add,
                    fpcr,
                    SINGLE_MINIMUM_SUBNORMAL | sign,
                    left,
                    HALF_ONE
                ),
                outcome(magnitude | sign, exceptions)
            );
        }
    }
}

#[test]
fn original_mixed_nan_priority_precedes_payload_widening() {
    const SIGNALING_ADDEND: u32 = 0x7f80_0011;
    const QUIET_ADDEND: u32 = SIGNALING_ADDEND | SINGLE_QUIET;
    const QUIET_LEFT: u16 = 0xfe22;
    const SIGNALING_RIGHT: u16 = 0x7c33;
    const QUIET_RIGHT: u16 = 0x7e33;
    const WIDE_LEFT: u32 = 0xffc4_4000;
    const WIDE_RIGHT: u32 = 0x7fc6_6000;
    for (addend, left, right, ordinary, alternative, exceptions) in [
        (
            SIGNALING_ADDEND,
            QUIET_LEFT,
            HALF_ONE,
            QUIET_ADDEND,
            WIDE_LEFT,
            INVALID,
        ),
        (
            QUIET_ADDEND,
            QUIET_LEFT,
            SIGNALING_RIGHT,
            WIDE_RIGHT,
            WIDE_LEFT,
            INVALID,
        ),
        (
            QUIET_ADDEND,
            HALF_ONE,
            QUIET_RIGHT,
            QUIET_ADDEND,
            WIDE_RIGHT,
            0,
        ),
        (SINGLE_ONE, QUIET_LEFT, QUIET_RIGHT, WIDE_LEFT, WIDE_LEFT, 0),
    ] {
        for (ah, expected) in [(0, ordinary), (FPCR_AH, alternative)] {
            for ignored in [0, FPCR_AHP | FPCR_NEP] {
                assert_eq!(
                    evaluate(WideningOperation::Add, ah | ignored, addend, left, right),
                    outcome(expected, exceptions)
                );
                assert_eq!(
                    evaluate(
                        WideningOperation::Add,
                        ah | ignored | FPCR_DN,
                        addend,
                        left,
                        right
                    ),
                    outcome(
                        SINGLE_INFINITY | SINGLE_QUIET | if ah == 0 { 0 } else { SINGLE_SIGN },
                        exceptions
                    )
                );
            }
        }
    }
}

#[test]
fn half_nan_payload_extremes_and_subtract_sign_are_preserved() {
    for (source, expected) in [(0x7dff, 0x7fff_e000), (0xfe01, 0xffc0_2000)] {
        assert_eq!(
            evaluate(WideningOperation::Add, 0, SINGLE_ONE, HALF_ONE, source),
            outcome(expected, if source == 0x7dff { INVALID } else { 0 })
        );
    }
    for (fpcr, expected) in [(0, 0x7fc4_4000), (FPCR_AH, 0xffc4_4000)] {
        assert_eq!(
            evaluate(
                WideningOperation::Subtract,
                fpcr,
                SINGLE_ONE,
                0xfe22,
                HALF_ONE
            ),
            outcome(expected, 0)
        );
    }
}

#[test]
fn invalid_product_override_differs_from_nan_and_infinity_selection() {
    const QUIET_ADDEND: u32 = 0x7fc0_0011;
    for ignored in [0, FPCR_AHP] {
        assert_eq!(
            evaluate(
                WideningOperation::Add,
                ignored,
                QUIET_ADDEND,
                0,
                HALF_INFINITY
            ),
            outcome(SINGLE_INFINITY | SINGLE_QUIET, INVALID)
        );
        assert_eq!(
            evaluate(
                WideningOperation::Add,
                ignored | FPCR_AH,
                QUIET_ADDEND,
                0,
                HALF_INFINITY
            ),
            outcome(QUIET_ADDEND, 0)
        );
        for ah in [0, FPCR_AH] {
            let default_nan =
                SINGLE_INFINITY | SINGLE_QUIET | if ah == 0 { 0 } else { SINGLE_SIGN };
            assert_eq!(
                evaluate(
                    WideningOperation::Subtract,
                    ignored | ah,
                    SINGLE_INFINITY,
                    HALF_INFINITY,
                    HALF_ONE
                ),
                outcome(default_nan, INVALID)
            );
            assert_eq!(
                evaluate(
                    WideningOperation::Add,
                    ignored | ah,
                    SINGLE_INFINITY,
                    HALF_INFINITY,
                    HALF_ONE
                ),
                outcome(SINGLE_INFINITY, 0)
            );
        }
    }
}

#[test]
fn only_non_nan_non_invalid_completion_adds_alternative_accumulator_idc() {
    const HALF_QUIET_NAN: u16 = 0x7e01;
    const WIDE_QUIET_NAN: u32 = 0x7fc0_2000;
    for (left, right, expected, fresh) in [
        (HALF_INFINITY, HALF_ONE, SINGLE_INFINITY, 0),
        (
            HALF_INFINITY,
            0,
            SINGLE_INFINITY | SINGLE_QUIET | SINGLE_SIGN,
            INVALID,
        ),
        (HALF_QUIET_NAN, HALF_ONE, WIDE_QUIET_NAN, 0),
    ] {
        let valid = left == HALF_INFINITY && right == HALF_ONE;
        assert_eq!(
            evaluate(
                WideningOperation::Add,
                FPCR_AH,
                SINGLE_MINIMUM_SUBNORMAL,
                left,
                right
            ),
            outcome(expected, fresh | if valid { INPUT_DENORMAL } else { 0 })
        );
    }
    assert_eq!(
        evaluate(
            WideningOperation::Add,
            FPCR_FZ,
            SINGLE_MINIMUM_SUBNORMAL,
            HALF_INFINITY,
            0
        ),
        outcome(SINGLE_INFINITY | SINGLE_QUIET, INVALID | INPUT_DENORMAL)
    );
}

#[test]
fn signed_zero_products_and_exact_cancellation_follow_rounding_mode() {
    for operation in [WideningOperation::Add, WideningOperation::Subtract] {
        for a in [false, true] {
            for n in [false, true] {
                for m in [false, true] {
                    for round in ROUNDINGS {
                        let product_negative = n ^ m ^ (operation == WideningOperation::Subtract);
                        let negative = if a == product_negative {
                            a
                        } else {
                            round == ROUND_NEGATIVE
                        };
                        assert_eq!(
                            evaluate(
                                operation,
                                round << FPCR_ROUNDING_SHIFT,
                                if a { SINGLE_SIGN } else { 0 },
                                if n {
                                    Format::Half.sign_mask() as u16
                                } else {
                                    0
                                },
                                if m {
                                    HALF_ONE | Format::Half.sign_mask() as u16
                                } else {
                                    HALF_ONE
                                }
                            ),
                            outcome(if negative { SINGLE_SIGN } else { 0 }, 0)
                        );
                    }
                }
            }
        }
    }
    for round in ROUNDINGS {
        assert_eq!(
            evaluate(
                WideningOperation::Subtract,
                round << FPCR_ROUNDING_SHIFT,
                SINGLE_ONE,
                HALF_ONE,
                HALF_ONE
            ),
            outcome(
                if round == ROUND_NEGATIVE {
                    SINGLE_SIGN
                } else {
                    0
                },
                0
            )
        );
    }
}

#[test]
fn tiny_half_product_can_still_cause_directed_single_overflow() {
    const MAXIMUM_SINGLE: u32 = 0x7f7f_ffff;
    for ah in [0, FPCR_AH] {
        for (sign, overflow_round) in [(0, ROUND_POSITIVE), (SINGLE_SIGN, ROUND_NEGATIVE)] {
            for round in ROUNDINGS {
                let overflow = round == overflow_round;
                assert_eq!(
                    evaluate(
                        if sign == 0 {
                            WideningOperation::Add
                        } else {
                            WideningOperation::Subtract
                        },
                        ah | round << FPCR_ROUNDING_SHIFT,
                        MAXIMUM_SINGLE | sign,
                        HALF_ONE,
                        HALF_ONE
                    ),
                    outcome(
                        (if overflow {
                            SINGLE_INFINITY
                        } else {
                            MAXIMUM_SINGLE
                        }) | sign,
                        INEXACT | if overflow { OVERFLOW } else { 0 }
                    )
                );
            }
        }
    }
}

#[test]
fn every_retained_enable_refuses_before_all_arithmetic_under_both_ah_modes() {
    for ah in [0, FPCR_AH] {
        for enabled in [
            INVALID,
            DIVIDE_BY_ZERO,
            OVERFLOW,
            UNDERFLOW,
            INEXACT,
            INPUT_DENORMAL,
            EXCEPTIONS,
        ] {
            for operation in [WideningOperation::Add, WideningOperation::Subtract] {
                assert_eq!(
                    evaluate(
                        operation,
                        ah | enabled << FPCR_EXCEPTION_ENABLE_SHIFT,
                        SINGLE_ONE,
                        HALF_ONE,
                        HALF_ONE
                    ),
                    Err(UnsupportedControl {
                        enabled_exceptions: enabled
                    })
                );
            }
        }
    }
}
