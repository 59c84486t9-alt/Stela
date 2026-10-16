use super::AbsoluteMinMaxOperation::{Maximum, Minimum};
use super::*;
use crate::aarch64::floating::{
    EXCEPTIONS, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_NEP, FPCR_ROUNDING_SHIFT,
    INVALID,
};

const FORMATS: [Format; 3] = [Format::Half, Format::Single, Format::Double];
const IGNORED_CONTROLS: u32 = FPCR_AH | FPCR_FIZ | FPCR_FZ | FPCR_FZ16;

fn result(bits: u64, exceptions: u32) -> Result<Outcome, UnsupportedControl> {
    Ok(Outcome { bits, exceptions })
}

#[test]
fn numeric_results_are_positive_and_flush_controls_are_ignored() {
    for format in FORMATS {
        let sign = format.sign_mask();
        let one = u64::from(format.exponent_bias()) << format.fraction_bits();
        let infinity = format.infinity(false);
        let values = [0, 1, format.fraction_mask(), one, infinity];
        for left in values {
            for right in values {
                for left_sign in [0, sign] {
                    for right_sign in [0, sign] {
                        for controls in [0, IGNORED_CONTROLS] {
                            for (operation, expected) in
                                [(Minimum, left.min(right)), (Maximum, left.max(right))]
                            {
                                assert_eq!(
                                    evaluate(
                                        format,
                                        operation,
                                        controls,
                                        left | left_sign,
                                        right | right_sign,
                                    ),
                                    result(expected, 0),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn nan_priority_preserves_original_sign_with_ah_disabled() {
    for format in FORMATS {
        let negative_quiet = format.infinity(true) | format.quiet_bit() | 1;
        let positive_quiet = format.infinity(false) | format.quiet_bit() | 2;
        let negative_signaling = format.infinity(true) | 3;
        let positive_signaling = format.infinity(false) | 4;
        let one = u64::from(format.exponent_bias()) << format.fraction_bits();
        for operation in [Minimum, Maximum] {
            for controls in [0, IGNORED_CONTROLS] {
                for (left, right, expected, exceptions) in [
                    (negative_quiet, one, negative_quiet, 0),
                    (one, negative_quiet, negative_quiet, 0),
                    (negative_quiet, positive_quiet, negative_quiet, 0),
                    (
                        negative_quiet,
                        positive_signaling,
                        positive_signaling | format.quiet_bit(),
                        INVALID,
                    ),
                    (
                        negative_signaling,
                        positive_signaling,
                        negative_signaling | format.quiet_bit(),
                        INVALID,
                    ),
                    (
                        negative_signaling,
                        1,
                        negative_signaling | format.quiet_bit(),
                        INVALID,
                    ),
                ] {
                    assert_eq!(
                        evaluate(format, operation, controls, left, right),
                        result(expected, exceptions),
                    );
                    assert_eq!(
                        evaluate(format, operation, controls | FPCR_DN, left, right),
                        result(format.infinity(false) | format.quiet_bit(), exceptions),
                    );
                }
            }
        }
    }
}

#[test]
fn all_subnormal_significands_and_rounding_controls_preserve_exact_selection() {
    // Exhaust all half subnormal significands; corresponding H/S/D lanes
    // exercise every integer-comparison tie and adjacent magnitude boundary.
    for format in FORMATS {
        for fraction in 1..=Format::Half.fraction_mask() {
            for rounding in 0..4 {
                let controls =
                    IGNORED_CONTROLS | FPCR_AHP | FPCR_NEP | (rounding << FPCR_ROUNDING_SHIFT);
                assert_eq!(
                    evaluate(
                        format,
                        Minimum,
                        controls,
                        fraction | format.sign_mask(),
                        fraction + 1,
                    ),
                    result(fraction, 0),
                );
                assert_eq!(
                    evaluate(
                        format,
                        Maximum,
                        controls,
                        fraction,
                        (fraction + 1) | format.sign_mask(),
                    ),
                    result(fraction + 1, 0),
                );
            }
        }
    }
}

#[test]
fn narrow_lanes_discard_poisoned_upper_bits() {
    for format in [Format::Half, Format::Single] {
        let poison = u64::MAX << format.bits();
        let signaling = format.infinity(true) | 1;
        for operation in [Minimum, Maximum] {
            assert_eq!(
                evaluate(format, operation, IGNORED_CONTROLS, poison | 1, poison | 1),
                result(1, 0),
            );
            assert_eq!(
                evaluate(format, operation, IGNORED_CONTROLS, signaling | poison, 0),
                result(signaling | format.quiet_bit(), INVALID),
            );
        }
    }
}

#[test]
fn enabled_exceptions_decline_before_numeric_or_nan_selection() {
    for enabled_exceptions in [INVALID, EXCEPTIONS] {
        for operation in [Minimum, Maximum] {
            for (left, right) in [(0, 0), (0x7f80_0001, 1)] {
                assert_eq!(
                    evaluate(
                        Format::Single,
                        operation,
                        IGNORED_CONTROLS | (enabled_exceptions << FPCR_EXCEPTION_ENABLE_SHIFT),
                        left,
                        right,
                    ),
                    Err(UnsupportedControl { enabled_exceptions }),
                );
            }
        }
    }
}
