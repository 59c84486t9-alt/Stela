//! Exact same-format min/max outcomes; callers own shape, merging and reduction order.
use super::{
    Class, Control, Format, INEXACT, INVALID, Outcome, UNDERFLOW, UnsupportedControl,
    compare_operands, nan, process_denormals, unpack,
};
use core::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinMaxOperation {
    Minimum,
    Maximum,
    MinimumNumber,
    MaximumNumber,
}

impl MinMaxOperation {
    const fn minimum(self) -> bool {
        matches!(self, Self::Minimum | Self::MinimumNumber)
    }

    const fn number(self) -> bool {
        matches!(self, Self::MinimumNumber | Self::MaximumNumber)
    }
}

/// Evaluate one lane with fresh exception bits and no host floating-point effects.
/// Number variants restrict alternative min/max behavior while retaining AH's
/// ordinary NaN priority, output flushing and post-operation denormal checks.
pub fn evaluate(
    format: Format,
    operation: MinMaxOperation,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let mut exceptions = 0;
    let mut left = unpack(format, left, control, &mut exceptions);
    let mut right = unpack(format, right, control, &mut exceptions);
    let alternative_minmax = control.alternative() && !operation.number();

    if alternative_minmax {
        if left.class == Class::Zero
            && right.class == Class::Zero
            && left.negative != right.negative
        {
            return Ok(Outcome {
                bits: right.bits,
                exceptions,
            });
        }
        if left.class.nan() || right.class.nan() {
            // AH selects the raw second operand, including signaling NaNs.
            // Unpack has already converted a flushed second input to signed zero.
            return Ok(Outcome {
                bits: right.bits,
                exceptions: exceptions | INVALID,
            });
        }
    }

    if operation.number() && !(control.alternative() && left.class.nan() && right.class.nan()) {
        // Replace a lone quiet NaN before the ordinary NaN-priority rules.
        // Under AH=0 this also replaces a quiet NaN paired with signaling NaN.
        let replacement = format.infinity(!operation.minimum());
        if left.class == Class::QuietNaN && right.class != Class::QuietNaN {
            left = unpack(format, replacement, control, &mut exceptions);
        } else if left.class != Class::QuietNaN && right.class == Class::QuietNaN {
            right = unpack(format, replacement, control, &mut exceptions);
        }
    }
    if let Some(bits) = nan(format, left, right, control, &mut exceptions) {
        return Ok(Outcome { bits, exceptions });
    }

    let preferred = if operation.minimum() {
        Ordering::Less
    } else {
        Ordering::Greater
    };
    let selected = if compare_operands(left, right) == preferred {
        left
    } else {
        right
    };
    let bits = if selected.class == Class::Zero {
        // Standard min/max zero signs also apply to number variants under AH.
        let sign = if operation.minimum() {
            left.bits | right.bits
        } else {
            left.bits & right.bits
        };
        sign & format.sign_mask()
    } else if selected.class == Class::Denormal
        && control.alternative()
        && operation.number()
        && control.flush_output(format)
    {
        // Plain AH min/max clears output FZ/FZ16; number variants do not.
        // The selected exact denormal is flushed after unconstrained rounding.
        exceptions |= UNDERFLOW | INEXACT;
        selected.bits & format.sign_mask()
    } else {
        // Selected finite values and infinities are already exact in this format.
        selected.bits
    };
    process_denormals(format, control, left, right, &mut exceptions);
    Ok(Outcome { bits, exceptions })
}

#[cfg(test)]
mod tests {
    use super::MinMaxOperation::{Maximum, MaximumNumber, Minimum, MinimumNumber};
    use super::*;
    use crate::aarch64::floating::{
        DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT,
        FPCR_FIZ, FPCR_FZ, FPCR_FZ16, FPCR_ROUNDING_SHIFT, INPUT_DENORMAL, OVERFLOW,
    };

    const SINGLE_QNAN_LEFT: u64 = 0x7fc00111;
    const SINGLE_QNAN_RIGHT: u64 = 0xffc00222;
    const SINGLE_SNAN_LEFT: u64 = 0x7f800333;
    const SINGLE_SNAN_RIGHT: u64 = 0xff800444;
    const SINGLE_ONE: u64 = 0x3f800000;
    const SINGLE_TWO: u64 = 0x40000000;
    const SINGLE_THREE: u64 = 0x40400000;
    const SINGLE_NEGATIVE_ZERO: u64 = 0x80000000;
    const SINGLE_QUIET_BIT: u64 = 0x00400000;

    #[test]
    fn primary_source_directed_single_corners() {
        for (operation, fpcr, left, right, bits, exceptions) in [
            (
                Minimum,
                0,
                SINGLE_QNAN_LEFT,
                SINGLE_ONE,
                SINGLE_QNAN_LEFT,
                0,
            ),
            (
                Maximum,
                0,
                SINGLE_QNAN_LEFT,
                SINGLE_SNAN_RIGHT,
                SINGLE_SNAN_RIGHT | SINGLE_QUIET_BIT,
                INVALID,
            ),
            (
                Minimum,
                0,
                SINGLE_SNAN_LEFT,
                SINGLE_SNAN_RIGHT,
                SINGLE_SNAN_LEFT | SINGLE_QUIET_BIT,
                INVALID,
            ),
            (
                Minimum,
                FPCR_AH,
                SINGLE_QNAN_LEFT,
                SINGLE_ONE,
                SINGLE_ONE,
                INVALID,
            ),
            (
                Maximum,
                FPCR_AH | FPCR_DN,
                SINGLE_ONE,
                SINGLE_SNAN_RIGHT,
                SINGLE_SNAN_RIGHT,
                INVALID,
            ),
            (
                Minimum,
                FPCR_AH,
                SINGLE_SNAN_LEFT,
                SINGLE_QNAN_RIGHT,
                SINGLE_QNAN_RIGHT,
                INVALID,
            ),
            (Minimum, FPCR_AH, SINGLE_QNAN_LEFT, 1, 1, INVALID),
            (Minimum, FPCR_AH | FPCR_FIZ, SINGLE_QNAN_LEFT, 1, 0, INVALID),
            (
                Maximum,
                FPCR_AH | FPCR_FIZ,
                SINGLE_QNAN_LEFT,
                0x80000001,
                SINGLE_NEGATIVE_ZERO,
                INVALID,
            ),
            (
                Minimum,
                FPCR_AH,
                0,
                SINGLE_NEGATIVE_ZERO,
                SINGLE_NEGATIVE_ZERO,
                0,
            ),
            (Minimum, FPCR_AH, SINGLE_NEGATIVE_ZERO, 0, 0, 0),
            (
                Maximum,
                FPCR_AH,
                0,
                SINGLE_NEGATIVE_ZERO,
                SINGLE_NEGATIVE_ZERO,
                0,
            ),
            (Maximum, FPCR_AH, SINGLE_NEGATIVE_ZERO, 0, 0, 0),
            (Minimum, 0, 0, SINGLE_NEGATIVE_ZERO, SINGLE_NEGATIVE_ZERO, 0),
            (Maximum, 0, SINGLE_NEGATIVE_ZERO, 0, 0, 0),
            (
                MinimumNumber,
                FPCR_AH,
                0,
                SINGLE_NEGATIVE_ZERO,
                SINGLE_NEGATIVE_ZERO,
                0,
            ),
            (MaximumNumber, FPCR_AH, 0, SINGLE_NEGATIVE_ZERO, 0, 0),
            (
                MinimumNumber,
                FPCR_AH,
                SINGLE_QNAN_LEFT,
                SINGLE_ONE,
                SINGLE_ONE,
                0,
            ),
            (
                MaximumNumber,
                FPCR_AH,
                SINGLE_ONE,
                SINGLE_QNAN_RIGHT,
                SINGLE_ONE,
                0,
            ),
            (
                MinimumNumber,
                0,
                SINGLE_QNAN_LEFT,
                SINGLE_SNAN_RIGHT,
                SINGLE_SNAN_RIGHT | SINGLE_QUIET_BIT,
                INVALID,
            ),
            (
                MinimumNumber,
                FPCR_AH,
                SINGLE_QNAN_LEFT,
                SINGLE_SNAN_RIGHT,
                SINGLE_QNAN_LEFT,
                INVALID,
            ),
            (
                MaximumNumber,
                FPCR_AH | FPCR_DN,
                SINGLE_QNAN_LEFT,
                SINGLE_SNAN_RIGHT,
                0xffc00000,
                INVALID,
            ),
            (
                MinimumNumber,
                FPCR_AH,
                SINGLE_QNAN_LEFT,
                SINGLE_QNAN_RIGHT,
                SINGLE_QNAN_LEFT,
                0,
            ),
            (Minimum, FPCR_AH | FPCR_FZ, 1, SINGLE_ONE, 1, INPUT_DENORMAL),
            (
                MinimumNumber,
                FPCR_AH | FPCR_FZ,
                1,
                SINGLE_ONE,
                0,
                INPUT_DENORMAL | UNDERFLOW | INEXACT,
            ),
            (
                MinimumNumber,
                FPCR_AH | FPCR_FZ,
                SINGLE_QNAN_LEFT,
                1,
                0,
                INPUT_DENORMAL | UNDERFLOW | INEXACT,
            ),
            (
                MinimumNumber,
                FPCR_AH,
                SINGLE_SNAN_LEFT,
                1,
                SINGLE_SNAN_LEFT | SINGLE_QUIET_BIT,
                INVALID,
            ),
            (Maximum, FPCR_AH, 1, SINGLE_ONE, SINGLE_ONE, INPUT_DENORMAL),
            (
                Minimum,
                FPCR_FZ,
                SINGLE_QNAN_LEFT,
                1,
                SINGLE_QNAN_LEFT,
                INPUT_DENORMAL,
            ),
            (Minimum, FPCR_AH | FPCR_FIZ, 1, SINGLE_ONE, 0, 0),
            (
                MaximumNumber,
                FPCR_AH | FPCR_FZ | FPCR_FIZ,
                1,
                SINGLE_ONE,
                SINGLE_ONE,
                0,
            ),
        ] {
            assert_eq!(
                evaluate(Format::Single, operation, fpcr, left, right),
                Ok(Outcome { bits, exceptions }),
                "{operation:?} fpcr={fpcr:x} left={left:x} right={right:x}",
            );
        }
    }

    #[test]
    fn balanced_number_reduction_preserves_intermediate_nan_effects() {
        // The high pair quiets sNaN, which the tree root then ignores. A linear
        // fold encounters sNaN later and instead selects the final numeric lane.
        for (operation, lanes, expected, folded) in [
            (
                MinimumNumber,
                [SINGLE_ONE, SINGLE_TWO, SINGLE_SNAN_LEFT, SINGLE_THREE],
                SINGLE_ONE,
                SINGLE_THREE,
            ),
            (
                MaximumNumber,
                [SINGLE_THREE, SINGLE_TWO, SINGLE_SNAN_LEFT, SINGLE_ONE],
                SINGLE_THREE,
                SINGLE_ONE,
            ),
        ] {
            let high = evaluate(Format::Single, operation, 0, lanes[2], lanes[3]).unwrap();
            let low = evaluate(Format::Single, operation, 0, lanes[0], lanes[1]).unwrap();
            let result = evaluate(Format::Single, operation, 0, low.bits, high.bits).unwrap();
            assert_eq!(result.bits, expected);
            assert_eq!(
                high.exceptions | low.exceptions | result.exceptions,
                INVALID
            );
            let mut linear = lanes[0];
            for lane in &lanes[1..] {
                linear = evaluate(Format::Single, operation, 0, linear, *lane)
                    .unwrap()
                    .bits;
            }
            assert_eq!(linear, folded);
            assert_ne!(result.bits, linear);
        }
    }

    #[test]
    fn all_formats_preserve_raw_second_nan_and_restrict_number_rules() {
        for format in [Format::Half, Format::Single, Format::Double] {
            let signaling = format.infinity(true) | 1;
            let quiet = format.infinity(false) | format.quiet_bit() | 2;
            let poison = if format == Format::Double {
                0
            } else {
                u64::MAX << format.bits()
            };
            for controls in [FPCR_AH, FPCR_AH | FPCR_DN | FPCR_AHP] {
                assert_eq!(
                    evaluate(
                        format,
                        Minimum,
                        controls,
                        quiet | poison,
                        signaling | poison
                    ),
                    Ok(Outcome {
                        bits: signaling,
                        exceptions: INVALID
                    })
                );
                assert_eq!(
                    evaluate(format, MaximumNumber, controls, quiet, signaling),
                    Ok(Outcome {
                        bits: if controls & FPCR_DN != 0 {
                            format.infinity(true) | format.quiet_bit()
                        } else {
                            quiet
                        },
                        exceptions: INVALID
                    })
                );
            }
        }
    }

    #[test]
    fn half_flush_ignores_ahp_and_has_no_input_denormal_status() {
        for operation in [Minimum, Maximum, MinimumNumber, MaximumNumber] {
            for controls in [0, FPCR_AH, FPCR_AHP, FPCR_AH | FPCR_AHP] {
                assert_eq!(
                    evaluate(Format::Half, operation, controls | FPCR_FZ16, 1, 0x8001),
                    Ok(Outcome {
                        bits: if operation.minimum()
                            || controls & FPCR_AH != 0 && !operation.number()
                        {
                            0x8000
                        } else {
                            0
                        },
                        exceptions: 0
                    })
                );
                assert_eq!(
                    evaluate(
                        Format::Half,
                        operation,
                        controls | FPCR_FIZ | FPCR_FZ,
                        1,
                        0x8001
                    ),
                    Ok(Outcome {
                        bits: if operation.minimum() { 0x8001 } else { 1 },
                        exceptions: 0
                    })
                );
            }
        }
        assert_eq!(
            evaluate(Format::Half, MinimumNumber, FPCR_AHP, 0x7c01, 0x3c00),
            Ok(Outcome {
                bits: 0x7e01,
                exceptions: INVALID
            })
        );
    }

    #[test]
    fn numeric_ordering_is_exact_for_both_signs_infinities_and_all_rounding_modes() {
        for format in [Format::Half, Format::Single, Format::Double] {
            let positive = format.exponent_mask() - 1;
            let negative = positive | format.sign_mask();
            for rounding in 0..4 {
                for operation in [Minimum, Maximum, MinimumNumber, MaximumNumber] {
                    let expected = if operation.minimum() {
                        negative
                    } else {
                        positive
                    };
                    assert_eq!(
                        evaluate(
                            format,
                            operation,
                            rounding << FPCR_ROUNDING_SHIFT,
                            positive,
                            negative
                        ),
                        Ok(Outcome {
                            bits: expected,
                            exceptions: 0
                        })
                    );
                    assert_eq!(
                        evaluate(
                            format,
                            operation,
                            rounding << FPCR_ROUNDING_SHIFT,
                            negative,
                            positive
                        ),
                        Ok(Outcome {
                            bits: expected,
                            exceptions: 0
                        })
                    );
                    let expected = format.infinity(operation.minimum());
                    assert_eq!(
                        evaluate(
                            format,
                            operation,
                            0,
                            format.infinity(true),
                            format.infinity(false)
                        ),
                        Ok(Outcome {
                            bits: expected,
                            exceptions: 0
                        })
                    );
                }
            }
        }
    }

    #[test]
    fn negative_double_denormal_flush_preserves_sign_and_skipped_nan_status() {
        let denormal = Format::Double.sign_mask() | 1;
        let infinity = Format::Double.infinity(true);
        assert_eq!(
            evaluate(
                Format::Double,
                MaximumNumber,
                FPCR_AH | FPCR_FZ,
                denormal,
                infinity
            ),
            Ok(Outcome {
                bits: Format::Double.sign_mask(),
                exceptions: INPUT_DENORMAL | UNDERFLOW | INEXACT,
            })
        );
        assert_eq!(
            evaluate(
                Format::Double,
                Maximum,
                FPCR_AH | FPCR_FZ,
                denormal,
                infinity
            ),
            Ok(Outcome {
                bits: denormal,
                exceptions: INPUT_DENORMAL,
            })
        );
        assert_eq!(
            evaluate(
                Format::Double,
                Maximum,
                FPCR_AH | FPCR_FZ,
                infinity | 1,
                denormal
            ),
            Ok(Outcome {
                bits: denormal,
                exceptions: INVALID,
            })
        );
    }

    #[test]
    fn all_enabled_exceptions_refuse_before_nan_or_zero_branches() {
        for exception in [
            INVALID,
            DIVIDE_BY_ZERO,
            OVERFLOW,
            UNDERFLOW,
            INEXACT,
            INPUT_DENORMAL,
            EXCEPTIONS,
        ] {
            for operation in [Minimum, Maximum, MinimumNumber, MaximumNumber] {
                for (left, right) in [(0, 0), (SINGLE_QNAN_LEFT, SINGLE_SNAN_RIGHT)] {
                    assert_eq!(
                        evaluate(
                            Format::Single,
                            operation,
                            FPCR_AH | (exception << FPCR_EXCEPTION_ENABLE_SHIFT),
                            left,
                            right
                        ),
                        Err(UnsupportedControl {
                            enabled_exceptions: exception
                        })
                    );
                }
            }
        }
    }
}
