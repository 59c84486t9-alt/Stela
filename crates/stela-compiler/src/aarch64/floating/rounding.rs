//! FRINT* rounding to integral values, including the bounded FRINT32/64 forms.
use super::{
    Class, Control, FPCR_DN, Format, INEXACT, INVALID, Outcome, UnsupportedControl, unpack,
};
use rustc_apfloat::{
    Float, Round, Status,
    ieee::{Double, Half, Single},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundingOperation {
    NearestEven,
    NearestAway,
    TowardPositive,
    TowardNegative,
    TowardZero,
    Current,
    CurrentExact,
    Signed32Zero,
    Signed32Current,
    Signed64Zero,
    Signed64Current,
}

impl RoundingOperation {
    fn round(self, control: Control) -> Round {
        match self {
            Self::NearestEven => Round::NearestTiesToEven,
            Self::NearestAway => Round::NearestTiesToAway,
            Self::TowardPositive => Round::TowardPositive,
            Self::TowardNegative => Round::TowardNegative,
            Self::TowardZero | Self::Signed32Zero | Self::Signed64Zero => Round::TowardZero,
            Self::Current | Self::CurrentExact | Self::Signed32Current | Self::Signed64Current => {
                control.round()
            }
        }
    }

    pub(crate) const fn signed_width(self) -> Option<u32> {
        match self {
            Self::Signed32Zero | Self::Signed32Current => Some(u32::BITS),
            Self::Signed64Zero | Self::Signed64Current => Some(u64::BITS),
            _ => None,
        }
    }

    pub(crate) const fn exact(self) -> bool {
        matches!(self, Self::CurrentExact) || self.signed_width().is_some()
    }
}

fn signed_limit<F: Float>(width: u32) -> F {
    F::from_u128(1).value.scalbn(width as i32 - 1)
}

fn indefinite(format: Format, width: u32) -> u64 {
    match format {
        Format::Single => (-signed_limit::<Single>(width)).to_bits() as u64,
        Format::Double => (-signed_limit::<Double>(width)).to_bits() as u64,
        Format::Half => unreachable!("bounded integral rounding has no half form"),
    }
}

fn finite<F: Float>(operation: RoundingOperation, control: Control, bits: u64) -> Outcome {
    let source = F::from_bits(u128::from(bits));
    // Same-format integral rounding is exact after the integer is selected.
    // The integer-only library preserves source sign for zero and leaves large
    // already integral values unchanged, without host FP or double rounding.
    let result = source.round_to_integral(operation.round(control));
    debug_assert!(!result.status.intersects(
        Status::INVALID_OP | Status::DIV_BY_ZERO | Status::OVERFLOW | Status::UNDERFLOW
    ));
    if let Some(width) = operation.signed_width() {
        let limit = signed_limit::<F>(width);
        // The positive maximum (limit-1) may not be representable in F. Using
        // the exact power-of-two boundary tests the rounded integer directly.
        if result.value >= limit || result.value < -limit {
            return Outcome {
                bits: (-limit).to_bits() as u64,
                exceptions: INVALID,
            };
        }
    }
    Outcome {
        bits: result.value.to_bits() as u64,
        exceptions: if operation.exact() && result.status.contains(Status::INEXACT) {
            INEXACT
        } else {
            0
        },
    }
}

/// Evaluate one FRINT lane with fresh status only. AHP is ignored, FZ16 is
/// observed, and AH suppresses IDC without any post-operation denormal check.
/// Scalar merging, active lanes and sticky status belong to the caller.
pub fn evaluate(
    format: Format,
    operation: RoundingOperation,
    fpcr: u32,
    bits: u64,
) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    assert!(
        format != Format::Half || operation.signed_width().is_none(),
        "decoded bounded integral rounding requires S/D"
    );
    let mut exceptions = 0;
    // Shared unpack raises IDC only for AH0 S/D input flushing. FPRoundInt/N
    // suppress AH1 input-denormal exceptions and never process denormals later.
    let operand = unpack(format, bits, control, &mut exceptions);
    let result = if let Some(width) = operation.signed_width()
        && (operand.class.nan() || operand.class == Class::Infinity)
    {
        // Bounded forms replace every NaN and infinity with signed minimum,
        // independent of NaN payload, signaling, DN and the source sign.
        Outcome {
            bits: indefinite(format, width),
            exceptions: INVALID,
        }
    } else if operand.class.nan() {
        Outcome {
            bits: if control.0 & FPCR_DN != 0 {
                control.default_nan(format)
            } else {
                operand.bits | format.quiet_bit()
            },
            exceptions: if operand.class == Class::SignalingNaN {
                INVALID
            } else {
                0
            },
        }
    } else if matches!(operand.class, Class::Zero | Class::Infinity) {
        Outcome {
            bits: operand.bits,
            exceptions: 0,
        }
    } else {
        match format {
            Format::Half => finite::<Half>(operation, control, operand.bits),
            Format::Single => finite::<Single>(operation, control, operand.bits),
            Format::Double => finite::<Double>(operation, control, operand.bits),
        }
    };
    Ok(Outcome {
        bits: result.bits,
        exceptions: exceptions | result.exceptions,
    })
}

#[cfg(test)]
mod tests {
    use super::RoundingOperation::*;
    use super::*;
    use crate::aarch64::floating::{
        DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_AHP, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FIZ,
        FPCR_FZ, FPCR_FZ16, FPCR_NEP, FPCR_ROUNDING_SHIFT, INPUT_DENORMAL, OVERFLOW,
        ROUND_NEGATIVE, ROUND_POSITIVE, ROUND_ZERO, UNDERFLOW,
    };

    const OPERATIONS: [RoundingOperation; 11] = [
        NearestEven,
        NearestAway,
        TowardPositive,
        TowardNegative,
        TowardZero,
        Current,
        CurrentExact,
        Signed32Zero,
        Signed32Current,
        Signed64Zero,
        Signed64Current,
    ];
    const VALUES: [(Format, u64, u64, u64, u64); 3] = [
        (Format::Half, 0x3c00, 0x4000, 0x4100, 0x4200),
        (
            Format::Single,
            0x3f80_0000,
            0x4000_0000,
            0x4020_0000,
            0x4040_0000,
        ),
        (
            Format::Double,
            0x3ff0_0000_0000_0000,
            0x4000_0000_0000_0000,
            0x4004_0000_0000_0000,
            0x4008_0000_0000_0000,
        ),
    ];

    fn result(format: Format, operation: RoundingOperation, fpcr: u32, bits: u64) -> Outcome {
        evaluate(format, operation, fpcr, bits).unwrap()
    }

    #[test]
    fn explicit_rounding_modes_handle_positive_and_negative_halfway_values() {
        for (format, _, two, halfway, three) in VALUES {
            for (operation, positive, negative) in [
                (NearestEven, two, two),
                (NearestAway, three, three),
                (TowardPositive, three, two),
                (TowardNegative, two, three),
                (TowardZero, two, two),
            ] {
                for rounding in 0..4 {
                    let control = rounding << FPCR_ROUNDING_SHIFT;
                    assert_eq!(
                        result(format, operation, control, halfway),
                        Outcome {
                            bits: positive,
                            exceptions: 0
                        }
                    );
                    assert_eq!(
                        result(format, operation, control, halfway | format.sign_mask()),
                        Outcome {
                            bits: negative | format.sign_mask(),
                            exceptions: 0
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn current_mode_and_exact_status_are_independent_choices() {
        for (format, _, two, halfway, three) in VALUES {
            for (rounding, expected) in [
                (0, two),
                (ROUND_POSITIVE, three),
                (ROUND_NEGATIVE, two),
                (ROUND_ZERO, two),
            ] {
                let control = rounding << FPCR_ROUNDING_SHIFT;
                assert_eq!(
                    result(format, Current, control, halfway),
                    Outcome {
                        bits: expected,
                        exceptions: 0
                    }
                );
                assert_eq!(
                    result(format, CurrentExact, control, halfway),
                    Outcome {
                        bits: expected,
                        exceptions: INEXACT
                    }
                );
            }
        }
    }

    #[test]
    fn signed_zero_is_preserved_for_original_and_rounded_zero() {
        for (format, _, _, _, _) in VALUES {
            let sign = format.sign_mask();
            for operation in OPERATIONS {
                if format == Format::Half && operation.signed_width().is_some() {
                    continue;
                }
                for zero in [0, sign] {
                    assert_eq!(
                        result(format, operation, 0, zero),
                        Outcome {
                            bits: zero,
                            exceptions: 0
                        }
                    );
                }
            }
            for operation in [
                NearestEven,
                NearestAway,
                TowardPositive,
                TowardZero,
                Current,
                CurrentExact,
            ] {
                assert_eq!(
                    result(format, operation, 0, sign | 1),
                    Outcome {
                        bits: sign,
                        exceptions: if operation == CurrentExact {
                            INEXACT
                        } else {
                            0
                        }
                    }
                );
            }
        }
    }

    #[test]
    fn ordinary_nan_quieting_payloads_and_default_sign_are_explicit() {
        for (format, _, _, _, _) in VALUES {
            let signaling = format.infinity(true) | 1;
            let quiet = signaling | format.quiet_bit();
            for operation in [NearestEven, NearestAway, Current, CurrentExact] {
                assert_eq!(
                    result(format, operation, 0, signaling),
                    Outcome {
                        bits: quiet,
                        exceptions: INVALID
                    }
                );
                assert_eq!(
                    result(format, operation, 0, quiet),
                    Outcome {
                        bits: quiet,
                        exceptions: 0
                    }
                );
                for (control, sign) in [(FPCR_DN, false), (FPCR_DN | FPCR_AH, true)] {
                    assert_eq!(
                        result(format, operation, control, signaling),
                        Outcome {
                            bits: format.infinity(sign) | format.quiet_bit(),
                            exceptions: INVALID
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn bounded_special_values_ignore_nan_controls_and_return_signed_minimum() {
        for (format, width, expected) in [
            (Format::Single, 32, 0xcf00_0000),
            (Format::Double, 32, 0xc1e0_0000_0000_0000),
            (Format::Single, 64, 0xdf00_0000),
            (Format::Double, 64, 0xc3e0_0000_0000_0000),
        ] {
            let operations = if width == 32 {
                [Signed32Zero, Signed32Current]
            } else {
                [Signed64Zero, Signed64Current]
            };
            for operation in operations {
                for input in [
                    format.infinity(false),
                    format.infinity(true),
                    format.infinity(false) | 1,
                    format.infinity(true) | format.quiet_bit(),
                ] {
                    assert_eq!(
                        result(format, operation, FPCR_AH | FPCR_DN, input),
                        Outcome {
                            bits: expected,
                            exceptions: INVALID
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn bounded_range_is_checked_after_rounding_and_invalid_suppresses_inexact() {
        // Double inputs represent signed32 boundary fractions exactly.
        for (operation, control, source, bits, exceptions) in [
            (
                Signed32Zero,
                0,
                0x41df_ffff_fff0_0000,
                0x41df_ffff_ffc0_0000,
                INEXACT,
            ),
            (
                Signed32Current,
                0,
                0x41df_ffff_fff0_0000,
                0xc1e0_0000_0000_0000,
                INVALID,
            ),
            (
                Signed32Current,
                ROUND_POSITIVE << FPCR_ROUNDING_SHIFT,
                0xc1e0_0000_0008_0000,
                0xc1e0_0000_0000_0000,
                INEXACT,
            ),
            (
                Signed32Current,
                ROUND_NEGATIVE << FPCR_ROUNDING_SHIFT,
                0xc1e0_0000_0008_0000,
                0xc1e0_0000_0000_0000,
                INVALID,
            ),
            (
                Signed64Zero,
                0,
                0x43e0_0000_0000_0000,
                0xc3e0_0000_0000_0000,
                INVALID,
            ),
            (
                Signed64Zero,
                0,
                0xc3e0_0000_0000_0000,
                0xc3e0_0000_0000_0000,
                0,
            ),
        ] {
            assert_eq!(
                result(Format::Double, operation, control, source),
                Outcome { bits, exceptions }
            );
        }
        for operation in [Signed32Zero, Signed32Current, Signed64Zero, Signed64Current] {
            assert_eq!(
                result(Format::Double, operation, 0, 0x3ff8_0000_0000_0000).exceptions,
                INEXACT
            );
        }
    }

    #[test]
    fn denormal_status_and_early_flush_are_distinct_from_fractional_inexact() {
        for format in [Format::Single, Format::Double] {
            for (control, ordinary, exact) in [
                (0, 0, INEXACT),
                (FPCR_AH, 0, INEXACT),
                (FPCR_AH | FPCR_FZ, 0, INEXACT),
                (FPCR_FZ, INPUT_DENORMAL, INPUT_DENORMAL),
                (FPCR_FIZ, 0, 0),
                (FPCR_FIZ | FPCR_FZ, INPUT_DENORMAL, INPUT_DENORMAL),
                (FPCR_AH | FPCR_FIZ | FPCR_FZ, 0, 0),
            ] {
                assert_eq!(
                    result(format, Current, control, 1),
                    Outcome {
                        bits: 0,
                        exceptions: ordinary
                    }
                );
                for operation in [CurrentExact, Signed32Zero, Signed64Zero] {
                    assert_eq!(
                        result(format, operation, control, 1),
                        Outcome {
                            bits: 0,
                            exceptions: exact
                        }
                    );
                }
            }
        }
        assert_eq!(
            result(Format::Half, CurrentExact, FPCR_FZ16, 0x8001),
            Outcome {
                bits: 0x8000,
                exceptions: 0
            }
        );
        assert_eq!(
            result(
                Format::Half,
                CurrentExact,
                FPCR_AHP | FPCR_FIZ | FPCR_FZ,
                0x8001
            ),
            Outcome {
                bits: 0x8000,
                exceptions: INEXACT
            }
        );
    }

    #[test]
    fn integral_maxima_lane_poison_and_irrelevant_controls_preserve_bits() {
        for (format, one, _, _, _) in VALUES {
            let mask = u64::MAX >> (u64::BITS - format.bits());
            let maximum = format.exponent_mask() - 1;
            for operation in [
                NearestEven,
                NearestAway,
                TowardPositive,
                TowardNegative,
                TowardZero,
                Current,
                CurrentExact,
            ] {
                assert_eq!(
                    result(format, operation, 0, maximum),
                    Outcome {
                        bits: maximum,
                        exceptions: 0
                    }
                );
                assert_eq!(
                    result(
                        format,
                        operation,
                        FPCR_AHP | FPCR_NEP | FPCR_DN,
                        one | !mask
                    ),
                    Outcome {
                        bits: one,
                        exceptions: 0
                    }
                );
            }
        }
    }

    #[test]
    fn retained_enables_decline_before_exact_zero_or_invalid_cases() {
        for (format, _, _, _, _) in VALUES {
            for operation in OPERATIONS {
                if format == Format::Half && operation.signed_width().is_some() {
                    continue;
                }
                for exception in [
                    INVALID,
                    DIVIDE_BY_ZERO,
                    OVERFLOW,
                    UNDERFLOW,
                    INEXACT,
                    INPUT_DENORMAL,
                    EXCEPTIONS,
                ] {
                    assert_eq!(
                        evaluate(
                            format,
                            operation,
                            exception << FPCR_EXCEPTION_ENABLE_SHIFT,
                            0
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
