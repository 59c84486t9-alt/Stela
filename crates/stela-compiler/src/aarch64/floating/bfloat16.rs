//! BF16 conversion and Single fused arithmetic in the standard BF16 profile.
pub mod arithmetic;
mod dot;
pub mod extended_dot;

pub use dot::dot_add;

use super::{
    Class, Control, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_ROUNDING_MASK,
    FPCR_ROUNDING_SHIFT, Format, INEXACT, INVALID, OVERFLOW, Operand, Outcome, UNDERFLOW,
    UnsupportedControl,
    fused::{self, FusedOperation},
    unpack,
};
use rustc_apfloat::Round;

pub const BFLOAT16_BITS: u32 = 16;
pub const BFLOAT16_FRACTION_BITS: u32 = 7;
pub const BFLOAT16_TO_SINGLE_SHIFT: u32 = Format::Single.bits() - BFLOAT16_BITS;

const BFLOAT16_EXPONENT_BITS: u32 = BFLOAT16_BITS - BFLOAT16_FRACTION_BITS - 1;
const BFLOAT16_SIGN_MASK: u32 = 1 << (BFLOAT16_BITS - 1);
const BFLOAT16_INFINITY: u32 = ((1 << BFLOAT16_EXPONENT_BITS) - 1) << BFLOAT16_FRACTION_BITS;
const RETAINED_LOW_BIT: u32 = 1;
const DISCARDED_MASK: u32 = (1 << BFLOAT16_TO_SINGLE_SHIFT) - 1;
const DISCARDED_MIDPOINT: u32 = 1 << (BFLOAT16_TO_SINGLE_SHIFT - 1);

/// BF16 shares Single's exponent and high fraction fields, including NaNs.
pub const fn widen(bits: u16) -> u32 {
    (bits as u32) << BFLOAT16_TO_SINGLE_SHIFT
}

/// BFNeg preserves NaN sign under AH and raises no status.
pub fn negate(fpcr: u32, bits: u16) -> u16 {
    (super::negate(Format::Single, u64::from(widen(bits)), Control(fpcr))
        >> BFLOAT16_TO_SINGLE_SHIFT) as u16
}

fn effective_control(fpcr: u32) -> Result<Control, UnsupportedControl> {
    let control = Control(fpcr);
    if control.alternative() {
        // FPConvertBF and BFMulAddH suppress exceptions under AH. Retain AH/DN
        // while forcing input/output flush and nearest-even independently.
        Ok(Control(
            (fpcr | FPCR_FIZ | FPCR_FZ)
                & !(FPCR_EXCEPTION_ENABLE_MASK | FPCR_ROUNDING_MASK << FPCR_ROUNDING_SHIFT),
        ))
    } else {
        Control::checked(fpcr)
    }
}

fn round_finite(source: Operand, control: Control) -> Outcome {
    let sign = (source.bits >> BFLOAT16_TO_SINGLE_SHIFT) as u32 & BFLOAT16_SIGN_MASK;
    let magnitude = (source.bits & !Format::Single.sign_mask()) as u32;
    let retained = magnitude >> BFLOAT16_TO_SINGLE_SHIFT;
    let discarded = magnitude & DISCARDED_MASK;
    let inexact = discarded != 0;
    let increment = match control.round() {
        Round::NearestTiesToEven => {
            discarded > DISCARDED_MIDPOINT
                || discarded == DISCARDED_MIDPOINT && retained & RETAINED_LOW_BIT != 0
        }
        Round::TowardPositive => inexact && !source.negative,
        Round::TowardNegative => inexact && source.negative,
        Round::TowardZero => false,
        _ => unreachable!("two-bit FPCR rounding field"),
    };
    let rounded = retained + u32::from(increment);
    let mut exceptions = if inexact { INEXACT } else { 0 };
    // BF16 and Single have the same minimum normal exponent. Unflushed tiny
    // sources are Single subnormals; AH0 detects tininess before rounding,
    // including a rounded BF16 minimum normal. Exact subnormals raise no flag.
    if source.class == Class::Denormal && inexact {
        exceptions |= UNDERFLOW;
    }
    if rounded == BFLOAT16_INFINITY {
        exceptions |= OVERFLOW | INEXACT;
    }
    Outcome {
        bits: u64::from(sign | rounded),
        exceptions,
    }
}

/// Convert original Single bits to BF16 with one target rounding. No late IDC
/// processing applies; AH0 FZ may already flush the Single input with IDC.
pub fn convert(fpcr: u32, bits: u32) -> Result<Outcome, UnsupportedControl> {
    let control = effective_control(fpcr)?;
    let mut exceptions = 0;
    let source = unpack(Format::Single, u64::from(bits), control, &mut exceptions);
    let mut result = if source.class.nan() {
        if source.class == Class::SignalingNaN {
            exceptions |= INVALID;
        }
        let quiet = if control.0 & FPCR_DN != 0 {
            control.default_nan(Format::Single)
        } else {
            source.bits | Format::Single.quiet_bit()
        };
        Outcome {
            bits: quiet >> BFLOAT16_TO_SINGLE_SHIFT,
            exceptions: 0,
        }
    } else if matches!(source.class, Class::Zero | Class::Infinity) {
        Outcome {
            bits: source.bits >> BFLOAT16_TO_SINGLE_SHIFT,
            exceptions: 0,
        }
    } else {
        // Any source small enough for BF16 output flush is a Single subnormal
        // and was already flushed during unpack when the policy enables FZ.
        round_finite(source, control)
    };
    result.exceptions = if control.alternative() {
        0
    } else {
        result.exceptions | exceptions
    };
    Ok(result)
}

/// BFMLAL widens both BF16 operands exactly and reuses Single FPMulAdd. The
/// absent EBF16 feature cannot select a different algorithm through raw FPCR.
pub fn multiply_add(
    fpcr: u32,
    addend: u32,
    left: u16,
    right: u16,
) -> Result<Outcome, UnsupportedControl> {
    let control = effective_control(fpcr)?;
    let mut result = fused::evaluate(
        Format::Single,
        FusedOperation::Add,
        control.0,
        u64::from(addend),
        u64::from(widen(left)),
        u64::from(widen(right)),
    )?;
    if control.alternative() {
        result.exceptions = 0;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::floating::{
        DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_AHP, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FZ16,
        INPUT_DENORMAL,
    };

    const BFLOAT16_ONE: u16 = 0x3f80;
    const SINGLE_ONE: u32 = 0x3f80_0000;
    const SINGLE_SIGN: u32 = 0x8000_0000;
    const SINGLE_QUIET: u32 = 0x0040_0000;
    const SINGLE_INFINITY: u32 = 0x7f80_0000;
    const RAW_UNADVERTISED_EBF: u32 = 1 << 13;
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
    fn widening_retains_every_raw_bfloat16_field() {
        for (input, expected) in [
            (0, 0),
            (0x8000, SINGLE_SIGN),
            (1, 0x0001_0000),
            (0x0080, 0x0080_0000),
            (BFLOAT16_ONE, SINGLE_ONE),
            (0x7f80, SINGLE_INFINITY),
            (0xff81, 0xff81_0000),
            (0x7fff, 0x7fff_0000),
        ] {
            assert_eq!(widen(input), expected);
        }
    }

    #[test]
    fn finite_conversion_rounds_once_at_even_odd_and_adjacent_midpoints() {
        for (input, expected) in [
            (0x3f80_7fff, [0x3f80, 0x3f81, 0x3f80, 0x3f80]),
            (0x3f80_8000, [0x3f80, 0x3f81, 0x3f80, 0x3f80]),
            (0x3f80_8001, [0x3f81, 0x3f81, 0x3f80, 0x3f80]),
            (0x3f81_8000, [0x3f82, 0x3f82, 0x3f81, 0x3f81]),
            (0xbf80_8000, [0xbf80, 0xbf80, 0xbf81, 0xbf80]),
            (0xbf81_8000, [0xbf82, 0xbf81, 0xbf82, 0xbf81]),
        ] {
            for (round, result) in ROUNDINGS.into_iter().zip(expected) {
                assert_eq!(
                    convert(round << FPCR_ROUNDING_SHIFT, input),
                    outcome(result, INEXACT)
                );
            }
        }
    }

    #[test]
    fn conversion_tininess_is_detected_before_rounding_to_minimum_normal() {
        for (input, expected) in [
            (0x0000_0001, [0x0000, 0x0001, 0x0000, 0x0000]),
            (0x007f_8000, [0x0080, 0x0080, 0x007f, 0x007f]),
            (0x807f_8000, [0x8080, 0x807f, 0x8080, 0x807f]),
        ] {
            for (round, result) in ROUNDINGS.into_iter().zip(expected) {
                assert_eq!(
                    convert(round << FPCR_ROUNDING_SHIFT, input),
                    outcome(result, UNDERFLOW | INEXACT)
                );
            }
        }
        for input in [0x0001_0000, 0x007f_0000, 0x0080_0000] {
            for round in ROUNDINGS {
                assert_eq!(
                    convert(round << FPCR_ROUNDING_SHIFT, input),
                    outcome(input >> BFLOAT16_TO_SINGLE_SHIFT, 0)
                );
            }
        }
        assert_eq!(convert(0, 0x0080_0001), outcome(0x0080, INEXACT));
    }

    #[test]
    fn conversion_flushes_source_subnormals_with_only_source_specific_status() {
        for sign in [0, SINGLE_SIGN] {
            for input in [0x0000_0001, 0x0001_0000, 0x007f_8000] {
                for (control, exceptions) in [
                    (FPCR_FIZ, 0),
                    (FPCR_FZ, INPUT_DENORMAL),
                    (FPCR_FIZ | FPCR_FZ, INPUT_DENORMAL),
                    (FPCR_AH, 0),
                    (FPCR_AH | FPCR_FIZ, 0),
                    (FPCR_AH | FPCR_FZ, 0),
                ] {
                    for round in ROUNDINGS {
                        assert_eq!(
                            convert(control | round << FPCR_ROUNDING_SHIFT, input | sign),
                            outcome(sign >> BFLOAT16_TO_SINGLE_SHIFT, exceptions)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn conversion_overflow_depends_on_sign_and_rounding_carry() {
        for (input, expected) in [
            (0x7f7f_7fff, [0x7f7f, 0x7f80, 0x7f7f, 0x7f7f]),
            (0x7f7f_8000, [0x7f80, 0x7f80, 0x7f7f, 0x7f7f]),
            (0xff7f_8000, [0xff80, 0xff7f, 0xff80, 0xff7f]),
        ] {
            for (round, result) in ROUNDINGS.into_iter().zip(expected) {
                let overflow = result & !BFLOAT16_SIGN_MASK == BFLOAT16_INFINITY;
                assert_eq!(
                    convert(round << FPCR_ROUNDING_SHIFT, input),
                    outcome(result, INEXACT | if overflow { OVERFLOW } else { 0 })
                );
            }
        }
    }

    #[test]
    fn conversion_nan_quieting_precedes_payload_truncation_and_suppression() {
        for (input, result, invalid) in [
            (0x7f80_0001, 0x7fc0, INVALID),
            (0xff81_2345, 0xffc1, INVALID),
            (0xffc1_2345, 0xffc1, 0),
            (0x7fff_ffff, 0x7fff, 0),
        ] {
            for ah in [0, FPCR_AH] {
                assert_eq!(
                    convert(ah, input),
                    outcome(result, if ah == 0 { invalid } else { 0 })
                );
                assert_eq!(
                    convert(ah | FPCR_DN, input),
                    outcome(
                        if ah == 0 { 0x7fc0 } else { 0xffc0 },
                        if ah == 0 { invalid } else { 0 }
                    )
                );
            }
        }
        for input in [
            0,
            SINGLE_SIGN,
            SINGLE_INFINITY,
            SINGLE_INFINITY | SINGLE_SIGN,
        ] {
            assert_eq!(
                convert(0, input),
                outcome(input >> BFLOAT16_TO_SINGLE_SHIFT, 0)
            );
        }
    }

    #[test]
    fn alternative_conversion_forces_nearest_and_suppresses_retained_enables() {
        const MIDPOINT_ODD: u32 = 0x3f81_8000;
        for round in ROUNDINGS {
            for controls in [0, FPCR_FIZ, FPCR_FZ, FPCR_FIZ | FPCR_FZ] {
                assert_eq!(
                    convert(
                        FPCR_AH
                            | controls
                            | FPCR_EXCEPTION_ENABLE_MASK
                            | round << FPCR_ROUNDING_SHIFT,
                        MIDPOINT_ODD
                    ),
                    outcome(0x3f82, 0)
                );
            }
        }
        assert_eq!(
            convert(FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK, 0x7f7f_8000),
            outcome(0x7f80, 0)
        );
        assert_eq!(
            convert(FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK, 0x7f80_0001),
            outcome(0x7fc0, 0)
        );
    }

    #[test]
    fn fused_multiply_add_preserves_residuals_and_cancels_an_overflowing_product() {
        // (1+2^-7)*(1-2^-7)-1 = -2^-14. The second case's product
        // exceeds Single range, but its fused sum is exactly 0x7f7e0001.
        for (addend, left, right, result) in [
            (SINGLE_ONE | SINGLE_SIGN, 0x3f81, 0x3f7e, 0xb880_0000),
            (0xff7f_ffff, 0x7f7f, 0x4000, 0x7f7e_0001),
        ] {
            for ah in [0, FPCR_AH] {
                for round in ROUNDINGS {
                    assert_eq!(
                        multiply_add(ah | round << FPCR_ROUNDING_SHIFT, addend, left, right),
                        outcome(result, 0)
                    );
                }
            }
        }
    }

    #[test]
    fn multiply_add_uses_single_flush_and_alternative_forced_rounding() {
        const BFLOAT16_HALF: u16 = 0x3f00;
        const BFLOAT16_MINIMUM_NORMAL: u16 = 0x0080;
        const BFLOAT16_SINGLE_HALF_ULP: u16 = 0x3380;
        for (control, result, exceptions) in [
            (0, 0x0040_0000, 0),
            (FPCR_FZ, 0, UNDERFLOW),
            (FPCR_AH, 0, 0),
        ] {
            assert_eq!(
                multiply_add(control, 0, BFLOAT16_MINIMUM_NORMAL, BFLOAT16_HALF),
                outcome(result, exceptions)
            );
        }
        for round in ROUNDINGS {
            assert_eq!(
                multiply_add(
                    round << FPCR_ROUNDING_SHIFT,
                    SINGLE_ONE,
                    BFLOAT16_ONE,
                    BFLOAT16_SINGLE_HALF_ULP
                ),
                outcome(SINGLE_ONE + u32::from(round == ROUND_POSITIVE), INEXACT)
            );
            assert_eq!(
                multiply_add(
                    FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK | round << FPCR_ROUNDING_SHIFT,
                    SINGLE_ONE,
                    BFLOAT16_ONE,
                    BFLOAT16_SINGLE_HALF_ULP
                ),
                outcome(SINGLE_ONE, 0)
            );
        }
        assert_eq!(multiply_add(0, 0, 1, BFLOAT16_ONE), outcome(0x0001_0000, 0));
        assert_eq!(
            multiply_add(FPCR_FZ, 0, 1, BFLOAT16_ONE),
            outcome(0, INPUT_DENORMAL)
        );
        assert_eq!(
            multiply_add(FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK, 0, 1, BFLOAT16_ONE),
            outcome(0, 0)
        );
    }

    #[test]
    fn multiply_add_keeps_alternative_nan_priority_and_default_sign() {
        const SIGNALING_ADDEND: u32 = 0x7f80_0011;
        const QUIET_LEFT: u16 = 0xffc1;
        assert_eq!(
            multiply_add(0, SIGNALING_ADDEND, QUIET_LEFT, BFLOAT16_ONE),
            outcome(SIGNALING_ADDEND | SINGLE_QUIET, INVALID)
        );
        assert_eq!(
            multiply_add(
                FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK,
                SIGNALING_ADDEND,
                QUIET_LEFT,
                BFLOAT16_ONE
            ),
            outcome(0xffc1_0000, 0)
        );
        for (control, result, exceptions) in [
            (0, 0x7fc0_0000, INVALID),
            (FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK, 0xffc0_0000, 0),
        ] {
            assert_eq!(
                multiply_add(control, SINGLE_ONE, 0, 0x7f80),
                outcome(result, exceptions)
            );
            assert_eq!(
                multiply_add(
                    control | FPCR_DN,
                    SIGNALING_ADDEND,
                    QUIET_LEFT,
                    BFLOAT16_ONE
                ),
                outcome(result, exceptions)
            );
        }
    }

    #[test]
    fn absent_extended_and_half_controls_cannot_select_another_algorithm() {
        for ignored in [
            FPCR_AHP,
            FPCR_FZ16,
            RAW_UNADVERTISED_EBF,
            FPCR_AHP | FPCR_FZ16 | RAW_UNADVERTISED_EBF,
        ] {
            for ah in [0, FPCR_AH] {
                assert_eq!(convert(ignored | ah, 0x007f_8000), convert(ah, 0x007f_8000));
                assert_eq!(convert(ignored | ah, 0x7f80_0001), convert(ah, 0x7f80_0001));
                assert_eq!(
                    multiply_add(ignored | ah, SINGLE_ONE | SINGLE_SIGN, 0x3f81, 0x3f7e),
                    outcome(0xb880_0000, 0)
                );
            }
        }
    }

    #[test]
    fn ordinary_mode_refuses_every_retained_enable_before_exact_operations() {
        for enabled in [
            INVALID,
            DIVIDE_BY_ZERO,
            OVERFLOW,
            UNDERFLOW,
            INEXACT,
            INPUT_DENORMAL,
            EXCEPTIONS,
        ] {
            let fpcr = enabled << FPCR_EXCEPTION_ENABLE_SHIFT;
            let expected = Err(UnsupportedControl {
                enabled_exceptions: enabled,
            });
            assert_eq!(convert(fpcr, SINGLE_ONE), expected);
            assert_eq!(multiply_add(fpcr, 0, BFLOAT16_ONE, BFLOAT16_ONE), expected);
        }
    }

    #[test]
    fn negate_honors_alternative_nan_sign_without_quieting() {
        const SIGNALING_NAN: u16 = 0x7f81;
        const NEGATIVE_ZERO: u16 = 0x8000;
        const INFINITY: u16 = 0x7f80;
        assert_eq!(negate(0, SIGNALING_NAN), SIGNALING_NAN | NEGATIVE_ZERO);
        assert_eq!(negate(FPCR_AH, SIGNALING_NAN), SIGNALING_NAN);
        assert_eq!(negate(FPCR_AH, INFINITY), INFINITY | NEGATIVE_ZERO);
        assert_eq!(negate(FPCR_AH, 1), 1 | NEGATIVE_ZERO);
    }
}
