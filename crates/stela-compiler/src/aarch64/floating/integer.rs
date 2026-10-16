//! Conversions between floating-point and integer or fixed-point values.
use super::{
    Class, Control, EXCEPTIONS, FPCR_AHP, FPCR_EXCEPTION_ENABLE_SHIFT, Format, INEXACT, INVALID,
    Outcome, UnsupportedControl, unpack, widen,
};
use rustc_apfloat::{
    Float, Round, Status,
    ieee::{Double, Half, Quad, Single},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerWidth {
    Bits16,
    Bits32,
    Bits64,
}

impl IntegerWidth {
    pub const fn bits(self) -> u32 {
        match self {
            Self::Bits16 => 16,
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }

    pub const fn mask(self) -> u64 {
        u64::MAX >> (u64::BITS - self.bits())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegerFormat {
    pub width: IntegerWidth,
    pub signed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerRounding {
    NearestEven,
    NearestAway,
    TowardPositive,
    TowardNegative,
    TowardZero,
}

impl IntegerRounding {
    const fn round(self) -> Round {
        match self {
            Self::NearestEven => Round::NearestTiesToEven,
            Self::NearestAway => Round::NearestTiesToAway,
            Self::TowardPositive => Round::TowardPositive,
            Self::TowardNegative => Round::TowardNegative,
            Self::TowardZero => Round::TowardZero,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JavaScriptOutcome {
    pub result: Outcome,
    pub nzcv: u32,
}

const DOUBLE_EXPONENT_BIAS: i32 = 1023;
const DOUBLE_MINIMUM_EXPONENT: i32 = 1 - DOUBLE_EXPONENT_BIAS;
const JAVASCRIPT_WIDTH: IntegerWidth = IntegerWidth::Bits32;
const JAVASCRIPT_SIGN_LIMIT: u64 = 1 << (JAVASCRIPT_WIDTH.bits() - 1);
const NZCV_ZERO: u32 = 1 << 30;

fn control(fpcr: u32) -> Result<Control, UnsupportedControl> {
    let enabled_exceptions = (fpcr >> FPCR_EXCEPTION_ENABLE_SHIFT) & EXCEPTIONS;
    if enabled_exceptions != 0 {
        return Err(UnsupportedControl { enabled_exceptions });
    }
    // Integer conversions always interpret half as IEEE, regardless of AHP.
    Ok(Control(fpcr & !FPCR_AHP))
}

/// Interpret the integer exactly, scale by a power of two, then round once to
/// the destination format. Quad holds every supported integer without loss.
pub fn from_integer(
    integer: IntegerFormat,
    destination: Format,
    frac_bits: u8,
    fpcr: u32,
    bits: u64,
) -> Result<Outcome, UnsupportedControl> {
    let control = control(fpcr)?;
    let bits = bits & integer.width.mask();
    let value = if integer.signed {
        let shift = u64::BITS - integer.width.bits();
        let signed = ((bits << shift) as i64) >> shift;
        Quad::from_i128(i128::from(signed)).value
    } else {
        Quad::from_u128(u128::from(bits)).value
    };
    let value = value.scalbn(-i32::from(frac_bits));
    Ok(super::precision::round_ieee(
        value,
        destination,
        control,
        control.round(),
        true,
        false,
    ))
}

fn source_value(source: Format, bits: u64) -> Quad {
    match source {
        Format::Half => widen(Half::from_bits(u128::from(bits))),
        Format::Single => widen(Single::from_bits(u128::from(bits))),
        Format::Double => widen(Double::from_bits(u128::from(bits))),
    }
}

/// Scale the exact input, round to an integer, then saturate. Invalid conversion
/// suppresses inexact for this lane; unpacked input-denormal status is retained.
pub fn to_integer(
    source: Format,
    integer: IntegerFormat,
    frac_bits: u8,
    rounding: IntegerRounding,
    fpcr: u32,
    bits: u64,
) -> Result<Outcome, UnsupportedControl> {
    let control = control(fpcr)?;
    let mut exceptions = 0;
    let operand = unpack(source, bits, control, &mut exceptions);
    // NaN converts directly to integer zero. In particular, signaling NaN
    // must not enter widening's exact-value contract or get quieted first.
    if operand.class.nan() {
        return Ok(Outcome {
            bits: 0,
            exceptions: exceptions | INVALID,
        });
    }
    let value = source_value(source, operand.bits).scalbn(i32::from(frac_bits));
    let mut exact = false;
    let converted = if integer.signed {
        value
            .to_i128_r(integer.width.bits() as usize, rounding.round(), &mut exact)
            .map(|value| value as u64)
    } else {
        value
            .to_u128_r(integer.width.bits() as usize, rounding.round(), &mut exact)
            .map(|value| value as u64)
    };
    if converted.status.contains(Status::INVALID_OP) {
        exceptions |= INVALID;
    } else if converted.status.contains(Status::INEXACT) {
        exceptions |= INEXACT;
    }
    Ok(Outcome {
        bits: converted.value & integer.width.mask(),
        exceptions,
    })
}

/// FJCVTZS truncates Double and returns its low 32 integer bits, rather than
/// saturating. Its Z result distinguishes exact signed integers from coercions.
pub fn to_javascript(fpcr: u32, bits: u64) -> Result<JavaScriptOutcome, UnsupportedControl> {
    let control = control(fpcr)?;
    let mut exceptions = 0;
    let operand = unpack(Format::Double, bits, control, &mut exceptions);
    if operand.class.nan() || operand.class == Class::Infinity {
        return Ok(JavaScriptOutcome {
            result: Outcome {
                bits: 0,
                exceptions: exceptions | INVALID,
            },
            nzcv: 0,
        });
    }
    if operand.class == Class::Zero {
        // A flushed positive subnormal is numerically +0 but is not exact JS
        // input zero. Negative zero likewise clears Z without setting IXC.
        let exact_zero = !operand.negative && bits & Format::Double.fraction_mask() == 0;
        return Ok(JavaScriptOutcome {
            result: Outcome {
                bits: 0,
                exceptions,
            },
            nzcv: if exact_zero { NZCV_ZERO } else { 0 },
        });
    }

    let fraction_bits = Format::Double.fraction_bits();
    let exponent = (operand.bits & Format::Double.exponent_mask()) >> fraction_bits;
    let fraction = operand.bits & Format::Double.fraction_mask();
    let (significand, exponent) = if exponent == 0 {
        (fraction, DOUBLE_MINIMUM_EXPONENT)
    } else {
        (
            fraction | (1 << fraction_bits),
            exponent as i32 - DOUBLE_EXPONENT_BIAS,
        )
    };
    let shift = exponent - fraction_bits as i32;
    let (low_bits, invalid, inexact) = if shift >= 0 {
        // Such a Double has exponent >=52 and cannot fit in signed32. Large
        // powers of two have no low32 bits, so no oversized shift is needed.
        let low_bits = if shift >= JAVASCRIPT_WIDTH.bits() as i32 {
            0
        } else {
            (significand << shift) & JAVASCRIPT_WIDTH.mask()
        };
        (low_bits, true, false)
    } else {
        let discarded = (-shift) as u32;
        let (magnitude, inexact) = if discarded >= u64::BITS {
            (0, true)
        } else {
            (
                significand >> discarded,
                significand & ((1 << discarded) - 1) != 0,
            )
        };
        let limit = JAVASCRIPT_SIGN_LIMIT - u64::from(!operand.negative);
        (
            magnitude & JAVASCRIPT_WIDTH.mask(),
            magnitude > limit,
            inexact,
        )
    };
    if invalid {
        exceptions |= INVALID;
    } else if inexact {
        exceptions |= INEXACT;
    }
    let bits = if operand.negative {
        low_bits.wrapping_neg() & JAVASCRIPT_WIDTH.mask()
    } else {
        low_bits
    };
    Ok(JavaScriptOutcome {
        result: Outcome { bits, exceptions },
        nzcv: if !invalid && !inexact { NZCV_ZERO } else { 0 },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::floating::{
        FPCR_AH, FPCR_FIZ, FPCR_FZ, FPCR_FZ16, FPCR_ROUNDING_SHIFT, INPUT_DENORMAL, OVERFLOW,
        UNDERFLOW,
    };

    const SIGNED16: IntegerFormat = IntegerFormat {
        width: IntegerWidth::Bits16,
        signed: true,
    };
    const UNSIGNED32: IntegerFormat = IntegerFormat {
        width: IntegerWidth::Bits32,
        signed: false,
    };
    const UNSIGNED64: IntegerFormat = IntegerFormat {
        width: IntegerWidth::Bits64,
        signed: false,
    };

    #[test]
    fn integer_sign_extension_ignores_poisoned_high_bits() {
        for width in [
            IntegerWidth::Bits16,
            IntegerWidth::Bits32,
            IntegerWidth::Bits64,
        ] {
            assert_eq!(width.mask().count_ones(), width.bits());
            assert_eq!(
                from_integer(
                    IntegerFormat {
                        width,
                        signed: true
                    },
                    Format::Double,
                    0,
                    0,
                    u64::MAX
                ),
                Ok(Outcome {
                    bits: 0xbff0000000000000,
                    exceptions: 0
                })
            );
        }
        assert_eq!(
            from_integer(SIGNED16, Format::Single, 1, 0, 0x1234ffff),
            Ok(Outcome {
                bits: 0xbf000000,
                exceptions: 0
            })
        );
    }

    #[test]
    fn fixed_integer_rounds_directly_to_half_without_double_rounding() {
        let halfway_plus_one = (1 << 63) | (1 << 52) | 1;
        assert_eq!(
            from_integer(UNSIGNED64, Format::Half, 63, FPCR_AHP, halfway_plus_one),
            Ok(Outcome {
                bits: 0x3c01,
                exceptions: INEXACT
            })
        );
        for (fpcr, bits, exceptions) in [
            (0, 0x400, UNDERFLOW | INEXACT),
            (FPCR_AH, 0x400, INEXACT),
            (FPCR_FZ16, 0, UNDERFLOW),
            (FPCR_AH | FPCR_FZ16, 0x400, INEXACT),
        ] {
            assert_eq!(
                from_integer(SIGNED16, Format::Half, 26, fpcr, 4095),
                Ok(Outcome { bits, exceptions })
            );
        }
    }

    #[test]
    fn integer_to_half_observes_ieee_overflow_and_output_flush() {
        for (fpcr, bits, exceptions) in [
            (0, 1, 0),
            (FPCR_FZ16, 0, UNDERFLOW),
            (FPCR_FZ16 | FPCR_AH, 0, UNDERFLOW | INEXACT),
        ] {
            assert_eq!(
                from_integer(UNSIGNED32, Format::Half, 24, fpcr, 1),
                Ok(Outcome { bits, exceptions })
            );
        }
        for (fpcr, bits) in [
            (FPCR_AHP, 0x7c00),
            (FPCR_AHP | (3 << FPCR_ROUNDING_SHIFT), 0x7bff),
        ] {
            assert_eq!(
                from_integer(UNSIGNED32, Format::Half, 0, fpcr, 65536),
                Ok(Outcome {
                    bits,
                    exceptions: OVERFLOW | INEXACT
                })
            );
        }
        assert_eq!(
            from_integer(SIGNED16, Format::Half, 64, FPCR_AH, 0),
            Ok(Outcome {
                bits: 0,
                exceptions: 0
            })
        );
    }

    #[test]
    fn full_width_integer_endpoints_survive_exact_scaling_and_saturation() {
        let signed64 = IntegerFormat {
            width: IntegerWidth::Bits64,
            signed: true,
        };
        assert_eq!(
            from_integer(signed64, Format::Double, 0, 0, 1 << 63),
            Ok(Outcome {
                bits: 0xc3e0000000000000,
                exceptions: 0,
            })
        );
        assert_eq!(
            from_integer(UNSIGNED64, Format::Double, 0, 0, u64::MAX),
            Ok(Outcome {
                bits: 0x43f0000000000000,
                exceptions: INEXACT,
            })
        );
        for (integer, source, bits, exceptions) in [
            (signed64, 0xc3e0000000000000, 1 << 63, 0),
            (signed64, 0x43e0000000000000, (1 << 63) - 1, INVALID),
            (UNSIGNED64, 0x43f0000000000000, u64::MAX, INVALID),
            (UNSIGNED64, 0x8000000000000000, 0, 0),
        ] {
            assert_eq!(
                to_integer(
                    Format::Double,
                    integer,
                    0,
                    IntegerRounding::TowardZero,
                    0,
                    source,
                ),
                Ok(Outcome { bits, exceptions })
            );
        }
    }

    #[test]
    fn every_nan_class_converts_to_zero_and_invalid_even_in_alternative_half() {
        for (source, nan) in [
            (Format::Half, 0x7c01),
            (Format::Half, 0xfe01),
            (Format::Single, 0x7f800001),
            (Format::Single, 0xffc00001),
            (Format::Double, 0x7ff0000000000001),
            (Format::Double, 0xfff8000000000001),
        ] {
            assert_eq!(
                to_integer(
                    source,
                    UNSIGNED64,
                    64,
                    IntegerRounding::NearestAway,
                    FPCR_AHP | FPCR_AH,
                    nan,
                ),
                Ok(Outcome {
                    bits: 0,
                    exceptions: INVALID,
                })
            );
        }
    }

    #[test]
    fn instruction_rounding_and_unsigned_negative_zero_are_distinct() {
        for (rounding, bits, exceptions) in [
            (IntegerRounding::NearestEven, 0, INEXACT),
            (IntegerRounding::NearestAway, 0, INVALID),
            (IntegerRounding::TowardPositive, 0, INEXACT),
            (IntegerRounding::TowardNegative, 0, INVALID),
            (IntegerRounding::TowardZero, 0, INEXACT),
        ] {
            assert_eq!(
                to_integer(
                    Format::Double,
                    UNSIGNED32,
                    0,
                    rounding,
                    0,
                    0xbfe0000000000000
                ),
                Ok(Outcome { bits, exceptions })
            );
        }
        for (rounding, bits) in [
            (IntegerRounding::NearestEven, 2),
            (IntegerRounding::NearestAway, 3),
            (IntegerRounding::TowardPositive, 3),
            (IntegerRounding::TowardNegative, 2),
            (IntegerRounding::TowardZero, 2),
        ] {
            assert_eq!(
                to_integer(
                    Format::Double,
                    SIGNED16,
                    0,
                    rounding,
                    3 << FPCR_ROUNDING_SHIFT,
                    0x4004000000000000
                ),
                Ok(Outcome {
                    bits,
                    exceptions: INEXACT
                })
            );
        }
    }

    #[test]
    fn saturation_suppresses_inexact_but_does_not_set_qc() {
        for (bits, rounding, expected, exceptions) in [
            (
                0x40dfffe000000000,
                IntegerRounding::NearestEven,
                0x7fff,
                INVALID,
            ),
            (
                0x40dfffe000000000,
                IntegerRounding::TowardZero,
                0x7fff,
                INEXACT,
            ),
            (
                0xc0e0001000000000,
                IntegerRounding::NearestEven,
                0x8000,
                INEXACT,
            ),
            (
                0x7ff0000000000000,
                IntegerRounding::TowardZero,
                0x7fff,
                INVALID,
            ),
            (
                0xfff0000000000000,
                IntegerRounding::TowardZero,
                0x8000,
                INVALID,
            ),
            (0xfff8000000000001, IntegerRounding::TowardZero, 0, INVALID),
        ] {
            assert_eq!(
                to_integer(Format::Double, SIGNED16, 0, rounding, 0, bits),
                Ok(Outcome {
                    bits: expected,
                    exceptions
                })
            );
        }
    }

    #[test]
    fn input_flush_and_exact_scaling_keep_integer_conversion_status() {
        for (fpcr, exceptions) in [
            (0, INEXACT),
            (FPCR_AH | FPCR_FZ, INEXACT),
            (FPCR_FIZ, 0),
            (FPCR_FZ, INPUT_DENORMAL),
            (FPCR_FIZ | FPCR_FZ, INPUT_DENORMAL),
        ] {
            assert_eq!(
                to_integer(
                    Format::Single,
                    SIGNED16,
                    0,
                    IntegerRounding::TowardZero,
                    fpcr,
                    1
                ),
                Ok(Outcome {
                    bits: 0,
                    exceptions
                })
            );
        }
        assert_eq!(
            to_integer(
                Format::Half,
                SIGNED16,
                24,
                IntegerRounding::TowardZero,
                FPCR_AHP,
                1
            ),
            Ok(Outcome {
                bits: 1,
                exceptions: 0
            })
        );
        assert_eq!(
            to_integer(
                Format::Half,
                SIGNED16,
                24,
                IntegerRounding::TowardZero,
                FPCR_FZ16,
                1
            ),
            Ok(Outcome {
                bits: 0,
                exceptions: 0
            })
        );
    }

    #[test]
    fn javascript_modulo_range_fraction_and_zero_flags() {
        for (source, bits, exceptions, nzcv) in [
            (0, 0, 0, NZCV_ZERO),
            (0x8000000000000000, 0, 0, 0),
            (0x3ff0000000000000, 1, 0, NZCV_ZERO),
            (0xbff8000000000000, 0xffffffff, INEXACT, 0),
            (0x41e0000000000000, 0x80000000, INVALID, 0),
            (0xc1e0000000000000, 0x80000000, 0, NZCV_ZERO),
            (0x41f0000000100000, 1, INVALID, 0),
            (0xc1f0000000100000, 0xffffffff, INVALID, 0),
            (0x7fefffffffffffff, 0, INVALID, 0),
            (0xfff0000000000000, 0, INVALID, 0),
            (0x7ff8000000000001, 0, INVALID, 0),
            (0x41dfffffffe00000, 0x7fffffff, INEXACT, 0),
        ] {
            assert_eq!(
                to_javascript(0, source),
                Ok(JavaScriptOutcome {
                    result: Outcome { bits, exceptions },
                    nzcv
                })
            );
        }
        for source in [1, 0x8000000000000001] {
            for (fpcr, exceptions) in [
                (FPCR_FZ, INPUT_DENORMAL),
                (FPCR_FIZ, 0),
                (FPCR_AH | FPCR_FIZ, 0),
                (FPCR_AH | FPCR_FZ, INEXACT),
            ] {
                assert_eq!(
                    to_javascript(fpcr, source),
                    Ok(JavaScriptOutcome {
                        result: Outcome {
                            bits: 0,
                            exceptions
                        },
                        nzcv: 0
                    })
                );
            }
        }
    }

    #[test]
    fn retained_enables_decline_before_integer_or_special_value_effects() {
        for exception in [
            INVALID,
            super::super::DIVIDE_BY_ZERO,
            OVERFLOW,
            UNDERFLOW,
            INEXACT,
            INPUT_DENORMAL,
            EXCEPTIONS,
        ] {
            let fpcr = exception << FPCR_EXCEPTION_ENABLE_SHIFT;
            let unsupported = Err(UnsupportedControl {
                enabled_exceptions: exception,
            });
            assert_eq!(
                from_integer(SIGNED16, Format::Half, 0, fpcr, 0),
                unsupported
            );
            assert_eq!(
                to_integer(
                    Format::Half,
                    SIGNED16,
                    0,
                    IntegerRounding::TowardZero,
                    fpcr,
                    0x7e01
                ),
                unsupported
            );
            assert_eq!(
                to_javascript(fpcr, 0),
                Err(UnsupportedControl {
                    enabled_exceptions: exception
                })
            );
        }
    }
}
