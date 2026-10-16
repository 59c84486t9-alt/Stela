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
mod tests;
