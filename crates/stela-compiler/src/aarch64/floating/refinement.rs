//! FRECPS and FRSQRTS fused steps, including the halving before rounding.
use super::{
    Class, Control, FPCR_FIZ, FPCR_FZ, FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT, Format, Outcome,
    UnsupportedControl, nan, negate, precision, unpack, widen,
};
use crate::aarch64::simd::refinement::Kind;
use rustc_apfloat::{
    Float, Round, Status,
    ieee::{Double, Half, Quad, Single},
};

const RECIPROCAL_ADDEND: u128 = 2;
const RECIPROCAL_SQUARE_ROOT_ADDEND: u128 = 3;
const HALVE_EXPONENT: i32 = -1;
const ODD_SIGNIFICAND_BIT: u128 = 1;

fn wide(format: Format, bits: u64) -> Quad {
    let bits = u128::from(bits);
    match format {
        Format::Half => widen(Half::from_bits(bits)),
        Format::Single => widen(Single::from_bits(bits)),
        Format::Double => widen(Double::from_bits(bits)),
    }
}

fn finite(format: Format, kind: Kind, control: Control, left: u64, right: u64) -> Outcome {
    let addend = Quad::from_u128(match kind {
        Kind::Reciprocal => RECIPROCAL_ADDEND,
        Kind::ReciprocalSquareRoot => RECIPROCAL_SQUARE_ROOT_ADDEND,
    })
    .value;
    // Every H/S/D product is exact in Quad and fits its exponent range. Adding
    // the constant can lose distant bits. Round-to-odd preserves their side of
    // all H/S/D rounding boundaries (at least 59 additional precision bits).
    let intermediate = wide(format, left).mul_add_r(wide(format, right), addend, Round::TowardZero);
    let mut value = intermediate.value;
    if intermediate.status.contains(Status::INEXACT) {
        value = Quad::from_bits(value.to_bits() | ODD_SIGNIFICAND_BIT);
    }
    if kind == Kind::ReciprocalSquareRoot {
        value = value.scalbn(HALVE_EXPONENT);
    }
    if value.is_zero() {
        return Outcome {
            bits: if control.round() == Round::TowardNegative {
                format.sign_mask()
            } else {
                0
            },
            exceptions: 0,
        };
    }
    // A jammed Quad cannot be exact in a <=53-bit target, so final conversion
    // supplies IXC. Do not OR wide IXC into the AH0 tiny-flush UFC-only result.
    precision::round_ieee(value, format, control, control.round(), true, false)
}

/// Fresh status only. AH suppresses all exceptions, so retained enables cannot
/// trap; AH0 retains the current explicit enabled-exception refusal boundary.
pub fn evaluate(
    kind: Kind,
    format: Format,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<Outcome, UnsupportedControl> {
    let original = Control(fpcr);
    let left = negate(format, left, original);
    let control = if original.alternative() {
        Control((fpcr | FPCR_FIZ | FPCR_FZ) & !(FPCR_ROUNDING_MASK << FPCR_ROUNDING_SHIFT))
    } else {
        Control::checked(fpcr)?
    };
    let mut exceptions = 0;
    let left = unpack(format, left, control, &mut exceptions);
    let right = unpack(format, right, control, &mut exceptions);
    let mut result = if let Some(bits) = nan(format, left, right, control, &mut exceptions) {
        Outcome {
            bits,
            exceptions: 0,
        }
    } else if left.class == Class::Infinity && right.class == Class::Zero
        || left.class == Class::Zero && right.class == Class::Infinity
    {
        Outcome {
            bits: match kind {
                Kind::Reciprocal => u64::from(format.exponent_bias() + 1) << format.fraction_bits(),
                Kind::ReciprocalSquareRoot => {
                    u64::from(format.exponent_bias()) << format.fraction_bits()
                        | 1 << (format.fraction_bits() - 1)
                }
            },
            exceptions: 0,
        }
    } else if left.class == Class::Infinity || right.class == Class::Infinity {
        Outcome {
            bits: format.infinity(left.negative ^ right.negative),
            exceptions: 0,
        }
    } else {
        finite(format, kind, control, left.bits, right.bits)
    };
    result.exceptions = if original.alternative() {
        0
    } else {
        result.exceptions | exceptions
    };
    Ok(result)
}

#[cfg(test)]
mod tests;
