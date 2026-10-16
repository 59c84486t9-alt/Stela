//! Three-operand Arm fused arithmetic with one architectural rounding.
use super::{
    Class, Control, EXCEPTIONS, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, Format, INPUT_DENORMAL,
    INVALID, Operand, Outcome, UnsupportedControl, negate, rounded_outcome, unpack, widen,
};
use rustc_apfloat::{
    Float, FloatConvert, Round, Status, StatusAnd,
    ieee::{Double, Half, Quad, Single},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FusedOperation {
    Add,
    Subtract,
    NegatedAdd,
    NegatedSubtract,
}

impl FusedOperation {
    pub const fn negate_addend(self) -> bool {
        matches!(self, Self::NegatedAdd | Self::NegatedSubtract)
    }
    pub const fn negate_left(self) -> bool {
        matches!(self, Self::Subtract | Self::NegatedAdd)
    }
}

fn nan(
    format: Format,
    addend: Operand,
    left: Operand,
    right: Operand,
    control: Control,
    exceptions: &mut u32,
) -> Option<u64> {
    let operands = [addend, left, right];
    let signaling = operands
        .iter()
        .any(|operand| operand.class == Class::SignalingNaN);
    let selected = if control.alternative()
        && operands
            .iter()
            .filter(|operand| operand.class.nan())
            .count()
            >= 2
    {
        if left.class.nan() { left } else { right }
    } else {
        operands
            .iter()
            .find(|operand| operand.class == Class::SignalingNaN)
            .or_else(|| {
                operands
                    .iter()
                    .find(|operand| operand.class == Class::QuietNaN)
            })
            .copied()?
    };
    if signaling {
        *exceptions |= INVALID;
    }
    Some(if control.0 & FPCR_DN != 0 {
        control.default_nan(format)
    } else {
        selected.bits | format.quiet_bit()
    })
}

pub(super) fn tiny<F: Float>(
    addend: F,
    left: F,
    right: F,
    result: StatusAnd<F>,
    control: Control,
) -> bool {
    let minimum = F::smallest_normalized();
    if result.value.abs() < minimum {
        return !result.value.is_zero() || result.status.contains(Status::INEXACT);
    }
    if result.value.abs() != minimum || !result.status.contains(Status::INEXACT) {
        return false;
    }
    if !control.alternative() {
        return left.mul_add_r(right, addend, Round::TowardZero).value.abs() < minimum;
    }
    // A nonzero tiny fused cancellation bounds the addend's and product's
    // significant bits far below overflow. Double the addend and the smaller
    // product operand exactly, then test unconstrained rounding at twice min.
    let double = |value: F| {
        let scaled = value.scalbn(1);
        debug_assert!(scaled.is_finite() && scaled.scalbn(-1).bitwise_eq(value));
        scaled
    };
    let (left, right) = if left.abs() <= right.abs() {
        (double(left), right)
    } else {
        (left, double(right))
    };
    left.mul_add_r(right, double(addend), control.round())
        .value
        .abs()
        < double(minimum)
}

pub(super) fn finite<F: Float + FloatConvert<Quad>>(
    format: Format,
    addend: u64,
    left: u64,
    right: u64,
    control: Control,
) -> Outcome {
    let addend = F::from_bits(u128::from(addend));
    let left = F::from_bits(u128::from(left));
    let right = F::from_bits(u128::from(right));
    let result = left.mul_add_r(right, addend, control.round());
    let tiny = tiny(addend, left, right, result, control);
    let clamped_overflow =
        result.value.abs().bitwise_eq(F::largest()) && result.status.contains(Status::INEXACT) && {
            let extended = widen(left).mul_add_r(widen(right), widen(addend), Round::TowardZero);
            extended.value.abs() >= Quad::from_u128(1).value.scalbn(F::MAX_EXP + 1)
        };
    rounded_outcome(
        format,
        control,
        result,
        tiny,
        result.status.contains(Status::OVERFLOW) || clamped_overflow,
    )
}

/// Evaluate A + N*M after the instruction's FPNeg operations. State, sticky
/// status, lane selection and scalar merging remain the caller's responsibility.
pub fn evaluate(
    format: Format,
    operation: FusedOperation,
    fpcr: u32,
    addend: u64,
    left: u64,
    right: u64,
) -> Result<Outcome, UnsupportedControl> {
    let enabled_exceptions = (fpcr >> FPCR_EXCEPTION_ENABLE_SHIFT) & EXCEPTIONS;
    if enabled_exceptions != 0 {
        return Err(UnsupportedControl { enabled_exceptions });
    }
    let control = Control(fpcr);
    let addend = if operation.negate_addend() {
        negate(format, addend, control)
    } else {
        addend
    };
    let left = if operation.negate_left() {
        negate(format, left, control)
    } else {
        left
    };
    let mut exceptions = 0;
    let addend = unpack(format, addend, control, &mut exceptions);
    let left = unpack(format, left, control, &mut exceptions);
    let right = unpack(format, right, control, &mut exceptions);
    let invalid_product = left.class == Class::Infinity && right.class == Class::Zero
        || left.class == Class::Zero && right.class == Class::Infinity;
    if let Some(mut bits) = nan(format, addend, left, right, control, &mut exceptions) {
        if !control.alternative() && addend.class == Class::QuietNaN && invalid_product {
            bits = control.default_nan(format);
            exceptions |= INVALID;
        }
        return Ok(Outcome { bits, exceptions });
    }
    let product_negative = left.negative ^ right.negative;
    let product_infinite = left.class == Class::Infinity || right.class == Class::Infinity;
    if invalid_product
        || addend.class == Class::Infinity
            && product_infinite
            && addend.negative != product_negative
    {
        return Ok(Outcome {
            bits: control.default_nan(format),
            exceptions: exceptions | INVALID,
        });
    }
    let mut result = if addend.class == Class::Infinity || product_infinite {
        Outcome {
            bits: format.infinity(if addend.class == Class::Infinity {
                addend.negative
            } else {
                product_negative
            }),
            exceptions: 0,
        }
    } else if addend.class == Class::Zero
        && (left.class == Class::Zero || right.class == Class::Zero)
        && addend.negative == product_negative
    {
        Outcome {
            bits: if addend.negative {
                format.sign_mask()
            } else {
                0
            },
            exceptions: 0,
        }
    } else {
        match format {
            Format::Half => finite::<Half>(format, addend.bits, left.bits, right.bits, control),
            Format::Single => finite::<Single>(format, addend.bits, left.bits, right.bits, control),
            Format::Double => finite::<Double>(format, addend.bits, left.bits, right.bits, control),
        }
    };
    if control.alternative()
        && format != Format::Half
        && [addend, left, right]
            .iter()
            .any(|operand| operand.class == Class::Denormal)
    {
        exceptions |= INPUT_DENORMAL;
    }
    result.exceptions |= exceptions;
    Ok(result)
}

#[cfg(test)]
mod tests;
