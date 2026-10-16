//! Nonwidening BF arithmetic rounds once at BF precision, independently of
//! host FP state. Callers own streaming effective controls and status commit.
use super::super::{
    self as floating, BinaryOperation, Class, Control, Format, INPUT_DENORMAL, Outcome,
    UnsupportedControl, apply, clamped_overflow, fused as fused_math, minmax as minmax_math,
    process_denormals, rounded_outcome, tiny, unpack, widen,
};
use super::{BFLOAT16_TO_SINGLE_SHIFT, widen as widen_bfloat};
use minmax_math::MinMaxOperation;
use rustc_apfloat::{
    Float, Round, Status, StatusAnd,
    ieee::{BFloat, Quad, Single},
};

const SINGLE_FORMAT: Format = Format::Single;
const BFLOAT_EXPONENT_MASK: u16 =
    (SINGLE_FORMAT.exponent_mask() >> BFLOAT16_TO_SINGLE_SHIFT) as u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BfloatBinaryOperation {
    Add,
    Subtract,
    Multiply,
}

impl BfloatBinaryOperation {
    const fn ordinary(self) -> BinaryOperation {
        match self {
            Self::Add => BinaryOperation::Add,
            Self::Subtract => BinaryOperation::Subtract,
            Self::Multiply => BinaryOperation::Multiply,
        }
    }
}

fn exceptional(bits: u16) -> bool {
    bits & BFLOAT_EXPONENT_MASK == BFLOAT_EXPONENT_MASK
}

fn narrow(result: Outcome) -> Outcome {
    Outcome {
        bits: result.bits >> BFLOAT16_TO_SINGLE_SHIFT,
        exceptions: result.exceptions,
    }
}

fn bfloat(bits: u64) -> BFloat {
    BFloat::from_bits(u128::from(bits >> BFLOAT16_TO_SINGLE_SHIFT))
}

fn round_result(
    result: StatusAnd<BFloat>,
    control: Control,
    tiny: bool,
    overflow: bool,
) -> Outcome {
    // Widen the already-rounded representation exactly; retain the original
    // BF operation's status. The shared output policy then uses Single's sign
    // position for both normal results and flushed zeros.
    let widened = StatusAnd {
        status: result.status,
        value: Single::from_bits(result.value.to_bits() << BFLOAT16_TO_SINGLE_SHIFT),
    };
    narrow(rounded_outcome(
        SINGLE_FORMAT,
        control,
        widened,
        tiny,
        overflow,
    ))
}

/// BFAdd/BFSub/BFMul with fresh status and a low-16-bit result.
/// The caller must remove exception enables suppressed by its execution mode.
pub fn binary(
    operation: BfloatBinaryOperation,
    fpcr: u32,
    left: u16,
    right: u16,
) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let operation = operation.ordinary();
    if exceptional(left) || exceptional(right) {
        // NaN/Infinity handling depends on no target-precision finite rounding.
        return floating::evaluate(
            SINGLE_FORMAT,
            operation,
            fpcr,
            u64::from(widen_bfloat(left)),
            u64::from(widen_bfloat(right)),
        )
        .map(narrow);
    }
    let mut exceptions = 0;
    let left = unpack(
        SINGLE_FORMAT,
        u64::from(widen_bfloat(left)),
        control,
        &mut exceptions,
    );
    let right = unpack(
        SINGLE_FORMAT,
        u64::from(widen_bfloat(right)),
        control,
        &mut exceptions,
    );
    let left_value = bfloat(left.bits);
    let right_value = bfloat(right.bits);
    let result = apply(operation, left_value, right_value, control.round());
    let tiny = tiny(operation, left_value, right_value, result, control);
    let overflow = result.status.contains(Status::OVERFLOW)
        || clamped_overflow(operation, left_value, right_value, result);
    let mut outcome = round_result(result, control, tiny, overflow);
    process_denormals(SINGLE_FORMAT, control, left, right, &mut exceptions);
    outcome.exceptions |= exceptions;
    Ok(outcome)
}

/// BFMulAdd with one BF target rounding; BFNeg transformations precede this
/// helper. Single FMA followed by BF conversion can double round.
pub fn fused(fpcr: u32, addend: u16, left: u16, right: u16) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    if [addend, left, right].into_iter().any(exceptional) {
        return fused_math::evaluate(
            SINGLE_FORMAT,
            fused_math::FusedOperation::Add,
            fpcr,
            u64::from(widen_bfloat(addend)),
            u64::from(widen_bfloat(left)),
            u64::from(widen_bfloat(right)),
        )
        .map(narrow);
    }
    let mut exceptions = 0;
    let addend = unpack(
        SINGLE_FORMAT,
        u64::from(widen_bfloat(addend)),
        control,
        &mut exceptions,
    );
    let left = unpack(
        SINGLE_FORMAT,
        u64::from(widen_bfloat(left)),
        control,
        &mut exceptions,
    );
    let right = unpack(
        SINGLE_FORMAT,
        u64::from(widen_bfloat(right)),
        control,
        &mut exceptions,
    );
    let addend_value = bfloat(addend.bits);
    let left_value = bfloat(left.bits);
    let right_value = bfloat(right.bits);
    let result = left_value.mul_add_r(right_value, addend_value, control.round());
    let tiny = fused_math::tiny(addend_value, left_value, right_value, result, control);
    let overflow = result.status.contains(Status::OVERFLOW)
        || result.value.abs().bitwise_eq(BFloat::largest())
            && result.status.contains(Status::INEXACT)
            && {
                let extended = widen(left_value).mul_add_r(
                    widen(right_value),
                    widen(addend_value),
                    Round::TowardZero,
                );
                extended.value.abs() >= Quad::from_u128(1).value.scalbn(BFloat::MAX_EXP + 1)
            };
    let mut outcome = round_result(result, control, tiny, overflow);
    if control.alternative()
        && [addend, left, right]
            .into_iter()
            .any(|operand| operand.class == Class::Denormal)
    {
        exceptions |= INPUT_DENORMAL;
    }
    outcome.exceptions |= exceptions;
    Ok(outcome)
}

/// BFMin/Max/MinNum/MaxNum select an already-exact BF value. Single comparison
/// shares the same NaN, zero-sign, flush and denormal policy without rounding.
pub fn minmax(
    operation: MinMaxOperation,
    fpcr: u32,
    left: u16,
    right: u16,
) -> Result<Outcome, UnsupportedControl> {
    minmax_math::evaluate(
        SINGLE_FORMAT,
        operation,
        fpcr,
        u64::from(widen_bfloat(left)),
        u64::from(widen_bfloat(right)),
    )
    .map(narrow)
}

/// BFClamp composes maximum-number then minimum-number, preserving both stages'
/// fresh status. The original destination supplies `value`.
pub fn clamp(fpcr: u32, value: u16, lower: u16, upper: u16) -> Result<Outcome, UnsupportedControl> {
    let maximum = minmax(MinMaxOperation::MaximumNumber, fpcr, lower, value)?;
    let mut result = minmax(
        MinMaxOperation::MinimumNumber,
        fpcr,
        maximum.bits as u16,
        upper,
    )?;
    result.exceptions |= maximum.exceptions;
    Ok(result)
}

/// Architectural BFNeg preserves a NaN's sign under AH; it raises no status.
pub fn negate(fpcr: u32, bits: u16) -> u16 {
    (floating::negate(SINGLE_FORMAT, u64::from(widen_bfloat(bits)), Control(fpcr))
        >> BFLOAT16_TO_SINGLE_SHIFT) as u16
}

#[cfg(test)]
mod tests;
