//! Non-widening BF16 arithmetic, rounded once at BF16 precision.
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
    // Widen the already-rounded representation exactly; keep the original
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
mod tests {
    use super::*;
    use floating::{
        EXCEPTIONS, FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_FIZ, FPCR_FZ,
        FPCR_ROUNDING_SHIFT, INEXACT, INVALID, OVERFLOW, UNDERFLOW,
    };

    const ONE: u16 = 0x3f80;
    const NEGATIVE_ONE: u16 = 0xbf80;
    const TWO: u16 = 0x4000;
    const POSITIVE_ZERO: u16 = 0;
    const NEGATIVE_ZERO: u16 = 0x8000;
    const INFINITY: u16 = 0x7f80;
    const MAXIMUM: u16 = 0x7f7f;
    const MINIMUM: u16 = 0x0080;
    const HALF: u16 = 0x3f00;
    const QUIET_NAN: u16 = 0x7fc1;
    const SIGNALING_NAN: u16 = 0x7f81;

    fn outcome(bits: u16, exceptions: u32) -> Result<Outcome, UnsupportedControl> {
        Ok(Outcome {
            bits: u64::from(bits),
            exceptions,
        })
    }

    #[test]
    fn binary_rounds_directly_at_bfloat_precision_in_all_modes() {
        for (rounding, product) in [0x3f80, 0x3f80, 0x3f7f, 0x3f7f].into_iter().enumerate() {
            let fpcr = (rounding as u32) << FPCR_ROUNDING_SHIFT;
            assert_eq!(
                binary(BfloatBinaryOperation::Add, fpcr, ONE, ONE),
                outcome(TWO, 0)
            );
            assert_eq!(
                binary(BfloatBinaryOperation::Subtract, fpcr, ONE, ONE),
                outcome(
                    if rounding == 2 {
                        NEGATIVE_ZERO
                    } else {
                        POSITIVE_ZERO
                    },
                    0
                )
            );
            assert_eq!(
                binary(BfloatBinaryOperation::Multiply, fpcr, 0x3f81, 0x3f7e),
                outcome(product, INEXACT)
            );
        }
    }

    #[test]
    fn fused_target_precision_avoids_single_double_rounding() {
        assert_eq!(fused(0, 0xb080, 0x3fc0, 0x3f81), outcome(0x3fc1, INEXACT));
        assert_eq!(fused(0, NEGATIVE_ONE, 0x3f81, 0x3f7e), outcome(0xb880, 0));
    }

    #[test]
    fn alternative_tininess_uses_unconstrained_bfloat_rounding() {
        const NEGATIVE_MINIMUM_SUBNORMAL: u16 = 0x8001;
        const QUARTER: u16 = 0x3e80;
        assert_eq!(
            fused(0, MINIMUM, NEGATIVE_MINIMUM_SUBNORMAL, QUARTER),
            outcome(MINIMUM, UNDERFLOW | INEXACT)
        );
        assert_eq!(
            fused(
                FPCR_AH | FPCR_FZ,
                MINIMUM,
                NEGATIVE_MINIMUM_SUBNORMAL,
                QUARTER
            ),
            outcome(MINIMUM, INPUT_DENORMAL | INEXACT)
        );
        assert_eq!(
            fused(FPCR_AH | FPCR_FZ, 0, MINIMUM, ONE - 1),
            outcome(0, UNDERFLOW | INEXACT)
        );
    }

    #[test]
    fn input_flush_and_alternative_late_denormal_status_are_distinct() {
        for (fpcr, bits, exceptions) in [
            (0, 1, 0),
            (FPCR_FIZ, 0, 0),
            (FPCR_FZ, 0, INPUT_DENORMAL),
            (FPCR_AH, 1, INPUT_DENORMAL),
            (FPCR_AH | FPCR_FIZ, 0, 0),
        ] {
            assert_eq!(
                binary(BfloatBinaryOperation::Multiply, fpcr, 1, ONE),
                outcome(bits, exceptions)
            );
        }
        assert_eq!(
            binary(BfloatBinaryOperation::Multiply, FPCR_FZ, MINIMUM, HALF),
            outcome(0, UNDERFLOW)
        );
        assert_eq!(
            binary(
                BfloatBinaryOperation::Multiply,
                FPCR_AH | FPCR_FZ,
                MINIMUM,
                HALF
            ),
            outcome(0, UNDERFLOW | INEXACT)
        );
    }

    #[test]
    fn directed_overflow_and_nan_priority_use_arm_policy() {
        assert_eq!(
            binary(BfloatBinaryOperation::Multiply, 0, MAXIMUM, TWO),
            outcome(INFINITY, OVERFLOW | INEXACT)
        );
        assert_eq!(
            binary(
                BfloatBinaryOperation::Multiply,
                3 << FPCR_ROUNDING_SHIFT,
                MAXIMUM,
                TWO
            ),
            outcome(MAXIMUM, OVERFLOW | INEXACT)
        );
        assert_eq!(fused(0, QUIET_NAN, 0, INFINITY), outcome(0x7fc0, INVALID));
        assert_eq!(
            fused(FPCR_AH, QUIET_NAN, 0, INFINITY),
            outcome(QUIET_NAN, 0)
        );
        assert_eq!(
            fused(FPCR_AH | FPCR_DN, QUIET_NAN, 0, INFINITY),
            outcome(0xffc0, 0)
        );
    }

    #[test]
    fn minmax_alternative_number_policy_and_clamp_preserve_status() {
        assert_eq!(
            minmax(MinMaxOperation::Maximum, FPCR_AH, QUIET_NAN, ONE),
            outcome(ONE, INVALID)
        );
        assert_eq!(
            minmax(MinMaxOperation::Minimum, FPCR_AH, ONE, SIGNALING_NAN),
            outcome(SIGNALING_NAN, INVALID)
        );
        assert_eq!(
            minmax(MinMaxOperation::MaximumNumber, FPCR_AH, QUIET_NAN, ONE),
            outcome(ONE, 0)
        );
        assert_eq!(
            minmax(
                MinMaxOperation::MinimumNumber,
                FPCR_AH,
                QUIET_NAN,
                SIGNALING_NAN
            ),
            outcome(QUIET_NAN, INVALID)
        );
        assert_eq!(clamp(0, POSITIVE_ZERO, ONE, TWO), outcome(ONE, 0));
        assert_eq!(clamp(0, SIGNALING_NAN, ONE, TWO), outcome(TWO, INVALID));
    }

    #[test]
    fn negate_honors_alternative_nan_sign_without_quieting() {
        assert_eq!(negate(0, SIGNALING_NAN), SIGNALING_NAN | NEGATIVE_ZERO);
        assert_eq!(negate(FPCR_AH, SIGNALING_NAN), SIGNALING_NAN);
        assert_eq!(negate(FPCR_AH, INFINITY), INFINITY | NEGATIVE_ZERO);
        assert_eq!(negate(FPCR_AH, 1), 1 | NEGATIVE_ZERO);
    }

    #[test]
    fn retained_enables_require_caller_execution_profile_handling() {
        let fpcr = EXCEPTIONS << FPCR_EXCEPTION_ENABLE_SHIFT;
        let expected = Err(UnsupportedControl {
            enabled_exceptions: EXCEPTIONS,
        });
        assert_eq!(binary(BfloatBinaryOperation::Add, fpcr, ONE, ONE), expected);
        assert_eq!(fused(fpcr, ONE, ONE, ONE), expected);
        assert_eq!(minmax(MinMaxOperation::Minimum, fpcr, ONE, ONE), expected);
        assert_eq!(clamp(fpcr, ONE, ONE, ONE), expected);
    }
}
