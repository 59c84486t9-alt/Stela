//! Shared Arm FP fields and binary arithmetic outcomes, independent of native execution.
//! FP/FP16/AFP enabled, non-streaming; numerical trap delivery remains unsupported.
pub mod absolute_minmax;
pub mod bfloat16;
pub mod comparison;
pub mod complex;
pub mod dot;
pub mod estimate;
pub mod exponent;
pub mod features;
pub mod fp8;
pub mod fused;
pub mod integer;
pub mod minmax;
pub mod precision;
pub mod refinement;
pub mod rounding;
pub mod sign;
pub mod sqrt;
pub mod widening;

use rustc_apfloat::{
    Float, FloatConvert, Round, Status, StatusAnd,
    ieee::{Double, Half, Quad, Single},
};

pub const INVALID: u32 = 1 << 0;
pub const DIVIDE_BY_ZERO: u32 = 1 << 1;
pub const OVERFLOW: u32 = 1 << 2;
pub const UNDERFLOW: u32 = 1 << 3;
pub const INEXACT: u32 = 1 << 4;
pub const INPUT_DENORMAL: u32 = 1 << 7;
pub const EXCEPTIONS: u32 =
    INVALID | DIVIDE_BY_ZERO | OVERFLOW | UNDERFLOW | INEXACT | INPUT_DENORMAL;
pub const FPCR_EXCEPTION_ENABLE_SHIFT: u32 = 8;
pub const FPCR_FIZ: u32 = 1 << 0;
pub const FPCR_AH: u32 = 1 << 1;
pub const FPCR_EBF: u32 = 1 << 13;
pub const FPCR_NEP: u32 = 1 << 2;
pub const FPCR_FZ16: u32 = 1 << 19;
pub const FPCR_ROUNDING_SHIFT: u32 = 22;
pub const FPCR_ROUNDING_MASK: u32 = 3;
const ROUND_NEAREST_EVEN: u32 = 0;
const ROUND_POSITIVE: u32 = 1;
const ROUND_NEGATIVE: u32 = 2;
const ROUND_ZERO: u32 = 3;
pub const FPCR_FZ: u32 = 1 << 24;
pub const FPCR_DN: u32 = 1 << 25;
pub const FPCR_AHP: u32 = 1 << 26;
pub const FPCR_EXCEPTION_ENABLE_MASK: u32 = EXCEPTIONS << FPCR_EXCEPTION_ENABLE_SHIFT;
pub const FPSR_QC: u32 = 1 << 27;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Half,
    Single,
    Double,
}

impl Format {
    pub const fn bits(self) -> u32 {
        match self {
            Self::Half => 16,
            Self::Single => 32,
            Self::Double => 64,
        }
    }
    pub(crate) const fn fraction_bits(self) -> u32 {
        match self {
            Self::Half => 10,
            Self::Single => 23,
            Self::Double => 52,
        }
    }
    pub(crate) const fn exponent_bias(self) -> u32 {
        (self.exponent_mask() >> (self.fraction_bits() + 1)) as u32
    }
    pub(crate) const fn sign_mask(self) -> u64 {
        1 << (self.bits() - 1)
    }
    pub(crate) const fn fraction_mask(self) -> u64 {
        (1 << self.fraction_bits()) - 1
    }
    pub(crate) const fn exponent_mask(self) -> u64 {
        (self.sign_mask() - 1) & !self.fraction_mask()
    }
    const fn quiet_bit(self) -> u64 {
        1 << (self.fraction_bits() - 1)
    }
    const fn infinity(self, negative: bool) -> u64 {
        self.exponent_mask() | if negative { self.sign_mask() } else { 0 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperation {
    Add,
    Subtract,
    Multiply,
    Divide,
    NegatedMultiply,
    AbsoluteDifference,
    MultiplyExtended,
}

/// Fresh exception bits only; the caller owns sticky FPSR and destination commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub bits: u64,
    pub exceptions: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedControl {
    pub enabled_exceptions: u32,
}

#[derive(Clone, Copy)]
struct Control(u32);
impl Control {
    fn checked(fpcr: u32) -> Result<Self, UnsupportedControl> {
        let enabled_exceptions = (fpcr >> FPCR_EXCEPTION_ENABLE_SHIFT) & EXCEPTIONS;
        if enabled_exceptions != 0 {
            Err(UnsupportedControl { enabled_exceptions })
        } else {
            Ok(Self(fpcr))
        }
    }
    fn alternative(self) -> bool {
        self.0 & FPCR_AH != 0
    }
    fn round(self) -> Round {
        match (self.0 >> FPCR_ROUNDING_SHIFT) & FPCR_ROUNDING_MASK {
            ROUND_NEAREST_EVEN => Round::NearestTiesToEven,
            ROUND_POSITIVE => Round::TowardPositive,
            ROUND_NEGATIVE => Round::TowardNegative,
            ROUND_ZERO => Round::TowardZero,
            _ => unreachable!("two-bit rounding field"),
        }
    }
    fn flush_output(self, format: Format) -> bool {
        self.0
            & if format == Format::Half {
                FPCR_FZ16
            } else {
                FPCR_FZ
            }
            != 0
    }
    fn default_nan(self, format: Format) -> u64 {
        format.infinity(self.alternative()) | format.quiet_bit()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Zero,
    Normal,
    Denormal,
    Infinity,
    QuietNaN,
    SignalingNaN,
}
impl Class {
    fn nan(self) -> bool {
        matches!(self, Self::QuietNaN | Self::SignalingNaN)
    }
}
#[derive(Clone, Copy)]
struct Operand {
    bits: u64,
    class: Class,
    negative: bool,
}

fn unpack(format: Format, bits: u64, control: Control, exceptions: &mut u32) -> Operand {
    // Narrow callers may supply poisoned upper bits. Classification uses the
    // original lane; flushing preserves only its sign and does not mutate state.
    let mut bits = bits & (format.sign_mask() | (format.sign_mask() - 1));
    let negative = bits & format.sign_mask() != 0;
    let exponent = bits & format.exponent_mask();
    let fraction = bits & format.fraction_mask();
    let class = if exponent == format.exponent_mask() {
        if fraction == 0 {
            Class::Infinity
        } else if fraction & format.quiet_bit() != 0 {
            Class::QuietNaN
        } else {
            Class::SignalingNaN
        }
    } else if exponent != 0 {
        Class::Normal
    } else if fraction == 0 {
        Class::Zero
    } else {
        let flush = if format == Format::Half {
            control.0 & FPCR_FZ16 != 0
        } else {
            control.0 & FPCR_FIZ != 0 || control.0 & FPCR_FZ != 0 && !control.alternative()
        };
        if flush {
            if format != Format::Half && control.0 & FPCR_FZ != 0 && !control.alternative() {
                *exceptions |= INPUT_DENORMAL;
            }
            bits &= format.sign_mask();
            Class::Zero
        } else {
            Class::Denormal
        }
    };
    Operand {
        bits,
        class,
        negative,
    }
}

/// Arm FPNeg preserves NaN signs under AH before arithmetic unpacking.
fn negate(format: Format, bits: u64, control: Control) -> u64 {
    let nan = bits & format.exponent_mask() == format.exponent_mask()
        && bits & format.fraction_mask() != 0;
    if control.alternative() && nan {
        bits
    } else {
        bits ^ format.sign_mask()
    }
}

/// Compare already unpacked, non-NaN values without numerical host effects.
fn compare_operands(left: Operand, right: Operand) -> std::cmp::Ordering {
    debug_assert!(!left.class.nan() && !right.class.nan());
    if left.class == Class::Zero && right.class == Class::Zero {
        std::cmp::Ordering::Equal
    } else if left.negative != right.negative {
        if left.negative {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    } else if left.negative {
        right.bits.cmp(&left.bits)
    } else {
        left.bits.cmp(&right.bits)
    }
}

/// Post-operation IDC is separate from unpack-time flushing and is skipped by
/// NaN/other early branches according to each instruction's architectural helper.
fn process_denormals(
    format: Format,
    control: Control,
    left: Operand,
    right: Operand,
    exceptions: &mut u32,
) {
    if format != Format::Half
        && control.alternative()
        && (left.class == Class::Denormal || right.class == Class::Denormal)
    {
        *exceptions |= INPUT_DENORMAL;
    }
}

fn nan(
    format: Format,
    left: Operand,
    right: Operand,
    control: Control,
    exceptions: &mut u32,
) -> Option<u64> {
    let signaling = left.class == Class::SignalingNaN || right.class == Class::SignalingNaN;
    let selected = if left.class == Class::SignalingNaN
        || control.alternative() && left.class.nan() && right.class.nan()
    {
        left
    } else if right.class == Class::SignalingNaN {
        right
    } else if left.class == Class::QuietNaN {
        left
    } else if right.class == Class::QuietNaN {
        right
    } else {
        return None;
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

fn apply<F: Float>(operation: BinaryOperation, left: F, right: F, round: Round) -> StatusAnd<F> {
    match operation {
        BinaryOperation::Add => left.add_r(right, round),
        BinaryOperation::Subtract | BinaryOperation::AbsoluteDifference => left.sub_r(right, round),
        BinaryOperation::Multiply
        | BinaryOperation::NegatedMultiply
        | BinaryOperation::MultiplyExtended => left.mul_r(right, round),
        BinaryOperation::Divide => left.div_r(right, round),
    }
}

/// At the minimum-normal boundary only, distinguish Arm's exact-value and
/// unconstrained-rounding tininess from the library's constrained IEEE status.
fn tiny<F: Float>(
    operation: BinaryOperation,
    left: F,
    right: F,
    result: StatusAnd<F>,
    control: Control,
) -> bool {
    let magnitude = result.value.abs();
    let minimum = F::smallest_normalized();
    if magnitude < minimum {
        return !result.value.is_zero() || result.status.contains(Status::INEXACT);
    }
    if magnitude != minimum || !result.status.contains(Status::INEXACT) {
        return false;
    }
    if !control.alternative() {
        return apply(operation, left, right, Round::TowardZero).value.abs() < minimum;
    }
    // Power-of-two scaling is exact here. A nonzero tiny ADD/SUB cancellation
    // bounds operand ULPs far below overflow; MUL scales its smaller operand;
    // a tiny finite quotient bounds its numerator. Exact zero never reaches here.
    let double = |value: F| {
        let scaled = value.scalbn(1);
        debug_assert!(scaled.is_finite() && scaled.scalbn(-1).bitwise_eq(value));
        scaled
    };
    let (left, right) = match operation {
        BinaryOperation::Add | BinaryOperation::Subtract | BinaryOperation::AbsoluteDifference => {
            (double(left), double(right))
        }
        BinaryOperation::Multiply
        | BinaryOperation::NegatedMultiply
        | BinaryOperation::MultiplyExtended
            if left.abs() <= right.abs() =>
        {
            (double(left), right)
        }
        BinaryOperation::Multiply
        | BinaryOperation::NegatedMultiply
        | BinaryOperation::MultiplyExtended => (left, double(right)),
        BinaryOperation::Divide => (double(left), right),
    };
    let scaled = apply(operation, left, right, control.round());
    scaled.value.abs() < double(minimum)
}

/// APFloat omits OVERFLOW when clamping to largest finite. Toward-zero rounding
/// in Quad preserves comparison with the exact power-of-two overflow threshold.
/// Inputs convert exactly and all finite H/S/D four-operation exponents fit Quad;
/// no widened result is converted back into the architectural result.
fn clamped_overflow<F: Float + FloatConvert<Quad>>(
    operation: BinaryOperation,
    left: F,
    right: F,
    result: StatusAnd<F>,
) -> bool {
    if !result.value.abs().bitwise_eq(F::largest()) || !result.status.contains(Status::INEXACT) {
        return false;
    }
    let extended = apply(operation, widen(left), widen(right), Round::TowardZero);
    extended.value.abs() >= Quad::from_u128(1).value.scalbn(F::MAX_EXP + 1)
}

fn widen<F: Float + FloatConvert<Quad>>(value: F) -> Quad {
    let mut loses_info = false;
    let converted: StatusAnd<Quad> = value.convert(&mut loses_info);
    debug_assert!(!loses_info && converted.status == Status::OK);
    converted.value
}

fn rounded_outcome<F: Float>(
    format: Format,
    control: Control,
    result: StatusAnd<F>,
    tiny: bool,
    overflow: bool,
) -> Outcome {
    if tiny && control.flush_output(format) {
        return Outcome {
            bits: if result.value.is_negative() {
                format.sign_mask()
            } else {
                0
            },
            exceptions: UNDERFLOW | if control.alternative() { INEXACT } else { 0 },
        };
    }
    let mut exceptions = 0;
    if overflow {
        exceptions |= OVERFLOW;
    }
    if result.status.contains(Status::INEXACT) {
        exceptions |= INEXACT;
        if tiny {
            exceptions |= UNDERFLOW;
        }
    }
    debug_assert!(
        !result
            .status
            .intersects(Status::INVALID_OP | Status::DIV_BY_ZERO)
    );
    Outcome {
        bits: result.value.to_bits() as u64,
        exceptions,
    }
}

fn finite<F: Float + FloatConvert<Quad>>(
    format: Format,
    operation: BinaryOperation,
    left: u64,
    right: u64,
    control: Control,
) -> Outcome {
    let left = F::from_bits(u128::from(left));
    let right = F::from_bits(u128::from(right));
    let result = apply(operation, left, right, control.round());
    let tiny = tiny(operation, left, right, result, control);
    let overflow = result.status.contains(Status::OVERFLOW)
        || clamped_overflow(operation, left, right, result);
    rounded_outcome(format, control, result, tiny, overflow)
}

/// Evaluate one scalar arithmetic lane. No caller state or host FP environment
/// is read or modified. AHP/NEP do not affect lane arithmetic; merge is a caller duty.
pub fn evaluate(
    format: Format,
    operation: BinaryOperation,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<Outcome, UnsupportedControl> {
    let enabled_exceptions = (fpcr >> FPCR_EXCEPTION_ENABLE_SHIFT) & EXCEPTIONS;
    if enabled_exceptions != 0 {
        return Err(UnsupportedControl { enabled_exceptions });
    }
    let control = Control(fpcr);
    // FPNeg/FPAbs act on the rounded result, including a selected NaN. Moving
    // either transform onto an input would change directed rounding and NaNs.
    let transform_result = |bits| match operation {
        BinaryOperation::NegatedMultiply => negate(format, bits, control),
        BinaryOperation::AbsoluteDifference if bits & format.sign_mask() != 0 => {
            negate(format, bits, control)
        }
        _ => bits,
    };
    let mut exceptions = 0;
    let left = unpack(format, left, control, &mut exceptions);
    let right = unpack(format, right, control, &mut exceptions);
    if let Some(bits) = nan(format, left, right, control, &mut exceptions) {
        return Ok(Outcome {
            bits: transform_result(bits),
            exceptions,
        });
    }
    let zero = |negative| if negative { format.sign_mask() } else { 0 };
    let mut invalid = || {
        exceptions |= INVALID;
        control.default_nan(format)
    };
    let bits = match operation {
        BinaryOperation::Add | BinaryOperation::Subtract | BinaryOperation::AbsoluteDifference => {
            let right_negative = right.negative ^ (operation != BinaryOperation::Add);
            if left.class == Class::Infinity
                && right.class == Class::Infinity
                && left.negative != right_negative
            {
                Some(invalid())
            } else if left.class == Class::Infinity {
                Some(left.bits)
            } else if right.class == Class::Infinity {
                Some(format.infinity(right_negative))
            } else if left.class == Class::Zero && right.class == Class::Zero {
                Some(zero(if left.negative == right_negative {
                    left.negative
                } else {
                    control.round() == Round::TowardNegative
                }))
            } else {
                None
            }
        }
        BinaryOperation::Multiply
        | BinaryOperation::NegatedMultiply
        | BinaryOperation::MultiplyExtended => {
            if left.class == Class::Infinity && right.class == Class::Zero
                || right.class == Class::Infinity && left.class == Class::Zero
            {
                if operation == BinaryOperation::MultiplyExtended {
                    let two = u64::from(format.exponent_bias() + 1) << format.fraction_bits();
                    Some(two | zero(left.negative ^ right.negative))
                } else {
                    Some(invalid())
                }
            } else if left.class == Class::Infinity || right.class == Class::Infinity {
                Some(format.infinity(left.negative ^ right.negative))
            } else if left.class == Class::Zero || right.class == Class::Zero {
                Some(zero(left.negative ^ right.negative))
            } else {
                None
            }
        }
        BinaryOperation::Divide => {
            if left.class == Class::Infinity && right.class == Class::Infinity
                || left.class == Class::Zero && right.class == Class::Zero
            {
                Some(invalid())
            } else if left.class == Class::Infinity || right.class == Class::Zero {
                if left.class != Class::Infinity {
                    exceptions |= DIVIDE_BY_ZERO;
                }
                Some(format.infinity(left.negative ^ right.negative))
            } else if left.class == Class::Zero || right.class == Class::Infinity {
                Some(zero(left.negative ^ right.negative))
            } else {
                None
            }
        }
    };
    let result = if let Some(bits) = bits {
        Outcome {
            bits,
            exceptions: 0,
        }
    } else {
        match format {
            Format::Half => finite::<Half>(format, operation, left.bits, right.bits, control),
            Format::Single => finite::<Single>(format, operation, left.bits, right.bits, control),
            Format::Double => finite::<Double>(format, operation, left.bits, right.bits, control),
        }
    };
    // FPCR_AH input-denormal processing follows arithmetic/NaNs, and FDIV omits it
    // for a zero denominator. Earlier FPCR_AH=0 input-flush IDC remains accumulated.
    if control.alternative()
        && format != Format::Half
        && (operation != BinaryOperation::Divide || right.class != Class::Zero)
        && (left.class == Class::Denormal || right.class == Class::Denormal)
    {
        exceptions |= INPUT_DENORMAL;
    }
    Ok(Outcome {
        bits: transform_result(result.bits),
        exceptions: exceptions | result.exceptions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(
        format: Format,
        operation: BinaryOperation,
        fpcr: u32,
        left: u64,
        right: u64,
    ) -> Outcome {
        evaluate(format, operation, fpcr, left, right).unwrap()
    }

    #[test]
    fn negated_multiply_changes_the_rounded_result_under_every_direction() {
        for format in [Format::Half, Format::Single, Format::Double] {
            let one = u64::from(format.exponent_bias()) << format.fraction_bits();
            for ah in [0, FPCR_AH] {
                for round in [
                    ROUND_NEAREST_EVEN,
                    ROUND_POSITIVE,
                    ROUND_NEGATIVE,
                    ROUND_ZERO,
                ] {
                    assert_eq!(
                        result(
                            format,
                            BinaryOperation::NegatedMultiply,
                            ah | (round << FPCR_ROUNDING_SHIFT),
                            one + 1,
                            one + 1,
                        ),
                        Outcome {
                            bits: format.sign_mask()
                                | (one + if round == ROUND_POSITIVE { 3 } else { 2 }),
                            exceptions: INEXACT,
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn absolute_difference_rounds_the_negative_difference_before_clearing_sign() {
        for format in [Format::Half, Format::Single, Format::Double] {
            let one = u64::from(format.exponent_bias()) << format.fraction_bits();
            let minimum_normal = 1 << format.fraction_bits();
            for ah in [0, FPCR_AH] {
                for round in [
                    ROUND_NEAREST_EVEN,
                    ROUND_POSITIVE,
                    ROUND_NEGATIVE,
                    ROUND_ZERO,
                ] {
                    assert_eq!(
                        result(
                            format,
                            BinaryOperation::AbsoluteDifference,
                            ah | (round << FPCR_ROUNDING_SHIFT),
                            minimum_normal,
                            one,
                        ),
                        Outcome {
                            bits: one - u64::from(matches!(round, ROUND_POSITIVE | ROUND_ZERO)),
                            exceptions: INEXACT,
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn post_arithmetic_sign_transforms_keep_ah_nan_signs_and_fresh_invalid() {
        for format in [Format::Half, Format::Single, Format::Double] {
            let one = u64::from(format.exponent_bias()) << format.fraction_bits();
            let signaling = format.sign_mask() | format.exponent_mask() | 1;
            for operation in [
                BinaryOperation::NegatedMultiply,
                BinaryOperation::AbsoluteDifference,
            ] {
                for ah in [0, FPCR_AH] {
                    assert_eq!(
                        result(format, operation, ah, signaling, one),
                        Outcome {
                            bits: (signaling | format.quiet_bit())
                                ^ if ah == 0 { format.sign_mask() } else { 0 },
                            exceptions: INVALID,
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn extended_multiply_zero_times_infinity_returns_signed_two_without_invalid() {
        for format in [Format::Half, Format::Single, Format::Double] {
            let two = u64::from(format.exponent_bias() + 1) << format.fraction_bits();
            for ah in [0, FPCR_AH] {
                for zero_negative in [false, true] {
                    for infinity_negative in [false, true] {
                        let zero = if zero_negative { format.sign_mask() } else { 0 };
                        let infinity = format.infinity(infinity_negative);
                        for (left, right) in [(zero, infinity), (infinity, zero)] {
                            assert_eq!(
                                result(format, BinaryOperation::MultiplyExtended, ah, left, right),
                                Outcome {
                                    bits: two
                                        | if zero_negative ^ infinity_negative {
                                            format.sign_mask()
                                        } else {
                                            0
                                        },
                                    exceptions: 0,
                                }
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn extended_multiply_flush_and_nan_shortcuts_keep_denormal_status_order() {
        for format in [Format::Single, Format::Double] {
            let two = u64::from(format.exponent_bias() + 1) << format.fraction_bits();
            let infinity = format.infinity(false);
            for (control, expected, exceptions) in [
                (0, infinity, 0),
                (FPCR_FZ, two, INPUT_DENORMAL),
                (FPCR_FIZ, two, 0),
                (FPCR_AH, infinity, INPUT_DENORMAL),
                (FPCR_AH | FPCR_FIZ, two, 0),
            ] {
                assert_eq!(
                    result(
                        format,
                        BinaryOperation::MultiplyExtended,
                        control,
                        1,
                        infinity
                    ),
                    Outcome {
                        bits: expected,
                        exceptions
                    }
                );
            }
            let quiet = infinity | format.quiet_bit() | 1;
            assert_eq!(
                result(format, BinaryOperation::MultiplyExtended, FPCR_AH, 1, quiet),
                Outcome {
                    bits: quiet,
                    exceptions: 0
                }
            );
        }
    }

    #[test]
    fn enabled_exceptions_decline_before_any_numerical_effect() {
        for exception in [
            INVALID,
            DIVIDE_BY_ZERO,
            OVERFLOW,
            UNDERFLOW,
            INEXACT,
            INPUT_DENORMAL,
            EXCEPTIONS,
        ] {
            for operation in [
                BinaryOperation::Divide,
                BinaryOperation::NegatedMultiply,
                BinaryOperation::AbsoluteDifference,
                BinaryOperation::MultiplyExtended,
            ] {
                for ah in [0, FPCR_AH] {
                    assert_eq!(
                        evaluate(
                            Format::Double,
                            operation,
                            ah | (exception << FPCR_EXCEPTION_ENABLE_SHIFT),
                            0,
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

    #[test]
    fn signaling_priority_and_alternative_nan_selection_preserve_payloads() {
        let quiet = 0x7fc00123;
        let signaling = 0xff800456;
        for operation in [
            BinaryOperation::Add,
            BinaryOperation::Subtract,
            BinaryOperation::Multiply,
            BinaryOperation::Divide,
        ] {
            assert_eq!(
                result(Format::Single, operation, 0, quiet, signaling),
                Outcome {
                    bits: 0xffc00456,
                    exceptions: INVALID
                }
            );
            assert_eq!(
                result(Format::Single, operation, FPCR_AH, quiet, signaling),
                Outcome {
                    bits: quiet,
                    exceptions: INVALID
                }
            );
            assert_eq!(
                result(
                    Format::Single,
                    operation,
                    FPCR_AH | FPCR_DN,
                    quiet,
                    signaling
                ),
                Outcome {
                    bits: 0xffc00000,
                    exceptions: INVALID
                }
            );
        }
    }

    #[test]
    fn input_denormal_order_is_distinct_from_host_denormal_status() {
        assert_eq!(
            result(Format::Single, BinaryOperation::Add, FPCR_FZ, 1, 0x7fc00123),
            Outcome {
                bits: 0x7fc00123,
                exceptions: INPUT_DENORMAL
            }
        );
        assert_eq!(
            result(
                Format::Single,
                BinaryOperation::Add,
                FPCR_AH | FPCR_FZ,
                1,
                0x7fc00123
            ),
            Outcome {
                bits: 0x7fc00123,
                exceptions: 0
            }
        );
        assert_eq!(
            result(Format::Single, BinaryOperation::Divide, FPCR_AH, 1, 0),
            Outcome {
                bits: 0x7f800000,
                exceptions: DIVIDE_BY_ZERO
            }
        );
        assert_eq!(
            result(
                Format::Single,
                BinaryOperation::Multiply,
                FPCR_AH,
                1,
                0x3f800000
            ),
            Outcome {
                bits: 1,
                exceptions: INPUT_DENORMAL
            }
        );
        assert_eq!(
            result(Format::Single, BinaryOperation::Divide, FPCR_FIZ, 1, 0),
            Outcome {
                bits: 0x7fc00000,
                exceptions: INVALID
            }
        );
        assert_eq!(
            result(
                Format::Single,
                BinaryOperation::Divide,
                FPCR_FIZ | FPCR_FZ,
                1,
                0
            ),
            Outcome {
                bits: 0x7fc00000,
                exceptions: INVALID | INPUT_DENORMAL
            }
        );
    }

    #[test]
    fn exact_tiny_output_flushes_with_architectural_inexact_policy() {
        for (format, minimum, half) in [
            (Format::Half, 0x0400, 0x3800),
            (Format::Single, 0x00800000, 0x3f000000),
            (Format::Double, 0x0010000000000000, 0x3fe0000000000000),
        ] {
            let flush = if format == Format::Half {
                FPCR_FZ16
            } else {
                FPCR_FZ
            };
            assert_eq!(
                result(format, BinaryOperation::Multiply, 0, minimum, half),
                Outcome {
                    bits: minimum / 2,
                    exceptions: 0
                }
            );
            assert_eq!(
                result(format, BinaryOperation::Multiply, flush, minimum, half),
                Outcome {
                    bits: 0,
                    exceptions: UNDERFLOW
                }
            );
            assert_eq!(
                result(
                    format,
                    BinaryOperation::Multiply,
                    flush | FPCR_AH,
                    minimum,
                    half
                ),
                Outcome {
                    bits: 0,
                    exceptions: UNDERFLOW | INEXACT
                }
            );
        }
    }

    #[test]
    fn unconstrained_rounding_differs_at_minimum_normal_boundary() {
        // (1+2^-23)*(1-2^-23)*2^-126 = minimum_normal - 2^-172.
        // The stored result is normal in both modes; exact-value tininess and
        // precision-only rounded tininess nevertheless have different outcomes.
        let left = 0x00800001;
        let right = 0x3f7ffffe;
        assert_eq!(
            result(Format::Single, BinaryOperation::Multiply, 0, left, right),
            Outcome {
                bits: 0x00800000,
                exceptions: UNDERFLOW | INEXACT
            }
        );
        assert_eq!(
            result(
                Format::Single,
                BinaryOperation::Multiply,
                FPCR_AH,
                left,
                right
            ),
            Outcome {
                bits: 0x00800000,
                exceptions: INEXACT
            }
        );
        assert_eq!(
            result(
                Format::Single,
                BinaryOperation::Multiply,
                FPCR_FZ,
                left,
                right
            ),
            Outcome {
                bits: 0,
                exceptions: UNDERFLOW
            }
        );
        assert_eq!(
            result(
                Format::Single,
                BinaryOperation::Multiply,
                FPCR_FZ | FPCR_AH,
                left,
                right
            ),
            Outcome {
                bits: 0x00800000,
                exceptions: INEXACT
            }
        );
    }

    #[test]
    fn exact_cancellation_skips_scaling_and_obeys_zero_sign() {
        let maximum = 0x7fefffffffffffff;
        for rounding in 0..4 {
            let fpcr = FPCR_AH | (rounding << FPCR_ROUNDING_SHIFT);
            let expected = Outcome {
                bits: if rounding == ROUND_NEGATIVE {
                    1 << 63
                } else {
                    0
                },
                exceptions: 0,
            };
            assert_eq!(
                result(
                    Format::Double,
                    BinaryOperation::Subtract,
                    fpcr,
                    maximum,
                    maximum
                ),
                expected
            );
        }
    }

    #[test]
    fn clamped_overflow_raises_overflow_without_confusing_inexact_maximum() {
        for format in [Format::Half, Format::Single, Format::Double] {
            let maximum = format.exponent_mask() - 1;
            for negative in [false, true] {
                let sign = if negative { format.sign_mask() } else { 0 };
                for rounding in [
                    ROUND_NEAREST_EVEN,
                    ROUND_POSITIVE,
                    ROUND_NEGATIVE,
                    ROUND_ZERO,
                ] {
                    let fpcr = rounding << FPCR_ROUNDING_SHIFT;
                    let infinite = rounding == ROUND_NEAREST_EVEN
                        || rounding == ROUND_POSITIVE && !negative
                        || rounding == ROUND_NEGATIVE && negative;
                    assert_eq!(
                        result(
                            format,
                            BinaryOperation::Add,
                            fpcr,
                            maximum | sign,
                            maximum | sign
                        ),
                        Outcome {
                            bits: if infinite {
                                format.infinity(negative)
                            } else {
                                maximum | sign
                            },
                            exceptions: OVERFLOW | INEXACT
                        }
                    );
                    // A tiny increment beyond largest finite is inexact, but its
                    // exact exponent has not reached the overflow threshold.
                    if !infinite || rounding == ROUND_NEAREST_EVEN {
                        assert_eq!(
                            result(format, BinaryOperation::Add, fpcr, maximum | sign, 1 | sign),
                            Outcome {
                                bits: maximum | sign,
                                exceptions: INEXACT
                            }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn lane_width_and_irrelevant_arithmetic_controls_do_not_leak() {
        const AHP: u32 = 1 << 26;
        const NEP: u32 = 1 << 2;
        for (format, one, expected) in [
            (Format::Half, 0x3c00, 0x4000),
            (Format::Single, 0x3f800000, 0x40000000),
        ] {
            let poison = !((1u64 << format.bits()) - 1);
            assert_eq!(
                result(
                    format,
                    BinaryOperation::Add,
                    AHP | NEP,
                    one | poison,
                    one | poison
                ),
                Outcome {
                    bits: expected,
                    exceptions: 0
                }
            );
        }
    }
}
