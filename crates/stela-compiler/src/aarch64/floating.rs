//! Arm binary arithmetic outcomes, independent of native execution and state.
//! FP/FP16/AFP enabled, non-streaming; enabled numerical traps are explicit errors.
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
const EXCEPTION_ENABLE_SHIFT: u32 = 8;
const FIZ: u32 = 1 << 0;
const AH: u32 = 1 << 1;
const FZ16: u32 = 1 << 19;
const ROUNDING_SHIFT: u32 = 22;
const ROUNDING_MASK: u32 = 3;
const ROUND_NEAREST_EVEN: u32 = 0;
const ROUND_POSITIVE: u32 = 1;
const ROUND_NEGATIVE: u32 = 2;
const ROUND_ZERO: u32 = 3;
const FZ: u32 = 1 << 24;
const DN: u32 = 1 << 25;

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
    const fn fraction_bits(self) -> u32 {
        match self {
            Self::Half => 10,
            Self::Single => 23,
            Self::Double => 52,
        }
    }
    const fn sign_mask(self) -> u64 {
        1 << (self.bits() - 1)
    }
    const fn fraction_mask(self) -> u64 {
        (1 << self.fraction_bits()) - 1
    }
    const fn exponent_mask(self) -> u64 {
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
    fn alternative(self) -> bool {
        self.0 & AH != 0
    }
    fn round(self) -> Round {
        match (self.0 >> ROUNDING_SHIFT) & ROUNDING_MASK {
            ROUND_NEAREST_EVEN => Round::NearestTiesToEven,
            ROUND_POSITIVE => Round::TowardPositive,
            ROUND_NEGATIVE => Round::TowardNegative,
            ROUND_ZERO => Round::TowardZero,
            _ => unreachable!("two-bit rounding field"),
        }
    }
    fn flush_output(self, format: Format) -> bool {
        self.0 & if format == Format::Half { FZ16 } else { FZ } != 0
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
            control.0 & FZ16 != 0
        } else {
            control.0 & FIZ != 0 || control.0 & FZ != 0 && !control.alternative()
        };
        if flush {
            if format != Format::Half && control.0 & FZ != 0 && !control.alternative() {
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
    Some(if control.0 & DN != 0 {
        control.default_nan(format)
    } else {
        selected.bits | format.quiet_bit()
    })
}

fn apply<F: Float>(operation: BinaryOperation, left: F, right: F, round: Round) -> StatusAnd<F> {
    match operation {
        BinaryOperation::Add => left.add_r(right, round),
        BinaryOperation::Subtract => left.sub_r(right, round),
        BinaryOperation::Multiply => left.mul_r(right, round),
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
        BinaryOperation::Add | BinaryOperation::Subtract => (double(left), double(right)),
        BinaryOperation::Multiply if left.abs() <= right.abs() => (double(left), right),
        BinaryOperation::Multiply => (left, double(right)),
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
    let widen = |value: F| {
        let mut loses_info = false;
        let converted: StatusAnd<Quad> = value.convert(&mut loses_info);
        debug_assert!(!loses_info && converted.status == Status::OK);
        converted.value
    };
    let extended = apply(operation, widen(left), widen(right), Round::TowardZero);
    extended.value.abs() >= Quad::from_u128(1).value.scalbn(F::MAX_EXP + 1)
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
    if result.status.contains(Status::OVERFLOW) || clamped_overflow(operation, left, right, result)
    {
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

/// Evaluate one scalar arithmetic lane. No caller state or host FP environment
/// is read or modified. AHP/NEP do not affect lane arithmetic; merge is a caller duty.
pub fn evaluate(
    format: Format,
    operation: BinaryOperation,
    fpcr: u32,
    left: u64,
    right: u64,
) -> Result<Outcome, UnsupportedControl> {
    let enabled_exceptions = (fpcr >> EXCEPTION_ENABLE_SHIFT) & EXCEPTIONS;
    if enabled_exceptions != 0 {
        return Err(UnsupportedControl { enabled_exceptions });
    }
    let control = Control(fpcr);
    let mut exceptions = 0;
    let left = unpack(format, left, control, &mut exceptions);
    let right = unpack(format, right, control, &mut exceptions);
    if let Some(bits) = nan(format, left, right, control, &mut exceptions) {
        return Ok(Outcome { bits, exceptions });
    }
    let zero = |negative| if negative { format.sign_mask() } else { 0 };
    let mut invalid = || {
        exceptions |= INVALID;
        control.default_nan(format)
    };
    let bits = match operation {
        BinaryOperation::Add | BinaryOperation::Subtract => {
            let right_negative = right.negative ^ (operation == BinaryOperation::Subtract);
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
        BinaryOperation::Multiply => {
            if left.class == Class::Infinity && right.class == Class::Zero
                || right.class == Class::Infinity && left.class == Class::Zero
            {
                Some(invalid())
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
    // AH input-denormal processing follows arithmetic/NaNs, and FDIV omits it
    // for a zero denominator. Earlier AH=0 input-flush IDC remains accumulated.
    if control.alternative()
        && format != Format::Half
        && (operation != BinaryOperation::Divide || right.class != Class::Zero)
        && (left.class == Class::Denormal || right.class == Class::Denormal)
    {
        exceptions |= INPUT_DENORMAL;
    }
    Ok(Outcome {
        bits: result.bits,
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
            assert_eq!(
                evaluate(
                    Format::Double,
                    BinaryOperation::Divide,
                    exception << EXCEPTION_ENABLE_SHIFT,
                    0,
                    0
                ),
                Err(UnsupportedControl {
                    enabled_exceptions: exception
                })
            );
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
                result(Format::Single, operation, AH, quiet, signaling),
                Outcome {
                    bits: quiet,
                    exceptions: INVALID
                }
            );
            assert_eq!(
                result(Format::Single, operation, AH | DN, quiet, signaling),
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
            result(Format::Single, BinaryOperation::Add, FZ, 1, 0x7fc00123),
            Outcome {
                bits: 0x7fc00123,
                exceptions: INPUT_DENORMAL
            }
        );
        assert_eq!(
            result(Format::Single, BinaryOperation::Add, AH | FZ, 1, 0x7fc00123),
            Outcome {
                bits: 0x7fc00123,
                exceptions: 0
            }
        );
        assert_eq!(
            result(Format::Single, BinaryOperation::Divide, AH, 1, 0),
            Outcome {
                bits: 0x7f800000,
                exceptions: DIVIDE_BY_ZERO
            }
        );
        assert_eq!(
            result(Format::Single, BinaryOperation::Multiply, AH, 1, 0x3f800000),
            Outcome {
                bits: 1,
                exceptions: INPUT_DENORMAL
            }
        );
        assert_eq!(
            result(Format::Single, BinaryOperation::Divide, FIZ, 1, 0),
            Outcome {
                bits: 0x7fc00000,
                exceptions: INVALID
            }
        );
        assert_eq!(
            result(Format::Single, BinaryOperation::Divide, FIZ | FZ, 1, 0),
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
            let flush = if format == Format::Half { FZ16 } else { FZ };
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
                result(format, BinaryOperation::Multiply, flush | AH, minimum, half),
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
            result(Format::Single, BinaryOperation::Multiply, AH, left, right),
            Outcome {
                bits: 0x00800000,
                exceptions: INEXACT
            }
        );
        assert_eq!(
            result(Format::Single, BinaryOperation::Multiply, FZ, left, right),
            Outcome {
                bits: 0,
                exceptions: UNDERFLOW
            }
        );
        assert_eq!(
            result(
                Format::Single,
                BinaryOperation::Multiply,
                FZ | AH,
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
            let fpcr = AH | (rounding << ROUNDING_SHIFT);
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
                    let fpcr = rounding << ROUNDING_SHIFT;
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
