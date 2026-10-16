//! Classic BF16 dot stages: fixed flushing, separately rounded Single products
//! and additions, and no architectural exception or trap effects.
use super::super::{Control, Format};
use super::widen;
use rustc_apfloat::{
    Float, FloatConvert, Round, Status, StatusAnd,
    ieee::{Double, Single},
};

const SINGLE_SIGN: u32 = Format::Single.sign_mask() as u32;
const SINGLE_EXPONENT: u32 = Format::Single.exponent_mask() as u32;
const SINGLE_FRACTION: u32 = Format::Single.fraction_mask() as u32;
const SINGLE_MINIMUM_AS_DOUBLE: u128 =
    ((Format::Double.exponent_bias() - Format::Single.exponent_bias() + 1) as u128)
        << Format::Double.fraction_bits();
const SINGLE_OVERFLOW_AS_DOUBLE: u128 =
    ((Format::Double.exponent_bias() + Format::Single.exponent_bias() + 1) as u128)
        << Format::Double.fraction_bits();
const ODD_SIGNIFICAND_BIT: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum OperandClass {
    Zero,
    Finite,
    Infinity,
    NaN,
}

#[derive(Clone, Copy)]
struct Operand {
    bits: u32,
    class: OperandClass,
}

impl Operand {
    fn unpack(bits: u32) -> Self {
        let exponent = bits & SINGLE_EXPONENT;
        let class = if exponent == 0 {
            OperandClass::Zero
        } else if exponent != SINGLE_EXPONENT {
            OperandClass::Finite
        } else if bits & SINGLE_FRACTION == 0 {
            OperandClass::Infinity
        } else {
            // BFUnpack has no signaling NaN class, including Single addends.
            OperandClass::NaN
        };
        Self {
            bits: if class == OperandClass::Zero {
                bits & SINGLE_SIGN
            } else {
                bits
            },
            class,
        }
    }

    fn sign(self) -> u32 {
        self.bits & SINGLE_SIGN
    }
}

fn default_nan(fpcr: u32) -> u32 {
    Control(fpcr).default_nan(Format::Single) as u32
}

fn widen_single(bits: u32) -> Double {
    let mut loses_info = false;
    let result: StatusAnd<Double> =
        Single::from_bits(u128::from(bits)).convert_r(Round::TowardZero, &mut loses_info);
    debug_assert_eq!(result.status, Status::OK);
    debug_assert!(!loses_info);
    result.value
}

/// Double products are exact. A Double addition can discard distant Single
/// low bits; preserve that RTZ sticky bit through the second RTZ conversion.
/// Every Single boundary, including min-normal and 2^128, is exact in Double,
/// so the first RTZ cannot cross any boundary before the final odd-bit jam.
fn round_odd(result: StatusAnd<Double>) -> u32 {
    debug_assert!(result.value.is_finite() && !result.value.is_zero());
    let sign = if result.value.is_negative() {
        SINGLE_SIGN
    } else {
        0
    };
    let magnitude = result.value.abs().to_bits();
    // BFRound classifies the exact exponent before rounding. In particular,
    // neither tiny sticky values nor finite values above max-Single jam to
    // a subnormal or infinity merely because APFloat reports target overflow.
    if magnitude < SINGLE_MINIMUM_AS_DOUBLE {
        return sign;
    }
    if magnitude >= SINGLE_OVERFLOW_AS_DOUBLE {
        return sign | SINGLE_EXPONENT;
    }
    let mut loses_info = false;
    let converted: StatusAnd<Single> = result.value.convert_r(Round::TowardZero, &mut loses_info);
    let bits = converted.value.to_bits() as u32;
    if result.status.contains(Status::INEXACT) || converted.status.contains(Status::INEXACT) {
        bits | ODD_SIGNIFICAND_BIT
    } else {
        bits
    }
}

fn multiply(fpcr: u32, left: u16, right: u16) -> u32 {
    let left = Operand::unpack(widen(left));
    let right = Operand::unpack(widen(right));
    if left.class == OperandClass::NaN || right.class == OperandClass::NaN {
        return default_nan(fpcr);
    }
    let sign = left.sign() ^ right.sign();
    if (left.class == OperandClass::Infinity && right.class == OperandClass::Zero)
        || (left.class == OperandClass::Zero && right.class == OperandClass::Infinity)
    {
        return default_nan(fpcr);
    }
    if left.class == OperandClass::Infinity || right.class == OperandClass::Infinity {
        return sign | SINGLE_EXPONENT;
    }
    if left.class == OperandClass::Zero || right.class == OperandClass::Zero {
        return sign;
    }
    // Two eight-bit BF significands need at most sixteen exact product bits;
    // their exponent range is far inside normal Double without host FP use.
    let result = widen_single(left.bits).mul_r(widen_single(right.bits), Round::TowardZero);
    debug_assert_eq!(result.status, Status::OK);
    round_odd(result)
}

fn add(fpcr: u32, left: u32, right: u32) -> u32 {
    let left = Operand::unpack(left);
    let right = Operand::unpack(right);
    if left.class == OperandClass::NaN || right.class == OperandClass::NaN {
        return default_nan(fpcr);
    }
    if left.class == OperandClass::Infinity
        && right.class == OperandClass::Infinity
        && left.sign() != right.sign()
    {
        return default_nan(fpcr);
    }
    if left.class == OperandClass::Infinity {
        return left.bits;
    }
    if right.class == OperandClass::Infinity {
        return right.bits;
    }
    if left.class == OperandClass::Zero
        && right.class == OperandClass::Zero
        && left.sign() == right.sign()
    {
        return left.sign();
    }
    let result = widen_single(left.bits).add_r(widen_single(right.bits), Round::TowardZero);
    if result.value.is_zero() {
        // Opposite zeros and exact finite cancellation produce positive zero.
        0
    } else {
        round_odd(result)
    }
}

/// EBF16 is absent from the declared profile. Each classic stage rounds
/// independently; only AH's default-NaN sign is read from the supplied FPCR.
pub fn dot_add(fpcr: u32, addend: u32, left: [u16; 2], right: [u16; 2]) -> u32 {
    let first = multiply(fpcr, left[0], right[0]);
    let second = multiply(fpcr, left[1], right[1]);
    let pair = add(fpcr, first, second);
    add(fpcr, addend, pair)
}

#[cfg(test)]
mod tests;
