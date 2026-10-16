//! FSQRT computed from an integer radicand and remainder.
use super::{
    Class, Control, Format, INEXACT, INVALID, Outcome, UnsupportedControl, nan, process_denormals,
    unpack,
};
use rustc_apfloat::Round;

fn positive_finite(format: Format, rounding: Round, bits: u64) -> Outcome {
    let fraction_bits = format.fraction_bits();
    let hidden_bit = 1u64 << fraction_bits;
    let bias = format.exponent_bias() as i32;
    let encoded_exponent = ((bits & format.exponent_mask()) >> fraction_bits) as i32;
    let mut significand = bits & format.fraction_mask();
    let exponent = if encoded_exponent == 0 {
        let normalization = fraction_bits - significand.ilog2();
        significand <<= normalization;
        1 - bias - normalization as i32
    } else {
        significand |= hidden_bit;
        encoded_exponent - bias
    };

    // x = significand * 2^(exponent-fraction_bits). Scaling its root to the
    // destination significand gives this integer radicand, at most 106 bits.
    // Euclidean parity/division are required for negative odd exponents.
    let radicand = u128::from(significand) << (fraction_bits + exponent.rem_euclid(2) as u32);
    let mut root = radicand.isqrt();
    let remainder = radicand - root * root;
    let increment = match rounding {
        // (root+1/2)^2 = root^2+root+1/4. An integer radicand cannot tie.
        Round::NearestTiesToEven | Round::NearestTiesToAway => remainder > root,
        Round::TowardPositive => remainder != 0,
        Round::TowardNegative | Round::TowardZero => false,
    };
    root += u128::from(increment);
    let mut result_exponent = exponent.div_euclid(2);
    if root == u128::from(hidden_bit) << 1 {
        root >>= 1;
        result_exponent += 1;
    }
    debug_assert!((u128::from(hidden_bit)..u128::from(hidden_bit) << 1).contains(&root));
    let bits =
        ((result_exponent + bias) as u64) << fraction_bits | (root as u64 & format.fraction_mask());
    Outcome {
        bits,
        exceptions: if remainder == 0 { 0 } else { INEXACT },
    }
}

/// Fresh status only. Scalar merging, active lanes and sticky FPSR belong to
/// the caller. AHP is ignored; input controls and early-branch IDC follow FPSqrt.
pub fn evaluate(format: Format, fpcr: u32, bits: u64) -> Result<Outcome, UnsupportedControl> {
    let control = Control::checked(fpcr)?;
    let mut exceptions = 0;
    let operand = unpack(format, bits, control, &mut exceptions);
    let bits = if let Some(bits) = nan(format, operand, operand, control, &mut exceptions) {
        bits
    } else if operand.class == Class::Zero || operand.class == Class::Infinity && !operand.negative
    {
        operand.bits
    } else if operand.negative {
        exceptions |= INVALID;
        control.default_nan(format)
    } else {
        let result = positive_finite(format, control.round(), operand.bits);
        exceptions |= result.exceptions;
        // Negative invalid inputs and all other early returns skip this check.
        process_denormals(format, control, operand, operand, &mut exceptions);
        result.bits
    };
    Ok(Outcome { bits, exceptions })
}

#[cfg(test)]
mod tests;
