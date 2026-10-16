//! Deterministic standard-precision estimates in the RPRES-disabled A64 profile.
//! AFP controls are supported; this does not assert a closed Apple hardware profile.
pub mod precision;

use super::{
    Class, Control, DIVIDE_BY_ZERO, FPCR_FIZ, FPCR_FZ, FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT,
    Format, INEXACT, OVERFLOW, Outcome, UNDERFLOW, UnsupportedControl, nan, unpack,
};
use crate::aarch64::simd::estimate::Kind;
use rustc_apfloat::Round;

const ESTIMATE_FRACTION_BITS: u32 = 8;
const ESTIMATE_UNIT: u64 = 1 << ESTIMATE_FRACTION_BITS;
const RECIPROCAL_NUMERATOR: u64 = 1 << 19;
const RECIPROCAL_SQRT_NUMERATOR: u64 = 1 << 28;
const UNSIGNED_WIDTH: u32 = 32;
const UNSIGNED_TABLE_SHIFT: u32 = UNSIGNED_WIDTH - ESTIMATE_FRACTION_BITS - 1;
const UNSIGNED_RECIPROCAL_MINIMUM: u64 = 1 << (UNSIGNED_WIDTH - 1);
const UNSIGNED_RECIPROCAL_SQRT_MINIMUM: u64 = 1 << (UNSIGNED_WIDTH - 2);

fn reciprocal_table(scaled: u64) -> u64 {
    debug_assert!((ESTIMATE_UNIT..ESTIMATE_UNIT * 2).contains(&scaled));
    let midpoint = scaled * 2 + 1;
    (RECIPROCAL_NUMERATOR / midpoint).div_ceil(2)
}

fn reciprocal_sqrt_table(scaled: u64) -> u64 {
    debug_assert!((ESTIMATE_UNIT / 2..ESTIMATE_UNIT * 2).contains(&scaled));
    let midpoint = if scaled < ESTIMATE_UNIT {
        scaled * 2 + 1
    } else {
        ((scaled & !1) + 1) * 2
    };
    // The source loop chooses the largest b with midpoint*b*b < numerator.
    // Subtracting one before division retains that strict inequality exactly.
    let bound = ((RECIPROCAL_SQRT_NUMERATOR - 1) / midpoint).isqrt();
    bound.div_ceil(2)
}

fn unsigned(kind: Kind, bits: u64) -> Outcome {
    let bits = u64::from(bits as u32);
    let minimum = if kind == Kind::UnsignedReciprocal {
        UNSIGNED_RECIPROCAL_MINIMUM
    } else {
        UNSIGNED_RECIPROCAL_SQRT_MINIMUM
    };
    let bits = if bits < minimum {
        u64::from(u32::MAX)
    } else {
        let scaled = bits >> UNSIGNED_TABLE_SHIFT;
        let estimate = if kind == Kind::UnsignedReciprocal {
            reciprocal_table(scaled)
        } else {
            reciprocal_sqrt_table(scaled)
        };
        estimate << UNSIGNED_TABLE_SHIFT
    };
    Outcome {
        bits,
        exceptions: 0,
    }
}

fn reciprocal(format: Format, control: Control, bits: u64, exceptions: &mut u32) -> u64 {
    let fraction_bits = format.fraction_bits();
    let fraction_mask = format.fraction_mask();
    let sign = bits & format.sign_mask();
    let mut fraction = bits & fraction_mask;
    let mut exponent = ((bits & format.exponent_mask()) >> fraction_bits) as i32;
    let reciprocal_exponent_base = format.exponent_bias() as i32 * 2 - 1;

    // The overflow threshold is one quarter of minimum normal in every format.
    if exponent == 0 && fraction < 1 << (fraction_bits - 2) {
        *exceptions |= OVERFLOW | INEXACT;
        let infinity = match control.round() {
            Round::NearestTiesToEven | Round::NearestTiesToAway => true,
            Round::TowardPositive => sign == 0,
            Round::TowardNegative => sign != 0,
            Round::TowardZero => false,
        };
        return sign
            | if infinity {
                format.exponent_mask()
            } else {
                format.exponent_mask() - 1
            };
    }
    if control.flush_output(format) && exponent >= reciprocal_exponent_base {
        // Estimate output flushing directly sets UFC, without IXC.
        *exceptions |= UNDERFLOW;
        return sign;
    }

    if exponent == 0 {
        if fraction & (1 << (fraction_bits - 1)) == 0 {
            exponent = -1;
            fraction = (fraction << 2) & fraction_mask;
        } else {
            fraction = (fraction << 1) & fraction_mask;
        }
    }
    let scaled = ESTIMATE_UNIT | (fraction >> (fraction_bits - ESTIMATE_FRACTION_BITS));
    let estimate = reciprocal_table(scaled);
    let exponent = reciprocal_exponent_base - exponent;
    let significand = estimate << (fraction_bits - ESTIMATE_FRACTION_BITS);
    if exponent <= 0 {
        sign | (significand >> (1 - exponent))
    } else {
        sign | ((exponent as u64) << fraction_bits) | (significand & fraction_mask)
    }
}

fn reciprocal_sqrt(format: Format, bits: u64) -> u64 {
    let fraction_bits = format.fraction_bits();
    let mut fraction = bits & format.fraction_mask();
    let mut exponent = ((bits & format.exponent_mask()) >> fraction_bits) as i32;
    if exponent == 0 {
        let normalization = fraction_bits - fraction.ilog2();
        fraction = (fraction << normalization) & format.fraction_mask();
        exponent = 1 - normalization as i32;
    }
    let scaled = if exponent.rem_euclid(2) == 0 {
        ESTIMATE_UNIT | (fraction >> (fraction_bits - ESTIMATE_FRACTION_BITS))
    } else {
        (ESTIMATE_UNIT / 2) | (fraction >> (fraction_bits - ESTIMATE_FRACTION_BITS + 1))
    };
    let estimate = reciprocal_sqrt_table(scaled);
    let exponent = (format.exponent_bias() as i32 * 3 - 1 - exponent).div_euclid(2);
    ((exponent as u64) << fraction_bits)
        | ((estimate - ESTIMATE_UNIT) << (fraction_bits - ESTIMATE_FRACTION_BITS))
}

fn reciprocal_exponent(format: Format, bits: u64) -> u64 {
    let exponent = bits & format.exponent_mask();
    let result_exponent = if exponent == 0 {
        format.exponent_mask() - (1 << format.fraction_bits())
    } else {
        format.exponent_mask() ^ exponent
    };
    (bits & format.sign_mask()) | result_exponent
}

/// Evaluate one lane; callers own scalar merging, active lanes and sticky commit.
/// Unsigned kinds always interpret low32 bits and ignore format/FPCR entirely.
/// AH floating kinds suppress all exception effects and accept retained enables.
pub fn evaluate(
    kind: Kind,
    format: Format,
    fpcr: u32,
    bits: u64,
) -> Result<Outcome, UnsupportedControl> {
    if kind.is_unsigned() {
        return Ok(unsigned(kind, bits));
    }
    let alternative = Control(fpcr).alternative();
    let control = if alternative {
        let mut effective = fpcr | FPCR_FIZ | FPCR_FZ;
        if kind == Kind::Reciprocal {
            effective &= !(FPCR_ROUNDING_MASK << FPCR_ROUNDING_SHIFT);
        }
        Control(effective)
    } else {
        Control::checked(fpcr)?
    };
    let mut exceptions = 0;
    let operand = unpack(format, bits, control, &mut exceptions);
    let bits = if let Some(bits) = nan(format, operand, operand, control, &mut exceptions) {
        bits
    } else {
        match kind {
            Kind::ReciprocalExponent => reciprocal_exponent(format, bits),
            Kind::Reciprocal if operand.class == Class::Infinity => {
                operand.bits & format.sign_mask()
            }
            Kind::Reciprocal | Kind::ReciprocalSquareRoot if operand.class == Class::Zero => {
                exceptions |= DIVIDE_BY_ZERO;
                format.infinity(operand.negative)
            }
            Kind::Reciprocal => reciprocal(format, control, operand.bits, &mut exceptions),
            Kind::ReciprocalSquareRoot if operand.negative => {
                exceptions |= super::INVALID;
                control.default_nan(format)
            }
            Kind::ReciprocalSquareRoot if operand.class == Class::Infinity => 0,
            Kind::ReciprocalSquareRoot => reciprocal_sqrt(format, operand.bits),
            Kind::UnsignedReciprocal | Kind::UnsignedReciprocalSquareRoot => {
                unreachable!("unsigned handled before FP controls")
            }
        }
    };
    // fpexc=false in all AH estimate helpers, including direct output UFC writes.
    Ok(Outcome {
        bits,
        exceptions: if alternative { 0 } else { exceptions },
    })
}

#[cfg(test)]
mod tests;
