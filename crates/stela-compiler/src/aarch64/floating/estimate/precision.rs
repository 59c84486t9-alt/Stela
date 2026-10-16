//! FEAT_RPRES Single estimates under alternative floating-point behavior.
//! The caller selects this module only for Single + AH + available RPRES.
use super::super::{Class, Control, FPCR_FIZ, FPCR_FZ, Format, Outcome, nan, unpack};

const FORMAT: Format = Format::Single;
const INPUT_FRACTION_BITS: u32 = 11;
const RESULT_FRACTION_BITS: u32 = 12;
const INPUT_UNIT: u64 = 1 << INPUT_FRACTION_BITS;
const RESULT_UNIT: u64 = 1 << RESULT_FRACTION_BITS;
const RECIPROCAL_NUMERATOR: u64 = 1 << 26;
const RECIPROCAL_SQRT_NUMERATOR: u64 = 1 << 39;

fn reciprocal_table(scaled: u64) -> u64 {
    debug_assert!((INPUT_UNIT..INPUT_UNIT * 2).contains(&scaled));
    (RECIPROCAL_NUMERATOR / (scaled * 2 + 1)).div_ceil(2)
}

fn reciprocal_sqrt_table(scaled: u64) -> u64 {
    debug_assert!((INPUT_UNIT / 2..INPUT_UNIT * 2).contains(&scaled));
    let midpoint = if scaled < INPUT_UNIT {
        scaled * 2 + 1
    } else {
        ((scaled & !1) + 1) * 2
    };
    // The source's strict midpoint*(b+1)^2 < numerator loop is equivalent
    // to this integer root after subtracting one from its numerator.
    ((RECIPROCAL_SQRT_NUMERATOR - 1) / midpoint)
        .isqrt()
        .div_ceil(2)
}

fn finite_reciprocal(bits: u64) -> u64 {
    let fraction_bits = FORMAT.fraction_bits();
    let exponent = (bits & FORMAT.exponent_mask()) >> fraction_bits;
    let sign = bits & FORMAT.sign_mask();
    let base_exponent = u64::from(FORMAT.exponent_bias()) * 2 - 1;
    // AH forces FIZ and FZ. Subnormal inputs took the zero branch, and these
    // large normal inputs flush their estimated output to signed zero.
    if exponent >= base_exponent {
        return sign;
    }
    let fraction = bits & FORMAT.fraction_mask();
    let scaled = INPUT_UNIT | (fraction >> (fraction_bits - INPUT_FRACTION_BITS));
    let estimate = reciprocal_table(scaled);
    sign | ((base_exponent - exponent) << fraction_bits)
        | ((estimate - RESULT_UNIT) << (fraction_bits - RESULT_FRACTION_BITS))
}

fn finite_reciprocal_sqrt(bits: u64) -> u64 {
    let fraction_bits = FORMAT.fraction_bits();
    let exponent = (bits & FORMAT.exponent_mask()) >> fraction_bits;
    let fraction = bits & FORMAT.fraction_mask();
    let scaled = if exponent.is_multiple_of(2) {
        INPUT_UNIT | (fraction >> (fraction_bits - INPUT_FRACTION_BITS))
    } else {
        (INPUT_UNIT / 2) | (fraction >> (fraction_bits - INPUT_FRACTION_BITS + 1))
    };
    let estimate = reciprocal_sqrt_table(scaled);
    let exponent = (u64::from(FORMAT.exponent_bias()) * 3 - 1 - exponent) / 2;
    (exponent << fraction_bits)
        | ((estimate - RESULT_UNIT) << (fraction_bits - RESULT_FRACTION_BITS))
}

fn evaluate(fpcr: u32, bits: u64, square_root: bool) -> Outcome {
    let control = Control(fpcr | FPCR_FIZ | FPCR_FZ);
    assert!(control.alternative(), "RPRES Single estimates require AH");
    // fpexc=false suppresses all newly computed status, including signaling
    // NaNs and the estimate helper's direct output-underflow status write.
    let mut discarded_exceptions = 0;
    let operand = unpack(FORMAT, bits, control, &mut discarded_exceptions);
    let bits = if let Some(bits) = nan(FORMAT, operand, operand, control, &mut discarded_exceptions)
    {
        bits
    } else if operand.class == Class::Zero {
        FORMAT.infinity(operand.negative)
    } else if square_root && operand.negative {
        control.default_nan(FORMAT)
    } else if operand.class == Class::Infinity {
        if square_root {
            0
        } else {
            operand.bits & FORMAT.sign_mask()
        }
    } else if square_root {
        finite_reciprocal_sqrt(operand.bits)
    } else {
        finite_reciprocal(operand.bits)
    };
    Outcome {
        bits,
        exceptions: 0,
    }
}

/// Increased-precision FPRecipEstimate for Single + AH; retained enables cannot trap.
pub fn reciprocal(fpcr: u32, bits: u64) -> Outcome {
    evaluate(fpcr, bits, false)
}

/// Increased-precision FPRSqrtEstimate for Single + AH; retained enables cannot trap.
pub fn reciprocal_sqrt(fpcr: u32, bits: u64) -> Outcome {
    evaluate(fpcr, bits, true)
}

#[cfg(test)]
mod tests;
