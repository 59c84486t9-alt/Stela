//! FEAT_RPRES single-precision estimates, used only when FPCR.AH is set.
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
mod tests {
    use super::super::super::{FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK};
    use super::*;

    #[test]
    fn every_table_bin_matches_the_architectural_integer_loop() {
        for scaled in INPUT_UNIT / 2..INPUT_UNIT * 2 {
            let midpoint = if scaled < INPUT_UNIT {
                scaled * 2 + 1
            } else {
                ((scaled >> 1) * 2 + 1) * 2
            };
            let mut bound = RESULT_UNIT * 2;
            while midpoint * (bound + 1) * (bound + 1) < RECIPROCAL_SQRT_NUMERATOR {
                bound += 1;
            }
            assert_eq!(reciprocal_sqrt_table(scaled), bound.div_ceil(2));
            if scaled >= INPUT_UNIT {
                assert_eq!(
                    reciprocal_table(scaled),
                    (RECIPROCAL_NUMERATOR / (scaled * 2 + 1)).div_ceil(2)
                );
            }
        }
    }

    #[test]
    fn unit_special_values_and_retained_enables_have_fixed_bits_without_status() {
        let controls = FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK;
        for (input, reciprocal_bits, sqrt_bits) in [
            (0x3f80_0000, 0x3f7f_f000, 0x3f7f_f000),
            (0, 0x7f80_0000, 0x7f80_0000),
            (0x8000_0001, 0xff80_0000, 0xff80_0000),
            (0x7f80_0000, 0, 0),
            (0xff80_0000, 0x8000_0000, 0xffc0_0000),
            (0x7f80_0123, 0x7fc0_0123, 0x7fc0_0123),
            (0x7e80_0000, 0, 0x1fff_f000),
        ] {
            assert_eq!(
                reciprocal(controls, input),
                Outcome {
                    bits: reciprocal_bits,
                    exceptions: 0
                }
            );
            assert_eq!(
                reciprocal_sqrt(controls, input),
                Outcome {
                    bits: sqrt_bits,
                    exceptions: 0
                }
            );
        }
        assert_eq!(
            reciprocal(controls | FPCR_DN, 0x7f80_0123).bits,
            0xffc0_0000
        );
    }
}
