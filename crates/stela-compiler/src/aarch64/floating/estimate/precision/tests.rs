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
