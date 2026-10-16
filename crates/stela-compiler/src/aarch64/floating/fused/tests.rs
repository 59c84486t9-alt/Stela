use super::*;
use crate::aarch64::floating::{FPCR_AH, FPCR_ROUNDING_SHIFT};

#[test]
fn fused_residual_survives_in_every_format_and_rounding_mode() {
    for (format, addend, left, right, expected) in [
        (Format::Half, 0xbc00, 0x3c01, 0x3bfe, 0x8010),
        (
            Format::Single,
            0xbf800000,
            0x3f800001,
            0x3f7ffffe,
            0xa8800000,
        ),
        (
            Format::Double,
            0xbff0000000000000,
            0x3ff0000000000001,
            0x3feffffffffffffe,
            0xb970000000000000,
        ),
    ] {
        for round in 0..4 {
            assert_eq!(
                evaluate(
                    format,
                    FusedOperation::Add,
                    round << FPCR_ROUNDING_SHIFT,
                    addend,
                    left,
                    right
                ),
                Ok(Outcome {
                    bits: expected,
                    exceptions: 0
                })
            );
        }
    }
}

#[test]
fn alternative_nan_priority_and_invalid_product_override_are_distinct() {
    const QNAN_A: u64 = 0x7fc00011;
    const SNAN_N: u64 = 0x7f800022;
    const QNAN_M: u64 = 0x7fc00033;
    for (control, expected) in [(0, SNAN_N | 0x00400000), (FPCR_AH, SNAN_N | 0x00400000)] {
        assert_eq!(
            evaluate(
                Format::Single,
                FusedOperation::Add,
                control,
                QNAN_A,
                SNAN_N,
                QNAN_M
            ),
            Ok(Outcome {
                bits: expected,
                exceptions: INVALID
            })
        );
    }
    const SNAN_A: u64 = 0x7f800011;
    const QNAN_N: u64 = 0x7fc00022;
    const ONE: u64 = 0x3f800000;
    for (control, expected) in [(0, SNAN_A | 0x00400000), (FPCR_AH, QNAN_N)] {
        assert_eq!(
            evaluate(
                Format::Single,
                FusedOperation::Add,
                control,
                SNAN_A,
                QNAN_N,
                ONE
            ),
            Ok(Outcome {
                bits: expected,
                exceptions: INVALID
            })
        );
    }
    for (control, bits, exceptions) in [(0, 0x7fc00000, INVALID), (FPCR_AH, QNAN_A, 0)] {
        assert_eq!(
            evaluate(
                Format::Single,
                FusedOperation::Add,
                control,
                QNAN_A,
                0,
                0x7f800000
            ),
            Ok(Outcome { bits, exceptions })
        );
    }
}
