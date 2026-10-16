use super::*;
use crate::aarch64::floating::{FPCR_AH, FPCR_ROUNDING_SHIFT};

#[test]
fn fp8_nan_classes_and_unsupported_formats_are_architectural() {
    for negative in [0, FP8_SIGN] {
        assert_eq!(
            unpack(FP8Format::E4M3, 127 | negative).class,
            FP8Class::SignalingNaN
        );
        assert_eq!(
            unpack(FP8Format::E5M2, 125 | negative).class,
            FP8Class::SignalingNaN
        );
        for quiet in [126, 127] {
            assert_eq!(
                unpack(FP8Format::E5M2, quiet | negative).class,
                FP8Class::QuietNaN
            );
        }
    }
    for bits in 0..=255 {
        assert_eq!(
            unpack(FP8Format::Unsupported, bits).class,
            FP8Class::SignalingNaN
        );
        assert_eq!(
            from_fp8(ConversionFormat::Half, false, FPCR_AH, 2, bits),
            Ok(Outcome {
                bits: 0xfe00,
                exceptions: INVALID
            })
        );
    }
}

#[test]
fn scale_widths_are_specific_to_each_conversion() {
    // E5M2 1.0: BF LSCALE bit6 is ignored; Half sees only low4.
    assert_eq!(
        from_fp8(
            ConversionFormat::BFloat16,
            false,
            0,
            64 << FPMR_LSCALE_SHIFT,
            0x3c
        ),
        Ok(Outcome {
            bits: 0x3f80,
            exceptions: 0
        })
    );
    assert_eq!(
        from_fp8(
            ConversionFormat::Half,
            false,
            0,
            16 << FPMR_LSCALE_SHIFT,
            0x3c
        ),
        Ok(Outcome {
            bits: 0x3c00,
            exceptions: 0
        })
    );
    // NSCALE low5 sign extends -16 for Half; Single sees +16.
    assert_eq!(
        to_fp8(ConversionFormat::Half, 0, 16 << FPMR_NSCALE_SHIFT, 0x3c00),
        Ok(Outcome {
            bits: 1,
            exceptions: 0
        })
    );
    assert_eq!(
        to_fp8(
            ConversionFormat::Single,
            0,
            16 << FPMR_NSCALE_SHIFT,
            0x3f80_0000
        ),
        Ok(Outcome {
            bits: 0x7c,
            exceptions: OVERFLOW | INEXACT
        })
    );
}

#[test]
fn forced_controls_and_default_nan_sign_preserve_status() {
    for controls in [
        0,
        FPCR_AHP,
        FPCR_FIZ | FPCR_FZ | FPCR_FZ16,
        3 << FPCR_ROUNDING_SHIFT,
    ] {
        assert_eq!(
            to_fp8(ConversionFormat::Half, controls, 0, 0x7c00),
            Ok(Outcome {
                bits: 0x7c,
                exceptions: 0
            })
        );
        assert_eq!(
            to_fp8(ConversionFormat::Half, controls, 0, 0x7c01),
            Ok(Outcome {
                bits: 0x7e,
                exceptions: INVALID
            })
        );
    }
    assert_eq!(
        to_fp8(
            ConversionFormat::Single,
            FPCR_AH,
            1 << FPMR_F8D_SHIFT,
            0x7fc0_1234
        ),
        Ok(Outcome {
            bits: 0xff,
            exceptions: 0
        })
    );
    assert!(to_fp8(ConversionFormat::Half, FPCR_EXCEPTION_ENABLE_MASK, 0, 0).is_err());
    assert!(
        from_fp8(
            ConversionFormat::Half,
            false,
            FPCR_EXCEPTION_ENABLE_MASK,
            0,
            0
        )
        .is_err()
    );
}

#[test]
fn saturation_and_tininess_have_independent_architectural_effects() {
    let e4 = 1 << FPMR_F8D_SHIFT;
    assert_eq!(
        to_fp8(ConversionFormat::Single, 0, e4, 0xc3f0_0000),
        Ok(Outcome {
            bits: 0xff,
            exceptions: OVERFLOW | INEXACT
        })
    );
    assert_eq!(
        to_fp8(ConversionFormat::Single, 0, e4 | FPMR_OSC, 0xc3f0_0000),
        Ok(Outcome {
            bits: 0xfe,
            exceptions: OVERFLOW | INEXACT
        })
    );
    // 15 * 2^-18 is halfway from E5M2's top subnormal to min normal.
    // Unconstrained two-fraction-bit rounding rounds to the next binade.
    for ah in [0, FPCR_AH] {
        let expected = INEXACT | if ah == 0 { UNDERFLOW } else { 0 };
        assert_eq!(
            to_fp8(ConversionFormat::Single, ah, 0, 0x3870_0000),
            Ok(Outcome {
                bits: 4,
                exceptions: expected
            })
        );
    }
}

#[test]
fn fused_dot_retains_sticky_below_quad_precision_and_suppresses_traps() {
    // Dot is exactly 1 + 2^-24, a Single midpoint. The minimum Single
    // addend moves it above the midpoint despite lying below Quad precision.
    for controls in [
        0,
        FPCR_EXCEPTION_ENABLE_MASK | FPCR_AHP | FPCR_FIZ | FPCR_FZ | FPCR_FZ16,
    ] {
        assert_eq!(
            dot_add(Format::Single, controls, 0, 1, &[0x3c, 0x0c], &[0x3c, 0x0c]),
            0x3f80_0001
        );
        assert_eq!(
            dot_add(Format::Half, controls, 0, 0x7c00, &[0], &[0]),
            0x7c00
        );
    }
    assert_eq!(
        dot_add(Format::Single, 0, 0, 0x8000_0000, &[0x80], &[0]),
        0x8000_0000
    );
    assert_eq!(
        dot_add(Format::Single, 0, 0, 0, &[0x3c, 0xbc], &[0x3c, 0x3c]),
        0
    );
    assert_eq!(
        dot_add(Format::Half, 0, FPMR_OSM, 0, &[0x7b], &[0x7b]),
        0x7bff
    );
    assert_eq!(
        dot_add(Format::Single, FPCR_AH, 2, 0, &[0], &[0]),
        0xffc0_0000
    );
}
