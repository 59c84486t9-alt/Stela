use super::*;
use crate::aarch64::floating::{
    FPCR_AH, FPCR_FIZ, FPCR_FZ, FPCR_FZ16, FPCR_ROUNDING_SHIFT, INPUT_DENORMAL, OVERFLOW, UNDERFLOW,
};

const SIGNED16: IntegerFormat = IntegerFormat {
    width: IntegerWidth::Bits16,
    signed: true,
};
const UNSIGNED32: IntegerFormat = IntegerFormat {
    width: IntegerWidth::Bits32,
    signed: false,
};
const UNSIGNED64: IntegerFormat = IntegerFormat {
    width: IntegerWidth::Bits64,
    signed: false,
};

#[test]
fn integer_sign_extension_ignores_poisoned_high_bits() {
    for width in [
        IntegerWidth::Bits16,
        IntegerWidth::Bits32,
        IntegerWidth::Bits64,
    ] {
        assert_eq!(width.mask().count_ones(), width.bits());
        assert_eq!(
            from_integer(
                IntegerFormat {
                    width,
                    signed: true
                },
                Format::Double,
                0,
                0,
                u64::MAX
            ),
            Ok(Outcome {
                bits: 0xbff0000000000000,
                exceptions: 0
            })
        );
    }
    assert_eq!(
        from_integer(SIGNED16, Format::Single, 1, 0, 0x1234ffff),
        Ok(Outcome {
            bits: 0xbf000000,
            exceptions: 0
        })
    );
}

#[test]
fn fixed_integer_rounds_directly_to_half_without_double_rounding() {
    let halfway_plus_one = (1 << 63) | (1 << 52) | 1;
    assert_eq!(
        from_integer(UNSIGNED64, Format::Half, 63, FPCR_AHP, halfway_plus_one),
        Ok(Outcome {
            bits: 0x3c01,
            exceptions: INEXACT
        })
    );
    for (fpcr, bits, exceptions) in [
        (0, 0x400, UNDERFLOW | INEXACT),
        (FPCR_AH, 0x400, INEXACT),
        (FPCR_FZ16, 0, UNDERFLOW),
        (FPCR_AH | FPCR_FZ16, 0x400, INEXACT),
    ] {
        assert_eq!(
            from_integer(SIGNED16, Format::Half, 26, fpcr, 4095),
            Ok(Outcome { bits, exceptions })
        );
    }
}

#[test]
fn integer_to_half_observes_ieee_overflow_and_output_flush() {
    for (fpcr, bits, exceptions) in [
        (0, 1, 0),
        (FPCR_FZ16, 0, UNDERFLOW),
        (FPCR_FZ16 | FPCR_AH, 0, UNDERFLOW | INEXACT),
    ] {
        assert_eq!(
            from_integer(UNSIGNED32, Format::Half, 24, fpcr, 1),
            Ok(Outcome { bits, exceptions })
        );
    }
    for (fpcr, bits) in [
        (FPCR_AHP, 0x7c00),
        (FPCR_AHP | (3 << FPCR_ROUNDING_SHIFT), 0x7bff),
    ] {
        assert_eq!(
            from_integer(UNSIGNED32, Format::Half, 0, fpcr, 65536),
            Ok(Outcome {
                bits,
                exceptions: OVERFLOW | INEXACT
            })
        );
    }
    assert_eq!(
        from_integer(SIGNED16, Format::Half, 64, FPCR_AH, 0),
        Ok(Outcome {
            bits: 0,
            exceptions: 0
        })
    );
}

#[test]
fn full_width_integer_endpoints_survive_exact_scaling_and_saturation() {
    let signed64 = IntegerFormat {
        width: IntegerWidth::Bits64,
        signed: true,
    };
    assert_eq!(
        from_integer(signed64, Format::Double, 0, 0, 1 << 63),
        Ok(Outcome {
            bits: 0xc3e0000000000000,
            exceptions: 0,
        })
    );
    assert_eq!(
        from_integer(UNSIGNED64, Format::Double, 0, 0, u64::MAX),
        Ok(Outcome {
            bits: 0x43f0000000000000,
            exceptions: INEXACT,
        })
    );
    for (integer, source, bits, exceptions) in [
        (signed64, 0xc3e0000000000000, 1 << 63, 0),
        (signed64, 0x43e0000000000000, (1 << 63) - 1, INVALID),
        (UNSIGNED64, 0x43f0000000000000, u64::MAX, INVALID),
        (UNSIGNED64, 0x8000000000000000, 0, 0),
    ] {
        assert_eq!(
            to_integer(
                Format::Double,
                integer,
                0,
                IntegerRounding::TowardZero,
                0,
                source,
            ),
            Ok(Outcome { bits, exceptions })
        );
    }
}

#[test]
fn every_nan_class_converts_to_zero_and_invalid_even_in_alternative_half() {
    for (source, nan) in [
        (Format::Half, 0x7c01),
        (Format::Half, 0xfe01),
        (Format::Single, 0x7f800001),
        (Format::Single, 0xffc00001),
        (Format::Double, 0x7ff0000000000001),
        (Format::Double, 0xfff8000000000001),
    ] {
        assert_eq!(
            to_integer(
                source,
                UNSIGNED64,
                64,
                IntegerRounding::NearestAway,
                FPCR_AHP | FPCR_AH,
                nan,
            ),
            Ok(Outcome {
                bits: 0,
                exceptions: INVALID,
            })
        );
    }
}

#[test]
fn instruction_rounding_and_unsigned_negative_zero_are_distinct() {
    for (rounding, bits, exceptions) in [
        (IntegerRounding::NearestEven, 0, INEXACT),
        (IntegerRounding::NearestAway, 0, INVALID),
        (IntegerRounding::TowardPositive, 0, INEXACT),
        (IntegerRounding::TowardNegative, 0, INVALID),
        (IntegerRounding::TowardZero, 0, INEXACT),
    ] {
        assert_eq!(
            to_integer(
                Format::Double,
                UNSIGNED32,
                0,
                rounding,
                0,
                0xbfe0000000000000
            ),
            Ok(Outcome { bits, exceptions })
        );
    }
    for (rounding, bits) in [
        (IntegerRounding::NearestEven, 2),
        (IntegerRounding::NearestAway, 3),
        (IntegerRounding::TowardPositive, 3),
        (IntegerRounding::TowardNegative, 2),
        (IntegerRounding::TowardZero, 2),
    ] {
        assert_eq!(
            to_integer(
                Format::Double,
                SIGNED16,
                0,
                rounding,
                3 << FPCR_ROUNDING_SHIFT,
                0x4004000000000000
            ),
            Ok(Outcome {
                bits,
                exceptions: INEXACT
            })
        );
    }
}

#[test]
fn saturation_suppresses_inexact_but_does_not_set_qc() {
    for (bits, rounding, expected, exceptions) in [
        (
            0x40dfffe000000000,
            IntegerRounding::NearestEven,
            0x7fff,
            INVALID,
        ),
        (
            0x40dfffe000000000,
            IntegerRounding::TowardZero,
            0x7fff,
            INEXACT,
        ),
        (
            0xc0e0001000000000,
            IntegerRounding::NearestEven,
            0x8000,
            INEXACT,
        ),
        (
            0x7ff0000000000000,
            IntegerRounding::TowardZero,
            0x7fff,
            INVALID,
        ),
        (
            0xfff0000000000000,
            IntegerRounding::TowardZero,
            0x8000,
            INVALID,
        ),
        (0xfff8000000000001, IntegerRounding::TowardZero, 0, INVALID),
    ] {
        assert_eq!(
            to_integer(Format::Double, SIGNED16, 0, rounding, 0, bits),
            Ok(Outcome {
                bits: expected,
                exceptions
            })
        );
    }
}

#[test]
fn input_flush_and_exact_scaling_keep_integer_conversion_status() {
    for (fpcr, exceptions) in [
        (0, INEXACT),
        (FPCR_AH | FPCR_FZ, INEXACT),
        (FPCR_FIZ, 0),
        (FPCR_FZ, INPUT_DENORMAL),
        (FPCR_FIZ | FPCR_FZ, INPUT_DENORMAL),
    ] {
        assert_eq!(
            to_integer(
                Format::Single,
                SIGNED16,
                0,
                IntegerRounding::TowardZero,
                fpcr,
                1
            ),
            Ok(Outcome {
                bits: 0,
                exceptions
            })
        );
    }
    assert_eq!(
        to_integer(
            Format::Half,
            SIGNED16,
            24,
            IntegerRounding::TowardZero,
            FPCR_AHP,
            1
        ),
        Ok(Outcome {
            bits: 1,
            exceptions: 0
        })
    );
    assert_eq!(
        to_integer(
            Format::Half,
            SIGNED16,
            24,
            IntegerRounding::TowardZero,
            FPCR_FZ16,
            1
        ),
        Ok(Outcome {
            bits: 0,
            exceptions: 0
        })
    );
}

#[test]
fn javascript_modulo_range_fraction_and_zero_flags() {
    for (source, bits, exceptions, nzcv) in [
        (0, 0, 0, NZCV_ZERO),
        (0x8000000000000000, 0, 0, 0),
        (0x3ff0000000000000, 1, 0, NZCV_ZERO),
        (0xbff8000000000000, 0xffffffff, INEXACT, 0),
        (0x41e0000000000000, 0x80000000, INVALID, 0),
        (0xc1e0000000000000, 0x80000000, 0, NZCV_ZERO),
        (0x41f0000000100000, 1, INVALID, 0),
        (0xc1f0000000100000, 0xffffffff, INVALID, 0),
        (0x7fefffffffffffff, 0, INVALID, 0),
        (0xfff0000000000000, 0, INVALID, 0),
        (0x7ff8000000000001, 0, INVALID, 0),
        (0x41dfffffffe00000, 0x7fffffff, INEXACT, 0),
    ] {
        assert_eq!(
            to_javascript(0, source),
            Ok(JavaScriptOutcome {
                result: Outcome { bits, exceptions },
                nzcv
            })
        );
    }
    for source in [1, 0x8000000000000001] {
        for (fpcr, exceptions) in [
            (FPCR_FZ, INPUT_DENORMAL),
            (FPCR_FIZ, 0),
            (FPCR_AH | FPCR_FIZ, 0),
            (FPCR_AH | FPCR_FZ, INEXACT),
        ] {
            assert_eq!(
                to_javascript(fpcr, source),
                Ok(JavaScriptOutcome {
                    result: Outcome {
                        bits: 0,
                        exceptions
                    },
                    nzcv: 0
                })
            );
        }
    }
}

#[test]
fn kept_enables_decline_before_integer_or_special_value_effects() {
    for exception in [
        INVALID,
        super::super::DIVIDE_BY_ZERO,
        OVERFLOW,
        UNDERFLOW,
        INEXACT,
        INPUT_DENORMAL,
        EXCEPTIONS,
    ] {
        let fpcr = exception << FPCR_EXCEPTION_ENABLE_SHIFT;
        let unsupported = Err(UnsupportedControl {
            enabled_exceptions: exception,
        });
        assert_eq!(
            from_integer(SIGNED16, Format::Half, 0, fpcr, 0),
            unsupported
        );
        assert_eq!(
            to_integer(
                Format::Half,
                SIGNED16,
                0,
                IntegerRounding::TowardZero,
                fpcr,
                0x7e01
            ),
            unsupported
        );
        assert_eq!(
            to_javascript(fpcr, 0),
            Err(UnsupportedControl {
                enabled_exceptions: exception
            })
        );
    }
}
