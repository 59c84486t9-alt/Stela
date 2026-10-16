use super::*;

const FORMAT_RESERVED: u32 = 2;
const REGISTER_COUNT: u32 = REGISTER_MASK + 1;
const GENERAL_OPERATIONS: [(u32, Direction); 6] = [
    (GENERAL_SCVTF, Direction::FromInteger),
    (
        GENERAL_FCVTNS,
        Direction::ToInteger(IntegerRounding::NearestEven),
    ),
    (
        GENERAL_FCVTAS,
        Direction::ToInteger(IntegerRounding::NearestAway),
    ),
    (
        GENERAL_FCVTPS,
        Direction::ToInteger(IntegerRounding::TowardPositive),
    ),
    (
        GENERAL_FCVTMS,
        Direction::ToInteger(IntegerRounding::TowardNegative),
    ),
    (
        GENERAL_FCVTZS,
        Direction::ToInteger(IntegerRounding::TowardZero),
    ),
];
const SIMD_OPERATIONS: [(u32, Direction); 6] = [
    (SIMD_SCVTF, Direction::FromInteger),
    (
        SIMD_FCVTNS,
        Direction::ToInteger(IntegerRounding::NearestEven),
    ),
    (
        SIMD_FCVTAS,
        Direction::ToInteger(IntegerRounding::NearestAway),
    ),
    (
        SIMD_FCVTPS,
        Direction::ToInteger(IntegerRounding::TowardPositive),
    ),
    (
        SIMD_FCVTMS,
        Direction::ToInteger(IntegerRounding::TowardNegative),
    ),
    (
        SIMD_FCVTZS,
        Direction::ToInteger(IntegerRounding::TowardZero),
    ),
];
const FORMATS: [(u32, Format); 3] = [
    (FORMAT_SINGLE, Format::Single),
    (FORMAT_DOUBLE, Format::Double),
    (FORMAT_HALF, Format::Half),
];

fn apply_registers(operand: Operand, destination: u8, source: u8) -> Operand {
    match operand {
        Operand::Precision(mut operand) => {
            operand.destination = destination;
            operand.source = source;
            Operand::Precision(operand)
        }
        Operand::JavaScript { .. } => Operand::JavaScript {
            destination: general_register(destination),
            source,
        },
        Operand::FromInteger(mut operand) => {
            operand.float = destination;
            operand.integer = integer_register(operand.integer, source);
            Operand::FromInteger(operand)
        }
        Operand::ToInteger {
            mut operand,
            rounding,
        } => {
            operand.float = source;
            operand.integer = integer_register(operand.integer, destination);
            Operand::ToInteger { operand, rounding }
        }
    }
}

fn integer_register(operand: IntegerOperand, register: u8) -> IntegerOperand {
    match operand {
        IntegerOperand::General { format, .. } => IntegerOperand::General {
            register: general_register(register),
            format,
        },
        IntegerOperand::Simd { format, shape, .. } => IntegerOperand::Simd {
            register,
            format,
            shape,
        },
    }
}

// Every arrangement exercises all source/destination aliases and V31/ZR
// roles, independently of the register values used by native fixtures.
fn check_registers(word: u32, expected: Operand) {
    for destination in 0..REGISTER_COUNT {
        for source in 0..REGISTER_COUNT {
            let word = word | (source << SOURCE_SHIFT) | destination;
            assert_eq!(
                decode(word),
                Some(Ok(apply_registers(
                    expected,
                    destination as u8,
                    source as u8
                ))),
                "word={word:08x}"
            );
        }
    }
}

fn precision(word: u32, mode: PrecisionMode) {
    check_registers(
        word,
        Operand::Precision(PrecisionOperand {
            mode,
            destination: 0,
            source: 0,
        }),
    );
}

#[test]
fn precision_formats_parts_rounding_and_all_aliases_are_explicit() {
    let mut arrangements = 0;
    for (source_field, source) in FORMATS {
        for (destination_field, destination) in FORMATS {
            let word = SCALAR_FCVT
                | (source_field << FORMAT_SHIFT)
                | (destination_field << DESTINATION_FORMAT_SHIFT);
            if source == destination {
                assert_eq!(decode(word), Some(Err(())));
            } else {
                precision(
                    word,
                    PrecisionMode::Scalar {
                        source,
                        destination,
                        rounding: PrecisionRounding::Fpcr,
                    },
                );
                arrangements += 1;
            }
        }
    }
    for (size, small, large) in [
        (0, Format::Half, Format::Single),
        (SIMD_DOUBLE, Format::Single, Format::Double),
    ] {
        for (q, upper) in [(0, false), (VECTOR_Q, true)] {
            let long = PrecisionMode::Widen {
                source: small,
                upper,
            };
            assert_eq!(long.source_format(), small);
            assert_eq!(long.destination_format(), large);
            precision(FCVTL | size | q, long);
            let narrow = PrecisionMode::Narrow {
                destination: small,
                upper,
                rounding: PrecisionRounding::Fpcr,
            };
            assert_eq!(narrow.source_format(), large);
            assert_eq!(narrow.destination_format(), small);
            precision(FCVTN | size | q, narrow);
            arrangements += 2;
        }
    }
    precision(
        SCALAR_FCVTXN,
        PrecisionMode::Scalar {
            source: Format::Double,
            destination: Format::Single,
            rounding: PrecisionRounding::ToOdd,
        },
    );
    for (q, upper) in [(0, false), (VECTOR_Q, true)] {
        precision(
            VECTOR_FCVTXN | q,
            PrecisionMode::Narrow {
                destination: Format::Single,
                upper,
                rounding: PrecisionRounding::ToOdd,
            },
        );
    }
    assert_eq!(arrangements + 3, 17);
}

#[test]
fn general_integer_widths_rounding_scales_and_all_register_roles_are_explicit() {
    let mut unscaled = 0;
    let mut fixed = 0;
    for (unsigned, signed) in [(0, true), (GENERAL_UNSIGNED, false)] {
        for (wide, width, bits) in [
            (0, IntegerWidth::Bits32, 32),
            (GENERAL_WIDE, IntegerWidth::Bits64, 64),
        ] {
            for (format_field, format) in FORMATS {
                let integer = IntegerOperand::General {
                    register: Register::X(0),
                    format: IntegerFormat { width, signed },
                };
                let expected = IntegerConversion {
                    integer,
                    float: 0,
                    format,
                    frac_bits: 0,
                };
                assert_eq!(integer.format(), IntegerFormat { width, signed });
                assert_eq!(integer.shape(), Shape::Scalar);
                for (opcode, direction) in GENERAL_OPERATIONS {
                    check_registers(
                        opcode | unsigned | wide | (format_field << FORMAT_SHIFT),
                        direction.operand(expected),
                    );
                    unscaled += 1;
                }
                for (opcode, direction) in [
                    (GENERAL_FIXED_SCVTF, Direction::FromInteger),
                    (
                        GENERAL_FIXED_FCVTZS,
                        Direction::ToInteger(IntegerRounding::TowardZero),
                    ),
                ] {
                    for frac_bits in 1..=bits {
                        check_registers(
                            opcode
                                | unsigned
                                | wide
                                | (format_field << FORMAT_SHIFT)
                                | ((SCALE_BIAS - frac_bits) << SCALE_SHIFT),
                            direction.operand(IntegerConversion {
                                frac_bits: frac_bits as u8,
                                ..expected
                            }),
                        );
                        fixed += 1;
                    }
                }
            }
        }
    }
    assert_eq!(unscaled, 72);
    assert_eq!(fixed, 1152);
}

#[test]
fn simd_integer_widths_rounding_scales_shapes_and_all_aliases_are_explicit() {
    let mut unscaled = 0;
    let mut fixed = 0;
    for (unsigned, signed) in [(0, true), (SIMD_UNSIGNED, false)] {
        for format in [Format::Half, Format::Single, Format::Double] {
            for (shape, prefix) in [
                (Shape::Scalar, SIMD_SCALAR_PREFIX),
                (Shape::Vector64, 0),
                (Shape::Vector128, VECTOR_Q),
            ] {
                if format == Format::Double && shape == Shape::Vector64 {
                    continue;
                }
                let width = integer_width(format);
                let integer = IntegerOperand::Simd {
                    register: 0,
                    format: IntegerFormat { width, signed },
                    shape,
                };
                let expected = IntegerConversion {
                    integer,
                    float: 0,
                    format,
                    frac_bits: 0,
                };
                assert_eq!(integer.format(), IntegerFormat { width, signed });
                assert_eq!(integer.shape(), shape);
                let size = match format {
                    Format::Half => SIMD_HALF_ADJUSTMENT,
                    Format::Single => 0,
                    Format::Double => SIMD_DOUBLE,
                };
                for (opcode, direction) in SIMD_OPERATIONS {
                    check_registers(
                        (opcode ^ size) | unsigned | prefix,
                        direction.operand(expected),
                    );
                    unscaled += 1;
                }
                for (opcode, direction) in [
                    (SIMD_FIXED_SCVTF, Direction::FromInteger),
                    (
                        SIMD_FIXED_FCVTZS,
                        Direction::ToInteger(IntegerRounding::TowardZero),
                    ),
                ] {
                    for frac_bits in 1..=format.bits() {
                        check_registers(
                            opcode
                                | unsigned
                                | prefix
                                | ((2 * format.bits() - frac_bits) << IMMEDIATE_SHIFT),
                            direction.operand(IntegerConversion {
                                frac_bits: frac_bits as u8,
                                ..expected
                            }),
                        );
                        fixed += 1;
                    }
                }
            }
        }
    }
    assert_eq!(unscaled, 96);
    assert_eq!(fixed, 1088);
}

#[test]
fn javascript_destination_uses_zero_register_and_source_uses_v31() {
    check_registers(
        FJCVTZS,
        Operand::JavaScript {
            destination: Register::X(0),
            source: 0,
        },
    );
}

#[test]
fn reserved_formats_scales_and_vector_one_double_are_rejected() {
    for (opcode, _) in GENERAL_OPERATIONS {
        for signed in [0, GENERAL_UNSIGNED] {
            for wide in [0, GENERAL_WIDE] {
                assert_eq!(
                    decode(opcode | signed | wide | (FORMAT_RESERVED << FORMAT_SHIFT)),
                    Some(Err(()))
                );
            }
        }
    }
    for opcode in [GENERAL_FIXED_SCVTF, GENERAL_FIXED_FCVTZS] {
        for signed in [0, GENERAL_UNSIGNED] {
            for (field, _) in FORMATS {
                for scale in 0..IMMEDIATE_SINGLE_MINIMUM {
                    assert_eq!(
                        decode(opcode | signed | (field << FORMAT_SHIFT) | (scale << SCALE_SHIFT)),
                        Some(Err(()))
                    );
                }
            }
            for wide in [0, GENERAL_WIDE] {
                assert_eq!(
                    decode(opcode | signed | wide | (FORMAT_RESERVED << FORMAT_SHIFT)),
                    Some(Err(()))
                );
            }
        }
    }
    for (opcode, _) in SIMD_OPERATIONS {
        for signed in [0, SIMD_UNSIGNED] {
            assert_eq!(decode(opcode | signed | SIMD_DOUBLE), Some(Err(())));
        }
    }
    for opcode in [SIMD_FIXED_SCVTF, SIMD_FIXED_FCVTZS] {
        for signed in [0, SIMD_UNSIGNED] {
            for prefix in [0, VECTOR_Q, SIMD_SCALAR_PREFIX] {
                for immediate in 0..IMMEDIATE_SHIFT_CLASS_MINIMUM {
                    assert_eq!(
                        decode(opcode | signed | prefix | (immediate << IMMEDIATE_SHIFT)),
                        None
                    );
                }
                for immediate in IMMEDIATE_SHIFT_CLASS_MINIMUM..IMMEDIATE_HALF_MINIMUM {
                    assert_eq!(
                        decode(opcode | signed | prefix | (immediate << IMMEDIATE_SHIFT)),
                        Some(Err(()))
                    );
                }
            }
            for immediate in IMMEDIATE_DOUBLE_MINIMUM..=IMMEDIATE_MASK {
                assert_eq!(
                    decode(opcode | signed | (immediate << IMMEDIATE_SHIFT)),
                    Some(Err(()))
                );
            }
        }
    }
    for destination in 0..=FORMAT_MASK {
        assert_eq!(
            decode(
                SCALAR_FCVT
                    | (FORMAT_RESERVED << FORMAT_SHIFT)
                    | (destination << DESTINATION_FORMAT_SHIFT)
            ),
            Some(Err(()))
        );
    }
}

#[test]
fn adjacent_features_and_unrelated_families_do_not_gain_support() {
    // Exact June canonical facts: BFCVT/BFCVTN, both FP8 FCVTN classes,
    // representative signed/unsigned FPRCVT forms, FMOV and FRINTN.
    const OTHER_FAMILIES: [u32; 12] = [
        0x1e634000, 0x0ea16800, 0x0e40f400, 0x0e60f400, 0x1e7a0000, 0x1e7b0000, 0x1e6a0000,
        0x1e6b0000, 0x9efc0000, 0x9efd0000, 0x1e204000, 0x1e244000,
    ];
    for word in OTHER_FAMILIES {
        assert_eq!(decode(word), None, "word={word:08x}");
    }
    // FCVTL/N bit23 is fixed zero; FCVTXN size23:22 is fixed01.
    const PRECISION_SIZE_HIGH: u32 = 1 << 23;
    for word in [FCVTL, FCVTN] {
        assert_eq!(decode(word | PRECISION_SIZE_HIGH), None);
    }
    for word in [VECTOR_FCVTXN, SCALAR_FCVTXN] {
        assert_eq!(decode(word ^ SIMD_DOUBLE), None);
        assert_eq!(decode(word | PRECISION_SIZE_HIGH), None);
    }
}

#[test]
fn modified_immediates_keep_their_existing_decoder_and_compiler_paths() {
    use crate::{GuestAddress, Lifter, aarch64, block};

    const MODIFIED_IMMEDIATE: u32 = 0x0f000400;
    const CMODE_SHIFT: u32 = 12;
    const CMODE_COUNT: u32 = 16;
    const HALF_FLOAT: u32 = 1 << 11;
    const IMMEDIATE_HIGH_SHIFT: u32 = 5;
    const IMMEDIATE_HIGH_MASK: u32 = 7;
    const IMMEDIATE_COUNT: u32 = 256;
    const MOVI_CMODE: u32 = 14;
    const FMOV_CMODE: u32 = 15;
    const RETURN_X30: u32 = 0xd65f03c0;
    const OLD_MOVI_TWO_D: u32 = 0x6f00e400;
    const BASE: GuestAddress = GuestAddress(0x1000);

    assert_eq!(decode(OLD_MOVI_TWO_D), None);
    let mut decoded = 0;
    let mut compiled = 0;
    for q in [0, VECTOR_Q] {
        for op in [0, SIMD_UNSIGNED] {
            for half in [0, HALF_FLOAT] {
                for cmode in 0..CMODE_COUNT {
                    for immediate in 0..IMMEDIATE_COUNT {
                        for destination in [0, REGISTER_MASK] {
                            let word = MODIFIED_IMMEDIATE
                                | q
                                | op
                                | half
                                | (cmode << CMODE_SHIFT)
                                | (((immediate >> IMMEDIATE_HIGH_SHIFT) & IMMEDIATE_HIGH_MASK)
                                    << IMMEDIATE_SHIFT)
                                | ((immediate & REGISTER_MASK) << SOURCE_SHIFT)
                                | destination;
                            assert_eq!(decode(word), None, "word={word:08x}");
                            let Some(Ok(expected)) = super::super::decode(word) else {
                                continue;
                            };
                            assert_eq!(
                                aarch64::Decoder.lift(BASE, word).unwrap().operation,
                                aarch64::Operation::Simd(expected),
                                "word={word:08x}"
                            );
                            decoded += 1;
                            // Compile every immediate/Q/register arrangement
                            // in the allocated classes intersecting our masks.
                            if (cmode == MOVI_CMODE && half == 0)
                                || (cmode == FMOV_CMODE && half == HALF_FLOAT)
                            {
                                let mut source = word.to_le_bytes().to_vec();
                                source.extend(RETURN_X30.to_le_bytes());
                                assert!(crate::compile(&source, BASE).is_ok(), "word={word:08x}");
                                assert!(block::compile(&source, BASE).is_ok(), "word={word:08x}");
                                compiled += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(decoded > 0);
    assert_eq!(compiled, 3072);
}
