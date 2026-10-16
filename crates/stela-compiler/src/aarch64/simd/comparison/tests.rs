use super::*;

const FORMATS: [(u32, Format); 3] = [
    (FORMAT_SINGLE, Format::Single),
    (FORMAT_DOUBLE, Format::Double),
    (FORMAT_HALF, Format::Half),
];
const REGISTER_OPERATIONS: [(u32, Predicate); 5] = [
    (FCMEQ, Predicate::Equal),
    (FCMGE, Predicate::GreaterEqual),
    (FCMGT, Predicate::Greater),
    (FACGE, Predicate::AbsoluteGreaterEqual),
    (FACGT, Predicate::AbsoluteGreater),
];
const ZERO_OPERATIONS: [(u32, Predicate); 5] = [
    (FCMEQ_ZERO, Predicate::Equal),
    (FCMGE_ZERO, Predicate::GreaterEqual),
    (FCMGT_ZERO, Predicate::Greater),
    (FCMLE_ZERO, Predicate::LessEqual),
    (FCMLT_ZERO, Predicate::Less),
];

#[test]
fn flags_formats_signaling_and_ignored_rm_cover_every_register() {
    for (field, format) in FORMATS {
        for signal in [0, SIGNAL_ALL_NANS] {
            for zero in [0, COMPARE_ZERO] {
                for left in 0..=REGISTER_MASK {
                    for right in 0..=REGISTER_MASK {
                        let word = FCMP
                            | (field << FORMAT_SHIFT)
                            | signal
                            | zero
                            | (left << LEFT_SHIFT)
                            | (right << RIGHT_SHIFT);
                        let expected = Operand::Flags {
                            format,
                            left: left as u8,
                            right: if zero == 0 {
                                CompareSource::Register(right as u8)
                            } else {
                                CompareSource::Zero
                            },
                            signal_all_nans: signal != 0,
                        };
                        assert_eq!(decode(word), Some(Ok(expected)), "word={word:08x}");
                        assert_eq!(expected.format(), format);
                    }
                }
            }
        }
    }
}

#[test]
fn conditional_flags_cover_all_conditions_fallbacks_signaling_and_aliases() {
    for (field, format) in FORMATS {
        for signal in [0, SIGNAL_ALL_NANS] {
            for condition in 0..=NZCV_MASK {
                for fallback in 0..=NZCV_MASK {
                    for left in 0..=REGISTER_MASK {
                        for right in 0..=REGISTER_MASK {
                            let word = FCCMP
                                | (field << FORMAT_SHIFT)
                                | signal
                                | (condition << CONDITION_SHIFT)
                                | fallback
                                | (left << LEFT_SHIFT)
                                | (right << RIGHT_SHIFT);
                            assert_eq!(
                                decode(word),
                                Some(Ok(Operand::ConditionalFlags {
                                    format,
                                    left: left as u8,
                                    right: right as u8,
                                    signal_all_nans: signal != 0,
                                    condition: condition as u8,
                                    fallback: fallback as u8,
                                })),
                                "word={word:08x}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn predicate_shapes_operations_register_aliases_and_zero_roles_are_explicit() {
    let mut arrangements = 0;
    for zero in [false, true] {
        let operations = if zero {
            ZERO_OPERATIONS
        } else {
            REGISTER_OPERATIONS
        };
        for (opcode, operation) in operations {
            for format in [Format::Half, Format::Single, Format::Double] {
                for (shape, prefix) in [
                    (Shape::Scalar, SIMD_SCALAR_PREFIX),
                    (Shape::Vector64, 0),
                    (Shape::Vector128, VECTOR_Q),
                ] {
                    if format == Format::Double && shape == Shape::Vector64 {
                        continue;
                    }
                    let adjustment = match format {
                        Format::Half => {
                            if zero {
                                HALF_ZERO_ADJUSTMENT
                            } else {
                                HALF_REGISTER_ADJUSTMENT
                            }
                        }
                        Format::Single => 0,
                        Format::Double => SIMD_DOUBLE,
                    };
                    let word = (opcode ^ adjustment) | prefix;
                    for destination in 0..=REGISTER_MASK {
                        for left in 0..=REGISTER_MASK {
                            for right in 0..=if zero { 0 } else { REGISTER_MASK } {
                                let word = word
                                    | destination
                                    | (left << LEFT_SHIFT)
                                    | (right << RIGHT_SHIFT);
                                assert_eq!(
                                    decode(word),
                                    Some(Ok(Operand::Predicate {
                                        operation,
                                        format,
                                        shape,
                                        destination: destination as u8,
                                        left: left as u8,
                                        right: if zero {
                                            CompareSource::Zero
                                        } else {
                                            CompareSource::Register(right as u8)
                                        },
                                    })),
                                    "word={word:08x}"
                                );
                            }
                        }
                    }
                    arrangements += 1;
                }
            }
        }
    }
    assert_eq!(arrangements, 80);
}

#[test]
fn reserved_formats_one_double_and_fixed_zero_register_fields_decline() {
    const RESERVED_FORMAT: u32 = 2;
    for opcode in [FCMP, FCCMP] {
        for signal in [0, SIGNAL_ALL_NANS] {
            assert_eq!(
                decode(opcode | signal | (RESERVED_FORMAT << FORMAT_SHIFT)),
                Some(Err(()))
            );
        }
    }
    for (opcode, _) in REGISTER_OPERATIONS.into_iter().chain(ZERO_OPERATIONS) {
        assert_eq!(decode(opcode | SIMD_DOUBLE), Some(Err(())));
    }
    for (opcode, _) in ZERO_OPERATIONS {
        for right in 1..=REGISTER_MASK {
            assert_eq!(decode(opcode | (right << RIGHT_SHIFT)), None);
        }
    }
}

#[test]
fn neighboring_allocated_arithmetic_and_integer_classes_remain_separate() {
    // Canonical June allocation facts: FADD, FMAX, FMLA, FAMAX, integer
    // CMEQ, and a modified immediate previously intercepted by conversions.
    const NEIGHBORS: [u32; 7] = [
        0x1e202800, 0x1e204800, 0x0e20cc00, 0x0ea0dc00, 0x2e208c00, 0x6f00e400, 0x1e220000,
    ];
    for word in NEIGHBORS {
        assert_eq!(decode(word), None, "word={word:08x}");
    }
}
