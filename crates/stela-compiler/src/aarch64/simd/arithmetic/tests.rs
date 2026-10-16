use super::*;

const FORMAT_RESERVED: u32 = 2;
const SCALAR_OPERATION_FIELD_MASK: u32 = 0xb000;
const VECTOR_OPERATION_FIELD_MASK: u32 = 0x2080_2800;
const SCALAR_OPERATIONS: [(u32, BinaryOperation); 5] = [
    (FADD, BinaryOperation::Add),
    (FSUB, BinaryOperation::Subtract),
    (FMUL, BinaryOperation::Multiply),
    (FDIV, BinaryOperation::Divide),
    (FNMUL, BinaryOperation::NegatedMultiply),
];
const ORIGINAL_VECTOR_OPERATIONS: [(u32, u32, BinaryOperation); 4] = [
    (VECTOR_FADD, VECTOR_HALF_FADD, BinaryOperation::Add),
    (VECTOR_FSUB, VECTOR_HALF_FSUB, BinaryOperation::Subtract),
    (VECTOR_FMUL, VECTOR_HALF_FMUL, BinaryOperation::Multiply),
    (VECTOR_FDIV, VECTOR_HALF_FDIV, BinaryOperation::Divide),
];
const NEW_VECTOR_OPERATIONS: [(u32, u32, BinaryOperation); 3] = [
    (
        VECTOR_FABD,
        VECTOR_HALF_FABD,
        BinaryOperation::AbsoluteDifference,
    ),
    (
        VECTOR_FMULX,
        VECTOR_HALF_FMULX,
        BinaryOperation::MultiplyExtended,
    ),
    (VECTOR_FADDP, VECTOR_HALF_FADDP, BinaryOperation::Add),
];

fn instruction(operation: u32, format: u32, destination: u32, left: u32, right: u32) -> u32 {
    operation
        | (format << FORMAT_SHIFT)
        | (left << LEFT_SHIFT)
        | (right << RIGHT_SHIFT)
        | destination
}

#[test]
fn every_scalar_operation_format_and_register_combination_is_explicit() {
    for (encoding, operation) in SCALAR_OPERATIONS {
        for format_field in 0..=FORMAT_MASK {
            let format = match format_field {
                FORMAT_SINGLE => Some(Format::Single),
                FORMAT_DOUBLE => Some(Format::Double),
                FORMAT_HALF => Some(Format::Half),
                FORMAT_RESERVED => None,
                _ => unreachable!(),
            };
            for destination in 0..=REGISTER_MASK {
                for left in 0..=REGISTER_MASK {
                    for right in 0..=REGISTER_MASK {
                        let expected = format.map_or(Err(()), |format| {
                            Ok(Operand {
                                operation,
                                format,
                                shape: Shape::Scalar,
                                destination: destination as u8,
                                inputs: Inputs::Elementwise {
                                    left: left as u8,
                                    right: right as u8,
                                },
                            })
                        });
                        assert_eq!(
                            decode(instruction(
                                encoding,
                                format_field,
                                destination,
                                left,
                                right
                            )),
                            Some(expected)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn all_vector_elementwise_and_pairwise_shapes_cover_every_alias() {
    for (ordinary, half, operation) in ORIGINAL_VECTOR_OPERATIONS
        .into_iter()
        .chain(NEW_VECTOR_OPERATIONS)
    {
        for (encoding, format, size) in [
            (ordinary, Format::Single, 0),
            (ordinary, Format::Double, VECTOR_DOUBLE),
            (half, Format::Half, 0),
        ] {
            for (q, shape) in [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)] {
                for destination in 0..=REGISTER_MASK {
                    for left in 0..=REGISTER_MASK {
                        for right in 0..=REGISTER_MASK {
                            let word = encoding
                                | size
                                | q
                                | (left << LEFT_SHIFT)
                                | (right << RIGHT_SHIFT)
                                | destination;
                            let expected = if format == Format::Double && shape == Shape::Vector64 {
                                Err(())
                            } else {
                                let inputs = if ordinary == VECTOR_FADDP {
                                    Inputs::Pairwise {
                                        left: left as u8,
                                        right: right as u8,
                                    }
                                } else {
                                    Inputs::Elementwise {
                                        left: left as u8,
                                        right: right as u8,
                                    }
                                };
                                Ok(Operand {
                                    operation,
                                    format,
                                    shape,
                                    destination: destination as u8,
                                    inputs,
                                })
                            };
                            assert_eq!(decode(word), Some(expected), "word={word:08x}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn advsimd_scalar_extended_multiply_and_absolute_difference_have_ordinary_v31() {
    for (ordinary, half, operation) in [
        (
            SCALAR_FABD,
            SCALAR_HALF_FABD,
            BinaryOperation::AbsoluteDifference,
        ),
        (
            SCALAR_FMULX,
            SCALAR_HALF_FMULX,
            BinaryOperation::MultiplyExtended,
        ),
    ] {
        for (encoding, format) in [
            (ordinary, Format::Single),
            (ordinary | VECTOR_DOUBLE, Format::Double),
            (half, Format::Half),
        ] {
            for destination in 0..=REGISTER_MASK {
                for left in 0..=REGISTER_MASK {
                    for right in 0..=REGISTER_MASK {
                        let word =
                            encoding | destination | (left << LEFT_SHIFT) | (right << RIGHT_SHIFT);
                        assert_eq!(
                            decode(word),
                            Some(Ok(Operand {
                                operation,
                                format,
                                shape: Shape::Scalar,
                                destination: destination as u8,
                                inputs: Inputs::Elementwise {
                                    left: left as u8,
                                    right: right as u8
                                },
                            })),
                            "word={word:08x}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn scalar_pairwise_uses_one_source_and_exactly_two_lanes() {
    for (encoding, format) in [
        (SCALAR_HALF_FADDP, Format::Half),
        (SCALAR_FADDP, Format::Single),
        (SCALAR_FADDP | VECTOR_DOUBLE, Format::Double),
    ] {
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                let word = encoding | destination | (source << LEFT_SHIFT);
                assert_eq!(
                    decode(word),
                    Some(Ok(Operand {
                        operation: BinaryOperation::Add,
                        format,
                        shape: Shape::Scalar,
                        destination: destination as u8,
                        inputs: Inputs::PairwiseScalar {
                            source: source as u8
                        },
                    }))
                );
                assert_eq!(
                    decode(
                        SCALAR_HALF_FADDP | VECTOR_DOUBLE | destination | (source << LEFT_SHIFT)
                    ),
                    Some(Err(()))
                );
            }
        }
    }
    for format in [Format::Half, Format::Single, Format::Double] {
        assert_eq!(Shape::Scalar.lane_count(format), 1);
    }
    assert_eq!(2 * Format::Half.bits(), 32);
}

fn indexed_word(base: u32, format: Format, lane: u32, right: u32) -> u32 {
    let fields = match format {
        Format::Half => {
            ((lane >> HALF_LANE_HIGH_SHIFT) << INDEX_H_SHIFT)
                | (((lane >> HALF_LANE_LOW_SHIFT) & INDEX_BIT_MASK) << INDEX_L_SHIFT)
                | ((lane & INDEX_BIT_MASK) << INDEX_M_SHIFT)
        }
        Format::Single => {
            ((lane >> SINGLE_LANE_HIGH_SHIFT) << INDEX_H_SHIFT)
                | ((lane & INDEX_BIT_MASK) << INDEX_L_SHIFT)
        }
        Format::Double => VECTOR_DOUBLE | (lane << INDEX_H_SHIFT),
    };
    base | fields | (right << RIGHT_SHIFT)
}

#[test]
fn indexed_multiply_all_widths_indices_registers_and_aliases_are_explicit() {
    let mut index_variants = 0;
    for (extended, operation) in [
        (0, BinaryOperation::Multiply),
        (INDEXED_EXTENDED_MULTIPLY, BinaryOperation::MultiplyExtended),
    ] {
        for format in [Format::Half, Format::Single, Format::Double] {
            for (shape, ordinary, half) in [
                (Shape::Scalar, INDEXED_SCALAR, INDEXED_SCALAR_HALF),
                (Shape::Vector64, INDEXED_VECTOR, INDEXED_VECTOR_HALF),
                (
                    Shape::Vector128,
                    INDEXED_VECTOR | VECTOR_Q,
                    INDEXED_VECTOR_HALF | VECTOR_Q,
                ),
            ] {
                if format == Format::Double && shape == Shape::Vector64 {
                    continue;
                }
                let base = (if format == Format::Half {
                    half
                } else {
                    ordinary
                }) | extended;
                let right_limit = if format == Format::Half {
                    INDEXED_HALF_REGISTER_MASK
                } else {
                    REGISTER_MASK
                };
                for lane in 0..VECTOR128_BITS / format.bits() {
                    for destination in 0..=REGISTER_MASK {
                        for left in 0..=REGISTER_MASK {
                            for right in 0..=right_limit {
                                let word = indexed_word(base, format, lane, right)
                                    | destination
                                    | (left << LEFT_SHIFT);
                                assert_eq!(
                                    decode(word),
                                    Some(Ok(Operand {
                                        operation,
                                        format,
                                        shape,
                                        destination: destination as u8,
                                        inputs: Inputs::Indexed {
                                            left: left as u8,
                                            right: right as u8,
                                            right_lane: lane as u8
                                        },
                                    })),
                                    "word={word:08x}"
                                );
                            }
                        }
                    }
                    index_variants += 1;
                }
            }
        }
    }
    assert_eq!(index_variants, 80);
}

#[test]
fn indexed_double_l_and_one_double_remain_reserved() {
    for extended in [0, INDEXED_EXTENDED_MULTIPLY] {
        for base in [INDEXED_SCALAR, INDEXED_VECTOR, INDEXED_VECTOR | VECTOR_Q] {
            for high in [0, 1 << INDEX_H_SHIFT] {
                for right in 0..=REGISTER_MASK {
                    for destination in 0..=REGISTER_MASK {
                        for left in 0..=REGISTER_MASK {
                            let word = base
                                | extended
                                | VECTOR_DOUBLE
                                | high
                                | (right << RIGHT_SHIFT)
                                | destination
                                | (left << LEFT_SHIFT);
                            assert_eq!(decode(word | (1 << INDEX_L_SHIFT)), Some(Err(())));
                            if base == INDEXED_VECTOR {
                                assert_eq!(decode(word), Some(Err(())));
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn half_index_m_is_a_lane_bit_and_q0_can_select_the_upper_source_half() {
    for extended in [0, INDEXED_EXTENDED_MULTIPLY] {
        let word = indexed_word(INDEXED_VECTOR_HALF | extended, Format::Half, 7, 15)
            | REGISTER_MASK
            | (REGISTER_MASK << LEFT_SHIFT);
        assert_eq!(
            decode(word),
            Some(Ok(Operand {
                operation: if extended == 0 {
                    BinaryOperation::Multiply
                } else {
                    BinaryOperation::MultiplyExtended
                },
                format: Format::Half,
                shape: Shape::Vector64,
                destination: 31,
                inputs: Inputs::Indexed {
                    left: 31,
                    right: 15,
                    right_lane: 7
                },
            }))
        );
        let word = indexed_word(INDEXED_VECTOR | extended, Format::Single, 3, 31);
        assert!(matches!(
            decode(word),
            Some(Ok(Operand {
                inputs: Inputs::Indexed {
                    right: 31,
                    right_lane: 3,
                    ..
                },
                shape: Shape::Vector64,
                ..
            }))
        ));
    }
}

#[test]
fn lane_counts_follow_allocated_scalar_and_vector_shapes() {
    for format in [Format::Half, Format::Single, Format::Double] {
        assert_eq!(Shape::Scalar.lane_count(format), 1);
    }
    for (shape, format, lanes) in [
        (Shape::Vector64, Format::Half, 4),
        (Shape::Vector128, Format::Half, 8),
        (Shape::Vector64, Format::Single, 2),
        (Shape::Vector128, Format::Single, 4),
        (Shape::Vector128, Format::Double, 2),
    ] {
        assert_eq!(shape.lane_count(format), lanes);
    }
}

#[test]
fn old_fixed_bit_neighbors_still_decline_outside_assigned_operation_fields() {
    let fixed_mask = SCALAR_MASK & !SCALAR_OPERATION_FIELD_MASK;
    for (encoding, _) in SCALAR_OPERATIONS {
        for format in 0..=FORMAT_MASK {
            let word = instruction(
                encoding,
                format,
                REGISTER_MASK,
                REGISTER_MASK,
                REGISTER_MASK,
            );
            for bit in 0..u32::BITS {
                let changed = 1 << bit;
                if fixed_mask & changed != 0 {
                    assert_eq!(decode(word ^ changed), None);
                }
            }
        }
    }
    for (ordinary, half, _) in ORIGINAL_VECTOR_OPERATIONS {
        for (encoding, mask) in [(ordinary, VECTOR_MASK), (half, VECTOR_HALF_MASK)] {
            let fixed_mask = mask & !VECTOR_OPERATION_FIELD_MASK;
            for q in [0, VECTOR_Q] {
                let word = encoding
                    | q
                    | (REGISTER_MASK << LEFT_SHIFT)
                    | (REGISTER_MASK << RIGHT_SHIFT)
                    | REGISTER_MASK;
                for bit in 0..u32::BITS {
                    let changed = 1 << bit;
                    if fixed_mask & changed != 0 {
                        assert_eq!(decode(word ^ changed), None);
                    }
                }
            }
        }
    }
}

#[test]
fn allocated_other_families_do_not_gain_arithmetic_semantics() {
    const SCALAR_NEIGHBORS: [u32; 7] = [
        0x1e20_4800,
        0x1e20_5800,
        0x1e20_6800,
        0x1e20_7800,
        0x1e20_0c00,
        0x1e20_2000,
        0x1f00_0000,
    ];
    for neighbor in SCALAR_NEIGHBORS {
        for format in 0..=FORMAT_MASK {
            assert_eq!(
                decode(instruction(
                    neighbor,
                    format,
                    REGISTER_MASK,
                    REGISTER_MASK,
                    REGISTER_MASK
                )),
                None
            );
        }
    }
    const VECTOR_NEIGHBORS: [u32; 12] = [
        0x0e20_cc00,
        0x0ea0_cc00,
        0x0e20_f400,
        0x0ea0_f400,
        0x0e20_e400,
        0x2e20_e400,
        0x0e20_8400,
        0x2e20_8400,
        0x0e20_fc00,
        0x0ea0_fc00,
        0x0f80_1000,
        0x6f00_e400,
    ];
    for neighbor in VECTOR_NEIGHBORS {
        for q in [0, VECTOR_Q] {
            for size in [0, VECTOR_DOUBLE] {
                assert_eq!(
                    decode(
                        neighbor
                            | q
                            | size
                            | (REGISTER_MASK << LEFT_SHIFT)
                            | (REGISTER_MASK << RIGHT_SHIFT)
                            | REGISTER_MASK
                    ),
                    None
                );
            }
        }
    }
}
