use super::*;

const SCALAR_OPERATIONS: [(u32, MinMaxOperation); 4] = [
    (SCALAR_FMAX, MinMaxOperation::Maximum),
    (SCALAR_FMIN, MinMaxOperation::Minimum),
    (SCALAR_FMAXNM, MinMaxOperation::MaximumNumber),
    (SCALAR_FMINNM, MinMaxOperation::MinimumNumber),
];
const VECTOR_OPERATIONS: [(u32, MinMaxOperation); 4] = [
    (VECTOR_FMAX, MinMaxOperation::Maximum),
    (VECTOR_FMIN, MinMaxOperation::Minimum),
    (VECTOR_FMAXNM, MinMaxOperation::MaximumNumber),
    (VECTOR_FMINNM, MinMaxOperation::MinimumNumber),
];
const PAIR_OPERATIONS: [(u32, MinMaxOperation); 4] = [
    (PAIR_FMAX, MinMaxOperation::Maximum),
    (PAIR_FMIN, MinMaxOperation::Minimum),
    (PAIR_FMAXNM, MinMaxOperation::MaximumNumber),
    (PAIR_FMINNM, MinMaxOperation::MinimumNumber),
];
const REDUCTION_OPERATIONS: [(u32, MinMaxOperation); 4] = [
    (REDUCTION_FMAX, MinMaxOperation::Maximum),
    (REDUCTION_FMIN, MinMaxOperation::Minimum),
    (REDUCTION_FMAXNM, MinMaxOperation::MaximumNumber),
    (REDUCTION_FMINNM, MinMaxOperation::MinimumNumber),
];

fn check_registers(word: u32, expected: Operand) {
    for destination in 0..=REGISTER_MASK {
        for left in 0..=REGISTER_MASK {
            let right_limit = if matches!(expected, Operand::Binary { .. }) {
                REGISTER_MASK
            } else {
                0
            };
            for right in 0..=right_limit {
                let word = word | destination | (left << LEFT_SHIFT) | (right << RIGHT_SHIFT);
                let operand = match expected {
                    Operand::Binary {
                        operation,
                        format,
                        shape,
                        mode,
                        ..
                    } => Operand::Binary {
                        operation,
                        format,
                        shape,
                        mode,
                        destination: destination as u8,
                        left: left as u8,
                        right: right as u8,
                    },
                    Operand::PairwiseScalar {
                        operation, format, ..
                    } => Operand::PairwiseScalar {
                        operation,
                        format,
                        destination: destination as u8,
                        source: left as u8,
                    },
                    Operand::Reduction {
                        operation,
                        format,
                        shape,
                        ..
                    } => Operand::Reduction {
                        operation,
                        format,
                        shape,
                        destination: destination as u8,
                        source: left as u8,
                    },
                };
                assert_eq!(decode(word), Some(Ok(operand)), "word={word:08x}");
                assert_eq!(operand.operation(), expected.operation());
                assert_eq!(operand.format(), expected.format());
                assert_eq!(operand.destination(), destination as u8);
            }
        }
    }
}

#[test]
fn binary_scalar_vector_and_pairwise_forms_cover_every_width_and_alias() {
    let mut arrangements = 0;
    for (opcode, operation) in SCALAR_OPERATIONS {
        for (field, format) in [
            (FORMAT_SINGLE, Format::Single),
            (FORMAT_DOUBLE, Format::Double),
            (FORMAT_HALF, Format::Half),
        ] {
            check_registers(
                opcode | (field << FORMAT_SHIFT),
                Operand::Binary {
                    operation,
                    format,
                    shape: Shape::Scalar,
                    mode: BinaryMode::Elementwise,
                    destination: 0,
                    left: 0,
                    right: 0,
                },
            );
            arrangements += 1;
        }
    }
    for (opcode, operation) in VECTOR_OPERATIONS {
        for (pairwise, mode) in [
            (0, BinaryMode::Elementwise),
            (VECTOR_PAIRWISE, BinaryMode::Pairwise),
        ] {
            for format in [Format::Half, Format::Single, Format::Double] {
                let size = match format {
                    Format::Half => HALF_REGISTER_ADJUSTMENT,
                    Format::Single => 0,
                    Format::Double => SIMD_DOUBLE,
                };
                for (q, shape) in [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)] {
                    if format == Format::Double && shape == Shape::Vector64 {
                        continue;
                    }
                    check_registers(
                        (opcode ^ size) | pairwise | q,
                        Operand::Binary {
                            operation,
                            format,
                            shape,
                            mode,
                            destination: 0,
                            left: 0,
                            right: 0,
                        },
                    );
                    arrangements += 1;
                }
            }
        }
    }
    assert_eq!(arrangements, 52);
}

#[test]
fn scalar_pairwise_distinguishes_two_half_inputs_from_vector64() {
    let mut arrangements = 0;
    for (opcode, operation) in PAIR_OPERATIONS {
        for (adjustment, format) in [
            (HALF_PAIR_ADJUSTMENT, Format::Half),
            (0, Format::Single),
            (SIMD_DOUBLE, Format::Double),
        ] {
            check_registers(
                opcode ^ adjustment,
                Operand::PairwiseScalar {
                    operation,
                    format,
                    destination: 0,
                    source: 0,
                },
            );
            arrangements += 1;
        }
    }
    assert_eq!(arrangements, 12);
}

#[test]
fn reductions_allow_four_or_eight_half_and_exactly_four_single() {
    let mut arrangements = 0;
    for (opcode, operation) in REDUCTION_OPERATIONS {
        for (adjustment, q, format, shape) in [
            (HALF_PAIR_ADJUSTMENT, 0, Format::Half, Shape::Vector64),
            (
                HALF_PAIR_ADJUSTMENT,
                VECTOR_Q,
                Format::Half,
                Shape::Vector128,
            ),
            (0, VECTOR_Q, Format::Single, Shape::Vector128),
        ] {
            check_registers(
                (opcode ^ adjustment) | q,
                Operand::Reduction {
                    operation,
                    format,
                    shape,
                    destination: 0,
                    source: 0,
                },
            );
            arrangements += 1;
        }
    }
    assert_eq!(arrangements, 12);
}

#[test]
fn reserved_formats_one_double_half_pair_size_and_reduction_sizes_decline() {
    const RESERVED_FORMAT: u32 = 2;
    for (opcode, _) in SCALAR_OPERATIONS {
        assert_eq!(
            decode(opcode | (RESERVED_FORMAT << FORMAT_SHIFT)),
            Some(Err(()))
        );
    }
    for (opcode, _) in VECTOR_OPERATIONS {
        for pairwise in [0, VECTOR_PAIRWISE] {
            assert_eq!(decode(opcode | SIMD_DOUBLE | pairwise), Some(Err(())));
        }
    }
    for (opcode, _) in PAIR_OPERATIONS {
        assert_eq!(
            decode((opcode ^ HALF_PAIR_ADJUSTMENT) | SIMD_DOUBLE),
            Some(Err(()))
        );
    }
    for (opcode, _) in REDUCTION_OPERATIONS {
        assert_eq!(decode(opcode), Some(Err(())));
        for q in [0, VECTOR_Q] {
            assert_eq!(decode(opcode | SIMD_DOUBLE | q), Some(Err(())));
        }
    }
}

#[test]
fn allocated_comparison_conversion_and_absolute_minmax_neighbors_stay_separate() {
    // June canonical facts: FAMIN/FAMAX H/S/D-vector classes, scalar FCMP,
    // AdvSIMD FCMEQ, conversion FCVTN and modified immediate MOVI.
    const NEIGHBORS: [u32; 8] = [
        0x0ea0dc00, 0x2ea0dc00, 0x0ec01c00, 0x2ec01c00, 0x1e202000, 0x0e20e400, 0x0e216800,
        0x6f00e400,
    ];
    for word in NEIGHBORS {
        assert_eq!(decode(word), None, "word={word:08x}");
    }
}
