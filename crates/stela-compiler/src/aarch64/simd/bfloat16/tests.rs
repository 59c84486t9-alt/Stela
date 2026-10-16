use super::*;

const PAIR_INDEX_MASK: u32 = 3;
const HALF_LANE_MASK: u32 = 7;
const SCALAR_CLASS: u32 = 1 << 28;
const FORMAT_CHANGE: u32 = 1 << 22;
const DOT_MULTIPLY_CHANGE: u32 = 1 << 23;
const MATRIX_DOT_CHANGE: u32 = 1 << 12;
const SHAPES: [(u32, Shape); 2] = [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)];
const PARITIES: [(u32, Parity); 2] = [(0, Parity::Even), (VECTOR_Q, Parity::Odd)];

fn pair_index_bits(index: u32) -> u32 {
    (((index >> PAIR_INDEX_HIGH_SHIFT) & INDEX_BIT_MASK) << INDEX_H_SHIFT)
        | ((index & INDEX_BIT_MASK) << INDEX_L_SHIFT)
}

fn half_index_bits(index: u32) -> u32 {
    (((index >> HALF_LANE_HIGH_SHIFT) & INDEX_BIT_MASK) << INDEX_H_SHIFT)
        | (((index >> HALF_LANE_LOW_SHIFT) & INDEX_BIT_MASK) << INDEX_L_SHIFT)
        | ((index & INDEX_BIT_MASK) << INDEX_M_SHIFT)
}

#[test]
fn conversions_preserve_scalar_and_destination_part_distinctions() {
    for (encoding, mode) in [
        (BFCVT, ConversionMode::Scalar),
        (BFCVTN, ConversionMode::Narrow { upper: false }),
        (BFCVTN | VECTOR_Q, ConversionMode::Narrow { upper: true }),
    ] {
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                let word = encoding | (source << LEFT_SHIFT) | destination;
                assert_eq!(
                    decode(word),
                    Some(Ok(Operand::Conversion(ConversionOperand {
                        mode,
                        destination: destination as u8,
                        source: source as u8,
                    })))
                );
            }
        }
    }
}

#[test]
fn dot_widths_and_all_vector_register_aliases_are_explicit() {
    for (q, shape) in SHAPES {
        for destination in 0..=REGISTER_MASK {
            for left in 0..=REGISTER_MASK {
                for right in 0..=REGISTER_MASK {
                    let word = VECTOR_BFDOT
                        | q
                        | (right << RIGHT_SHIFT)
                        | (left << LEFT_SHIFT)
                        | destination;
                    assert_eq!(
                        decode(word),
                        Some(Ok(Operand::Dot(DotOperand {
                            shape,
                            destination: destination as u8,
                            left: left as u8,
                            right: DotSource::Vector(right as u8),
                        })))
                    );
                }
            }
        }
    }
}

#[test]
fn dot_indexes_full_source_pairs_for_both_widths_and_all_registers() {
    for (q, shape) in SHAPES {
        for index in 0..=PAIR_INDEX_MASK {
            for destination in 0..=REGISTER_MASK {
                for left in 0..=REGISTER_MASK {
                    for right in 0..=REGISTER_MASK {
                        let word = INDEXED_BFDOT
                            | q
                            | pair_index_bits(index)
                            | (right << RIGHT_SHIFT)
                            | (left << LEFT_SHIFT)
                            | destination;
                        assert_eq!(
                            decode(word),
                            Some(Ok(Operand::Dot(DotOperand {
                                shape,
                                destination: destination as u8,
                                left: left as u8,
                                right: DotSource::Indexed {
                                    register: right as u8,
                                    index: index as u8,
                                },
                            })))
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn multiply_q_selects_even_or_odd_sources_with_all_vector_aliases() {
    for (q, parity) in PARITIES {
        for destination in 0..=REGISTER_MASK {
            for left in 0..=REGISTER_MASK {
                for right in 0..=REGISTER_MASK {
                    let word = VECTOR_BFMLAL
                        | q
                        | (right << RIGHT_SHIFT)
                        | (left << LEFT_SHIFT)
                        | destination;
                    assert_eq!(
                        decode(word),
                        Some(Ok(Operand::MultiplyAdd(MultiplyOperand {
                            parity,
                            destination: destination as u8,
                            left: left as u8,
                            right: MultiplySource::Vector(right as u8),
                        })))
                    );
                }
            }
        }
    }
    for (parity, expected) in [(Parity::Even, [0, 2, 4, 6]), (Parity::Odd, [1, 3, 5, 7])] {
        for (lane, source) in expected.into_iter().enumerate() {
            assert_eq!(parity.source_lane(lane as u32), source);
        }
    }
}

#[test]
fn multiply_index_m_is_a_lane_bit_and_never_a_register_bit() {
    for (q, parity) in PARITIES {
        for index in 0..=HALF_LANE_MASK {
            for destination in 0..=REGISTER_MASK {
                for left in 0..=REGISTER_MASK {
                    for right in 0..=INDEXED_MULTIPLY_REGISTER_MASK {
                        let word = INDEXED_BFMLAL
                            | q
                            | half_index_bits(index)
                            | (right << RIGHT_SHIFT)
                            | (left << LEFT_SHIFT)
                            | destination;
                        assert_eq!(
                            decode(word),
                            Some(Ok(Operand::MultiplyAdd(MultiplyOperand {
                                parity,
                                destination: destination as u8,
                                left: left as u8,
                                right: MultiplySource::Indexed {
                                    register: right as u8,
                                    index: index as u8,
                                },
                            })))
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn matrix_has_fixed_width_and_all_register_aliases() {
    for destination in 0..=REGISTER_MASK {
        for left in 0..=REGISTER_MASK {
            for right in 0..=REGISTER_MASK {
                let word = BFMMLA | (right << RIGHT_SHIFT) | (left << LEFT_SHIFT) | destination;
                assert_eq!(
                    decode(word),
                    Some(Ok(Operand::Matrix(MatrixOperand {
                        destination: destination as u8,
                        left: left as u8,
                        right: right as u8,
                    })))
                );
                assert_eq!(decode(word ^ VECTOR_Q), None);
            }
        }
    }
}

#[test]
fn fixed_bits_preserve_adjacent_families_and_allocated_bf16_transitions() {
    for (encoding, mask, transition) in [
        (BFCVT, SCALAR_MASK, 0),
        (BFCVTN, NARROW_MASK, 0),
        (VECTOR_BFDOT, VECTOR_MASK, DOT_MULTIPLY_CHANGE),
        (VECTOR_BFMLAL, VECTOR_MASK, DOT_MULTIPLY_CHANGE),
        (INDEXED_BFDOT, INDEXED_MASK, DOT_MULTIPLY_CHANGE),
        (INDEXED_BFMLAL, INDEXED_MASK, DOT_MULTIPLY_CHANGE),
        (BFMMLA, MATRIX_MASK, MATRIX_DOT_CHANGE),
    ] {
        for bit in 0..u32::BITS {
            let change = 1 << bit;
            if mask & change != 0 {
                let word = encoding ^ change;
                if change == transition {
                    assert!(decode(word).is_some_and(|operand| operand.is_ok()));
                } else {
                    assert_eq!(decode(word), None, "neighbor {word:#010x}");
                }
            }
        }
    }
    for encoding in [VECTOR_BFDOT, INDEXED_BFDOT, VECTOR_BFMLAL, INDEXED_BFMLAL] {
        for (q, _) in SHAPES {
            assert_eq!(decode(encoding | q | SCALAR_CLASS), None);
            assert_eq!(decode(encoding ^ FORMAT_CHANGE), None);
        }
    }
}

#[test]
fn precision_fhm_fp8_and_modified_immediate_neighbors_stay_unclaimed() {
    for word in [
        0x1e23_c000, // FCVT scalar Single to Half.
        0x0e21_6800, // FCVTN Single to Half.
        0x0e61_6800, // FCVTN Double to Single.
        0x0e20_ec00, // FMLAL lower vector.
        0x2e20_cc00, // FMLAL2 upper vector.
        0x0f80_0000, // FMLAL lower indexed.
        0x2f80_8000, // FMLAL2 upper indexed.
        0x0fc0_0000, // FP8 FMLALB indexed.
        0x4fc0_0000, // FP8 FMLALT indexed.
        0x6f00_e400, // MOVI modified immediate.
        0xd503_201f, // NOP.
        0xffff_ffff,
    ] {
        assert_eq!(decode(word), None, "allocated neighbor {word:#010x}");
    }
}
