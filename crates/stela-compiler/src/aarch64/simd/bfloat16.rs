//! AdvSIMD BF16: BFCVT, BFCVTN, BFDOT, BFMMLA and BFMLAL.
use super::arithmetic::Shape;
use crate::aarch64::Unsupported;

const SCALAR_MASK: u32 = 0xffff_fc00;
const BFCVT: u32 = 0x1e63_4000;
const NARROW_MASK: u32 = 0xbfff_fc00;
const BFCVTN: u32 = 0x0ea1_6800;
const VECTOR_MASK: u32 = 0xbfe0_fc00;
const VECTOR_BFDOT: u32 = 0x2e40_fc00;
const VECTOR_BFMLAL: u32 = 0x2ec0_fc00;
const INDEXED_MASK: u32 = 0xbfc0_f400;
const INDEXED_BFDOT: u32 = 0x0f40_f000;
const INDEXED_BFMLAL: u32 = 0x0fc0_f000;
const MATRIX_MASK: u32 = 0xffe0_fc00;
const BFMMLA: u32 = 0x6e40_ec00;
const VECTOR_Q: u32 = 1 << 30;
const REGISTER_MASK: u32 = 31;
const INDEXED_MULTIPLY_REGISTER_MASK: u32 = 15;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const INDEX_H_SHIFT: u32 = 11;
const INDEX_L_SHIFT: u32 = 21;
const INDEX_M_SHIFT: u32 = 20;
const INDEX_BIT_MASK: u32 = 1;
const PAIR_INDEX_HIGH_SHIFT: u32 = 1;
const HALF_LANE_HIGH_SHIFT: u32 = 2;
const HALF_LANE_LOW_SHIFT: u32 = 1;
const SOURCE_PAIR_LANES: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionMode {
    Scalar,
    Narrow { upper: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConversionOperand {
    pub mode: ConversionMode,
    pub destination: u8,
    pub source: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotSource {
    Vector(u8),
    Indexed { register: u8, index: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DotOperand {
    pub shape: Shape,
    pub destination: u8,
    pub left: u8,
    pub right: DotSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    Even,
    Odd,
}

impl Parity {
    /// BFMLAL selects the even or odd source lane of each destination pair.
    pub const fn source_lane(self, destination_lane: u32) -> u32 {
        destination_lane * SOURCE_PAIR_LANES
            + match self {
                Self::Even => 0,
                Self::Odd => 1,
            }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiplySource {
    Vector(u8),
    Indexed { register: u8, index: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiplyOperand {
    pub parity: Parity,
    pub destination: u8,
    pub left: u8,
    pub right: MultiplySource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatrixOperand {
    pub destination: u8,
    pub left: u8,
    pub right: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Conversion(ConversionOperand),
    Dot(DotOperand),
    MultiplyAdd(MultiplyOperand),
    Matrix(MatrixOperand),
}

/// The masks match only this family's formats. Indexed multiplies accept only
/// V0-V15.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    decode_conversion(word)
        .or_else(|| decode_dot(word))
        .or_else(|| decode_multiply(word))
        .or_else(|| decode_matrix(word))
        .map(Ok)
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

fn vector_shape(word: u32) -> Shape {
    if word & VECTOR_Q == 0 {
        Shape::Vector64
    } else {
        Shape::Vector128
    }
}

fn decode_conversion(word: u32) -> Option<Operand> {
    let mode = if word & SCALAR_MASK == BFCVT {
        ConversionMode::Scalar
    } else if word & NARROW_MASK == BFCVTN {
        ConversionMode::Narrow {
            upper: word & VECTOR_Q != 0,
        }
    } else {
        return None;
    };
    Some(Operand::Conversion(ConversionOperand {
        mode,
        destination: register(word, DESTINATION_SHIFT),
        source: register(word, LEFT_SHIFT),
    }))
}

fn decode_dot(word: u32) -> Option<Operand> {
    let right = if word & VECTOR_MASK == VECTOR_BFDOT {
        DotSource::Vector(register(word, RIGHT_SHIFT))
    } else if word & INDEXED_MASK == INDEXED_BFDOT {
        let high = (word >> INDEX_H_SHIFT) & INDEX_BIT_MASK;
        let low = (word >> INDEX_L_SHIFT) & INDEX_BIT_MASK;
        DotSource::Indexed {
            register: register(word, RIGHT_SHIFT),
            index: ((high << PAIR_INDEX_HIGH_SHIFT) | low) as u8,
        }
    } else {
        return None;
    };
    Some(Operand::Dot(DotOperand {
        shape: vector_shape(word),
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        right,
    }))
}

fn decode_multiply(word: u32) -> Option<Operand> {
    let right = if word & VECTOR_MASK == VECTOR_BFMLAL {
        MultiplySource::Vector(register(word, RIGHT_SHIFT))
    } else if word & INDEXED_MASK == INDEXED_BFMLAL {
        let high = (word >> INDEX_H_SHIFT) & INDEX_BIT_MASK;
        let low = (word >> INDEX_L_SHIFT) & INDEX_BIT_MASK;
        let middle = (word >> INDEX_M_SHIFT) & INDEX_BIT_MASK;
        MultiplySource::Indexed {
            register: ((word >> RIGHT_SHIFT) & INDEXED_MULTIPLY_REGISTER_MASK) as u8,
            index: ((high << HALF_LANE_HIGH_SHIFT) | (low << HALF_LANE_LOW_SHIFT) | middle) as u8,
        }
    } else {
        return None;
    };
    Some(Operand::MultiplyAdd(MultiplyOperand {
        parity: if word & VECTOR_Q == 0 {
            Parity::Even
        } else {
            Parity::Odd
        },
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        right,
    }))
}

fn decode_matrix(word: u32) -> Option<Operand> {
    if word & MATRIX_MASK != BFMMLA {
        return None;
    }
    Some(Operand::Matrix(MatrixOperand {
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        right: register(word, RIGHT_SHIFT),
    }))
}

#[cfg(test)]
mod tests {
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
}
