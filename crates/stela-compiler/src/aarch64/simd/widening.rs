//! FMLAL and FMLSL (half to single).
use crate::aarch64::Unsupported;
use crate::aarch64::floating::{Format, widening::WideningOperation};

use super::arithmetic::Shape;

const VECTOR_MASK: u32 = 0xbfe0_fc00;
const VECTOR_FMLAL: u32 = 0x0e20_ec00;
const VECTOR_FMLAL2: u32 = 0x2e20_cc00;
const VECTOR_FMLSL: u32 = 0x0ea0_ec00;
const VECTOR_FMLSL2: u32 = 0x2ea0_cc00;
const INDEXED_MASK: u32 = 0xbfc0_f400;
const INDEXED_FMLAL: u32 = 0x0f80_0000;
const INDEXED_FMLAL2: u32 = 0x2f80_8000;
const INDEXED_FMLSL: u32 = 0x0f80_4000;
const INDEXED_FMLSL2: u32 = 0x2f80_c000;
const VECTOR_Q: u32 = 1 << 30;
const REGISTER_MASK: u32 = 31;
const INDEXED_REGISTER_MASK: u32 = 15;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const INDEX_H_SHIFT: u32 = 11;
const INDEX_L_SHIFT: u32 = 21;
const INDEX_M_SHIFT: u32 = 20;
const INDEX_BIT_MASK: u32 = 1;
const HALF_LANE_HIGH_SHIFT: u32 = 2;
const HALF_LANE_LOW_SHIFT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Lower,
    Upper,
}

impl Part {
    /// The source part is relative to the active vector width: upper Q0 uses
    /// H2/H3, while upper Q1 uses H4..H7. Scalar FHM forms are not allocated.
    pub const fn source_lane_offset(self, shape: Shape) -> u32 {
        match shape {
            Shape::Scalar => panic!("widening FP16 requires a vector shape"),
            Shape::Vector64 | Shape::Vector128 => match self {
                Self::Lower => 0,
                Self::Upper => shape.lane_count(Format::Single),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub operation: WideningOperation,
    pub shape: Shape,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
    pub right_lane: Option<u8>,
    pub part: Part,
}

/// Exact fixed bits keep sz=1 and adjacent FP8/SME forms outside this family.
/// All registers are ordinary V registers; indexed Vm is limited to V0..V15.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    let (operation, part) = match word & VECTOR_MASK {
        VECTOR_FMLAL => (WideningOperation::Add, Part::Lower),
        VECTOR_FMLAL2 => (WideningOperation::Add, Part::Upper),
        VECTOR_FMLSL => (WideningOperation::Subtract, Part::Lower),
        VECTOR_FMLSL2 => (WideningOperation::Subtract, Part::Upper),
        _ => return decode_indexed(word),
    };
    Some(Ok(operand(
        word,
        operation,
        part,
        register(word, RIGHT_SHIFT),
        None,
    )))
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

fn operand(
    word: u32,
    operation: WideningOperation,
    part: Part,
    right: u8,
    right_lane: Option<u8>,
) -> Operand {
    Operand {
        operation,
        shape: if word & VECTOR_Q == 0 {
            Shape::Vector64
        } else {
            Shape::Vector128
        },
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        right,
        right_lane,
        part,
    }
}

fn decode_indexed(word: u32) -> Option<Result<Operand, Unsupported>> {
    let (operation, part) = match word & INDEXED_MASK {
        INDEXED_FMLAL => (WideningOperation::Add, Part::Lower),
        INDEXED_FMLAL2 => (WideningOperation::Add, Part::Upper),
        INDEXED_FMLSL => (WideningOperation::Subtract, Part::Lower),
        INDEXED_FMLSL2 => (WideningOperation::Subtract, Part::Upper),
        _ => return None,
    };
    let high = (word >> INDEX_H_SHIFT) & INDEX_BIT_MASK;
    let low = (word >> INDEX_L_SHIFT) & INDEX_BIT_MASK;
    let middle = (word >> INDEX_M_SHIFT) & INDEX_BIT_MASK;
    let right = ((word >> RIGHT_SHIFT) & INDEXED_REGISTER_MASK) as u8;
    let lane = (high << HALF_LANE_HIGH_SHIFT) | (low << HALF_LANE_LOW_SHIFT) | middle;
    Some(Ok(operand(word, operation, part, right, Some(lane as u8))))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR_SUBTRACT: u32 = 1 << 23;
    const INDEXED_SUBTRACT: u32 = 1 << 14;
    const SIZE_RESERVED: u32 = 1 << 22;
    const SCALAR_CLASS: u32 = 1 << 28;
    const HALF_LANE_MASK: u32 = 7;
    const VECTOR_FORMS: [(u32, WideningOperation, Part); 4] = [
        (VECTOR_FMLAL, WideningOperation::Add, Part::Lower),
        (VECTOR_FMLAL2, WideningOperation::Add, Part::Upper),
        (VECTOR_FMLSL, WideningOperation::Subtract, Part::Lower),
        (VECTOR_FMLSL2, WideningOperation::Subtract, Part::Upper),
    ];
    const INDEXED_FORMS: [(u32, WideningOperation, Part); 4] = [
        (INDEXED_FMLAL, WideningOperation::Add, Part::Lower),
        (INDEXED_FMLAL2, WideningOperation::Add, Part::Upper),
        (INDEXED_FMLSL, WideningOperation::Subtract, Part::Lower),
        (INDEXED_FMLSL2, WideningOperation::Subtract, Part::Upper),
    ];
    const SHAPES: [(u32, Shape); 2] = [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)];

    fn index_bits(lane: u32) -> u32 {
        (((lane >> HALF_LANE_HIGH_SHIFT) & INDEX_BIT_MASK) << INDEX_H_SHIFT)
            | (((lane >> HALF_LANE_LOW_SHIFT) & INDEX_BIT_MASK) << INDEX_L_SHIFT)
            | ((lane & INDEX_BIT_MASK) << INDEX_M_SHIFT)
    }

    #[test]
    fn source_parts_follow_the_active_vector_width() {
        for (shape, upper, lanes) in [
            (Shape::Vector64, 2, [2, 3, 0, 0]),
            (Shape::Vector128, 4, [4, 5, 6, 7]),
        ] {
            assert_eq!(Part::Lower.source_lane_offset(shape), 0);
            assert_eq!(Part::Upper.source_lane_offset(shape), upper);
            for lane in 0..shape.lane_count(Format::Single) {
                assert_eq!(
                    Part::Upper.source_lane_offset(shape) + lane,
                    lanes[lane as usize]
                );
            }
        }
    }

    #[test]
    #[should_panic(expected = "widening FP16 requires a vector shape")]
    fn lower_part_rejects_scalar_shape() {
        Part::Lower.source_lane_offset(Shape::Scalar);
    }

    #[test]
    #[should_panic(expected = "widening FP16 requires a vector shape")]
    fn upper_part_rejects_scalar_shape() {
        Part::Upper.source_lane_offset(Shape::Scalar);
    }

    #[test]
    fn vector_widths_parts_and_every_register_alias_are_explicit() {
        for (encoding, operation, part) in VECTOR_FORMS {
            for (q, shape) in SHAPES {
                for destination in 0..=REGISTER_MASK {
                    for left in 0..=REGISTER_MASK {
                        for right in 0..=REGISTER_MASK {
                            let word = encoding
                                | q
                                | (right << RIGHT_SHIFT)
                                | (left << LEFT_SHIFT)
                                | destination;
                            assert_eq!(
                                decode(word),
                                Some(Ok(Operand {
                                    operation,
                                    shape,
                                    destination: destination as u8,
                                    left: left as u8,
                                    right: right as u8,
                                    right_lane: None,
                                    part,
                                }))
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn indexed_widening_decoding_is_exhaustive() {
        for (encoding, operation, part) in INDEXED_FORMS {
            for (q, shape) in SHAPES {
                for lane in 0..=HALF_LANE_MASK {
                    for destination in 0..=REGISTER_MASK {
                        for left in 0..=REGISTER_MASK {
                            for right in 0..=INDEXED_REGISTER_MASK {
                                let word = encoding
                                    | q
                                    | index_bits(lane)
                                    | (right << RIGHT_SHIFT)
                                    | (left << LEFT_SHIFT)
                                    | destination;
                                assert_eq!(
                                    decode(word),
                                    Some(Ok(Operand {
                                        operation,
                                        shape,
                                        destination: destination as u8,
                                        left: left as u8,
                                        right: right as u8,
                                        right_lane: Some(lane as u8),
                                        part,
                                    }))
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn reserved_sizes_and_scalar_classes_are_not_admitted() {
        for (encoding, _, _) in VECTOR_FORMS.into_iter().chain(INDEXED_FORMS) {
            for (q, _) in SHAPES {
                for registers in [
                    0,
                    REGISTER_MASK
                        | (REGISTER_MASK << LEFT_SHIFT)
                        | (INDEXED_REGISTER_MASK << RIGHT_SHIFT),
                ] {
                    assert_eq!(decode(encoding | q | registers | SIZE_RESERVED), None);
                    assert_eq!(decode(encoding | q | registers | SCALAR_CLASS), None);
                }
            }
        }
    }

    #[test]
    fn fixed_bit_neighbors_do_not_widen_the_family() {
        for (forms, mask, subtract) in [
            (VECTOR_FORMS, VECTOR_MASK, VECTOR_SUBTRACT),
            (INDEXED_FORMS, INDEXED_MASK, INDEXED_SUBTRACT),
        ] {
            for (encoding, _, _) in forms {
                for (q, _) in SHAPES {
                    for bit in 0..u32::BITS {
                        let change = 1 << bit;
                        if mask & change != 0 && change != subtract {
                            let word = (encoding | q) ^ change;
                            assert_eq!(decode(word), None, "neighbor {word:#010x}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn allocated_fp8_bfloat16_fused_and_modified_immediates_stay_unclaimed() {
        for word in [
            0x0fc0_0000, // FP8 FMLALB, distinguished from FMLAL by sz.
            0x4fc0_0000, // FP8 FMLALT.
            0x2ec0_fc00, // BFMLALB.
            0x6ec0_fc00, // BFMLALT.
            0x0e20_cc00, // FMLA vector Single.
            0x0e40_0c00, // FMLA vector Half.
            0x0f80_1000, // FMLA indexed Single.
            0x0f00_1000, // FMLA indexed Half.
            0x1f00_0000, // FMADD scalar Single.
            0x6f00_e400, // MOVI modified immediate.
            0xd503_201f, // NOP.
            0xffff_ffff,
        ] {
            assert_eq!(decode(word), None, "allocated neighbor {word:#010x}");
        }
    }
}
