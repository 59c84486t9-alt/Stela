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
fn indexed_widths_parts_and_all_lanes_registers_and_aliases_are_explicit() {
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
