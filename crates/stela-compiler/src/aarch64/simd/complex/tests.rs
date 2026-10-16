use super::*;

const SIZE_RESERVED: u32 = 0;
const INDEX_M_SHIFT: u32 = 20;
const SCALAR_CLASS: u32 = 1 << 28;
const VECTOR_OPERATION_CHANGE: u32 = 1 << 13;
const COMPLEX_PAIR_LANES: u32 = 2;
const ROTATIONS: [(u32, Rotation); 4] = [
    (0, Rotation::Degrees0),
    (1, Rotation::Degrees90),
    (2, Rotation::Degrees180),
    (3, Rotation::Degrees270),
];
const SHAPES: [(u32, Shape); 2] = [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)];
const VECTOR_LAYOUTS: [(u32, u32, Format, Shape); 5] = [
    (SIZE_HALF, 0, Format::Half, Shape::Vector64),
    (SIZE_HALF, VECTOR_Q, Format::Half, Shape::Vector128),
    (SIZE_SINGLE, 0, Format::Single, Shape::Vector64),
    (SIZE_SINGLE, VECTOR_Q, Format::Single, Shape::Vector128),
    (SIZE_DOUBLE, VECTOR_Q, Format::Double, Shape::Vector128),
];

#[test]
fn register_forms_cover_every_width_rotation_and_register_alias() {
    for (encoding, kind, rotation_shift, rotations) in [
        (
            FCADD,
            Kind::Add,
            ADD_ROTATION_SHIFT,
            &[(0, Rotation::Degrees90), (1, Rotation::Degrees270)][..],
        ),
        (
            FCMLA,
            Kind::MultiplyAdd,
            MULTIPLY_ROTATION_SHIFT,
            &ROTATIONS[..],
        ),
    ] {
        for &(rotation_field, rotation) in rotations {
            for (size, q, format, shape) in VECTOR_LAYOUTS {
                for destination in 0..=REGISTER_MASK {
                    for left in 0..=REGISTER_MASK {
                        for right in 0..=REGISTER_MASK {
                            let word = encoding
                                | (size << SIZE_SHIFT)
                                | q
                                | (rotation_field << rotation_shift)
                                | (right << RIGHT_SHIFT)
                                | (left << LEFT_SHIFT)
                                | destination;
                            assert_eq!(
                                decode(word),
                                Some(Ok(Operand {
                                    kind,
                                    format,
                                    shape,
                                    rotation,
                                    destination: destination as u8,
                                    left: left as u8,
                                    right: Source::Vector(right as u8),
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
fn indexed_half_uses_whole_pairs_and_all_five_register_bits() {
    for (q, shape) in SHAPES {
        let pair_count = shape.lane_count(Format::Half) / COMPLEX_PAIR_LANES;
        for index in 0..pair_count {
            let index_bits = ((index >> HALF_PAIR_INDEX_HIGH_SHIFT) << INDEX_H_SHIFT)
                | ((index & INDEX_BIT_MASK) << INDEX_L_SHIFT);
            for (rotation_field, rotation) in ROTATIONS {
                for destination in 0..=REGISTER_MASK {
                    for left in 0..=REGISTER_MASK {
                        for right in 0..=REGISTER_MASK {
                            let word = INDEXED_FCMLA
                                | (SIZE_HALF << SIZE_SHIFT)
                                | q
                                | index_bits
                                | (rotation_field << INDEXED_ROTATION_SHIFT)
                                | (right << RIGHT_SHIFT)
                                | (left << LEFT_SHIFT)
                                | destination;
                            assert_eq!(
                                decode(word),
                                Some(Ok(Operand {
                                    kind: Kind::MultiplyAdd,
                                    format: Format::Half,
                                    shape,
                                    rotation,
                                    destination: destination as u8,
                                    left: left as u8,
                                    right: Source::Indexed {
                                        register: right as u8,
                                        index: index as u8
                                    },
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
fn indexed_single_requires_full_width_and_indexes_two_pairs() {
    for index in 0..=INDEX_BIT_MASK {
        for (rotation_field, rotation) in ROTATIONS {
            for destination in 0..=REGISTER_MASK {
                for left in 0..=REGISTER_MASK {
                    for right in 0..=REGISTER_MASK {
                        let word = INDEXED_FCMLA
                            | (SIZE_SINGLE << SIZE_SHIFT)
                            | VECTOR_Q
                            | (index << INDEX_H_SHIFT)
                            | (rotation_field << INDEXED_ROTATION_SHIFT)
                            | (right << RIGHT_SHIFT)
                            | (left << LEFT_SHIFT)
                            | destination;
                        assert_eq!(
                            decode(word),
                            Some(Ok(Operand {
                                kind: Kind::MultiplyAdd,
                                format: Format::Single,
                                shape: Shape::Vector128,
                                rotation,
                                destination: destination as u8,
                                left: left as u8,
                                right: Source::Indexed {
                                    register: right as u8,
                                    index: index as u8
                                },
                            }))
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn reserved_sizes_widths_and_indexes_are_recognized_errors() {
    for encoding in [FCADD, FCMLA, INDEXED_FCMLA] {
        for (q, _) in SHAPES {
            for right in 0..=REGISTER_MASK {
                let base = encoding | q | (right << RIGHT_SHIFT) | REGISTER_MASK;
                assert_eq!(decode(base | (SIZE_RESERVED << SIZE_SHIFT)), Some(Err(())));
                if encoding == INDEXED_FCMLA || q == 0 {
                    assert_eq!(decode(base | (SIZE_DOUBLE << SIZE_SHIFT)), Some(Err(())));
                }
            }
        }
    }
    for high in 0..=INDEX_BIT_MASK {
        for low in 0..=INDEX_BIT_MASK {
            let indexes = (high << INDEX_H_SHIFT) | (low << INDEX_L_SHIFT);
            assert_eq!(
                decode(INDEXED_FCMLA | (SIZE_SINGLE << SIZE_SHIFT) | indexes),
                Some(Err(()))
            );
            if low != 0 {
                assert_eq!(
                    decode(INDEXED_FCMLA | (SIZE_SINGLE << SIZE_SHIFT) | VECTOR_Q | indexes),
                    Some(Err(()))
                );
            }
            if high != 0 {
                assert_eq!(
                    decode(INDEXED_FCMLA | (SIZE_HALF << SIZE_SHIFT) | indexes),
                    Some(Err(()))
                );
            }
        }
    }
}

#[test]
fn indexed_m_changes_register_sixteen_without_changing_pair_index() {
    for (size, q) in [
        (SIZE_HALF, 0),
        (SIZE_HALF, VECTOR_Q),
        (SIZE_SINGLE, VECTOR_Q),
    ] {
        let word = INDEXED_FCMLA | (size << SIZE_SHIFT) | q;
        let Some(Ok(low)) = decode(word) else {
            panic!("allocated indexed form");
        };
        let Some(Ok(high)) = decode(word | (1 << INDEX_M_SHIFT)) else {
            panic!("allocated indexed form");
        };
        assert_eq!(
            low.right,
            Source::Indexed {
                register: 0,
                index: 0
            }
        );
        assert_eq!(
            high.right,
            Source::Indexed {
                register: 16,
                index: 0
            }
        );
    }
}

#[test]
fn fixed_bit_neighbors_only_admit_the_allocated_add_multiply_transition() {
    for (encoding, mask) in [
        (FCADD, ADD_MASK),
        (FCMLA, MULTIPLY_MASK),
        (INDEXED_FCMLA, INDEXED_MASK),
    ] {
        for bit in 0..u32::BITS {
            let change = 1 << bit;
            if mask & change == 0 {
                continue;
            }
            let word = (encoding | (SIZE_HALF << SIZE_SHIFT)) ^ change;
            if encoding != INDEXED_FCMLA && change == VECTOR_OPERATION_CHANGE {
                assert!(decode(word).is_some_and(|operand| operand.is_ok()));
            } else {
                assert_eq!(decode(word), None, "fixed-bit neighbor {word:#010x}");
            }
        }
    }
}

#[test]
fn scalar_and_other_numerical_families_stay_unclaimed() {
    for encoding in [FCADD, FCMLA, INDEXED_FCMLA] {
        assert_eq!(
            decode(encoding | (SIZE_HALF << SIZE_SHIFT) | SCALAR_CLASS),
            None
        );
    }
    for word in [
        0x0e20_cc00, // FMLA vector Single.
        0x0f80_1000, // FMLA indexed Single.
        0x0f80_0000, // FMLAL indexed Half to Single.
        0x0f40_f000, // BFDOT indexed.
        0x0fc0_f000, // BFMLAL indexed.
        0x1f00_0000, // FMADD scalar Single.
        0x6f00_e400, // MOVI modified immediate.
        0xd503_201f, // NOP.
        0xffff_ffff,
    ] {
        assert_eq!(decode(word), None, "allocated neighbor {word:#010x}");
    }
}
