use super::*;

#[test]
fn all_sixteen_arrangements_cover_every_register_combination_and_alias() {
    let mut arrangements = 0;
    for (opcode, kind) in [
        (FRECPS, Kind::Reciprocal),
        (FRSQRTS, Kind::ReciprocalSquareRoot),
    ] {
        for (size, format) in [
            (0, Format::Single),
            (DOUBLE_SIZE, Format::Double),
            (HALF_ADJUSTMENT, Format::Half),
        ] {
            for (prefix, shape) in [
                (SCALAR_PREFIX, Shape::Scalar),
                (0, Shape::Vector64),
                (VECTOR_Q, Shape::Vector128),
            ] {
                let word = (opcode ^ size) | prefix;
                if format == Format::Double && shape == Shape::Vector64 {
                    assert_eq!(decode(word), Some(Err(())));
                    continue;
                }
                for destination in 0..=REGISTER_MASK {
                    for left in 0..=REGISTER_MASK {
                        for right in 0..=REGISTER_MASK {
                            let word =
                                word | destination | (left << LEFT_SHIFT) | (right << RIGHT_SHIFT);
                            assert_eq!(
                                decode(word),
                                Some(Ok(Operand {
                                    kind,
                                    format,
                                    shape,
                                    destination: destination as u8,
                                    left: left as u8,
                                    right: right as u8,
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
    assert_eq!(arrangements, 16);
}

#[test]
fn vector_one_double_is_reserved_for_every_register_combination() {
    for opcode in [FRECPS, FRSQRTS] {
        for destination in 0..=REGISTER_MASK {
            for left in 0..=REGISTER_MASK {
                for right in 0..=REGISTER_MASK {
                    assert_eq!(
                        decode(
                            opcode
                                | DOUBLE_SIZE
                                | destination
                                | (left << LEFT_SHIFT)
                                | (right << RIGHT_SHIFT)
                        ),
                        Some(Err(()))
                    );
                }
            }
        }
    }
}

#[test]
fn allocated_arithmetic_estimate_and_modified_immediate_neighbors_stay_separate() {
    const NEIGHBORS: [u32; 7] = [
        0x2e20_fc00,
        0x2e40_3c00,
        0x0e20_cc00,
        0x0ea1_d800,
        0x2ea1_d800,
        0x2ea1_f800,
        0x6f00_e400,
    ];
    for word in NEIGHBORS {
        assert_eq!(decode(word), None, "word={word:08x}");
    }
}
