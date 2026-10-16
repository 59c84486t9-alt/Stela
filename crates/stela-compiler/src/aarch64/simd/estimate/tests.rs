use super::*;

const FLOATING_KINDS: [(u32, Kind); 3] = [
    (FRECPE, Kind::Reciprocal),
    (FRSQRTE, Kind::ReciprocalSquareRoot),
    (FRECPX, Kind::ReciprocalExponent),
];

fn check_registers(encoding: u32, kind: Kind, format: Format, shape: Shape) {
    for destination in 0..=REGISTER_MASK {
        for source in 0..=REGISTER_MASK {
            let word = encoding | destination | (source << SOURCE_SHIFT);
            assert_eq!(
                decode(word),
                Some(Ok(Operand {
                    kind,
                    format,
                    shape,
                    destination: destination as u8,
                    source: source as u8
                })),
                "word={word:08x}"
            );
        }
    }
}

#[test]
fn floating_shapes_and_every_register_alias_are_explicit() {
    let mut arrangements = 0;
    for (opcode, kind) in FLOATING_KINDS {
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
                if kind == Kind::ReciprocalExponent && shape != Shape::Scalar {
                    assert_eq!(decode(word), None);
                    continue;
                }
                if format == Format::Double && shape == Shape::Vector64 {
                    assert_eq!(decode(word), Some(Err(())));
                    continue;
                }
                check_registers(word, kind, format, shape);
                arrangements += 1;
            }
        }
    }
    assert_eq!(arrangements, 19);
}

#[test]
fn unsigned_estimates_only_admit_two_or_four_integer_single_lanes() {
    for (opcode, kind) in [
        (URECPE, Kind::UnsignedReciprocal),
        (URSQRTE, Kind::UnsignedReciprocalSquareRoot),
    ] {
        assert!(kind.is_unsigned());
        for (q, shape) in [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)] {
            check_registers(opcode | q, kind, Format::Single, shape);
            for destination in 0..=REGISTER_MASK {
                for source in 0..=REGISTER_MASK {
                    assert_eq!(
                        decode(opcode | q | DOUBLE_SIZE | destination | (source << SOURCE_SHIFT)),
                        Some(Err(()))
                    );
                }
            }
        }
        assert_eq!(decode(opcode | SCALAR_PREFIX), None);
        assert_eq!(decode(opcode ^ HALF_ADJUSTMENT), None);
    }
    for (_, kind) in FLOATING_KINDS {
        assert!(!kind.is_unsigned());
    }
}

#[test]
fn floating_vector_one_double_declines_for_every_register_pair() {
    for opcode in [FRECPE, FRSQRTE] {
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                assert_eq!(
                    decode(opcode | DOUBLE_SIZE | destination | (source << SOURCE_SHIFT)),
                    Some(Err(()))
                );
            }
        }
    }
}

#[test]
fn allocated_sqrt_rounding_refinement_and_modified_immediate_neighbors_stay_separate() {
    const NEIGHBORS: [u32; 8] = [
        0x1e21_c000,
        0x2ea1_f800,
        0x2ef9_f800,
        0x2e21_f800,
        0x0e20_fc00,
        0x0ea0_fc00,
        0x0ea0_c800,
        0x6f00_e400,
    ];
    for word in NEIGHBORS {
        assert_eq!(decode(word), None, "word={word:08x}");
    }
}
