use super::*;

const OPERATIONS: [(u32, u32, RoundingOperation); 11] = [
    (SCALAR_FRINTN, VECTOR_FRINTN, RoundingOperation::NearestEven),
    (SCALAR_FRINTA, VECTOR_FRINTA, RoundingOperation::NearestAway),
    (
        SCALAR_FRINTP,
        VECTOR_FRINTP,
        RoundingOperation::TowardPositive,
    ),
    (
        SCALAR_FRINTM,
        VECTOR_FRINTM,
        RoundingOperation::TowardNegative,
    ),
    (SCALAR_FRINTZ, VECTOR_FRINTZ, RoundingOperation::TowardZero),
    (SCALAR_FRINTI, VECTOR_FRINTI, RoundingOperation::Current),
    (
        SCALAR_FRINTX,
        VECTOR_FRINTX,
        RoundingOperation::CurrentExact,
    ),
    (
        SCALAR_FRINT32Z,
        VECTOR_FRINT32Z,
        RoundingOperation::Signed32Zero,
    ),
    (
        SCALAR_FRINT32X,
        VECTOR_FRINT32X,
        RoundingOperation::Signed32Current,
    ),
    (
        SCALAR_FRINT64Z,
        VECTOR_FRINT64Z,
        RoundingOperation::Signed64Zero,
    ),
    (
        SCALAR_FRINT64X,
        VECTOR_FRINT64X,
        RoundingOperation::Signed64Current,
    ),
];

fn check_registers(word: u32, operation: RoundingOperation, format: Format, shape: Shape) {
    for destination in 0..=REGISTER_MASK {
        for source in 0..=REGISTER_MASK {
            let word = word | destination | (source << SOURCE_SHIFT);
            assert_eq!(
                decode(word),
                Some(Ok(Operand {
                    operation,
                    format,
                    shape,
                    destination: destination as u8,
                    source: source as u8,
                })),
                "word={word:08x}"
            );
        }
    }
}

#[test]
fn scalar_operation_formats_and_all_register_aliases_are_explicit() {
    let mut arrangements = 0;
    for (scalar, _, operation) in OPERATIONS {
        for (field, format) in [
            (FORMAT_SINGLE, Format::Single),
            (FORMAT_DOUBLE, Format::Double),
            (FORMAT_HALF, Format::Half),
        ] {
            if format == Format::Half && operation.signed_width().is_some() {
                assert_eq!(decode(scalar | (field << FORMAT_SHIFT)), Some(Err(())));
                continue;
            }
            check_registers(
                scalar | (field << FORMAT_SHIFT),
                operation,
                format,
                Shape::Scalar,
            );
            arrangements += 1;
        }
    }
    assert_eq!(arrangements, 29);
}

#[test]
fn vector_operation_shapes_and_all_register_aliases_are_explicit() {
    let mut arrangements = 0;
    for (_, vector, operation) in OPERATIONS {
        for (adjustment, format) in [
            (0, Format::Single),
            (VECTOR_DOUBLE, Format::Double),
            (VECTOR_HALF_ADJUSTMENT, Format::Half),
        ] {
            for (q, shape) in [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)] {
                let word = (vector ^ adjustment) | q;
                if format == Format::Half && operation.signed_width().is_some() {
                    assert_eq!(decode(word), None);
                    continue;
                }
                if format == Format::Double && shape == Shape::Vector64 {
                    assert_eq!(decode(word), Some(Err(())));
                    continue;
                }
                check_registers(word, operation, format, shape);
                arrangements += 1;
            }
        }
    }
    assert_eq!(arrangements, 47);
}

#[test]
fn reserved_fields_decline_for_every_register_pair() {
    const RESERVED_FORMAT: u32 = 2;
    for (scalar, vector, operation) in OPERATIONS {
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                let registers = destination | (source << SOURCE_SHIFT);
                assert_eq!(
                    decode(scalar | (RESERVED_FORMAT << FORMAT_SHIFT) | registers),
                    Some(Err(()))
                );
                assert_eq!(decode(vector | VECTOR_DOUBLE | registers), Some(Err(())));
                if operation.signed_width().is_some() {
                    assert_eq!(
                        decode(scalar | (FORMAT_HALF << FORMAT_SHIFT) | registers),
                        Some(Err(()))
                    );
                }
            }
        }
    }
}

#[test]
fn allocated_neighbors_remain_owned_by_their_existing_families() {
    // Neighboring forms: FSQRT, FCVT, FCMP, FMAX, scalar FMOV, FCVTNS, vector
    // FRECPE/FCVTN/FCMEQ and the modified-immediate class.
    const NEIGHBORS: [u32; 10] = [
        0x1e21_c000,
        0x1e22_c000,
        0x1e20_2000,
        0x1e20_4800,
        0x1e20_4000,
        0x1e20_0000,
        0x0ea1_d800,
        0x0e21_6800,
        0x0e20_e400,
        0x6f00_e400,
    ];
    for word in NEIGHBORS {
        assert_eq!(decode(word), None, "word={word:08x}");
    }
}
