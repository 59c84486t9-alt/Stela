use super::*;

#[test]
fn all_eight_arrangements_cover_every_register_pair_and_alias() {
    const ARRANGEMENTS: [(u32, Format, Shape); 8] = [
        (SCALAR_FSQRT, Format::Single, Shape::Scalar),
        (
            SCALAR_FSQRT | (FORMAT_DOUBLE << FORMAT_SHIFT),
            Format::Double,
            Shape::Scalar,
        ),
        (
            SCALAR_FSQRT | (FORMAT_HALF << FORMAT_SHIFT),
            Format::Half,
            Shape::Scalar,
        ),
        (VECTOR_FSQRT, Format::Single, Shape::Vector64),
        (VECTOR_FSQRT | VECTOR_Q, Format::Single, Shape::Vector128),
        (
            VECTOR_FSQRT | VECTOR_DOUBLE | VECTOR_Q,
            Format::Double,
            Shape::Vector128,
        ),
        (VECTOR_HALF_FSQRT, Format::Half, Shape::Vector64),
        (VECTOR_HALF_FSQRT | VECTOR_Q, Format::Half, Shape::Vector128),
    ];
    for (encoding, format, shape) in ARRANGEMENTS {
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                let word = encoding | destination | (source << SOURCE_SHIFT);
                assert_eq!(
                    decode(word),
                    Some(Ok(Operand {
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
}

#[test]
fn reserved_scalar_format_and_vector_one_double_decline_for_all_registers() {
    const FORMAT_RESERVED: u32 = 2;
    for destination in 0..=REGISTER_MASK {
        for source in 0..=REGISTER_MASK {
            let registers = destination | (source << SOURCE_SHIFT);
            assert_eq!(
                decode(SCALAR_FSQRT | (FORMAT_RESERVED << FORMAT_SHIFT) | registers),
                Some(Err(()))
            );
            assert_eq!(
                decode(VECTOR_FSQRT | VECTOR_DOUBLE | registers),
                Some(Err(()))
            );
        }
    }
}

#[test]
fn fixed_bit_changes_do_not_retain_sqrt_semantics() {
    for (encoding, mask) in [
        (SCALAR_FSQRT, SCALAR_MASK),
        (VECTOR_FSQRT, VECTOR_MASK),
        (VECTOR_HALF_FSQRT, VECTOR_HALF_MASK),
    ] {
        for bit in 0..u32::BITS {
            if mask & (1 << bit) != 0 {
                assert_eq!(decode(encoding ^ (1 << bit)), None);
            }
        }
    }
}

#[test]
fn allocated_rounding_comparison_and_estimate_neighbors_stay_separate() {
    // Neighboring forms: scalar and vector FRINT64X, scalar FRINTN, FRSQRTE,
    // FRECPE, FCMP, FCVT and MOVI.
    const NEIGHBORS: [u32; 8] = [
        0x1e29_c000,
        0x2e21_f800,
        0x1e24_4000,
        0x2ea1_d800,
        0x0ea1_d800,
        0x1e20_2000,
        0x1e22_c000,
        0x6f00_e400,
    ];
    for word in NEIGHBORS {
        assert_eq!(decode(word), None, "word={word:08x}");
    }
}
