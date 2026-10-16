use super::*;

#[test]
fn all_allocated_arrangements_and_register_aliases_decode() {
    for (ordinary, half, kind) in [
        (
            FAMAX,
            HALF_FAMAX,
            Kind::Absolute(AbsoluteMinMaxOperation::Maximum),
        ),
        (
            FAMIN,
            HALF_FAMIN,
            Kind::Absolute(AbsoluteMinMaxOperation::Minimum),
        ),
        (FSCALE, HALF_FSCALE, Kind::Scale),
    ] {
        for (base, format) in [
            (ordinary, Format::Single),
            (ordinary | DOUBLE_SIZE, Format::Double),
            (half, Format::Half),
        ] {
            for (q, shape) in [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)] {
                for (destination, left, right) in [
                    (0, 1, 2),
                    (0, 0, 2),
                    (0, 1, 0),
                    (0, 1, 1),
                    (0, 0, 0),
                    (31, 31, 31),
                    (31, 0, 30),
                    (28, 31, 0),
                ] {
                    let word =
                        base | q | destination | (left << LEFT_SHIFT) | (right << RIGHT_SHIFT);
                    let expected = if format == Format::Double && shape == Shape::Vector64 {
                        Err(())
                    } else {
                        Ok(Operand {
                            kind,
                            format,
                            shape,
                            destination: destination as u8,
                            left: left as u8,
                            right: right as u8,
                        })
                    };
                    assert_eq!(decode(word), Some(expected), "{word:08x}");
                }
            }
        }
    }
}

#[test]
fn neighboring_families_and_unallocated_sizes_are_not_consumed() {
    for word in [
        0x0e20_dc00,
        0x2e20_dc00,
        0x0e40_1c00,
        0x2e40_1c00,
        0x0e20_f400,
        0x2e20_f400,
        0x1e20_4800,
        0x0e20_e400,
    ] {
        assert_eq!(decode(word), None, "{word:08x}");
    }
}
