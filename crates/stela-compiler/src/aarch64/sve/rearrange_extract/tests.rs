use super::*;

mod prefix;

#[test]
fn extraction_fields_preserve_scalar_and_vector_banks() {
    for (opcode, destination, position, conditional) in [
        (
            LASTA_GENERAL,
            Destination::General(Register::Zero),
            LastPosition::AfterLastActive,
            false,
        ),
        (
            LASTB_GENERAL,
            Destination::General(Register::Zero),
            LastPosition::LastActive,
            false,
        ),
        (
            LASTA_SCALAR,
            Destination::Scalar(31),
            LastPosition::AfterLastActive,
            false,
        ),
        (
            LASTB_SCALAR,
            Destination::Scalar(31),
            LastPosition::LastActive,
            false,
        ),
        (
            CLASTA_GENERAL,
            Destination::General(Register::Zero),
            LastPosition::AfterLastActive,
            true,
        ),
        (
            CLASTB_GENERAL,
            Destination::General(Register::Zero),
            LastPosition::LastActive,
            true,
        ),
        (
            CLASTA_SCALAR,
            Destination::Scalar(31),
            LastPosition::AfterLastActive,
            true,
        ),
        (
            CLASTB_SCALAR,
            Destination::Scalar(31),
            LastPosition::LastActive,
            true,
        ),
        (
            CLASTA_VECTOR,
            Destination::Vector(31),
            LastPosition::AfterLastActive,
            true,
        ),
        (
            CLASTB_VECTOR,
            Destination::Vector(31),
            LastPosition::LastActive,
            true,
        ),
    ] {
        for (size, element_size) in [
            ElementSize::Byte,
            ElementSize::Halfword,
            ElementSize::Word,
            ElementSize::Doubleword,
        ]
        .into_iter()
        .enumerate()
        {
            for predicate in 0..=PREDICATE_MASK {
                for source in 0..=REGISTER_MASK {
                    let word = opcode
                        | ((size as u32) << SIZE_SHIFT)
                        | (predicate << PREDICATE_SHIFT)
                        | (source << SOURCE_SHIFT)
                        | REGISTER_MASK;
                    assert_eq!(
                        decode(word),
                        Some(Ok(Operand {
                            element_size,
                            destination,
                            kind: Kind::Last {
                                source: source as u8,
                                predicate: predicate as u8,
                                position,
                                conditional
                            },
                        }))
                    );
                }
            }
        }
    }
}

#[test]
fn general_duplicate_uses_sp_but_insertion_uses_zero() {
    for (opcode, kind) in [
        (DUP_GENERAL, Kind::DuplicateGeneral(Register::Sp)),
        (INSR_GENERAL, Kind::InsertGeneral(Register::Zero)),
        (INSR_SCALAR, Kind::InsertScalar(31)),
    ] {
        let word = opcode | (REGISTER_MASK << SOURCE_SHIFT) | REGISTER_MASK;
        assert_eq!(
            decode(word),
            Some(Ok(Operand {
                element_size: ElementSize::Byte,
                destination: Destination::Vector(31),
                kind
            }))
        );
    }
}

#[test]
fn immediate_sign_extension_and_reserved_byte_shift_are_explicit() {
    for size in 0..=SIZE_MASK {
        for immediate in 0..=IMMEDIATE_MASK {
            for shifted in [false, true] {
                let word = DUP_IMMEDIATE
                    | (size << SIZE_SHIFT)
                    | (immediate << IMMEDIATE_SHIFT)
                    | if shifted { SHIFT_FLAG } else { 0 };
                if size == 0 && shifted {
                    assert_eq!(decode(word), Some(Err(())));
                } else {
                    let signed = immediate as u8 as i8 as i16;
                    let expected = if shifted {
                        signed << IMMEDIATE_SCALE_SHIFT
                    } else {
                        signed
                    };
                    assert!(matches!(decode(word), Some(Ok(Operand {
                        kind: Kind::DuplicateImmediate(value), .. })) if value == expected));
                }
            }
        }
    }
}

#[test]
fn indexed_duplicate_allows_quadwords_and_preserves_out_of_length_indices() {
    for size in 0..=INDEX_SIZE_MASK {
        for high in 0..=INDEX_HIGH_MASK {
            let word = DUP_INDEX | (size << INDEX_SIZE_SHIFT) | (high << INDEX_HIGH_SHIFT);
            if size == 0 {
                assert_eq!(decode(word), Some(Err(())));
                continue;
            }
            let lowest = size.trailing_zeros();
            let combined = (high << INDEX_HIGH_SCALE) | size;
            assert_eq!(
                decode(word),
                Some(Ok(Operand {
                    element_size: ElementSize::from_bytes(1 << lowest).unwrap(),
                    destination: Destination::Vector(0),
                    kind: Kind::DuplicateElement {
                        source: 0,
                        index: (combined >> (lowest + 1)) as u8
                    },
                }))
            );
        }
    }
}

#[test]
fn unrelated_encodings_decline() {
    for word in [0, u32::MAX, 0xd503_201f, DUP_INDEX ^ (1 << 31)] {
        assert_eq!(decode(word), None);
    }
}
