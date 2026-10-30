use super::*;

mod prefix {
    use super::*;
    use crate::aarch64::scalable::Predication;
    use crate::aarch64::sve::prefix::{self, DecodedPrefix, PrefixRequirement, PrefixViolation};

    const DESTINATION: u8 = 3;
    const SOURCE: u8 = 5;
    const PREDICATE: u8 = 2;
    const REGISTER_COUNT: u8 = 32;
    const PERMITTED: [u32; 4] = [CLASTA_VECTOR, CLASTB_VECTOR, INSR_GENERAL, INSR_SCALAR];
    const UNAUDITED: [u32; 11] = [
        LASTA_GENERAL,
        LASTB_GENERAL,
        LASTA_SCALAR,
        LASTB_SCALAR,
        CLASTA_GENERAL,
        CLASTB_GENERAL,
        CLASTA_SCALAR,
        CLASTB_SCALAR,
        DUP_IMMEDIATE,
        DUP_GENERAL,
        DUP_INDEX | (1 << INDEX_SIZE_SHIFT),
    ];

    fn operand(word: u32) -> Operand {
        decode(word)
            .expect("assigned allocation")
            .expect("valid operands")
    }

    fn word(class: u32, source: u8, destination: u8) -> u32 {
        class | (u32::from(source) << SOURCE_SHIFT) | u32::from(destination)
    }

    fn prefix(source: u8, mode: Predication) -> DecodedPrefix {
        DecodedPrefix {
            destination: DESTINATION,
            source,
            predication: mode,
            element: Some(ElementSize::Byte),
        }
    }

    #[test]
    fn all_fifteen_canonical_policies_are_classified() {
        for class in PERMITTED {
            let word = word(class, SOURCE, DESTINATION);
            assert_eq!(
                operand(word).prefix_requirement(word),
                Ok(Some(PrefixRequirement::Vector {
                    destination: DESTINATION,
                    predicated: None,
                    other_vector_sources: if class == INSR_GENERAL {
                        0
                    } else {
                        1_u32 << SOURCE
                    },
                }))
            );
        }
        for class in UNAUDITED {
            let word = word(class, SOURCE, DESTINATION);
            assert_eq!(operand(word).prefix_requirement(word), Ok(None));
        }
    }

    #[test]
    fn every_destination_and_source_preserves_the_correct_register_bank() {
        for class in PERMITTED {
            for destination in 0..REGISTER_COUNT {
                for source in 0..REGISTER_COUNT {
                    for size in 0..=SIZE_MASK {
                        let word = word(class, source, destination) | (size << SIZE_SHIFT);
                        assert_eq!(
                            operand(word).prefix_requirement(word),
                            Ok(Some(PrefixRequirement::Vector {
                                destination,
                                predicated: None,
                                other_vector_sources: if class == INSR_GENERAL {
                                    0
                                } else {
                                    1_u32 << source
                                },
                            }))
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn scalar_vector_source_aliases_are_rejected_but_same_numbered_gprs_are_disjoint() {
        for class in PERMITTED {
            let word = word(class, DESTINATION, DESTINATION);
            let requirement = operand(word).prefix_requirement(word).unwrap().unwrap();
            let expected = if class == INSR_GENERAL {
                Ok(())
            } else {
                Err(PrefixViolation::OtherSourceAlias)
            };
            assert_eq!(
                prefix::validate(prefix(SOURCE, Predication::Unpredicated), requirement),
                expected
            );
        }
        let word = word(INSR_GENERAL, REGISTER_MASK as u8, REGISTER_MASK as u8);
        assert_eq!(operand(word).kind, Kind::InsertGeneral(Register::Zero));
        assert_eq!(
            operand(word).prefix_requirement(word),
            Ok(Some(PrefixRequirement::Vector {
                destination: REGISTER_MASK as u8,
                predicated: None,
                other_vector_sources: 0,
            }))
        );
    }

    #[test]
    fn every_predicate_and_element_keeps_unpredicated_only_clast_policy() {
        for class in [CLASTA_VECTOR, CLASTB_VECTOR] {
            for size in 0..=SIZE_MASK {
                for predicate in 0..=PREDICATE_MASK {
                    let word = word(class, SOURCE, DESTINATION)
                        | (size << SIZE_SHIFT)
                        | (predicate << PREDICATE_SHIFT);
                    assert_eq!(
                        operand(word).prefix_requirement(word),
                        Ok(Some(PrefixRequirement::Vector {
                            destination: DESTINATION,
                            predicated: None,
                            other_vector_sources: 1_u32 << SOURCE,
                        }))
                    );
                }
            }
        }
    }

    #[test]
    fn insertion_elements_do_not_authorize_predicated_prefixes() {
        for class in PERMITTED {
            for size in 0..=SIZE_MASK {
                let word = word(class, SOURCE, DESTINATION) | (size << SIZE_SHIFT);
                let requirement = operand(word).prefix_requirement(word).unwrap().unwrap();
                for mode in [
                    Predication::Merging(PREDICATE),
                    Predication::Zeroing(PREDICATE),
                ] {
                    assert_eq!(
                        prefix::validate(prefix(SOURCE, mode), requirement),
                        Err(PrefixViolation::PredicatedPrefixForbidden)
                    );
                }
            }
        }
    }

    #[test]
    fn prefix_source_can_alias_its_destination_but_destinations_must_match() {
        for class in PERMITTED {
            let word = word(class, SOURCE, DESTINATION);
            let requirement = operand(word).prefix_requirement(word).unwrap().unwrap();
            for source in 0..REGISTER_COUNT {
                assert_eq!(
                    prefix::validate(prefix(source, Predication::Unpredicated), requirement),
                    Ok(())
                );
            }
            let mut other = prefix(SOURCE, Predication::Unpredicated);
            other.destination = SOURCE;
            assert_eq!(
                prefix::validate(other, requirement),
                Err(PrefixViolation::DestinationMismatch)
            );
        }
    }

    #[test]
    fn typed_word_mismatches_reserved_words_and_forged_operands_are_errors() {
        let word = word(INSR_SCALAR, SOURCE, DESTINATION);
        let decoded = operand(word);
        for other in [word ^ 1, 0, DUP_INDEX, DUP_IMMEDIATE | SHIFT_FLAG] {
            assert_eq!(decoded.prefix_requirement(other), Err(Unsupported));
        }
        for forged in [
            Operand {
                destination: Destination::Vector(REGISTER_COUNT),
                ..decoded
            },
            Operand {
                kind: Kind::InsertScalar(REGISTER_COUNT),
                ..decoded
            },
            Operand {
                kind: Kind::InsertGeneral(Register::X(SOURCE)),
                ..decoded
            },
        ] {
            assert_eq!(forged.prefix_requirement(word), Err(Unsupported));
        }
    }

    #[test]
    fn scalar_and_general_destination_banks_remain_unaudited_even_with_aliases() {
        for class in [
            LASTA_GENERAL,
            LASTB_GENERAL,
            LASTA_SCALAR,
            LASTB_SCALAR,
            CLASTA_GENERAL,
            CLASTB_GENERAL,
            CLASTA_SCALAR,
            CLASTB_SCALAR,
        ] {
            for size in 0..=SIZE_MASK {
                let word = word(class, REGISTER_MASK as u8, REGISTER_MASK as u8)
                    | (size << SIZE_SHIFT)
                    | (PREDICATE_MASK << PREDICATE_SHIFT);
                assert_eq!(operand(word).prefix_requirement(word), Ok(None));
            }
        }
    }
}

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
                    assert_eq!(decode(word), Some(Err(Unsupported)));
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
                assert_eq!(decode(word), Some(Err(Unsupported)));
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
