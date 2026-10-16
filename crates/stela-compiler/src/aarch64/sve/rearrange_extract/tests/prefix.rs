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
fn every_predicate_and_element_retains_unpredicated_only_clast_policy() {
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
        assert_eq!(decoded.prefix_requirement(other), Err(()));
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
        assert_eq!(forged.prefix_requirement(word), Err(()));
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
