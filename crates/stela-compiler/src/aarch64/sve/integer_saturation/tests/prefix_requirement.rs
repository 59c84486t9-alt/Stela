use super::*;
use crate::aarch64::sve::prefix::{
    DecodedPrefix, PredicatedPrefixRequirement, PrefixRequirement, PrefixViolation, validate,
};

#[derive(Clone, Copy)]
struct Fact {
    word: u32,
    allowed: bool,
    predicated: bool,
    sources: u8,
    minimum_size: u32,
}

// Independent table extracted from exact June XML fixed bits, operational
// notes, vector register fields, and the general MOVPRFX follower contract.
const FACTS: [Fact; 39] = [
    Fact {
        word: 0x4500f800,
        allowed: true,
        predicated: false,
        sources: 2,
        minimum_size: 0,
    }, // saba_z_zzz_
    Fact {
        word: 0x4500c000,
        allowed: true,
        predicated: false,
        sources: 2,
        minimum_size: 1,
    }, // sabalb_z_zzz_
    Fact {
        word: 0x4500c400,
        allowed: true,
        predicated: false,
        sources: 2,
        minimum_size: 1,
    }, // sabalt_z_zzz_
    Fact {
        word: 0x040c0000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // sabd_z_p_zz_
    Fact {
        word: 0x45003000,
        allowed: false,
        predicated: false,
        sources: 2,
        minimum_size: 1,
    }, // sabdlb_z_zz_
    Fact {
        word: 0x45003400,
        allowed: false,
        predicated: false,
        sources: 2,
        minimum_size: 1,
    }, // sabdlt_z_zz_
    Fact {
        word: 0x44108000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // shadd_z_p_zz_
    Fact {
        word: 0x44128000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // shsub_z_p_zz_
    Fact {
        word: 0x44168000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // shsubr_z_p_zz_
    Fact {
        word: 0x4408a000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // sqabs_z_p_z_m
    Fact {
        word: 0x44188000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // sqadd_z_p_zz_
    Fact {
        word: 0x2524c000,
        allowed: true,
        predicated: false,
        sources: 0,
        minimum_size: 0,
    }, // sqadd_z_zi_
    Fact {
        word: 0x04201000,
        allowed: false,
        predicated: false,
        sources: 2,
        minimum_size: 0,
    }, // sqadd_z_zz_
    Fact {
        word: 0x4501d800,
        allowed: true,
        predicated: false,
        sources: 1,
        minimum_size: 0,
    }, // sqcadd_z_zz_
    Fact {
        word: 0x4409a000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // sqneg_z_p_z_m
    Fact {
        word: 0x441a8000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // sqsub_z_p_zz_
    Fact {
        word: 0x2526c000,
        allowed: true,
        predicated: false,
        sources: 0,
        minimum_size: 0,
    }, // sqsub_z_zi_
    Fact {
        word: 0x04201800,
        allowed: false,
        predicated: false,
        sources: 2,
        minimum_size: 0,
    }, // sqsub_z_zz_
    Fact {
        word: 0x441e8000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // sqsubr_z_p_zz_
    Fact {
        word: 0x44148000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // srhadd_z_p_zz_
    Fact {
        word: 0x441c8000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // suqadd_z_p_zz_
    Fact {
        word: 0x4500fc00,
        allowed: true,
        predicated: false,
        sources: 2,
        minimum_size: 0,
    }, // uaba_z_zzz_
    Fact {
        word: 0x4500c800,
        allowed: true,
        predicated: false,
        sources: 2,
        minimum_size: 1,
    }, // uabalb_z_zzz_
    Fact {
        word: 0x4500cc00,
        allowed: true,
        predicated: false,
        sources: 2,
        minimum_size: 1,
    }, // uabalt_z_zzz_
    Fact {
        word: 0x040d0000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // uabd_z_p_zz_
    Fact {
        word: 0x45003800,
        allowed: false,
        predicated: false,
        sources: 2,
        minimum_size: 1,
    }, // uabdlb_z_zz_
    Fact {
        word: 0x45003c00,
        allowed: false,
        predicated: false,
        sources: 2,
        minimum_size: 1,
    }, // uabdlt_z_zz_
    Fact {
        word: 0x44118000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // uhadd_z_p_zz_
    Fact {
        word: 0x44138000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // uhsub_z_p_zz_
    Fact {
        word: 0x44178000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // uhsubr_z_p_zz_
    Fact {
        word: 0x44198000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // uqadd_z_p_zz_
    Fact {
        word: 0x2525c000,
        allowed: true,
        predicated: false,
        sources: 0,
        minimum_size: 0,
    }, // uqadd_z_zi_
    Fact {
        word: 0x04201400,
        allowed: false,
        predicated: false,
        sources: 2,
        minimum_size: 0,
    }, // uqadd_z_zz_
    Fact {
        word: 0x441b8000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // uqsub_z_p_zz_
    Fact {
        word: 0x2527c000,
        allowed: true,
        predicated: false,
        sources: 0,
        minimum_size: 0,
    }, // uqsub_z_zi_
    Fact {
        word: 0x04201c00,
        allowed: false,
        predicated: false,
        sources: 2,
        minimum_size: 0,
    }, // uqsub_z_zz_
    Fact {
        word: 0x441f8000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // uqsubr_z_p_zz_
    Fact {
        word: 0x44158000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // urhadd_z_p_zz_
    Fact {
        word: 0x441d8000,
        allowed: true,
        predicated: true,
        sources: 1,
        minimum_size: 0,
    }, // usqadd_z_p_zz_
];

const ELEMENTS: [ElementSize; 4] = [
    ElementSize::Byte,
    ElementSize::Halfword,
    ElementSize::Word,
    ElementSize::Doubleword,
];

fn expected(
    fact: Fact,
    destination: u8,
    source: u8,
    right: u8,
    predicate: u8,
    size: u32,
) -> PrefixRequirement {
    if !fact.allowed {
        return PrefixRequirement::Forbidden;
    }
    let other_vector_sources = match fact.sources {
        0 => 0,
        1 => 1_u32 << source,
        2 => (1_u32 << source) | (1_u32 << right),
        _ => panic!("bad independently extracted source count"),
    };
    PrefixRequirement::Vector {
        destination,
        predicated: fact.predicated.then_some(PredicatedPrefixRequirement {
            predicate,
            element: ELEMENTS[size as usize],
        }),
        other_vector_sources,
    }
}

fn canonical_word(
    fact: Fact,
    destination: u8,
    source: u8,
    right: u8,
    predicate: u8,
    size: u32,
) -> u32 {
    let mut word = fact.word | u32::from(destination) | (size << 22);
    if fact.sources >= 1 {
        word |= u32::from(source) << 5;
    }
    if fact.sources == 2 {
        word |= u32::from(right) << 16;
    }
    if fact.predicated {
        word |= u32::from(predicate) << 10;
    }
    word
}

#[test]
fn all_39_canonical_policies_widths_predicates_and_register_roles_match_independent_table() {
    let mut cases = 0;
    for fact in FACTS {
        for size in fact.minimum_size..4 {
            for predicate in 0..if fact.predicated { 8 } else { 1 } {
                for destination in 0..32 {
                    for source in 0..32 {
                        let right = 31 - source;
                        let word =
                            canonical_word(fact, destination, source, right, predicate, size);
                        let operand = decode(word)
                            .expect("canonical word")
                            .expect("allocated fields");
                        let requirement = operand
                            .prefix_requirement(word)
                            .expect("matching operand")
                            .expect("audited form");
                        assert_eq!(
                            requirement,
                            expected(fact, destination, source, right, predicate, size),
                            "word={word:08x}"
                        );
                        cases += 1;
                    }
                }
            }
        }
    }
    assert_eq!(cases, 724992);
}

#[test]
fn actual_prefix_validator_observes_aliasing_predicates_elements_and_forbidden_forms() {
    for fact in FACTS {
        for size in fact.minimum_size..4 {
            for predicate in 0..if fact.predicated { 8 } else { 1 } {
                for (destination, source, right) in
                    [(3, 5, 7), (31, 0, 30), (3, 3, 7), (3, 5, 3), (31, 31, 31)]
                {
                    let word = canonical_word(fact, destination, source, right, predicate, size);
                    let operand = decode(word).unwrap().unwrap();
                    let requirement = operand.prefix_requirement(word).unwrap().unwrap();
                    let alias = fact.sources >= 1 && source == destination
                        || fact.sources == 2 && right == destination;
                    let prior_error = if !fact.allowed {
                        Some(PrefixViolation::FollowerNotAuthorized)
                    } else if alias {
                        Some(PrefixViolation::OtherSourceAlias)
                    } else {
                        None
                    };
                    let base = DecodedPrefix {
                        destination,
                        source: 9,
                        predication: Predication::Unpredicated,
                        element: None,
                    };
                    assert_eq!(validate(base, requirement), prior_error.map_or(Ok(()), Err));
                    let changed_destination = DecodedPrefix {
                        destination: (destination + 1) % 32,
                        ..base
                    };
                    assert_eq!(
                        validate(changed_destination, requirement),
                        Err(if fact.allowed {
                            PrefixViolation::DestinationMismatch
                        } else {
                            PrefixViolation::FollowerNotAuthorized
                        })
                    );
                    for mode in [
                        Predication::Merging(predicate),
                        Predication::Zeroing(predicate),
                    ] {
                        for element in ELEMENTS {
                            let prefix = DecodedPrefix {
                                predication: mode,
                                element: Some(element),
                                ..base
                            };
                            let error = prior_error.or(if !fact.predicated {
                                Some(PrefixViolation::PredicatedPrefixForbidden)
                            } else if element != ELEMENTS[size as usize] {
                                Some(PrefixViolation::ElementMismatch)
                            } else {
                                None
                            });
                            assert_eq!(validate(prefix, requirement), error.map_or(Ok(()), Err));
                        }
                    }
                    let different_predicate = DecodedPrefix {
                        predication: Predication::Merging((predicate + 1) % 8),
                        element: Some(ELEMENTS[size as usize]),
                        ..base
                    };
                    let error = prior_error.or(Some(if fact.predicated {
                        PrefixViolation::PredicateMismatch
                    } else {
                        PrefixViolation::PredicatedPrefixForbidden
                    }));
                    assert_eq!(
                        validate(different_predicate, requirement),
                        error.map_or(Ok(()), Err)
                    );
                }
            }
        }
    }
}

#[test]
fn source_word_or_any_typed_operand_mismatch_is_an_error_before_authorization() {
    for fact in FACTS {
        let word = canonical_word(fact, 3, 5, 7, 2, fact.minimum_size);
        let operand = decode(word).unwrap().unwrap();
        let mut forged = operand;
        forged.destination = 4;
        assert_eq!(forged.prefix_requirement(word), Err(()));
        forged = operand;
        forged.left ^= 1;
        assert_eq!(forged.prefix_requirement(word), Err(()));
        forged = operand;
        forged.right = match operand.right {
            Input::Vector(v) => Input::Vector(v ^ 1),
            Input::Immediate(v) => Input::Immediate(v ^ 1),
            Input::None => Input::Vector(0),
        };
        assert_eq!(forged.prefix_requirement(word), Err(()));
        forged = operand;
        forged.element_size = ElementSize::Quadword;
        assert_eq!(forged.prefix_requirement(word), Err(()));
        forged = operand;
        forged.predication = Predication::Zeroing(2);
        assert_eq!(forged.prefix_requirement(word), Err(()));
        forged = operand;
        forged.kind = if operand.kind == Kind::Absolute {
            Kind::Negate
        } else {
            Kind::Absolute
        };
        assert_eq!(forged.prefix_requirement(word), Err(()));
        assert_eq!(operand.prefix_requirement(word ^ (1 << 31)), Err(()));
        assert_eq!(operand.prefix_requirement(0), Err(()));
    }
}

#[test]
fn immediate_scaling_rotation_and_reserved_fields_remain_exact() {
    for fact in FACTS {
        if fact.sources == 0 {
            for size in 0..4 {
                for immediate in [0, 1, 127, 128, 255] {
                    for shifted in [false, true] {
                        let word = fact.word
                            | (size << 22)
                            | (immediate << 5)
                            | 31
                            | if shifted { 1 << 13 } else { 0 };
                        if size == 0 && shifted {
                            assert_eq!(decode(word), Some(Err(())));
                            let operand = decode(fact.word).unwrap().unwrap();
                            assert_eq!(operand.prefix_requirement(word), Err(()));
                        } else {
                            let operand = decode(word).unwrap().unwrap();
                            assert_eq!(
                                operand.prefix_requirement(word),
                                Ok(Some(PrefixRequirement::Vector {
                                    destination: 31,
                                    predicated: None,
                                    other_vector_sources: 0
                                }))
                            );
                        }
                    }
                }
            }
        }
        if fact.minimum_size == 1 {
            assert_eq!(decode(fact.word), Some(Err(())));
            let operand = decode(fact.word | (1 << 22)).unwrap().unwrap();
            assert_eq!(operand.prefix_requirement(fact.word), Err(()));
        }
    }
    for size in 0..4 {
        for rotation in [0, 1 << 10] {
            let word = 0x4501d800 | (size << 22) | rotation | (31 << 5) | 3;
            let operand = decode(word).unwrap().unwrap();
            assert_eq!(
                operand.prefix_requirement(word),
                Ok(Some(PrefixRequirement::Vector {
                    destination: 3,
                    predicated: None,
                    other_vector_sources: 1_u32 << 31
                }))
            );
        }
    }
    for zeroing in [0x440aa000, 0x440ba000] {
        assert_eq!(decode(zeroing), None);
        let operand = decode(0x4408a000).unwrap().unwrap();
        assert_eq!(operand.prefix_requirement(zeroing), Err(()));
    }
}

#[test]
fn malformed_prefix_metadata_is_rejected_by_the_actual_frozen_validator() {
    let word = 0x44188000 | (7 << 10) | (5 << 5) | 3;
    let requirement = decode(word)
        .unwrap()
        .unwrap()
        .prefix_requirement(word)
        .unwrap()
        .unwrap();
    let base = DecodedPrefix {
        destination: 3,
        source: 9,
        predication: Predication::Merging(7),
        element: Some(ElementSize::Byte),
    };
    assert_eq!(
        validate(DecodedPrefix { source: 32, ..base }, requirement),
        Err(PrefixViolation::InvalidPrefixSource(32))
    );
    assert_eq!(
        validate(
            DecodedPrefix {
                destination: 32,
                ..base
            },
            requirement
        ),
        Err(PrefixViolation::InvalidPrefixDestination(32))
    );
    assert_eq!(
        validate(
            DecodedPrefix {
                predication: Predication::Zeroing(8),
                ..base
            },
            requirement
        ),
        Err(PrefixViolation::InvalidPrefixPredicate(8))
    );
    assert_eq!(
        validate(
            DecodedPrefix {
                element: None,
                ..base
            },
            requirement
        ),
        Err(PrefixViolation::MissingPrefixElement)
    );
    assert_eq!(
        validate(
            DecodedPrefix {
                element: Some(ElementSize::Quadword),
                ..base
            },
            requirement
        ),
        Err(PrefixViolation::UnallocatedPrefixElement(
            ElementSize::Quadword
        ))
    );
}
