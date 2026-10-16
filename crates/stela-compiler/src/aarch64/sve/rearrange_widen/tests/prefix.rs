use super::*;
use crate::aarch64::sve::prefix::{self, DecodedPrefix, PrefixRequirement, PrefixViolation};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Policy {
    Unknown,
    Unpredicated,
    Predicated,
}

// Independent canonical policy table from the pinned June facts. Minimum
// sizes are encoding fields; the decoder remains the only operand decoder.
const CASES: [(u32, u32, Policy); 25] = [
    (SUNPKLO, 1, Policy::Unknown),
    (SUNPKHI, 1, Policy::Unknown),
    (UUNPKLO, 1, Policy::Unknown),
    (UUNPKHI, 1, Policy::Unknown),
    (SXTB, 1, Policy::Predicated),
    (UXTB, 1, Policy::Predicated),
    (SXTH, 2, Policy::Predicated),
    (UXTH, 2, Policy::Predicated),
    (SXTW, 3, Policy::Predicated),
    (UXTW, 3, Policy::Predicated),
    (SADALP, 1, Policy::Predicated),
    (UADALP, 1, Policy::Predicated),
    (ADDP, 0, Policy::Unpredicated),
    (SMAXP, 0, Policy::Unpredicated),
    (UMAXP, 0, Policy::Unpredicated),
    (SMINP, 0, Policy::Unpredicated),
    (UMINP, 0, Policy::Unpredicated),
    (ADDHNB, 1, Policy::Unknown),
    (ADDHNT, 1, Policy::Unknown),
    (RADDHNB, 1, Policy::Unknown),
    (RADDHNT, 1, Policy::Unknown),
    (SUBHNB, 1, Policy::Unknown),
    (SUBHNT, 1, Policy::Unknown),
    (RSUBHNB, 1, Policy::Unknown),
    (RSUBHNT, 1, Policy::Unknown),
];

fn word(encoding: u32, size: u32, predicate: u32, destination: u32, source: u32) -> u32 {
    let template = decode(encoding | size << SIZE_SHIFT).unwrap().unwrap();
    encoding
        | size << SIZE_SHIFT
        | destination
        | source << SOURCE_SHIFT
        | if matches!(template.kind, Kind::NarrowHigh { .. }) {
            (REGISTER_MASK - source) << RIGHT_SHIFT
        } else {
            0
        }
        | if matches!(template.predication, Predication::Merging(_)) {
            predicate << PREDICATE_SHIFT
        } else {
            0
        }
}

fn prefix(
    operand: Operand,
    predication: Predication,
    element: Option<ElementSize>,
) -> DecodedPrefix {
    DecodedPrefix {
        destination: operand.destination,
        // The prefix's own source may alias its destination.
        source: operand.destination,
        predication,
        element,
    }
}

#[test]
fn exact_twenty_five_form_policies_cover_sizes_predicates_and_storage_aliases() {
    for (encoding, first_size, policy) in CASES {
        for size in first_size..=SIZE_MASK {
            let last_predicate = if policy == Policy::Unknown {
                0
            } else {
                PREDICATE_MASK
            };
            for predicate in 0..=last_predicate {
                for destination in [0, REGISTER_MASK] {
                    for source in [0, REGISTER_MASK] {
                        let original = word(encoding, size, predicate, destination, source);
                        let operand = decode(original).unwrap().unwrap();
                        let result = operand.prefix_requirement(original).unwrap();
                        if policy == Policy::Unknown {
                            assert_eq!(result, None);
                            continue;
                        }
                        let Some(PrefixRequirement::Vector {
                            destination: actual_destination,
                            predicated,
                            other_vector_sources,
                        }) = result
                        else {
                            panic!("documented follower lost its vector requirement");
                        };
                        assert_eq!(actual_destination, destination as u8);
                        assert_eq!(other_vector_sources, 1_u32 << source);
                        if policy == Policy::Unpredicated {
                            assert_eq!(predicated, None);
                        } else {
                            let required = predicated.unwrap();
                            assert_eq!(required.predicate, predicate as u8);
                            assert_eq!(required.element, operand.element_size);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn documented_pairs_enforce_pg_wide_size_and_explicit_source_alias_only() {
    for (encoding, first_size, policy) in CASES {
        if policy == Policy::Unknown {
            continue;
        }
        for size in first_size..=SIZE_MASK {
            for predicate in 0..=PREDICATE_MASK {
                for destination in [0, REGISTER_MASK] {
                    let source = destination ^ REGISTER_MASK;
                    let original = word(encoding, size, predicate, destination, source);
                    let operand = decode(original).unwrap().unwrap();
                    let requirement = operand.prefix_requirement(original).unwrap().unwrap();
                    let unpredicated = prefix(operand, Predication::Unpredicated, None);
                    // The implicit old D is excluded; the prefix source's
                    // own D alias therefore remains legal.
                    assert_eq!(prefix::validate(unpredicated, requirement), Ok(()));
                    assert_eq!(
                        prefix::validate(
                            DecodedPrefix {
                                destination: operand.destination ^ 1,
                                ..unpredicated
                            },
                            requirement
                        ),
                        Err(PrefixViolation::DestinationMismatch)
                    );
                    for mode in [
                        Predication::Merging(predicate as u8),
                        Predication::Zeroing(predicate as u8),
                    ] {
                        let predicated = prefix(operand, mode, Some(operand.element_size));
                        if policy == Policy::Unpredicated {
                            assert_eq!(
                                prefix::validate(predicated, requirement),
                                Err(PrefixViolation::PredicatedPrefixForbidden)
                            );
                        } else {
                            assert_eq!(prefix::validate(predicated, requirement), Ok(()));
                            let wrong_pg = match mode {
                                Predication::Merging(pg) => Predication::Merging(pg ^ 1),
                                Predication::Zeroing(pg) => Predication::Zeroing(pg ^ 1),
                                Predication::Unpredicated => unreachable!(),
                            };
                            assert_eq!(
                                prefix::validate(
                                    DecodedPrefix {
                                        predication: wrong_pg,
                                        ..predicated
                                    },
                                    requirement
                                ),
                                Err(PrefixViolation::PredicateMismatch)
                            );
                            // All eight predicated-compatible forms have a
                            // wide result. Byte is always the wrong size.
                            assert_eq!(
                                prefix::validate(
                                    DecodedPrefix {
                                        element: Some(ElementSize::Byte),
                                        ..predicated
                                    },
                                    requirement
                                ),
                                Err(PrefixViolation::ElementMismatch)
                            );
                            if let Kind::Extend { input_size, .. } = operand.kind {
                                assert_eq!(
                                    prefix::validate(
                                        DecodedPrefix {
                                            element: Some(input_size),
                                            ..predicated
                                        },
                                        requirement
                                    ),
                                    Err(PrefixViolation::ElementMismatch)
                                );
                            }
                        }
                    }
                    let alias_word = word(encoding, size, predicate, destination, destination);
                    let alias_operand = decode(alias_word).unwrap().unwrap();
                    let alias_requirement = alias_operand
                        .prefix_requirement(alias_word)
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        prefix::validate(
                            prefix(alias_operand, Predication::Unpredicated, None),
                            alias_requirement
                        ),
                        Err(PrefixViolation::OtherSourceAlias)
                    );
                }
            }
        }
    }
}

fn changed_source(kind: Kind, source: u8) -> Kind {
    match kind {
        Kind::Unpack {
            signedness, half, ..
        } => Kind::Unpack {
            source,
            signedness,
            half,
        },
        Kind::Extend {
            input_size,
            signedness,
            ..
        } => Kind::Extend {
            source,
            input_size,
            signedness,
        },
        Kind::PairAccumulate { signedness, .. } => Kind::PairAccumulate { source, signedness },
        Kind::Pair { operation, .. } => Kind::Pair {
            right: source,
            operation,
        },
        Kind::NarrowHigh {
            right,
            arithmetic,
            round,
            half,
            ..
        } => Kind::NarrowHigh {
            left: source,
            right,
            arithmetic,
            round,
            half,
        },
    }
}

#[test]
fn typed_mismatches_invalid_registers_unknown_and_reserved_words_decline() {
    for (encoding, first_size, _) in CASES {
        let original = word(encoding, first_size, 3, 3, 5);
        let operand = decode(original).unwrap().unwrap();
        let wrong_size = if operand.element_size == ElementSize::Halfword {
            ElementSize::Doubleword
        } else {
            ElementSize::Halfword
        };
        let wrong_predication = match operand.predication {
            Predication::Unpredicated => Predication::Merging(0),
            Predication::Merging(pg) => Predication::Zeroing(pg),
            Predication::Zeroing(_) => unreachable!(),
        };
        for changed in [
            Operand {
                destination: operand.destination ^ 1,
                ..operand
            },
            Operand {
                destination: 32,
                ..operand
            },
            Operand {
                element_size: wrong_size,
                ..operand
            },
            Operand {
                predication: wrong_predication,
                ..operand
            },
            Operand {
                predication: Predication::Merging(8),
                ..operand
            },
            Operand {
                kind: changed_source(operand.kind, 4),
                ..operand
            },
            Operand {
                kind: changed_source(operand.kind, 32),
                ..operand
            },
            Operand {
                kind: Kind::Pair {
                    right: 0,
                    operation: PairOperation::Add,
                },
                ..operand
            },
        ] {
            assert_eq!(changed.prefix_requirement(original), Err(()));
        }
        if let Kind::NarrowHigh {
            left,
            arithmetic,
            round,
            half,
            ..
        } = operand.kind
        {
            let changed = Operand {
                kind: Kind::NarrowHigh {
                    left,
                    right: 32,
                    arithmetic,
                    round,
                    half,
                },
                ..operand
            };
            assert_eq!(changed.prefix_requirement(original), Err(()));
        }
        for invalid_original in [0, u32::MAX, original ^ 1] {
            assert_eq!(operand.prefix_requirement(invalid_original), Err(()));
        }
        for size in 0..first_size {
            let reserved = encoding | size << SIZE_SHIFT;
            assert_eq!(decode(reserved), Some(Err(())));
            assert_eq!(operand.prefix_requirement(reserved), Err(()));
        }
    }
}
