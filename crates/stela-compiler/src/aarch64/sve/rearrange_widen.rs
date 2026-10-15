//! Streaming-SVE extension, pair arithmetic and narrowing-high operand decoding.
//! Feature/mode and MOVPRFX checks belong to the shared scalable boundary.
use crate::aarch64::scalable::{ElementSize, Predication};

const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const SOURCE_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const PREDICATE_SHIFT: u32 = 10;
const REGISTER_MASK: u32 = 31;
const PREDICATE_MASK: u32 = 7;
const UNPACK_MASK: u32 = 0xff3f_fc00;
const PREDICATED_MASK: u32 = 0xff3f_e000;
const NARROW_HIGH_MASK: u32 = 0xff20_fc00;

const SUNPKLO: u32 = 0x0530_3800;
const SUNPKHI: u32 = 0x0531_3800;
const UUNPKLO: u32 = 0x0532_3800;
const UUNPKHI: u32 = 0x0533_3800;
const SXTB: u32 = 0x0410_a000;
const UXTB: u32 = 0x0411_a000;
const SXTH: u32 = 0x0412_a000;
const UXTH: u32 = 0x0413_a000;
const SXTW: u32 = 0x0414_a000;
const UXTW: u32 = 0x0415_a000;
const SADALP: u32 = 0x4404_a000;
const UADALP: u32 = 0x4405_a000;
const ADDP: u32 = 0x4411_a000;
const SMAXP: u32 = 0x4414_a000;
const UMAXP: u32 = 0x4415_a000;
const SMINP: u32 = 0x4416_a000;
const UMINP: u32 = 0x4417_a000;
const ADDHNB: u32 = 0x4520_6000;
const ADDHNT: u32 = 0x4520_6400;
const RADDHNB: u32 = 0x4520_6800;
const RADDHNT: u32 = 0x4520_6c00;
const SUBHNB: u32 = 0x4520_7000;
const SUBHNT: u32 = 0x4520_7400;
const RSUBHNB: u32 = 0x4520_7800;
const RSUBHNT: u32 = 0x4520_7c00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signedness {
    Signed,
    Unsigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Half {
    Bottom,
    Top,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arithmetic {
    Add,
    Subtract,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairOperation {
    Add,
    Minimum(Signedness),
    Maximum(Signedness),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Unpack {
        source: u8,
        signedness: Signedness,
        half: Half,
    },
    Extend {
        source: u8,
        input_size: ElementSize,
        signedness: Signedness,
    },
    NarrowHigh {
        left: u8,
        right: u8,
        arithmetic: Arithmetic,
        round: bool,
        half: Half,
    },
    Pair {
        right: u8,
        operation: PairOperation,
    },
    PairAccumulate {
        source: u8,
        signedness: Signedness,
    },
}

/// NarrowHigh uses the wide source size. Other kinds use the result size.
/// Pair and PairAccumulate read the old destination before any destination write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: u8,
    pub element_size: ElementSize,
    pub predication: Predication,
    pub kind: Kind,
}

impl Operand {
    /// Supply only the exact June-reviewed canonical follower requirements.
    #[allow(clippy::result_unit_err)]
    pub fn prefix_requirement(
        self,
        original_word: u32,
    ) -> Result<Option<super::prefix::PrefixRequirement>, ()> {
        use super::prefix::{PredicatedPrefixRequirement, PrefixRequirement};

        if decode(original_word) != Some(Ok(self)) {
            return Err(());
        }
        let (source, predicated) = match (original_word & PREDICATED_MASK, self.kind) {
            (ADDP | SMAXP | UMAXP | SMINP | UMINP, Kind::Pair { right, .. }) => (right, None),
            (
                SXTB | UXTB | SXTH | UXTH | SXTW | UXTW | SADALP | UADALP,
                Kind::Extend { source, .. } | Kind::PairAccumulate { source, .. },
            ) => {
                let Predication::Merging(predicate) = self.predication else {
                    return Err(());
                };
                (
                    source,
                    Some(PredicatedPrefixRequirement {
                        predicate,
                        // The documented effective size is the wide result,
                        // not the fixed extension input or pair input size.
                        element: self.element_size,
                    }),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(PrefixRequirement::Vector {
            destination: self.destination,
            predicated,
            // Include the explicit source, excluding the implicit old D.
            // Exact decoder/self equality checked its register range first.
            other_vector_sources: 1_u32 << source,
        }))
    }
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    use Arithmetic::{Add, Subtract};
    use Half::{Bottom, Top};
    use Signedness::{Signed, Unsigned};
    let source = ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8;
    let right = ((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8;
    let kind = match word & UNPACK_MASK {
        SUNPKLO => Some(Kind::Unpack {
            source,
            signedness: Signed,
            half: Bottom,
        }),
        SUNPKHI => Some(Kind::Unpack {
            source,
            signedness: Signed,
            half: Top,
        }),
        UUNPKLO => Some(Kind::Unpack {
            source,
            signedness: Unsigned,
            half: Bottom,
        }),
        UUNPKHI => Some(Kind::Unpack {
            source,
            signedness: Unsigned,
            half: Top,
        }),
        _ => None,
    }
    .or(match word & PREDICATED_MASK {
        SXTB => Some(Kind::Extend {
            source,
            input_size: ElementSize::Byte,
            signedness: Signed,
        }),
        UXTB => Some(Kind::Extend {
            source,
            input_size: ElementSize::Byte,
            signedness: Unsigned,
        }),
        SXTH => Some(Kind::Extend {
            source,
            input_size: ElementSize::Halfword,
            signedness: Signed,
        }),
        UXTH => Some(Kind::Extend {
            source,
            input_size: ElementSize::Halfword,
            signedness: Unsigned,
        }),
        SXTW => Some(Kind::Extend {
            source,
            input_size: ElementSize::Word,
            signedness: Signed,
        }),
        UXTW => Some(Kind::Extend {
            source,
            input_size: ElementSize::Word,
            signedness: Unsigned,
        }),
        SADALP => Some(Kind::PairAccumulate {
            source,
            signedness: Signed,
        }),
        UADALP => Some(Kind::PairAccumulate {
            source,
            signedness: Unsigned,
        }),
        ADDP => Some(Kind::Pair {
            right: source,
            operation: PairOperation::Add,
        }),
        SMAXP => Some(Kind::Pair {
            right: source,
            operation: PairOperation::Maximum(Signed),
        }),
        UMAXP => Some(Kind::Pair {
            right: source,
            operation: PairOperation::Maximum(Unsigned),
        }),
        SMINP => Some(Kind::Pair {
            right: source,
            operation: PairOperation::Minimum(Signed),
        }),
        UMINP => Some(Kind::Pair {
            right: source,
            operation: PairOperation::Minimum(Unsigned),
        }),
        _ => None,
    })
    .or(match word & NARROW_HIGH_MASK {
        ADDHNB => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Add,
            round: false,
            half: Bottom,
        }),
        ADDHNT => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Add,
            round: false,
            half: Top,
        }),
        RADDHNB => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Add,
            round: true,
            half: Bottom,
        }),
        RADDHNT => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Add,
            round: true,
            half: Top,
        }),
        SUBHNB => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Subtract,
            round: false,
            half: Bottom,
        }),
        SUBHNT => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Subtract,
            round: false,
            half: Top,
        }),
        RSUBHNB => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Subtract,
            round: true,
            half: Bottom,
        }),
        RSUBHNT => Some(Kind::NarrowHigh {
            left: source,
            right,
            arithmetic: Subtract,
            round: true,
            half: Top,
        }),
        _ => None,
    })?;
    let element_size = ElementSize::from_bytes(1 << ((word >> SIZE_SHIFT) & SIZE_MASK))
        .expect("a two-bit element size is always a valid integer size");
    let minimum_bits = match kind {
        Kind::Pair { .. } => ElementSize::Byte.bits(),
        Kind::Extend { input_size, .. } => input_size.bits() * 2,
        _ => ElementSize::Halfword.bits(),
    };
    if element_size.bits() < minimum_bits {
        return Some(Err(()));
    }
    let predication = match kind {
        Kind::Extend { .. } | Kind::Pair { .. } | Kind::PairAccumulate { .. } => {
            Predication::Merging(((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8)
        }
        _ => Predication::Unpredicated,
    };
    Some(Ok(Operand {
        destination: (word & REGISTER_MASK) as u8,
        element_size,
        predication,
        kind,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST_SIZE: u32 = 1;
    const WORD_SIZE: u32 = 2;
    const DOUBLEWORD_SIZE: u32 = 3;
    const ENCODINGS: [(u32, u32); 25] = [
        (SUNPKLO, FIRST_SIZE),
        (SUNPKHI, FIRST_SIZE),
        (UUNPKLO, FIRST_SIZE),
        (UUNPKHI, FIRST_SIZE),
        (SXTB, FIRST_SIZE),
        (UXTB, FIRST_SIZE),
        (SXTH, WORD_SIZE),
        (UXTH, WORD_SIZE),
        (SXTW, DOUBLEWORD_SIZE),
        (UXTW, DOUBLEWORD_SIZE),
        (SADALP, FIRST_SIZE),
        (UADALP, FIRST_SIZE),
        (ADDP, 0),
        (SMAXP, 0),
        (UMAXP, 0),
        (SMINP, 0),
        (UMINP, 0),
        (ADDHNB, FIRST_SIZE),
        (ADDHNT, FIRST_SIZE),
        (RADDHNB, FIRST_SIZE),
        (RADDHNT, FIRST_SIZE),
        (SUBHNB, FIRST_SIZE),
        (SUBHNT, FIRST_SIZE),
        (RSUBHNB, FIRST_SIZE),
        (RSUBHNT, FIRST_SIZE),
    ];

    #[test]
    fn size_allocations_are_complete_and_reserved_sizes_decline() {
        for (encoding, minimum_size) in ENCODINGS {
            for size in 0..=SIZE_MASK {
                let result = decode(encoding | size << SIZE_SHIFT).unwrap();
                assert_eq!(result.is_ok(), size >= minimum_size);
                if let Ok(operand) = result {
                    assert_eq!(operand.element_size.bytes(), 1 << size);
                }
            }
        }
    }

    #[test]
    fn all_vector_registers_and_governing_predicates_decode() {
        for (encoding, minimum_size) in ENCODINGS {
            for destination in 0..=REGISTER_MASK {
                for source in 0..=REGISTER_MASK {
                    for predicate in 0..=PREDICATE_MASK {
                        let template = decode(encoding | minimum_size << SIZE_SHIFT)
                            .unwrap()
                            .unwrap();
                        let narrow = matches!(template.kind, Kind::NarrowHigh { .. });
                        let predicated = matches!(template.predication, Predication::Merging(_));
                        let right = REGISTER_MASK - source;
                        let word = encoding
                            | minimum_size << SIZE_SHIFT
                            | destination
                            | source << SOURCE_SHIFT
                            | if narrow { right << RIGHT_SHIFT } else { 0 }
                            | if predicated {
                                predicate << PREDICATE_SHIFT
                            } else {
                                0
                            };
                        let operand = decode(word).unwrap().unwrap();
                        assert_eq!(operand.destination, destination as u8);
                        assert_eq!(
                            operand.predication,
                            if predicated {
                                Predication::Merging(predicate as u8)
                            } else {
                                Predication::Unpredicated
                            }
                        );
                        match operand.kind {
                            Kind::Unpack { source: actual, .. }
                            | Kind::Extend { source: actual, .. }
                            | Kind::PairAccumulate { source: actual, .. } => {
                                assert_eq!(actual, source as u8);
                            }
                            Kind::Pair { right: actual, .. } => assert_eq!(actual, source as u8),
                            Kind::NarrowHigh {
                                left: actual_left,
                                right: actual_right,
                                ..
                            } => {
                                assert_eq!(actual_left, source as u8);
                                assert_eq!(actual_right, right as u8);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn distinct_families_and_zeroing_extension_forms_are_not_claimed() {
        const ZEROING_EXTENSION_BIT: u32 = 1 << 20;
        assert!(decode(0).is_none());
        for encoding in [SXTB, UXTB, SXTH, UXTH, SXTW, UXTW] {
            assert!(
                decode((encoding & !ZEROING_EXTENSION_BIT) | DOUBLEWORD_SIZE << SIZE_SHIFT)
                    .is_none()
            );
        }
    }
}

#[cfg(test)]
mod prefix_tests {
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
}
