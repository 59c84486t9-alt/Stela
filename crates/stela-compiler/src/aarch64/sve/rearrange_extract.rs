//! Register extraction, broadcast and insertion for streaming SVE.
//! The shared scalable core owns instruction permission and state storage.
use crate::aarch64::scalable::ElementSize;
use crate::aarch64::{Register, register};

const LAST_MASK: u32 = 0xff3f_e000;
const LASTA_GENERAL: u32 = 0x0520_a000;
const LASTB_GENERAL: u32 = 0x0521_a000;
const LASTA_SCALAR: u32 = 0x0522_8000;
const LASTB_SCALAR: u32 = 0x0523_8000;
const CLASTA_GENERAL: u32 = 0x0530_a000;
const CLASTB_GENERAL: u32 = 0x0531_a000;
const CLASTA_SCALAR: u32 = 0x052a_8000;
const CLASTB_SCALAR: u32 = 0x052b_8000;
const CLASTA_VECTOR: u32 = 0x0528_8000;
const CLASTB_VECTOR: u32 = 0x0529_8000;
const DUP_IMMEDIATE_MASK: u32 = 0xff3f_c000;
const DUP_IMMEDIATE: u32 = 0x2538_c000;
const REGISTER_OPCODE_MASK: u32 = 0xff3f_fc00;
const DUP_GENERAL: u32 = 0x0520_3800;
const INSR_GENERAL: u32 = 0x0524_3800;
const INSR_SCALAR: u32 = 0x0534_3800;
const DUP_INDEX_MASK: u32 = 0xff20_fc00;
const DUP_INDEX: u32 = 0x0520_2000;
const REGISTER_MASK: u32 = 31;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const SOURCE_SHIFT: u32 = 5;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const IMMEDIATE_SHIFT: u32 = 5;
const IMMEDIATE_MASK: u32 = 255;
const IMMEDIATE_SCALE_SHIFT: u32 = 8;
const SHIFT_FLAG: u32 = 1 << 13;
const INDEX_SIZE_SHIFT: u32 = 16;
const INDEX_SIZE_MASK: u32 = 31;
const INDEX_HIGH_SHIFT: u32 = 22;
const INDEX_HIGH_MASK: u32 = 3;
const INDEX_HIGH_SCALE: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    General(Register),
    Scalar(u8),
    Vector(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastPosition {
    LastActive,
    AfterLastActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Last {
        source: u8,
        predicate: u8,
        position: LastPosition,
        conditional: bool,
    },
    DuplicateImmediate(i16),
    DuplicateGeneral(Register),
    DuplicateElement {
        source: u8,
        index: u8,
    },
    InsertGeneral(Register),
    InsertScalar(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub element_size: ElementSize,
    pub destination: Destination,
    pub kind: Kind,
}

fn element_size(word: u32) -> ElementSize {
    match (word >> SIZE_SHIFT) & SIZE_MASK {
        0 => ElementSize::Byte,
        1 => ElementSize::Halfword,
        2 => ElementSize::Word,
        _ => ElementSize::Doubleword,
    }
}

/// None is outside this family; Some(Err(())) is a reserved family encoding.
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let mut element_size = element_size(word);
    let destination_index = (word & REGISTER_MASK) as u8;
    let source_index = ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8;
    let last = match word & LAST_MASK {
        LASTA_GENERAL => Some((
            Destination::General(register(word & REGISTER_MASK, false)),
            false,
            false,
        )),
        LASTB_GENERAL => Some((
            Destination::General(register(word & REGISTER_MASK, false)),
            true,
            false,
        )),
        LASTA_SCALAR => Some((Destination::Scalar(destination_index), false, false)),
        LASTB_SCALAR => Some((Destination::Scalar(destination_index), true, false)),
        CLASTA_GENERAL => Some((
            Destination::General(register(word & REGISTER_MASK, false)),
            false,
            true,
        )),
        CLASTB_GENERAL => Some((
            Destination::General(register(word & REGISTER_MASK, false)),
            true,
            true,
        )),
        CLASTA_SCALAR => Some((Destination::Scalar(destination_index), false, true)),
        CLASTB_SCALAR => Some((Destination::Scalar(destination_index), true, true)),
        CLASTA_VECTOR => Some((Destination::Vector(destination_index), false, true)),
        CLASTB_VECTOR => Some((Destination::Vector(destination_index), true, true)),
        _ => None,
    };
    let (destination, kind) = if let Some((destination, before, conditional)) = last {
        (
            destination,
            Kind::Last {
                source: source_index,
                predicate: ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8,
                position: if before {
                    LastPosition::LastActive
                } else {
                    LastPosition::AfterLastActive
                },
                conditional,
            },
        )
    } else if word & DUP_IMMEDIATE_MASK == DUP_IMMEDIATE {
        let shifted = word & SHIFT_FLAG != 0;
        if element_size == ElementSize::Byte && shifted {
            return Some(Err(()));
        }
        let immediate = ((word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK) as u8 as i8 as i16;
        (
            Destination::Vector(destination_index),
            Kind::DuplicateImmediate(if shifted {
                immediate << IMMEDIATE_SCALE_SHIFT
            } else {
                immediate
            }),
        )
    } else if word & REGISTER_OPCODE_MASK == DUP_GENERAL {
        (
            Destination::Vector(destination_index),
            Kind::DuplicateGeneral(register(source_index.into(), true)),
        )
    } else if word & DUP_INDEX_MASK == DUP_INDEX {
        let size = (word >> INDEX_SIZE_SHIFT) & INDEX_SIZE_MASK;
        if size == 0 {
            return Some(Err(()));
        }
        let lowest = size.trailing_zeros();
        element_size = ElementSize::from_bytes(1 << lowest)?;
        let combined = (((word >> INDEX_HIGH_SHIFT) & INDEX_HIGH_MASK) << INDEX_HIGH_SCALE) | size;
        (
            Destination::Vector(destination_index),
            Kind::DuplicateElement {
                source: source_index,
                index: (combined >> (lowest + 1)) as u8,
            },
        )
    } else if word & REGISTER_OPCODE_MASK == INSR_GENERAL {
        (
            Destination::Vector(destination_index),
            Kind::InsertGeneral(register(source_index.into(), false)),
        )
    } else if word & REGISTER_OPCODE_MASK == INSR_SCALAR {
        (
            Destination::Vector(destination_index),
            Kind::InsertScalar(source_index),
        )
    } else {
        return None;
    };
    Some(Ok(Operand {
        element_size,
        destination,
        kind,
    }))
}

impl Operand {
    /// Canonical-word MOVPRFX requirements for the four documented followers.
    /// Scalar V sources share Z storage; general-register sources do not.
    #[allow(clippy::result_unit_err)]
    pub fn prefix_requirement(
        self,
        original_word: u32,
    ) -> Result<Option<crate::aarch64::sve::prefix::PrefixRequirement>, ()> {
        use crate::aarch64::sve::prefix::PrefixRequirement;

        if decode(original_word) != Some(Ok(self)) {
            return Err(());
        }
        let Destination::Vector(destination) = self.destination else {
            return Ok(None);
        };
        let sources = match self.kind {
            Kind::Last { source, .. }
                if matches!(original_word & LAST_MASK, CLASTA_VECTOR | CLASTB_VECTOR) =>
            {
                Some(1_u32 << source)
            }
            Kind::InsertGeneral(_) if original_word & REGISTER_OPCODE_MASK == INSR_GENERAL => {
                Some(0)
            }
            Kind::InsertScalar(source) if original_word & REGISTER_OPCODE_MASK == INSR_SCALAR => {
                Some(1_u32 << source)
            }
            _ => None,
        };
        Ok(
            sources.map(|other_vector_sources| PrefixRequirement::Vector {
                destination,
                predicated: None,
                other_vector_sources,
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

#[cfg(test)]
mod prefix_tests {
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
}
