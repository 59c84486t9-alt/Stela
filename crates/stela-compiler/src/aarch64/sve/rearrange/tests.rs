use super::*;

mod prefix {
    use super::*;
    use crate::aarch64::scalable::Predication;
    use crate::aarch64::sve::prefix::{self, DecodedPrefix, PrefixRequirement, PrefixViolation};

    const DESTINATION: u8 = 3;
    const SECOND_SOURCE: u8 = 5;
    const GOVERNING_PREDICATE: u8 = 2;
    const Z_REGISTER_COUNT: u8 = 32;
    const PERMITTED_CLASSES: [u32; 3] = [
        EXT_Z_ZI_DES_CLASS,
        EXTQ_Z_ZI_DES_CLASS,
        SPLICE_Z_P_ZZ_DES_CLASS,
    ];
    const UNAUDITED_CLASSES: [u32; 25] = [
        DUPQ_Z_ZI_CLASS | (1 << SECOND_SHIFT),
        EXT_Z_ZI_CON_CLASS,
        REV_Z_Z_CLASS,
        REVD_Z_P_Z_M_CLASS,
        SPLICE_Z_P_ZZ_CON_CLASS,
        TBL_Z_ZZ_1_CLASS,
        TBL_Z_ZZ_2_CLASS,
        TBLQ_Z_ZZ_CLASS,
        TBX_Z_ZZ_CLASS,
        TBXQ_Z_ZZ_CLASS,
        TRN1_Z_ZZ_CLASS,
        TRN2_Z_ZZ_CLASS,
        UZP1_Z_ZZ_CLASS,
        UZP2_Z_ZZ_CLASS,
        UZPQ1_Z_ZZ_CLASS,
        UZPQ2_Z_ZZ_CLASS,
        ZIP1_Z_ZZ_CLASS,
        ZIP2_Z_ZZ_CLASS,
        ZIPQ1_Z_ZZ_CLASS,
        ZIPQ2_Z_ZZ_CLASS,
        DUPM_Z_I_CLASS,
        INDEX_Z_II_CLASS,
        INDEX_Z_IR_CLASS,
        INDEX_Z_RI_CLASS,
        INDEX_Z_RR_CLASS,
    ];

    fn operand(word: u32) -> Operand {
        decode(word)
            .expect("assigned allocation")
            .expect("valid operands")
    }

    fn prefix(source: u8, predication: Predication) -> DecodedPrefix {
        DecodedPrefix {
            destination: DESTINATION,
            source,
            predication,
            element: Some(ElementSize::Byte),
        }
    }

    #[test]
    fn all_twenty_eight_canonical_policies_are_explicit() {
        for class in PERMITTED_CLASSES {
            let word = class | (u32::from(SECOND_SOURCE) << SOURCE_SHIFT) | u32::from(DESTINATION);
            assert_eq!(
                operand(word).prefix_requirement(word),
                Ok(Some(PrefixRequirement::Vector {
                    destination: DESTINATION,
                    predicated: None,
                    other_vector_sources: 1_u32 << SECOND_SOURCE,
                }))
            );
        }
        for word in UNAUDITED_CLASSES {
            assert_eq!(operand(word).prefix_requirement(word), Ok(None));
        }
    }

    #[test]
    fn every_explicit_second_source_is_preserved_including_destination_aliases() {
        for class in PERMITTED_CLASSES {
            for destination in 0..Z_REGISTER_COUNT {
                for second in 0..Z_REGISTER_COUNT {
                    let word = class | (u32::from(second) << SOURCE_SHIFT) | u32::from(destination);
                    assert_eq!(
                        operand(word).prefix_requirement(word),
                        Ok(Some(PrefixRequirement::Vector {
                            destination,
                            predicated: None,
                            other_vector_sources: 1_u32 << second,
                        }))
                    );
                }
            }
        }
    }

    #[test]
    fn constructive_aliases_do_not_authorize_a_destructive_policy() {
        for (constructive, destructive) in [
            (EXT_Z_ZI_CON_CLASS, EXT_Z_ZI_DES_CLASS),
            (SPLICE_Z_P_ZZ_CON_CLASS, SPLICE_Z_P_ZZ_DES_CLASS),
        ] {
            let first =
                constructive | (u32::from(DESTINATION) << SOURCE_SHIFT) | u32::from(DESTINATION);
            let second =
                destructive | (u32::from(DESTINATION + 1) << SOURCE_SHIFT) | u32::from(DESTINATION);
            assert_eq!(operand(first), operand(second));
            assert_eq!(operand(first).prefix_requirement(first), Ok(None));
            assert!(matches!(
                operand(second).prefix_requirement(second),
                Ok(Some(PrefixRequirement::Vector { .. }))
            ));
        }
    }

    #[test]
    fn mismatched_unallocated_and_reserved_words_are_errors() {
        let word = EXT_Z_ZI_DES_CLASS
            | (u32::from(SECOND_SOURCE) << SOURCE_SHIFT)
            | u32::from(DESTINATION);
        let decoded = operand(word);
        for other in [
            word ^ 1,
            0,
            DUPQ_Z_ZI_CLASS,
            DUPM_Z_I_CLASS | (LOGICAL_IMMEDIATE_MASK << SOURCE_SHIFT),
            REVD_Z_P_Z_M_CLASS | (1 << SIZE_SHIFT),
        ] {
            assert_eq!(decoded.prefix_requirement(other), Err(Unsupported));
        }
        let forged = Operand::Extract {
            destination: DESTINATION,
            source: DESTINATION,
            second: Z_REGISTER_COUNT,
            byte_offset: 0,
            segment: false,
        };
        assert_eq!(forged.prefix_requirement(word), Err(Unsupported));
    }

    #[test]
    fn permitted_followers_accept_only_unpredicated_prefixes() {
        for class in PERMITTED_CLASSES {
            let word = class | (u32::from(SECOND_SOURCE) << SOURCE_SHIFT) | u32::from(DESTINATION);
            let requirement = operand(word).prefix_requirement(word).unwrap().unwrap();
            for source in 0..Z_REGISTER_COUNT {
                assert_eq!(
                    prefix::validate(prefix(source, Predication::Unpredicated), requirement),
                    Ok(())
                );
            }
            for mode in [
                Predication::Merging(GOVERNING_PREDICATE),
                Predication::Zeroing(GOVERNING_PREDICATE),
            ] {
                assert_eq!(
                    prefix::validate(prefix(SECOND_SOURCE, mode), requirement),
                    Err(PrefixViolation::PredicatedPrefixForbidden)
                );
            }
        }
    }

    #[test]
    fn an_explicit_second_destination_alias_is_rejected_by_the_shared_validator() {
        for class in PERMITTED_CLASSES {
            let word = class | (u32::from(DESTINATION) << SOURCE_SHIFT) | u32::from(DESTINATION);
            let requirement = operand(word).prefix_requirement(word).unwrap().unwrap();
            assert_eq!(
                prefix::validate(
                    prefix(SECOND_SOURCE, Predication::Unpredicated),
                    requirement
                ),
                Err(PrefixViolation::OtherSourceAlias)
            );
        }
    }
}
mod prefix_boundary {
    use super::*;
    use crate::aarch64::sve::prefix::PrefixRequirement;

    const DESTINATION: u8 = 3;
    const SECOND_SOURCE: u8 = 5;
    const ELEMENTS: [ElementSize; 4] = [
        ElementSize::Byte,
        ElementSize::Halfword,
        ElementSize::Word,
        ElementSize::Doubleword,
    ];

    fn operand(word: u32) -> Operand {
        decode(word)
            .expect("assigned allocation")
            .expect("valid operands")
    }

    #[test]
    fn unaudited_wrapped_tables_and_segment_aliases_remain_unaudited() {
        for class in [
            TBL_Z_ZZ_2_CLASS,
            TBLQ_Z_ZZ_CLASS,
            TBXQ_Z_ZZ_CLASS,
            UZPQ1_Z_ZZ_CLASS,
            UZPQ2_Z_ZZ_CLASS,
            ZIPQ1_Z_ZZ_CLASS,
            ZIPQ2_Z_ZZ_CLASS,
        ] {
            for destination in [0, REGISTER_MASK] {
                for second in [0, REGISTER_MASK] {
                    for size in 0..=SIZE_MASK {
                        let word = class
                            | (size << SIZE_SHIFT)
                            | (REGISTER_MASK << SOURCE_SHIFT)
                            | (second << SECOND_SHIFT)
                            | destination;
                        let decoded = operand(word);
                        if class == TBL_Z_ZZ_2_CLASS {
                            assert!(matches!(
                                decoded,
                                Operand::Table {
                                    source,
                                    register_count: 2,
                                    indexes,
                                    ..
                                } if u32::from(source) == REGISTER_MASK && u32::from(indexes) == second
                            ));
                        }
                        assert_eq!(decoded.prefix_requirement(word), Ok(None));
                    }
                }
            }
        }
    }

    #[test]
    fn reverse_merging_and_splice_predicate_size_boundaries_keep_their_policy() {
        for governing in 0..=PREDICATE_MASK {
            let reverse = REVD_Z_P_Z_M_CLASS
                | (governing << PREDICATE_SHIFT)
                | (u32::from(DESTINATION) << SOURCE_SHIFT)
                | u32::from(DESTINATION);
            assert!(matches!(
                operand(reverse),
                Operand::ReverseDouble { source, destination, governing: predicate }
                    if source == destination && u32::from(predicate) == governing
            ));
            assert_eq!(operand(reverse).prefix_requirement(reverse), Ok(None));
            for (size, element) in ELEMENTS.into_iter().enumerate() {
                let splice = SPLICE_Z_P_ZZ_DES_CLASS
                    | ((size as u32) << SIZE_SHIFT)
                    | (governing << PREDICATE_SHIFT)
                    | (u32::from(SECOND_SOURCE) << SOURCE_SHIFT)
                    | u32::from(DESTINATION);
                let decoded = operand(splice);
                assert!(matches!(
                    decoded,
                    Operand::Splice { governing: predicate, element_size, .. }
                        if u32::from(predicate) == governing && element_size == element
                ));
                assert_eq!(
                    decoded.prefix_requirement(splice),
                    Ok(Some(PrefixRequirement::Vector {
                        destination: DESTINATION,
                        predicated: None,
                        other_vector_sources: 1_u32 << SECOND_SOURCE,
                    }))
                );
            }
        }
    }
}

#[test]
fn consecutive_operands_wrap_and_destructive_operands_are_explicit() {
    assert_eq!(
        decode(EXT_Z_ZI_CON_CLASS | (31 << SOURCE_SHIFT) | 4),
        Some(Ok(Operand::Extract {
            destination: 4,
            source: 31,
            second: 0,
            byte_offset: 0,
            segment: false,
        }))
    );
    assert_eq!(
        decode(EXT_Z_ZI_DES_CLASS | (31 << SOURCE_SHIFT) | 4),
        Some(Ok(Operand::Extract {
            destination: 4,
            source: 4,
            second: 31,
            byte_offset: 0,
            segment: false,
        }))
    );
}

#[test]
fn index_register_zero_and_signed_immediate_roles_are_explicit() {
    assert_eq!(
        decode(INDEX_Z_RI_CLASS | (16 << SECOND_SHIFT) | (31 << SOURCE_SHIFT)),
        Some(Ok(Operand::Index {
            destination: 0,
            start: IndexOperand::Register(Register::Zero),
            step: IndexOperand::Immediate(-16),
            element_size: ElementSize::Byte,
        }))
    );
}

#[test]
fn segment_duplicate_rejects_zero_size_and_decodes_all_other_values() {
    for encoded in 0..=REGISTER_MASK {
        let decoded = decode(DUPQ_Z_ZI_CLASS | (encoded << SECOND_SHIFT));
        if encoded & SEGMENT_IMMEDIATE_MASK == 0 {
            assert_eq!(decoded, Some(Err(Unsupported)));
        } else {
            let Some(Ok(Operand::DuplicateSegment {
                element_size,
                index,
                ..
            })) = decoded
            else {
                panic!("allocated DUPQ failed");
            };
            assert!(usize::from(index) < 16 / element_size.bytes());
        }
    }
}

#[test]
fn logical_duplicate_uses_the_shared_reserved_mask_boundary() {
    for encoded in 0..=LOGICAL_IMMEDIATE_MASK {
        let expected = logical_mask(
            Width::X64,
            encoded >> LOGICAL_N_SHIFT,
            (encoded >> LOGICAL_ROTATION_SHIFT) & LOGICAL_FIELD_MASK,
            encoded & LOGICAL_FIELD_MASK,
        );
        let decoded = decode(DUPM_Z_I_CLASS | (encoded << SOURCE_SHIFT));
        assert_eq!(
            decoded.map(|result| result.map(|operand| match operand {
                Operand::DuplicateMask { mask, .. } => mask,
                _ => panic!("wrong duplicate allocation"),
            })),
            Some(expected.ok_or(Unsupported))
        );
    }
}

#[test]
fn reverse_double_requires_the_fixed_quadword_allocation() {
    assert_eq!(
        decode(REVD_Z_P_Z_M_CLASS),
        Some(Ok(Operand::ReverseDouble {
            destination: 0,
            source: 0,
            governing: 0,
        }))
    );
    for size in 1..=SIZE_MASK {
        assert_eq!(decode(REVD_Z_P_Z_M_CLASS | (size << SIZE_SHIFT)), None);
    }
    assert_eq!(decode(REVD_Z_P_Z_M_CLASS | (1 << 13)), None);
}
