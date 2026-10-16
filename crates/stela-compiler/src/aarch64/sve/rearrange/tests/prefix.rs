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
    let word =
        EXT_Z_ZI_DES_CLASS | (u32::from(SECOND_SOURCE) << SOURCE_SHIFT) | u32::from(DESTINATION);
    let decoded = operand(word);
    for other in [
        word ^ 1,
        0,
        DUPQ_Z_ZI_CLASS,
        DUPM_Z_I_CLASS | (LOGICAL_IMMEDIATE_MASK << SOURCE_SHIFT),
        REVD_Z_P_Z_M_CLASS | (1 << SIZE_SHIFT),
    ] {
        assert_eq!(decoded.prefix_requirement(other), Err(()));
    }
    let forged = Operand::Extract {
        destination: DESTINATION,
        source: DESTINATION,
        second: Z_REGISTER_COUNT,
        byte_offset: 0,
        segment: false,
    };
    assert_eq!(forged.prefix_requirement(word), Err(()));
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
