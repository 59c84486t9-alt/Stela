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
