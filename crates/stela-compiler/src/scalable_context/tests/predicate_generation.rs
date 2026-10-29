//! Predicate generation dispatch, feature limits and source maps.
use super::*;
use crate::aarch64::sve::predicate_generation;
use alloc::vec::Vec;

const RET_X30: u32 = 0xd65f_03c0;
const WORDS: [u32; 45] = [
    0x25104000, // brka_p_p_p_
    0x25504000, // brkas_p_p_p_z
    0x25904000, // brkb_p_p_p_
    0x25d04000, // brkbs_p_p_p_z
    0x25184000, // brkn_p_p_pp_
    0x25584000, // brkns_p_p_pp_
    0x2500c000, // brkpa_p_p_pp_
    0x2540c000, // brkpas_p_p_pp_
    0x2500c010, // brkpb_p_p_pp_
    0x2540c010, // brkpbs_p_p_pp_
    0x25a02000, // ctermeq_rr_
    0x25a02010, // ctermne_rr_
    0x2518e400, // pfalse_p_
    0x2558c000, // pfirst_p_p_p_
    0x2519c400, // pnext_p_p_p_
    0x2550c000, // ptest__p_p_
    0x2518e000, // ptrue_p_s_
    0x25207810, // ptrue_pn_i_
    0x2519e000, // ptrues_p_s_
    0x25200000, // whilege_p_p_rr_
    0x25204010, // whilege_pn_rr_
    0x25205010, // whilege_pp_rr_
    0x25200010, // whilegt_p_p_rr_
    0x25204018, // whilegt_pn_rr_
    0x25205011, // whilegt_pp_rr_
    0x25200810, // whilehi_p_p_rr_
    0x25204818, // whilehi_pn_rr_
    0x25205811, // whilehi_pp_rr_
    0x25200800, // whilehs_p_p_rr_
    0x25204810, // whilehs_pn_rr_
    0x25205810, // whilehs_pp_rr_
    0x25200410, // whilele_p_p_rr_
    0x25204418, // whilele_pn_rr_
    0x25205411, // whilele_pp_rr_
    0x25200c00, // whilelo_p_p_rr_
    0x25204c10, // whilelo_pn_rr_
    0x25205c10, // whilelo_pp_rr_
    0x25200c10, // whilels_p_p_rr_
    0x25204c18, // whilels_pn_rr_
    0x25205c11, // whilels_pp_rr_
    0x25200400, // whilelt_p_p_rr_
    0x25204410, // whilelt_pn_rr_
    0x25205410, // whilelt_pp_rr_
    0x25203010, // whilerw_p_rr_
    0x25203000, // whilewr_p_rr_
];
fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}
fn profile(bytes: usize, svcr: u64, sme2: bool) -> ScalableProfile {
    let length = VectorLength::from_bytes(bytes).unwrap();
    let mut features = ScalableFeatures::of(ScalableFeature::Sme);
    if sme2 {
        features = features.with(ScalableFeature::Sme2);
    }
    ScalableProfile::new_with_features(
        length,
        ScalableMode::from_svcr(svcr).unwrap(),
        features,
        ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
    )
    .unwrap()
}
#[test]
fn generation_production_dispatch_preserves_exact_body_source_maps() {
    for word in WORDS {
        let operand = predicate_generation::decode(word).unwrap().unwrap();
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::PredicateGeneration(
                operand
            )))
        );
        for bytes in [16, 32, 64, 128, 256] {
            for svcr in [1, 3] {
                for target in [TargetCpu::Baseline, TargetCpu::Bmi1] {
                    let native = crate::testing::context_leaf(
                        &source(&[word, RET_X30]),
                        GuestAddress(0x1000),
                        profile(bytes, svcr, true),
                        target,
                    )
                    .unwrap();
                    let mut expected = Code::new();
                    x86_64::sve::predicate_generation::emit(
                        &mut expected,
                        &operand,
                        VectorLength::from_bytes(bytes).unwrap(),
                        target,
                    );
                    assert_eq!(
                        &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                        context_wrapper()
                    );
                    assert_eq!(
                        native.source_map,
                        [
                            (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                            (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + expected.len())
                        ]
                    );
                    assert_eq!(
                        &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                        expected
                    );
                    assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
                }
            }
        }
    }
}
#[test]
fn generation_preflight_requires_streaming_and_sme2_only_for_counter_or_pair() {
    let mut sme2_forms = 0;
    for word in WORDS {
        let operand = predicate_generation::decode(word).unwrap().unwrap();
        sme2_forms += usize::from(operand.requires_sme2());
        for bytes in [16, 32, 64, 128, 256] {
            for svcr in [0, 2] {
                assert!(
                    crate::testing::context_leaf(
                        &source(&[word, RET_X30]),
                        GuestAddress(0),
                        profile(bytes, svcr, true),
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .to_string()
                    .contains("streaming mode required")
                );
            }
            for svcr in [1, 3] {
                let result = crate::testing::context_leaf(
                    &source(&[word, RET_X30]),
                    GuestAddress(0),
                    profile(bytes, svcr, false),
                    TargetCpu::Baseline,
                );
                if operand.requires_sme2() {
                    assert!(result.unwrap_err().to_string().contains("FEAT_SME2"));
                } else {
                    assert!(result.is_ok());
                }
            }
        }
        assert!(crate::testing::leaf(&source(&[word, RET_X30]), GuestAddress(0)).is_err());
    }
    assert_eq!(sme2_forms, 17);
}
