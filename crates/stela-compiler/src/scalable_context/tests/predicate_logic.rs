//! Predicate logic dispatch, feature limits and source maps.
use super::*;
use crate::aarch64::sve::predicate_logic;
use alloc::vec::Vec;

const RESERVED_PSEL_SIZE: u32 = 0x2520_4000;
const WORDS: [u32; 31] = [
    0x25024c20, // and_p_p_pp_z
    0x25424c20, // ands_p_p_pp_z
    0x25024c30, // bic_p_p_pp_z
    0x25424c30, // bics_p_p_pp_z
    0x25024e20, // eor_p_p_pp_z
    0x25424e20, // eors_p_p_pp_z
    0x25824e30, // nand_p_p_pp_z
    0x25c24e30, // nands_p_p_pp_z
    0x25824e20, // nor_p_p_pp_z
    0x25c24e20, // nors_p_p_pp_z
    0x25824c30, // orn_p_p_pp_z
    0x25c24c30, // orns_p_p_pp_z
    0x25824c20, // orr_p_p_pp_z
    0x25c24c20, // orrs_p_p_pp_z
    0x25207010, // pext_pn_rr_
    0x25207410, // pext_pp_rr_
    0x052a3800, // pmov_p_zi_b
    0x05a83800, // pmov_p_zi_d
    0x052c3800, // pmov_p_zi_h
    0x05683800, // pmov_p_zi_s
    0x25244440, // psel_p_ppi_
    0x05314020, // punpkhi_p_p_
    0x05304020, // punpklo_p_p_
    0x05344020, // rev_p_p_
    0x25024e30, // sel_p_p_pp_
    0x05225020, // trn1_p_pp_
    0x05225420, // trn2_p_pp_
    0x05224820, // uzp1_p_pp_
    0x05224c20, // uzp2_p_pp_
    0x05224020, // zip1_p_pp_
    0x05224420, // zip2_p_pp_
];

fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn profile(bytes: usize, svcr: u64, features: ScalableFeatures) -> ScalableProfile {
    ScalableProfile::new_with_features(
        VectorLength::from_bytes(bytes).unwrap(),
        ScalableMode::from_svcr(svcr).unwrap(),
        features,
        ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
    )
    .unwrap()
}

#[test]
fn predicate_logic_dispatch_preserves_exact_body_and_source_maps() {
    let features = ScalableFeatures::of(ScalableFeature::Sme)
        .with(ScalableFeature::Sme2)
        .with(ScalableFeature::Sme2p1);
    for word in WORDS {
        let operand = predicate_logic::decode(word).unwrap().unwrap();
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::PredicateLogic(operand)))
        );
        for bytes in [16, 32, 64, 128, 256] {
            for target in [TargetCpu::Baseline, TargetCpu::Sse42] {
                let native = crate::testing::context_leaf(
                    &source(&[word, RET_X30]),
                    GuestAddress(0x1000),
                    profile(bytes, 3, features),
                    target,
                )
                .unwrap();
                let mut expected = Code::new();
                x86_64::sve::predicate_logic::emit(
                    &mut expected,
                    &operand,
                    VectorLength::from_bytes(bytes).unwrap(),
                    target,
                );

                assert_single_body(&native, GuestAddress(0x1000), &expected);
            }
        }
    }
}

#[test]
fn predicate_logic_requires_streaming_and_declared_counter_or_move_features() {
    let sme = ScalableFeatures::of(ScalableFeature::Sme);
    let sme2 = sme.with(ScalableFeature::Sme2);
    let all = sme2.with(ScalableFeature::Sme2p1);
    let mut counter_forms = 0;
    let mut move_forms = 0;
    for word in WORDS {
        let operand = predicate_logic::decode(word).unwrap().unwrap();
        let counter = matches!(operand.kind, predicate_logic::Kind::ExtractCounter { .. });
        let vector_move = matches!(operand.kind, predicate_logic::Kind::MoveVector { .. });
        counter_forms += usize::from(counter);
        move_forms += usize::from(vector_move);
        for svcr in [0, 2] {
            assert!(
                crate::testing::context_leaf(
                    &source(&[word, RET_X30]),
                    GuestAddress(0),
                    profile(16, svcr, all),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .to_string()
                .contains("streaming mode required")
            );
        }
        for (features, permitted, missing) in [
            (
                sme,
                !counter && !vector_move,
                if vector_move {
                    "FEAT_SME2p1"
                } else {
                    "FEAT_SME2"
                },
            ),
            (sme2, !vector_move, "FEAT_SME2p1"),
            (all, true, ""),
        ] {
            let result = crate::testing::context_leaf(
                &source(&[word, RET_X30]),
                GuestAddress(0),
                profile(16, 3, features),
                TargetCpu::Baseline,
            );
            if permitted {
                assert!(result.is_ok());
            } else {
                assert!(result.unwrap_err().to_string().contains(missing));
            }
        }
        let v1 = ScalableProfile::new(
            VectorLength::from_bytes(16).unwrap(),
            ScalableMode::from_svcr(3).unwrap(),
        );
        let result = crate::testing::context_leaf(
            &source(&[word, RET_X30]),
            GuestAddress(0),
            v1,
            TargetCpu::Baseline,
        );
        if vector_move {
            assert!(result.unwrap_err().to_string().contains("FEAT_SME2p1"));
        } else {
            assert!(result.is_ok());
        }
        assert!(crate::testing::leaf(&source(&[word, RET_X30]), GuestAddress(0)).is_err());
    }
    assert_eq!(counter_forms, 2);
    assert_eq!(move_forms, 4);
    assert!(
        crate::testing::context_leaf(
            &source(&[RESERVED_PSEL_SIZE, RET_X30]),
            GuestAddress(0),
            profile(16, 3, all),
            TargetCpu::Baseline
        )
        .unwrap_err()
        .to_string()
        .contains("reserved streaming predicate logic")
    );
}
