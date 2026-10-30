//! SVE extraction dispatch, bodies and source maps.
use super::*;
use crate::aarch64::sve::rearrange_extract;
use alloc::vec::Vec;

const RESERVED_BYTE_SHIFT: u32 = 0x2538_e000;
const RESERVED_ZERO_INDEX_SIZE: u32 = 0x0520_2000;
const EXTRACTION_WORDS: [u32; 15] = [
    0x0520bca5, // lasta_r_p_z_
    0x0521bca5, // lastb_r_p_z_
    0x05229ca5, // lasta_v_p_z_
    0x05239ca5, // lastb_v_p_z_
    0x0530bca5, // clasta_r_p_z_
    0x0531bca5, // clastb_r_p_z_
    0x052a9ca5, // clasta_v_p_z_
    0x052b9ca5, // clastb_v_p_z_
    0x05289ca5, // clasta_z_p_zz_
    0x05299ca5, // clastb_z_p_zz_
    0x052038a5, // dup_z_r_
    0x052438a5, // insr_z_r_
    0x053438a5, // insr_z_v_
    0x2538d01f, // dup_z_i_
    0x052120a5, // dup_z_zi_
];

fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn profile(bytes: usize, svcr: u64) -> ScalableProfile {
    ScalableProfile::new(
        VectorLength::from_bytes(bytes).unwrap(),
        ScalableMode::from_svcr(svcr).unwrap(),
    )
}

#[test]
fn extraction_production_dispatch_has_exact_body_maps_and_target_encoding() {
    for word in EXTRACTION_WORDS {
        let operand = rearrange_extract::decode(word).unwrap().unwrap();
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::RearrangeExtract(operand)))
        );
        for bytes in [16, 32, 64, 128, 256] {
            for svcr in [1, 3] {
                for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                    let native = crate::testing::context_leaf(
                        &source(&[NOP, word, RET_X30]),
                        GuestAddress(0x1000),
                        profile(bytes, svcr),
                        target,
                    )
                    .unwrap();
                    let mut expected = Code::new();
                    x86_64::sve::rearrange_extract::emit(
                        &mut expected,
                        operand,
                        VectorLength::from_bytes(bytes).unwrap(),
                        target,
                    );

                    assert_bodies(&native, GuestAddress(0x1000), &[NOP_BODY, &expected]);
                }
            }
        }
    }
}

#[test]
fn extraction_preflight_preserves_mode_reserved_legacy_and_prefix_boundaries() {
    for word in EXTRACTION_WORDS {
        for bytes in [16, 32, 64, 128, 256] {
            for svcr in [0, 2] {
                assert!(
                    crate::testing::context_leaf(
                        &source(&[NOP, word, RET_X30]),
                        GuestAddress(0),
                        profile(bytes, svcr),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err()
                    .to_string()
                    .contains("streaming mode required")
                );
            }
        }
        assert!(crate::testing::leaf(&source(&[word, RET_X30]), GuestAddress(0)).is_err());
        assert!(
            crate::testing::context_leaf(
                &source(&[MOVPRFX_Z0_Z1, word, RET_X30]),
                GuestAddress(0),
                profile(32, 3),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .to_string()
            .contains("MOVPRFX pair validation")
        );
    }
    for word in [RESERVED_BYTE_SHIFT, RESERVED_ZERO_INDEX_SIZE] {
        assert!(
            crate::testing::context_leaf(
                &source(&[NOP, word, RET_X30]),
                GuestAddress(0),
                profile(32, 3),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .to_string()
            .contains("reserved streaming extraction")
        );
    }
}

#[test]
fn extraction_base_sme_profile_requires_no_sme2_or_za_enablement() {
    for bytes in [16, 32, 64, 128, 256] {
        let length = VectorLength::from_bytes(bytes).unwrap();
        for svcr in [1, 3] {
            let declared = ScalableProfile::new_with_features(
                length,
                ScalableMode::from_svcr(svcr).unwrap(),
                ScalableFeatures::of(ScalableFeature::Sme),
                ScalableControls::new(length, false),
            )
            .unwrap();
            assert!(!declared.features().contains(ScalableFeature::Sme2));
            assert!(!declared.features().contains(ScalableFeature::Sme2p1));
            for word in EXTRACTION_WORDS {
                for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                    let input = source(&[word, RET_X30]);
                    let base = GuestAddress(0x1000);
                    let v1 =
                        crate::testing::context_leaf(&input, base, profile(bytes, svcr), target)
                            .unwrap();
                    let v2 = crate::testing::context_leaf(&input, base, declared, target).unwrap();
                    assert_eq!(v1.x86_64_code, v2.x86_64_code);
                    assert_eq!(v1.source_map, v2.source_map);
                }
            }
        }
    }
}
