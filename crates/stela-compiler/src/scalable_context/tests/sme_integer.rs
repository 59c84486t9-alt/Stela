//! SME integer dot and matrix registration and profile limits.
use super::*;
use crate::aarch64::scalable::profile::ScalableControls;
use crate::aarch64::sme::{integer_dots, integer_matrix};
use alloc::vec::Vec;

const DOT_WORD: u32 = 0xc150_1000;
const DOT_DOUBLEWORD: u32 = 0xc1d0_0008;
const GUEST_BASE: GuestAddress = GuestAddress(0x1000);
const ALLOCATED_WORDS: [u32; 54] = [
    0xc150_1000, // sdot_za32_zzi_2xi
    0xc150_9000, // sdot_za32_zzi_4xi
    0xc160_1408, // sdot_za32_zzv_2x1
    0xc170_1408, // sdot_za32_zzv_4x1
    0xc1e0_1408, // sdot_za32_zzw_2x2
    0xc1e1_1408, // sdot_za32_zzw_4x4
    0xc150_1020, // sdot_za_zzi_s2xi
    0xc1d0_0008, // sdot_za_zzi_d2xi
    0xc150_9020, // sdot_za_zzi_s4xi
    0xc1d0_8008, // sdot_za_zzi_d4xi
    0xc120_1400, // sdot_za_zzv_2x1
    0xc130_1400, // sdot_za_zzv_4x1
    0xc1a0_1400, // sdot_za_zzw_2x2
    0xc1a1_1400, // sdot_za_zzw_4x4
    0xc150_1038, // sudot_za_zzi_s2xi
    0xc150_9038, // sudot_za_zzi_s4xi
    0xc120_1418, // sudot_za_zzv_s2x1
    0xc130_1418, // sudot_za_zzv_s4x1
    0xc150_8038, // suvdot_za_zzi_s4xi
    0xc150_0020, // svdot_za32_zzi_2xi
    0xc150_8020, // svdot_za_zzi_s4xi
    0xc1d0_8808, // svdot_za_zzi_d4xi
    0xc150_1010, // udot_za32_zzi_2xi
    0xc150_9010, // udot_za32_zzi_4xi
    0xc160_1418, // udot_za32_zzv_2x1
    0xc170_1418, // udot_za32_zzv_4x1
    0xc1e0_1418, // udot_za32_zzw_2x2
    0xc1e1_1418, // udot_za32_zzw_4x4
    0xc150_1030, // udot_za_zzi_s2xi
    0xc1d0_0018, // udot_za_zzi_d2xi
    0xc150_9030, // udot_za_zzi_s4xi
    0xc1d0_8018, // udot_za_zzi_d4xi
    0xc120_1410, // udot_za_zzv_2x1
    0xc130_1410, // udot_za_zzv_4x1
    0xc1a0_1410, // udot_za_zzw_2x2
    0xc1a1_1410, // udot_za_zzw_4x4
    0xc150_1028, // usdot_za_zzi_s2xi
    0xc150_9028, // usdot_za_zzi_s4xi
    0xc120_1408, // usdot_za_zzv_s2x1
    0xc130_1408, // usdot_za_zzv_s4x1
    0xc1a0_1408, // usdot_za_zzw_s2x2
    0xc1a1_1408, // usdot_za_zzw_s4x4
    0xc150_8028, // usvdot_za_zzi_s4xi
    0xc150_0030, // uvdot_za32_zzi_2xi
    0xc150_8030, // uvdot_za_zzi_s4xi
    0xc1d0_8818, // uvdot_za_zzi_d4xi
    0xc160_1400, // sdot_za_zzv_2x1 Doubleword
    0xc170_1400, // sdot_za_zzv_4x1 Doubleword
    0xc1e0_1400, // sdot_za_zzw_2x2 Doubleword
    0xc1e1_1400, // sdot_za_zzw_4x4 Doubleword
    0xc160_1410, // udot_za_zzv_2x1 Doubleword
    0xc170_1410, // udot_za_zzv_4x1 Doubleword
    0xc1e0_1410, // udot_za_zzw_2x2 Doubleword
    0xc1e1_1410, // udot_za_zzw_4x4 Doubleword
];

fn dot_body(word: u32) -> Vec<u8> {
    [word, RET_X30]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
}

fn profile(bytes: usize, mode: ScalableMode, features: ScalableFeatures) -> ScalableProfile {
    ScalableProfile::new_with_features(
        VectorLength::from_bytes(bytes).unwrap(),
        mode,
        features,
        ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
    )
    .unwrap()
}

fn features() -> ScalableFeatures {
    ScalableFeatures::of(ScalableFeature::Sme)
        .with(ScalableFeature::Sme2)
        .with(ScalableFeature::SmeI16I64)
}

#[test]
fn canonical_dots_emit_exact_bodies_and_maps() {
    for word in ALLOCATED_WORDS {
        let operand = integer_dots::decode(word).unwrap();
        assert_eq!(
            crate::aarch64::sme::decode(word),
            Some(Ok(crate::aarch64::sme::Operand::IntegerDots(operand))),
        );
        for bytes in [16, 32, 64, 128, 256] {
            for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                let profile = profile(bytes, ScalableMode::new(true, true), features());
                let native =
                    crate::testing::context_leaf(&dot_body(word), GUEST_BASE, profile, target)
                        .unwrap();
                let mut expected = Code::new();
                x86_64::sme::integer_dots::emit(
                    &mut expected,
                    &operand,
                    profile.vector_length(),
                    target,
                );

                assert_single_body(&native, GUEST_BASE, &expected);
            }
        }
        assert!(crate::testing::leaf(&dot_body(word), GUEST_BASE).is_err());
    }
}

#[test]
fn dots_require_each_guest_feature_and_both_mode_bits() {
    let sme_only = ScalableFeatures::of(ScalableFeature::Sme);
    let sme2 = sme_only.with(ScalableFeature::Sme2);
    for bytes in [16, 32, 64, 128, 256] {
        for (word, available, required) in [
            (DOT_WORD, sme_only, "FEAT_SME2"),
            (DOT_DOUBLEWORD, sme2, "FEAT_SME_I16I64"),
        ] {
            let error = crate::testing::context_leaf(
                &dot_body(word),
                GUEST_BASE,
                profile(bytes, ScalableMode::new(true, true), available),
                TargetCpu::Baseline,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains(required) && error.to_string().contains("0x1000"),
                "{error}"
            );
        }
        for (streaming, za, reason) in [
            (false, false, "streaming mode required"),
            (false, true, "streaming mode required"),
            (true, false, "ZA enable required"),
        ] {
            let error = crate::testing::context_leaf(
                &dot_body(DOT_WORD),
                GUEST_BASE,
                profile(bytes, ScalableMode::new(streaming, za), features()),
                TargetCpu::Baseline,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains(reason) && error.to_string().contains("0x1000"),
                "{error}"
            );
        }
        let fixed = ScalableProfile::new(
            VectorLength::from_bytes(bytes).unwrap(),
            ScalableMode::new(true, true),
        );
        assert!(
            crate::testing::context_leaf(
                &dot_body(DOT_WORD),
                GUEST_BASE,
                fixed,
                TargetCpu::Baseline
            )
            .is_ok()
        );
        assert!(
            crate::testing::context_leaf(
                &dot_body(DOT_DOUBLEWORD),
                GUEST_BASE,
                fixed,
                TargetCpu::Baseline
            )
            .unwrap_err()
            .to_string()
            .contains("FEAT_SME_I16I64")
        );
    }
}

#[test]
fn integer_matrix_admission_checks_features_mode_and_source_maps() {
    const MATRIX_WORDS: [u32; 6] = [
        0xc1a0_1c10, // ADD ZA.S pair.
        0xc100_0000, // SMLALL ZA.S indexed byte products.
        0xc180_0000, // SMLALL ZA.D indexed halfword products.
        0xa080_0000, // SMOPA ZA.S byte outer products.
        0xa0c0_0000, // SMOPA ZA.D halfword outer products.
        0x8080_0008, // BMOPA ZA.S XNOR outer products.
    ];
    for word in MATRIX_WORDS {
        let operand = integer_matrix::decode(word).unwrap();
        let source = words(&[word, RET_X30]);
        assert!(crate::testing::leaf(&source, GuestAddress(0)).is_err());
        let legacy = ScalableProfile::new(
            VectorLength::from_bytes(16).unwrap(),
            ScalableMode::new(true, true),
        );
        let legacy_result =
            crate::testing::context_leaf(&source, GuestAddress(0), legacy, TargetCpu::Baseline);
        assert_eq!(legacy_result.is_ok(), !operand.requires_i16i64());
        if operand.requires_i16i64() {
            assert!(
                legacy_result
                    .unwrap_err()
                    .to_string()
                    .contains("FEAT_SME_I16I64")
            );
        }
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            for sme2 in [false, true] {
                for i16i64 in [false, true] {
                    let mut features = ScalableFeatures::of(ScalableFeature::Sme);
                    if sme2 {
                        features = features.with(ScalableFeature::Sme2);
                    }
                    if i16i64 {
                        features = features.with(ScalableFeature::SmeI16I64);
                    }
                    for streaming in [false, true] {
                        for za in [false, true] {
                            let profile = ScalableProfile::new_with_features(
                                length,
                                ScalableMode::new(streaming, za),
                                features,
                                ScalableControls::new(length, false),
                            )
                            .unwrap();
                            let result = crate::testing::context_leaf(
                                &source,
                                GuestAddress(0),
                                profile,
                                TargetCpu::Baseline,
                            );
                            let permitted = streaming
                                && za
                                && (!operand.requires_sme2() || sme2)
                                && (!operand.requires_i16i64() || i16i64);
                            assert_eq!(
                                result.is_ok(),
                                permitted,
                                "word={word:#x} bytes={bytes} sme2={sme2} i16i64={i16i64} sm={streaming} za={za}"
                            );
                            if let Ok(native) = result {
                                let mut body = Code::new();
                                x86_64::sme::integer_matrix::emit(
                                    &mut body,
                                    &operand,
                                    length,
                                    TargetCpu::Baseline,
                                );
                                assert_single_body(&native, GuestAddress(0), &body);
                            }
                        }
                    }
                }
            }
        }
    }
}
