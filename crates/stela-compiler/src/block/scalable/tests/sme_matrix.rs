//! SME matrix family admission and feature requirements.
use super::*;
use crate::aarch64::scalable::features::ScalableFeature as Feature;
use crate::aarch64::scalable::{ScalableMode, VectorLength, profile::ScalableControls};

const BASE: GuestAddress = GuestAddress(0x1000);
const SVL_BYTES: [usize; 5] = [16, 32, 64, 128, 256];
const FADD_ZA_SINGLE: u32 = 0xc1a0_1c00;
const FMOPA_ZA_SINGLE: u32 = 0x8080_0000;
const NOP: u32 = 0xd503_201f;
const MATRIX_SAMPLES: &[(&str, u32, ScalableFeatures, ScalableFeatures)] = &[
    (
        "bfadd_za_zw_2x2_16",
        0xc1e41c00,
        ScalableFeatures::of(Feature::Sme).with(Feature::SmeB16B16),
        ScalableFeatures::empty(),
    ),
    (
        "fadd_za_zw_2x2",
        0xc1a01c00,
        ScalableFeatures::of(Feature::Sme).with(Feature::Sme2),
        ScalableFeatures::empty(),
    ),
    (
        "fadd_za_zw_2x2/sz=1",
        0xc1e01c00,
        ScalableFeatures::of(Feature::Sme)
            .with(Feature::Sme2)
            .with(Feature::SmeF64F64),
        ScalableFeatures::empty(),
    ),
    (
        "fadd_za_zw_2x2_16",
        0xc1a41c00,
        ScalableFeatures::of(Feature::Sme),
        ScalableFeatures::of(Feature::SmeF16F16).with(Feature::SmeF8F16),
    ),
    (
        "fmla_za_zzi_h2xi",
        0xc1101000,
        ScalableFeatures::of(Feature::Sme).with(Feature::SmeF16F16),
        ScalableFeatures::empty(),
    ),
    (
        "bfmopa_za32_pp_zz_",
        0x81800000,
        ScalableFeatures::of(Feature::Sme),
        ScalableFeatures::empty(),
    ),
    (
        "fmopa_za_pp_zz_64",
        0x80c00000,
        ScalableFeatures::of(Feature::Sme).with(Feature::SmeF64F64),
        ScalableFeatures::empty(),
    ),
];

fn profile(bytes: usize, mode: ScalableMode, features: ScalableFeatures) -> ScalableProfile {
    ScalableProfile::new_with_features(
        VectorLength::from_bytes(bytes).unwrap(),
        mode,
        features,
        ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
    )
    .unwrap()
}

fn decoded(word: u32) -> ScalableNumericalInstruction {
    decode_scalable_numerical_instruction(BASE, word)
        .unwrap()
        .expect("allocated matrix form")
}

#[test]
fn matrix_predicate_classes_keep_pinned_requirements_and_exact_source() {
    for &(name, word, all, any) in MATRIX_SAMPLES {
        let instruction = decoded(word);
        assert!(
            matches!(
                instruction.operation,
                ScalableNumericalOperation::SmeMatrix(_)
            ),
            "{name}"
        );
        let required = instruction
            .operation
            .required_streaming_features(NumericalFeatures::default());
        assert_eq!(required.all_features(), all, "{name}");
        assert_eq!(required.any_features(), any, "{name}");
        for bytes in SVL_BYTES {
            let available = all.union(any);
            let profile = profile(bytes, ScalableMode::new(true, true), available);
            let proof = admit_scalable_numerical_instruction(
                instruction,
                profile,
                NumericalFeatures::default(),
            )
            .unwrap();
            assert_eq!(proof.word(), word, "{name}");
            assert_eq!(proof.instruction_pc(), BASE, "{name}");
            assert_eq!(
                proof.next_pc(),
                GuestAddress(BASE.0 + INSTRUCTION_BYTES),
                "{name}"
            );
            assert_eq!(proof.profile(), profile, "{name}");
        }
    }
}

#[test]
fn matrix_admission_requires_both_streaming_and_za() {
    let features = ScalableFeatures::of(Feature::Sme).with(Feature::Sme2);
    for bytes in SVL_BYTES {
        for streaming in [false, true] {
            for za in [false, true] {
                let profile = profile(bytes, ScalableMode::new(streaming, za), features);
                let admitted = admit_scalable_numerical_instruction(
                    decoded(FADD_ZA_SINGLE),
                    profile,
                    NumericalFeatures::default(),
                );
                assert_eq!(admitted.is_ok(), streaming && za);
            }
        }
    }
}

#[test]
fn matrix_requirements_decline_missing_conjuncts_and_accept_each_alternative() {
    for &(name, word, all, any) in MATRIX_SAMPLES {
        let instruction = decoded(word);
        for missing in all.names() {
            if missing == Feature::Sme.name() {
                continue; // Profile construction itself rejects missing FEAT_SME.
            }
            let available = ScalableFeatures::checked_from_names(
                all.union(any)
                    .names()
                    .into_iter()
                    .filter(|&feature| feature != missing),
            )
            .unwrap();
            assert!(
                admit_scalable_numerical_instruction(
                    instruction,
                    profile(16, ScalableMode::new(true, true), available),
                    NumericalFeatures::default()
                )
                .is_err(),
                "{name}: {missing}"
            );
        }
        if !any.names().is_empty() {
            assert!(
                admit_scalable_numerical_instruction(
                    instruction,
                    profile(16, ScalableMode::new(true, true), all),
                    NumericalFeatures::default()
                )
                .is_err(),
                "{name}: no alternative"
            );
            for alternative in any.names() {
                let available =
                    all.union(ScalableFeatures::checked_from_names([alternative]).unwrap());
                assert!(
                    admit_scalable_numerical_instruction(
                        instruction,
                        profile(16, ScalableMode::new(true, true), available),
                        NumericalFeatures::default()
                    )
                    .is_ok(),
                    "{name}: {alternative}"
                );
            }
        }
    }
}

#[test]
fn matrix_proof_retains_immutable_numerical_features_and_full_a64_permission() {
    let sme = ScalableFeatures::of(Feature::Sme);
    for full_a64 in [false, true] {
        for ebf16 in [false, true] {
            for rpres in [false, true] {
                let numerical = NumericalFeatures::new(full_a64, ebf16, rpres);
                let ordinary = profile(16, ScalableMode::new(true, true), sme);
                assert_eq!(
                    admit_scalable_numerical_instruction(
                        decoded(FMOPA_ZA_SINGLE),
                        ordinary,
                        numerical
                    )
                    .is_ok(),
                    !full_a64
                );
                let declared = profile(
                    16,
                    ScalableMode::new(true, true),
                    sme.with(Feature::SmeFa64),
                );
                let proof = admit_scalable_numerical_instruction(
                    decoded(FMOPA_ZA_SINGLE),
                    declared,
                    numerical,
                )
                .unwrap();
                assert_eq!(proof.numerical_features(), numerical);
            }
        }
    }
}

#[test]
fn matrix_descriptor_mutations_fail_exact_source_redecode() {
    let profile = profile(
        16,
        ScalableMode::new(true, true),
        ScalableFeatures::of(Feature::Sme).with(Feature::Sme2),
    );
    let original = decoded(FADD_ZA_SINGLE);
    for altered in [
        ScalableNumericalInstruction {
            operation: decoded(FMOPA_ZA_SINGLE).operation,
            ..original
        },
        ScalableNumericalInstruction {
            word: NOP,
            ..original
        },
        ScalableNumericalInstruction {
            next_pc: BASE,
            ..original
        },
        ScalableNumericalInstruction {
            instruction_pc: GuestAddress(BASE.0 + INSTRUCTION_BYTES),
            ..original
        },
    ] {
        assert!(
            admit_scalable_numerical_instruction(altered, profile, NumericalFeatures::default())
                .is_err()
        );
    }
    assert!(
        decode_scalable_numerical_instruction(GuestAddress(BASE.0 + 1), FADD_ZA_SINGLE).is_err()
    );
    assert!(
        decode_scalable_numerical_instruction(
            GuestAddress(u64::MAX - INSTRUCTION_BYTES + 1),
            FADD_ZA_SINGLE
        )
        .is_err()
    );
}
