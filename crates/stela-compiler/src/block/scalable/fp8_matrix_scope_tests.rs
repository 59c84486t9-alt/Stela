//! Public matrix30 admission and the private vertical-dot verification boundary.
use super::*;
use crate::{
    TargetCpu,
    aarch64::scalable::{ScalableMode, VectorLength, profile::ScalableControls},
    block::BlockProfile,
    extended::block::{ExtendedBlockProfile, compile_for_profile},
};

const PC: GuestAddress = GuestAddress(0x1000);
const BFCVT_PENDING: u32 = 0xc164_e000;
const NOP_WORD: u32 = 0xd503_201f;
// Pinned June encoding facts: canonical ID, lowest operands, highest operands.
const PUBLIC_FORMS: &[(&str, u32, u32)] = &[
    ("fdot_za_z8z8i_2xi", 0xc1d00020, 0xc1df6fef),
    ("fdot_za_z8z8i_4xi", 0xc1109040, 0xc11fffcf),
    ("fdot_za_z8z8v_2x1", 0xc1201008, 0xc12f73ef),
    ("fdot_za_z8z8v_4x1", 0xc1301008, 0xc13f73ef),
    ("fdot_za_z8z8w_2x2", 0xc1a01020, 0xc1be73e7),
    ("fdot_za_z8z8w_4x4", 0xc1a11020, 0xc1bd73a7),
    ("fmlal_za_z8z8i_1", 0xc1c00000, 0xc1cfefef),
    ("fmlal_za_z8z8i_2xi", 0xc1901030, 0xc19f7fff),
    ("fmlal_za_z8z8i_4xi", 0xc1909020, 0xc19fffaf),
    ("fmlal_za_z8z8v_1", 0xc1300c00, 0xc13f6fe7),
    ("fmlal_za_z8z8v_2x1", 0xc1200804, 0xc12f6be7),
    ("fmlal_za_z8z8v_4x1", 0xc1300804, 0xc13f6be7),
    ("fmlal_za_z8z8w_2x2", 0xc1a00820, 0xc1be6be3),
    ("fmlal_za_z8z8w_4x4", 0xc1a10820, 0xc1bd6ba3),
    ("fmopa_za16_pp_z8z8_8", 0x80a00008, 0x80bfffe9),
    ("fmopa_za32_pp_z8z8_8", 0x80a00000, 0x80bfffe3),
    ("fmlall_za32_z8z8i_1", 0xc1400000, 0xc14fffe3),
    ("fmlall_za32_z8z8i_2xi", 0xc1900020, 0xc19f6fe7),
    ("fmlall_za32_z8z8i_4xi", 0xc1108040, 0xc11fefc7),
    ("fmlall_za32_z8z8v_1", 0xc1300400, 0xc13f67e3),
    ("fmlall_za32_z8z8v_2x1", 0xc1200002, 0xc12f63e3),
    ("fmlall_za32_z8z8v_4x1", 0xc1300002, 0xc13f63e3),
    ("fmlall_za32_z8z8w_2x2", 0xc1a00020, 0xc1be63e1),
    ("fmlall_za32_z8z8w_4x4", 0xc1a10020, 0xc1bd63a1),
    ("fdot_za32_z8z8i_2xi", 0xc1500038, 0xc15f6fff),
    ("fdot_za32_z8z8i_4xi", 0xc1508008, 0xc15fef8f),
    ("fdot_za32_z8z8v_2x1", 0xc1201018, 0xc12f73ff),
    ("fdot_za32_z8z8v_4x1", 0xc1301018, 0xc13f73ff),
    ("fdot_za32_z8z8w_2x2", 0xc1a01030, 0xc1be73f7),
    ("fdot_za32_z8z8w_4x4", 0xc1a11030, 0xc1bd73b7),
];
const PRIVATE_VERTICAL_FORMS: &[(&str, u32, u32)] = &[
    ("fvdotb_za32_z8z8i_2xi", 0xc1d00800, 0xc1df6fcf),
    ("fvdott_za32_z8z8i_2xi", 0xc1d00810, 0xc1df6fdf),
    ("fvdot_za_z8z8i_2xi", 0xc1d01020, 0xc1df7fef),
];

fn declared_profile(length: usize, available: bool, streaming: bool) -> ScalableProfile {
    let features = if available {
        ScalableFeatures::checked_from_names([
            "FEAT_SME",
            "FEAT_SME2",
            "FEAT_FPMR",
            "FEAT_FP8",
            "FEAT_SME_F8F16",
            "FEAT_SME_F8F32",
        ])
        .unwrap()
    } else {
        ScalableFeatures::of(ScalableFeature::Sme)
    };
    ScalableProfile::new_with_features(
        VectorLength::from_bytes(length).unwrap(),
        ScalableMode::new(streaming, streaming),
        features,
        ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false)
            .with_fpmr_enabled(available),
    )
    .unwrap()
}

#[test]
fn public_thirty_forms_admit_and_emit_exact_source() {
    assert_eq!(PUBLIC_FORMS.len(), 30);
    let profile = declared_profile(64, true, true);
    let numerical = NumericalFeatures::default();
    for &(id, low, high) in PUBLIC_FORMS {
        for word in [low, high] {
            let decoded = decode_scalable_numerical_instruction(PC, word)
                .unwrap()
                .unwrap();
            assert!(
                matches!(
                    decoded.operation,
                    ScalableNumericalOperation::SmeFp8Matrix(_)
                ),
                "{id}"
            );
            let admitted =
                admit_scalable_numerical_instruction(decoded, profile, numerical).unwrap();
            assert_eq!(admitted.word(), word);
            assert_eq!(admitted.next_pc(), GuestAddress(0x1004));
            let compiled = compile_for_profile(
                &word.to_le_bytes(),
                PC,
                ExtendedBlockProfile::new(profile, BlockProfile::Ordinary, numerical),
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(compiled.source_bytes, size_of::<u32>(), "{id}");
            assert_eq!(compiled.native.source_map.len(), 1, "{id}");
            assert_eq!(compiled.native.source_map[0].0, PC, "{id}");
            assert!(!compiled.native.x86_64_code.is_empty(), "{id}");
        }
    }
}

#[test]
fn all_vertical_forms_refuse_before_profile_or_emission() {
    assert_eq!(PRIVATE_VERTICAL_FORMS.len(), 3);
    for length in [16, 64, 256] {
        for available in [false, true] {
            for streaming in [false, true] {
                let profile = declared_profile(length, available, streaming);
                for &(id, low, high) in PRIVATE_VERTICAL_FORMS {
                    for word in [low, high] {
                        let decoded = decode_scalable_numerical_instruction(PC, word)
                            .unwrap()
                            .unwrap();
                        let error = admit_scalable_numerical_instruction(
                            decoded,
                            profile,
                            NumericalFeatures::default(),
                        )
                        .unwrap_err();
                        assert!(
                            error.0.contains("unadmitted SME FP8 vertical dot"),
                            "{id}: {error}"
                        );
                        let emitted = compile_for_profile(
                            &word.to_le_bytes(),
                            PC,
                            ExtendedBlockProfile::new(
                                profile,
                                BlockProfile::Ordinary,
                                NumericalFeatures::default(),
                            ),
                            TargetCpu::Baseline,
                        );
                        assert!(
                            emitted
                                .unwrap_err()
                                .0
                                .contains("unadmitted SME FP8 vertical dot"),
                            "{id}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn source_descriptor_mismatch_precedes_vertical_verification_refusal() {
    let word = PRIVATE_VERTICAL_FORMS[0].1;
    let mut decoded = decode_scalable_numerical_instruction(PC, word)
        .unwrap()
        .unwrap();
    decoded.word = NOP_WORD;
    let error = admit_scalable_numerical_instruction(
        decoded,
        declared_profile(16, false, false),
        NumericalFeatures::default(),
    )
    .unwrap_err();
    assert!(error.0.contains("source/descriptor mismatch"));
}

#[test]
fn supported_forms_retain_fpmr_and_za_access_requirements() {
    let word = PUBLIC_FORMS[0].1;
    let decoded = decode_scalable_numerical_instruction(PC, word)
        .unwrap()
        .unwrap();
    let error = admit_scalable_numerical_instruction(
        decoded,
        declared_profile(16, false, true),
        NumericalFeatures::default(),
    )
    .unwrap_err();
    assert!(error.0.contains("FPMR access"));
    let error = admit_scalable_numerical_instruction(
        decoded,
        declared_profile(16, true, false),
        NumericalFeatures::default(),
    )
    .unwrap_err();
    assert!(error.0.contains("mode unavailable"));
}

#[test]
fn existing_bfcvt_pending_policy_is_preserved() {
    let decoded = decode_scalable_numerical_instruction(PC, BFCVT_PENDING)
        .unwrap()
        .unwrap();
    let error = admit_scalable_numerical_instruction(
        decoded,
        declared_profile(16, true, true),
        NumericalFeatures::default(),
    )
    .unwrap_err();
    assert!(error.0.contains("unadmitted SME BF16-to-FP8 narrowing"));
}
