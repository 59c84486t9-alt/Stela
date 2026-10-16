//! Focused registration, profile-boundary and source-map checks for ZA movement.

use super::*;
use crate::aarch64::sme::movement;
use alloc::string::String;
use alloc::vec::Vec;

const RET_X30: u32 = 0xd65f_03c0;
const NOP: u32 = 0xd503_201f;
const MOVA_Z0_ZA0H_BYTE: u32 = 0xc002_0000;
const MOVA_ZA0H_BYTE_Z0: u32 = 0xc000_0000;
const MOVA_TWO_Z0_ZA0H_BYTE: u32 = 0xc006_0000;
const MOVA_FOUR_Z0_ZA0H_DOUBLEWORD: u32 = 0xc0c6_0400;
const MOVAZ_Z0_ZA0H_BYTE: u32 = 0xc002_0200;
const ZERO_ZA_EMPTY: u32 = 0xc008_0000;
const ZERO_ZA_ALL: u32 = 0xc008_00ff;
const ZERO_ZA_VECTOR_GROUP: u32 = 0xc00c_0000;
const ZERO_ZT0: u32 = 0xc048_0001;
const MOVT_X0_ZT0: u32 = 0xc04c_03e0;
const MOVT_ZT0_X0: u32 = 0xc04e_03e0;
const SOURCE_BASE: GuestAddress = GuestAddress(0x1000);
const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];
const ALL_MOVEMENT_FEATURES: ScalableFeatures = ScalableFeatures::of(ScalableFeature::Sme)
    .with(ScalableFeature::Sme2)
    .with(ScalableFeature::Sme2p1);

const NORMAL_FORMS: &[(&str, u32)] = &[
    ("mova_mz2_za_b1", 0xc006_0000),
    ("mova_mz2_za_d1", 0xc0c6_0000),
    ("mova_mz2_za_h1", 0xc046_0000),
    ("mova_mz2_za_w1", 0xc086_0000),
    ("mova_mz4_za_b1", 0xc006_0400),
    ("mova_mz4_za_d1", 0xc0c6_0400),
    ("mova_mz4_za_h1", 0xc046_0400),
    ("mova_mz4_za_w1", 0xc086_0400),
    ("mova_mz_za2_1", 0xc006_0800),
    ("mova_mz_za4_1", 0xc006_0c00),
    ("mova_z_p_rza_b", 0xc002_0000),
    ("mova_z_p_rza_d", 0xc0c2_0000),
    ("mova_z_p_rza_h", 0xc042_0000),
    ("mova_z_p_rza_q", 0xc0c3_0000),
    ("mova_z_p_rza_w", 0xc082_0000),
    ("mova_za2_z_b1", 0xc004_0000),
    ("mova_za2_z_d1", 0xc0c4_0000),
    ("mova_za2_z_h1", 0xc044_0000),
    ("mova_za2_z_w1", 0xc084_0000),
    ("mova_za4_z_b1", 0xc004_0400),
    ("mova_za4_z_d1", 0xc0c4_0400),
    ("mova_za4_z_h1", 0xc044_0400),
    ("mova_za4_z_w1", 0xc084_0400),
    ("mova_za_mz2_1", 0xc004_0800),
    ("mova_za_mz4_1", 0xc004_0c00),
    ("mova_za_p_rz_b", 0xc000_0000),
    ("mova_za_p_rz_d", 0xc0c0_0000),
    ("mova_za_p_rz_h", 0xc040_0000),
    ("mova_za_p_rz_q", 0xc0c1_0000),
    ("mova_za_p_rz_w", 0xc080_0000),
    ("movaz_mz2_za_b1", 0xc006_0200),
    ("movaz_mz2_za_d1", 0xc0c6_0200),
    ("movaz_mz2_za_h1", 0xc046_0200),
    ("movaz_mz2_za_w1", 0xc086_0200),
    ("movaz_mz4_za_b1", 0xc006_0600),
    ("movaz_mz4_za_d1", 0xc0c6_0600),
    ("movaz_mz4_za_h1", 0xc046_0600),
    ("movaz_mz4_za_w1", 0xc086_0600),
    ("movaz_mz_za2_1", 0xc006_0a00),
    ("movaz_mz_za4_1", 0xc006_0e00),
    ("movaz_z_rza_b", 0xc002_0200),
    ("movaz_z_rza_d", 0xc0c2_0200),
    ("movaz_z_rza_h", 0xc042_0200),
    ("movaz_z_rza_q", 0xc0c3_0200),
    ("movaz_z_rza_w", 0xc082_0200),
    ("zero_za1_ri_2", 0xc00c_0000),
    ("zero_za1_ri_4", 0xc00e_0000),
    ("zero_za2_ri_1", 0xc00c_8000),
    ("zero_za2_ri_2", 0xc00d_0000),
    ("zero_za2_ri_4", 0xc00d_8000),
    ("zero_za4_ri_1", 0xc00e_8000),
    ("zero_za4_ri_2", 0xc00f_0000),
    ("zero_za4_ri_4", 0xc00f_8000),
    ("zero_za_i_", 0xc008_0000),
    ("zero_zt_i_", 0xc048_0001),
];

fn words(input: &[u32]) -> Vec<u8> {
    input.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn profile(
    bytes: usize,
    streaming: bool,
    za: bool,
    features: ScalableFeatures,
    max_bytes: usize,
    zt0: bool,
) -> ScalableProfile {
    ScalableProfile::new_with_features(
        VectorLength::from_bytes(bytes).unwrap(),
        ScalableMode::new(streaming, za),
        features,
        ScalableControls::new(VectorLength::from_bytes(max_bytes).unwrap(), zt0),
    )
    .unwrap()
}

fn rejection(word: u32, profile: ScalableProfile) -> String {
    compile_for_profile(
        &words(&[NOP, word, RET_X30]),
        SOURCE_BASE,
        profile,
        TargetCpu::Baseline,
    )
    .unwrap_err()
    .0
}

#[test]
fn all_normal_forms_route_through_exact_compiler_body_and_maps() {
    assert_eq!(NORMAL_FORMS.len(), 55);
    for &(canonical, word) in NORMAL_FORMS {
        let operand = movement::decode(word).unwrap();
        assert_eq!(operand.canonical_id, canonical);
        assert!(!operand.requirements.halted);
        assert_eq!(
            crate::aarch64::sme::decode(word),
            Some(Ok(crate::aarch64::sme::Operand::Movement(operand)))
        );
        for bytes in LENGTHS {
            let profile = profile(bytes, true, true, ALL_MOVEMENT_FEATURES, 256, true);
            for target in [TargetCpu::Baseline, TargetCpu::Sse41] {
                let source = words(&[word, RET_X30]);
                if profile.vector_length().bits()
                    < usize::from(operand.requirements.minimum_current_svl_bits)
                {
                    assert!(compile_for_profile(&source, SOURCE_BASE, profile, target).is_err());
                    continue;
                }
                let native = compile_for_profile(&source, SOURCE_BASE, profile, target).unwrap();
                let mut body = Vec::new();
                x86_64::sme::movement::emit(&mut body, &operand, profile.vector_length(), target)
                    .unwrap();
                assert_eq!(
                    native.source_map,
                    [
                        (SOURCE_BASE, CONTEXT_WRAPPER_BYTES),
                        (
                            GuestAddress(SOURCE_BASE.0 + INSTRUCTION_BYTES as u64),
                            CONTEXT_WRAPPER_BYTES + body.len()
                        ),
                    ]
                );
                assert_eq!(
                    &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                    context_wrapper()
                );
                assert_eq!(
                    &native.x86_64_code[CONTEXT_WRAPPER_BYTES..CONTEXT_WRAPPER_BYTES + body.len()],
                    body
                );
                assert_eq!(
                    &native.x86_64_code[CONTEXT_WRAPPER_BYTES + body.len()..],
                    [RET]
                );
            }
        }
        assert!(crate::compile(&words(&[word, RET_X30]), SOURCE_BASE).is_err());
    }
}

#[test]
fn mode_guards_run_before_empty_zero_or_any_movement_emission() {
    for bytes in LENGTHS {
        for streaming in [false, true] {
            let no_za = profile(bytes, streaming, false, ALL_MOVEMENT_FEATURES, 256, true);
            for word in [
                ZERO_ZA_EMPTY,
                ZERO_ZA_ALL,
                ZERO_ZT0,
                MOVA_Z0_ZA0H_BYTE,
                MOVA_ZA0H_BYTE_Z0,
                MOVAZ_Z0_ZA0H_BYTE,
                ZERO_ZA_VECTOR_GROUP,
            ] {
                assert!(rejection(word, no_za).contains("ZA"));
            }
        }
        let no_stream = profile(bytes, false, true, ALL_MOVEMENT_FEATURES, 256, true);
        for word in [
            MOVA_Z0_ZA0H_BYTE,
            MOVA_ZA0H_BYTE_Z0,
            MOVAZ_Z0_ZA0H_BYTE,
            ZERO_ZA_VECTOR_GROUP,
        ] {
            assert!(rejection(word, no_stream).contains("streaming mode"));
        }
        for word in [ZERO_ZA_EMPTY, ZERO_ZA_ALL, ZERO_ZT0] {
            assert!(
                compile_for_profile(
                    &words(&[word, RET_X30]),
                    SOURCE_BASE,
                    no_stream,
                    TargetCpu::Baseline
                )
                .is_ok()
            );
        }
        let no_zt0 = profile(bytes, false, true, ALL_MOVEMENT_FEATURES, 256, false);
        assert!(rejection(ZERO_ZT0, no_zt0).contains("ZT0"));
    }
}

#[test]
fn guest_features_and_debug_requirements_do_not_come_from_host_target() {
    let sme = ScalableFeatures::of(ScalableFeature::Sme);
    let no_sme2 = profile(32, true, true, sme, 256, false);
    assert!(rejection(MOVA_TWO_Z0_ZA0H_BYTE, no_sme2).contains("FEAT_SME2"));
    let no_sme2p1 = profile(32, true, true, sme.with(ScalableFeature::Sme2), 256, true);
    for word in [MOVAZ_Z0_ZA0H_BYTE, ZERO_ZA_VECTOR_GROUP] {
        assert!(rejection(word, no_sme2p1).contains("FEAT_SME2p1"));
        assert!(
            compile_for_profile(
                &words(&[word, RET_X30]),
                SOURCE_BASE,
                no_sme2p1,
                TargetCpu::Sse41
            )
            .is_err()
        );
    }
    let declared = profile(32, true, true, ALL_MOVEMENT_FEATURES, 256, true);
    let original = ScalableProfile::new(
        VectorLength::from_bytes(32).unwrap(),
        ScalableMode::new(true, true),
    );
    for profile in [declared, original] {
        for word in [MOVT_X0_ZT0, MOVT_ZT0_X0] {
            assert!(rejection(word, profile).contains("halted debug"));
        }
    }
}

#[test]
fn current_and_maximum_length_guards_are_distinct() {
    let low_max = profile(16, true, true, ALL_MOVEMENT_FEATURES, 16, true);
    let larger_max = profile(16, true, true, ALL_MOVEMENT_FEATURES, 32, true);
    assert!(
        rejection(MOVA_FOUR_Z0_ZA0H_DOUBLEWORD, low_max)
            .contains("maximum streaming vector length")
    );
    assert!(
        rejection(MOVA_FOUR_Z0_ZA0H_DOUBLEWORD, larger_max)
            .contains("current streaming vector length")
    );
    assert!(
        ScalableProfile::new_with_features(
            VectorLength::from_bytes(32).unwrap(),
            ScalableMode::new(true, true),
            ALL_MOVEMENT_FEATURES,
            ScalableControls::new(VectorLength::from_bytes(16).unwrap(), true),
        )
        .is_err()
    );
}

#[test]
fn sme1_nonstreaming_za_zero_needs_no_zt0_or_streaming_banks() {
    let profile = profile(
        16,
        false,
        true,
        ScalableFeatures::of(ScalableFeature::Sme),
        16,
        false,
    );
    let mut za = [0_u8; 16 * 16];
    let mut view = ScalableStateView {
        svl_bytes: 16,
        reserved: [0; 6],
        svcr: ScalableMode::new(false, true).svcr(),
        tpidr2_el0: 0,
        fpmr: 0,
        z_upper: core::ptr::null_mut(),
        predicates: core::ptr::null_mut(),
        ffr: core::ptr::null_mut(),
        za: za.as_mut_ptr(),
        zt0: core::ptr::null_mut(),
    };
    let context = ExecutionContext {
        scalable: &mut view,
        ..ExecutionContext::default()
    };
    profile.validate_view(&context, &view).unwrap();
    assert!(
        compile_for_profile(
            &words(&[ZERO_ZA_ALL, RET_X30]),
            SOURCE_BASE,
            profile,
            TargetCpu::Baseline
        )
        .is_ok()
    );
}

#[test]
fn legacy_and_declared_profiles_keep_the_same_movement_bodies() {
    let length = VectorLength::from_bytes(32).unwrap();
    let legacy = ScalableProfile::new(length, ScalableMode::new(true, true));
    let declared = profile(32, true, true, ALL_MOVEMENT_FEATURES, 256, true);
    for word in [
        MOVA_Z0_ZA0H_BYTE,
        MOVA_ZA0H_BYTE_Z0,
        MOVA_TWO_Z0_ZA0H_BYTE,
        ZERO_ZA_EMPTY,
        ZERO_ZA_ALL,
    ] {
        let source = words(&[word, RET_X30]);
        let first = compile_for_profile(&source, SOURCE_BASE, legacy, TargetCpu::Baseline).unwrap();
        let second =
            compile_for_profile(&source, SOURCE_BASE, declared, TargetCpu::Baseline).unwrap();
        assert_eq!(first.x86_64_code, second.x86_64_code);
        assert_eq!(first.source_map, second.source_map);
    }
}
