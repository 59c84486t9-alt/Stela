//! Multi-Z caller dispatch, source maps and complete-body effect requirements.
use super::*;
use crate::context::memory::{SpAlignmentRequirement, flags, host_caps, profile_requirements};

const RET_X30: u32 = 0xd65f_03c0;
const NOP: u32 = 0xd503_201f;
const LD1D_Z0_Z1_PN8_X5_X0: u32 = 0xa000_60a0;
const LD1D_Z0_Z1_PN8_SP: u32 = 0xa040_63e0;
const STNT1B_Z0_Z3_PN8_X5: u32 = 0xa060_80a1;
const RESERVED_IMMEDIATE: u32 = 0xa050_0000;
const RESERVED_QUAD_TUPLE: u32 = 0xa040_8002;
const GUEST_BASE: GuestAddress = GuestAddress(0x1000);
const CANONICAL_BASE_X5: u32 = 5 << 5;

const WORDS: [u32; 64] = [
    0xa0400000, // ld1b_mz_p_bi_2
    0xa0408000, // ld1b_mz_p_bi_4
    0xa0000000, // ld1b_mz_p_br_2
    0xa0008000, // ld1b_mz_p_br_4
    0xa0406000, // ld1d_mz_p_bi_2
    0xa040e000, // ld1d_mz_p_bi_4
    0xa0006000, // ld1d_mz_p_br_2
    0xa000e000, // ld1d_mz_p_br_4
    0xa0402000, // ld1h_mz_p_bi_2
    0xa040a000, // ld1h_mz_p_bi_4
    0xa0002000, // ld1h_mz_p_br_2
    0xa000a000, // ld1h_mz_p_br_4
    0xa0404000, // ld1w_mz_p_bi_2
    0xa040c000, // ld1w_mz_p_bi_4
    0xa0004000, // ld1w_mz_p_br_2
    0xa000c000, // ld1w_mz_p_br_4
    0xa0400001, // ldnt1b_mz_p_bi_2
    0xa0408001, // ldnt1b_mz_p_bi_4
    0xa0000001, // ldnt1b_mz_p_br_2
    0xa0008001, // ldnt1b_mz_p_br_4
    0xa0406001, // ldnt1d_mz_p_bi_2
    0xa040e001, // ldnt1d_mz_p_bi_4
    0xa0006001, // ldnt1d_mz_p_br_2
    0xa000e001, // ldnt1d_mz_p_br_4
    0xa0402001, // ldnt1h_mz_p_bi_2
    0xa040a001, // ldnt1h_mz_p_bi_4
    0xa0002001, // ldnt1h_mz_p_br_2
    0xa000a001, // ldnt1h_mz_p_br_4
    0xa0404001, // ldnt1w_mz_p_bi_2
    0xa040c001, // ldnt1w_mz_p_bi_4
    0xa0004001, // ldnt1w_mz_p_br_2
    0xa000c001, // ldnt1w_mz_p_br_4
    0xa0600000, // st1b_mz_p_bi_2
    0xa0608000, // st1b_mz_p_bi_4
    0xa0200000, // st1b_mz_p_br_2
    0xa0208000, // st1b_mz_p_br_4
    0xa0606000, // st1d_mz_p_bi_2
    0xa060e000, // st1d_mz_p_bi_4
    0xa0206000, // st1d_mz_p_br_2
    0xa020e000, // st1d_mz_p_br_4
    0xa0602000, // st1h_mz_p_bi_2
    0xa060a000, // st1h_mz_p_bi_4
    0xa0202000, // st1h_mz_p_br_2
    0xa020a000, // st1h_mz_p_br_4
    0xa0604000, // st1w_mz_p_bi_2
    0xa060c000, // st1w_mz_p_bi_4
    0xa0204000, // st1w_mz_p_br_2
    0xa020c000, // st1w_mz_p_br_4
    0xa0600001, // stnt1b_mz_p_bi_2
    0xa0608001, // stnt1b_mz_p_bi_4
    0xa0200001, // stnt1b_mz_p_br_2
    0xa0208001, // stnt1b_mz_p_br_4
    0xa0606001, // stnt1d_mz_p_bi_2
    0xa060e001, // stnt1d_mz_p_bi_4
    0xa0206001, // stnt1d_mz_p_br_2
    0xa020e001, // stnt1d_mz_p_br_4
    0xa0602001, // stnt1h_mz_p_bi_2
    0xa060a001, // stnt1h_mz_p_bi_4
    0xa0202001, // stnt1h_mz_p_br_2
    0xa020a001, // stnt1h_mz_p_br_4
    0xa0604001, // stnt1w_mz_p_bi_2
    0xa060c001, // stnt1w_mz_p_bi_4
    0xa0204001, // stnt1w_mz_p_br_2
    0xa020c001, // stnt1w_mz_p_br_4
];

fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn profile(bytes: usize, streaming: bool) -> ScalableProfile {
    ScalableProfile::new(
        VectorLength::from_bytes(bytes).unwrap(),
        ScalableMode::new(streaming, false),
    )
}

#[test]
fn multi_forms_dispatch_exact_bodies_and_maps_at_vector_length_boundaries() {
    for canonical in WORDS {
        let word = canonical | CANONICAL_BASE_X5;
        let operand = memory_multi::decode(word).unwrap().unwrap();
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::MemoryMulti(operand)))
        );
        for bytes in [16, 256] {
            let profile = profile(bytes, true);
            let bytes = source(&[word, RET_X30]);
            let native =
                compile_for_profile(&bytes, GUEST_BASE, profile, TargetCpu::Baseline).unwrap();
            let mut expected = Vec::new();
            x86_64::sve::memory_multi::emit(
                &mut expected,
                &operand,
                profile.vector_length(),
                TargetCpu::Baseline,
                GUEST_BASE.0,
            );
            assert_eq!(
                &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                context_wrapper()
            );
            assert_eq!(
                native.source_map,
                [
                    (GUEST_BASE, CONTEXT_WRAPPER_BYTES),
                    (
                        GuestAddress(GUEST_BASE.0 + INSTRUCTION_BYTES as u64),
                        CONTEXT_WRAPPER_BYTES + expected.len()
                    ),
                ]
            );
            assert_eq!(
                &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                expected
            );
            assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
            assert_eq!(
                memory_requirements(&bytes, GUEST_BASE, profile, TargetCpu::Baseline).unwrap(),
                x86_64::sve::memory_multi::requirements(&operand)
            );
        }
    }
}

#[test]
fn multi_requirements_fold_every_effect_and_preserve_four_argument_descriptor() {
    let profile = profile(16, true);
    assert_eq!(
        memory_requirements(
            &source(&[NOP, RET_X30]),
            GUEST_BASE,
            profile,
            TargetCpu::Baseline,
        )
        .unwrap(),
        MemoryRequirements::default()
    );
    assert_eq!(
        memory_requirements(
            &source(&[
                LD1D_Z0_Z1_PN8_X5_X0,
                LD1D_Z0_Z1_PN8_SP,
                STNT1B_Z0_Z3_PN8_X5,
                RET_X30,
            ]),
            GUEST_BASE,
            profile,
            TargetCpu::Baseline,
        )
        .unwrap(),
        MemoryRequirements {
            required_pointer_arithmetic: None,
            required_address_checks: Default::default(),
            required_flags: flags::TAG_CHECKED | flags::WRITE | flags::NON_TEMPORAL,
            required_host_caps: host_caps::ATOMIC_LOAD16,
            required_profile: profile_requirements::NATIVE_ACCESS
                | profile_requirements::TAG_GRANULES
                | profile_requirements::SCALABLE_TAG_CHECKS,
            required_sp_alignment: SpAlignmentRequirement::Enabled,
        }
    );
    assert_eq!(
        memory_requirements(
            &source(&[LD1D_Z0_Z1_PN8_SP, RET_X30]),
            GUEST_BASE,
            profile,
            TargetCpu::Baseline,
        )
        .unwrap(),
        MemoryRequirements {
            required_pointer_arithmetic: None,
            required_address_checks: Default::default(),
            required_flags: 0,
            required_host_caps: 0,
            required_profile: profile_requirements::NATIVE_ACCESS,
            required_sp_alignment: SpAlignmentRequirement::Enabled,
        }
    );
}

#[test]
fn multi_scan_and_compile_share_reserved_mode_and_feature_declines() {
    let length = VectorLength::from_bytes(16).unwrap();
    let sme_without_sme2 = ScalableProfile::new_with_features(
        length,
        ScalableMode::new(true, false),
        ScalableFeatures::of(ScalableFeature::Sme),
        ScalableControls::new(length, false),
    )
    .unwrap();
    for (words, profile) in [
        (vec![RESERVED_IMMEDIATE, RET_X30], profile(16, true)),
        (vec![RESERVED_QUAD_TUPLE, RET_X30], profile(16, true)),
        (vec![LD1D_Z0_Z1_PN8_X5_X0, RET_X30], profile(16, false)),
        (vec![LD1D_Z0_Z1_PN8_X5_X0, RET_X30], sme_without_sme2),
        (vec![LD1D_Z0_Z1_PN8_X5_X0], profile(16, true)),
    ] {
        let bytes = source(&words);
        let scan =
            memory_requirements(&bytes, GUEST_BASE, profile, TargetCpu::Baseline).unwrap_err();
        let compile =
            compile_for_profile(&bytes, GUEST_BASE, profile, TargetCpu::Baseline).unwrap_err();
        assert_eq!(scan.0, compile.0);
    }
}
