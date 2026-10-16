//! SVE store routing and requirements.
use super::*;
use crate::aarch64::sve::memory_store;
use crate::context::memory::{SpAlignmentRequirement, flags, host_caps, profile_requirements};
use alloc::vec::Vec;

const RET_X30: u32 = 0xd65f_03c0;
const NOP: u32 = 0xd503_201f;
const ST1B_Z1_P0_SP: u32 = 0xe400_e3e1;
const STNT1D_Z1_P0_X5: u32 = 0xe590_e0a1;
const ST2Q_Z1_P0_X5: u32 = 0xe440_00a1;
const STR_Z1_X5: u32 = 0xe580_40a1;
const PRFB_P0_SP: u32 = 0x85c0_03e1;
const RESERVED_ST1B_Z1_P0_X5_XZR: u32 = 0xe41f_40a1;
const RESERVED_ST1H_BYTE_SOURCE: u32 = 0xe480_e0a1;
const GUEST_BASE: GuestAddress = GuestAddress(0x1000);
const FORMS: [(u32, &str); 56] = [
    (0x85c000a1, "prfb_i_p_bi_s"),
    (0x8400c0a1, "prfb_i_p_br_s"),
    (0x85c060a1, "prfd_i_p_bi_s"),
    (0x8580c0a1, "prfd_i_p_br_s"),
    (0x85c020a1, "prfh_i_p_bi_s"),
    (0x8480c0a1, "prfh_i_p_br_s"),
    (0x85c040a1, "prfw_i_p_bi_s"),
    (0x8500c0a1, "prfw_i_p_br_s"),
    (0xe400e0a1, "st1b_z_p_bi_"),
    (0xe40040a1, "st1b_z_p_br_"),
    (0xe5e0e0a1, "st1d_z_p_bi_"),
    (0xe5e040a1, "st1d_z_p_br_"),
    (0xe4a0e0a1, "st1h_z_p_bi_"),
    (0xe4a040a1, "st1h_z_p_br_"),
    (0xe540e0a1, "st1w_z_p_bi_"),
    (0xe54040a1, "st1w_z_p_br_"),
    (0xe430e0a1, "st2b_z_p_bi_contiguous"),
    (0xe42060a1, "st2b_z_p_br_contiguous"),
    (0xe5b0e0a1, "st2d_z_p_bi_contiguous"),
    (0xe5a060a1, "st2d_z_p_br_contiguous"),
    (0xe4b0e0a1, "st2h_z_p_bi_contiguous"),
    (0xe4a060a1, "st2h_z_p_br_contiguous"),
    (0xe44000a1, "st2q_z_p_bi_contiguous"),
    (0xe46000a1, "st2q_z_p_br_contiguous"),
    (0xe530e0a1, "st2w_z_p_bi_contiguous"),
    (0xe52060a1, "st2w_z_p_br_contiguous"),
    (0xe450e0a1, "st3b_z_p_bi_contiguous"),
    (0xe44060a1, "st3b_z_p_br_contiguous"),
    (0xe5d0e0a1, "st3d_z_p_bi_contiguous"),
    (0xe5c060a1, "st3d_z_p_br_contiguous"),
    (0xe4d0e0a1, "st3h_z_p_bi_contiguous"),
    (0xe4c060a1, "st3h_z_p_br_contiguous"),
    (0xe48000a1, "st3q_z_p_bi_contiguous"),
    (0xe4a000a1, "st3q_z_p_br_contiguous"),
    (0xe550e0a1, "st3w_z_p_bi_contiguous"),
    (0xe54060a1, "st3w_z_p_br_contiguous"),
    (0xe470e0a1, "st4b_z_p_bi_contiguous"),
    (0xe46060a1, "st4b_z_p_br_contiguous"),
    (0xe5f0e0a1, "st4d_z_p_bi_contiguous"),
    (0xe5e060a1, "st4d_z_p_br_contiguous"),
    (0xe4f0e0a1, "st4h_z_p_bi_contiguous"),
    (0xe4e060a1, "st4h_z_p_br_contiguous"),
    (0xe4c000a1, "st4q_z_p_bi_contiguous"),
    (0xe4e000a1, "st4q_z_p_br_contiguous"),
    (0xe570e0a1, "st4w_z_p_bi_contiguous"),
    (0xe56060a1, "st4w_z_p_br_contiguous"),
    (0xe410e0a1, "stnt1b_z_p_bi_contiguous"),
    (0xe40060a1, "stnt1b_z_p_br_contiguous"),
    (0xe590e0a1, "stnt1d_z_p_bi_contiguous"),
    (0xe58060a1, "stnt1d_z_p_br_contiguous"),
    (0xe490e0a1, "stnt1h_z_p_bi_contiguous"),
    (0xe48060a1, "stnt1h_z_p_br_contiguous"),
    (0xe510e0a1, "stnt1w_z_p_bi_contiguous"),
    (0xe50060a1, "stnt1w_z_p_br_contiguous"),
    (0xe58000a1, "str_p_bi_"),
    (0xe58040a1, "str_z_bi_"),
];

fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn profile(bytes: usize, streaming: bool, quadword: bool) -> ScalableProfile {
    let mut features = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
    if quadword {
        features = features.with(ScalableFeature::Sme2p1);
    }
    ScalableProfile::new_with_features(
        VectorLength::from_bytes(bytes).unwrap(),
        ScalableMode::new(streaming, false),
        features,
        ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
    )
    .unwrap()
}

#[test]
fn all_store_forms_dispatch_exact_bodies_and_maps_at_every_length() {
    for (word, canonical_id) in FORMS {
        let operand = memory_store::decode(word).unwrap().unwrap();
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::MemoryStore(operand))),
            "{canonical_id}"
        );
        for bytes in [16, 32, 64, 128, 256] {
            let profile = profile(bytes, true, true);
            let native = compile_for_profile(
                &source(&[word, RET_X30]),
                GUEST_BASE,
                profile,
                TargetCpu::Baseline,
            )
            .unwrap();
            let mut expected = Vec::new();
            x86_64::sve::memory_store::emit(
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
                expected,
                "{canonical_id} at SVL {bytes}"
            );
            assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
            assert_eq!(
                memory_requirements(
                    &source(&[word, RET_X30]),
                    GUEST_BASE,
                    profile,
                    TargetCpu::Baseline
                )
                .unwrap(),
                x86_64::sve::memory_store::requirements(&operand),
            );
        }
    }
}

#[test]
fn stores_preflight_write_caps_tags_and_original_sp_for_the_complete_body() {
    let profile = profile(16, true, true);
    let requirements = |words: &[u32]| {
        memory_requirements(&source(words), GUEST_BASE, profile, TargetCpu::Baseline).unwrap()
    };
    assert_eq!(
        requirements(&[NOP, PRFB_P0_SP, RET_X30]),
        MemoryRequirements::default()
    );
    assert_eq!(
        requirements(&[ST1B_Z1_P0_SP, RET_X30]),
        MemoryRequirements {
            required_pointer_arithmetic: None,
            required_address_checks: Default::default(),
            required_flags: flags::WRITE | flags::SVE_PREDICATED,
            required_host_caps: 0,
            required_profile: profile_requirements::NATIVE_ACCESS,
            required_sp_alignment: SpAlignmentRequirement::Enabled,
        }
    );
    assert_eq!(
        requirements(&[STR_Z1_X5, RET_X30]),
        MemoryRequirements {
            required_pointer_arithmetic: None,
            required_address_checks: Default::default(),
            required_flags: flags::WRITE | flags::TAG_CHECKED,
            required_host_caps: 0,
            required_profile: profile_requirements::NATIVE_ACCESS
                | profile_requirements::TAG_GRANULES
                | profile_requirements::SCALABLE_TAG_CHECKS,
            required_sp_alignment: SpAlignmentRequirement::Any,
        }
    );
    assert_eq!(
        requirements(&[NOP, ST1B_Z1_P0_SP, STNT1D_Z1_P0_X5, ST2Q_Z1_P0_X5, RET_X30]),
        MemoryRequirements {
            required_pointer_arithmetic: None,
            required_address_checks: Default::default(),
            required_flags: flags::WRITE
                | flags::TAG_CHECKED
                | flags::NON_TEMPORAL
                | flags::SVE_PREDICATED,
            required_host_caps: host_caps::CX16,
            required_profile: profile_requirements::NATIVE_ACCESS
                | profile_requirements::TAG_GRANULES
                | profile_requirements::SCALABLE_TAG_CHECKS,
            required_sp_alignment: SpAlignmentRequirement::Enabled,
        }
    );
}

#[test]
fn scan_and_compile_share_reserved_mode_and_q_feature_declines() {
    for (word, profile, reason) in [
        (
            RESERVED_ST1B_Z1_P0_X5_XZR,
            profile(16, true, true),
            "reserved streaming store",
        ),
        (
            RESERVED_ST1H_BYTE_SOURCE,
            profile(16, true, true),
            "reserved streaming store",
        ),
        (
            ST1B_Z1_P0_SP,
            profile(16, false, true),
            "streaming mode required",
        ),
        (
            PRFB_P0_SP,
            profile(16, false, true),
            "streaming mode required",
        ),
        (ST2Q_Z1_P0_X5, profile(16, true, false), "FEAT_SME2p1"),
    ] {
        let source = source(&[word, RET_X30]);
        let scan =
            memory_requirements(&source, GUEST_BASE, profile, TargetCpu::Baseline).unwrap_err();
        let compile =
            compile_for_profile(&source, GUEST_BASE, profile, TargetCpu::Baseline).unwrap_err();
        assert_eq!(scan.0, compile.0);
        assert!(scan.0.contains(reason), "{}", scan.0);
    }
}
