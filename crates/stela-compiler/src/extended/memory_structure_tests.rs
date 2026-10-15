//! Structured-load routing, declared features and complete-body requirements.
use super::*;
use crate::context::memory::{SpAlignmentRequirement, flags, host_caps, profile_requirements};

const RET_X30: u32 = 0xd65f_03c0;
const NOP: u32 = 0xd503_201f;
const GUEST_BASE: GuestAddress = GuestAddress(0x1000);
const MAXIMUM_VECTOR_BYTES: usize = 256;
const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];
const SOURCE_BYTES: u64 = size_of::<u32>() as u64;
const DESTINATION_Z31: u32 = 31;
const PREDICATE_P7: u32 = 7 << 10;
const BASE_X5: u32 = 5 << 5;
const BASE_SP: u32 = 31 << 5;
const REGISTER_OFFSET_XZR: u32 = 31 << 16;
const LD2B_IMMEDIATE: u32 = 0xa420_e000;
const LD2Q_IMMEDIATE: u32 = 0xa490_e000;

const CLASSES: [u32; 30] = [
    0xa420_e000, // ld2b_z_p_bi_contiguous
    0xa420_c000, // ld2b_z_p_br_contiguous
    0xa5a0_e000, // ld2d_z_p_bi_contiguous
    0xa5a0_c000, // ld2d_z_p_br_contiguous
    0xa4a0_e000, // ld2h_z_p_bi_contiguous
    0xa4a0_c000, // ld2h_z_p_br_contiguous
    0xa490_e000, // ld2q_z_p_bi_contiguous
    0xa4a0_8000, // ld2q_z_p_br_contiguous
    0xa520_e000, // ld2w_z_p_bi_contiguous
    0xa520_c000, // ld2w_z_p_br_contiguous
    0xa440_e000, // ld3b_z_p_bi_contiguous
    0xa440_c000, // ld3b_z_p_br_contiguous
    0xa5c0_e000, // ld3d_z_p_bi_contiguous
    0xa5c0_c000, // ld3d_z_p_br_contiguous
    0xa4c0_e000, // ld3h_z_p_bi_contiguous
    0xa4c0_c000, // ld3h_z_p_br_contiguous
    0xa510_e000, // ld3q_z_p_bi_contiguous
    0xa520_8000, // ld3q_z_p_br_contiguous
    0xa540_e000, // ld3w_z_p_bi_contiguous
    0xa540_c000, // ld3w_z_p_br_contiguous
    0xa460_e000, // ld4b_z_p_bi_contiguous
    0xa460_c000, // ld4b_z_p_br_contiguous
    0xa5e0_e000, // ld4d_z_p_bi_contiguous
    0xa5e0_c000, // ld4d_z_p_br_contiguous
    0xa4e0_e000, // ld4h_z_p_bi_contiguous
    0xa4e0_c000, // ld4h_z_p_br_contiguous
    0xa590_e000, // ld4q_z_p_bi_contiguous
    0xa5a0_8000, // ld4q_z_p_br_contiguous
    0xa560_e000, // ld4w_z_p_bi_contiguous
    0xa560_c000, // ld4w_z_p_br_contiguous
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
        ScalableControls::new(
            VectorLength::from_bytes(MAXIMUM_VECTOR_BYTES).unwrap(),
            true,
        ),
    )
    .unwrap()
}

#[test]
fn all_structure_forms_dispatch_exact_bodies_and_source_maps_at_every_length() {
    for class in CLASSES {
        let word = class | DESTINATION_Z31 | PREDICATE_P7 | BASE_X5;
        let operand = memory_structure::decode(word).unwrap().unwrap();
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::MemoryStructure(operand)))
        );
        for bytes in LENGTHS {
            let profile = profile(bytes, true, true);
            let input = source(&[word, RET_X30]);
            let native =
                compile_for_profile(&input, GUEST_BASE, profile, TargetCpu::Baseline).unwrap();
            let mut expected = Vec::new();
            x86_64::sve::memory_structure::emit(
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
                        GuestAddress(GUEST_BASE.0 + SOURCE_BYTES),
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
                memory_requirements(&input, GUEST_BASE, profile, TargetCpu::Baseline).unwrap(),
                x86_64::sve::memory_structure::requirements(operand)
            );
        }
    }
}

#[test]
fn structure_scan_and_compile_share_reserved_mode_and_feature_declines() {
    for class in CLASSES {
        let word = class | DESTINATION_Z31 | PREDICATE_P7 | BASE_X5;
        let operand = memory_structure::decode(word).unwrap().unwrap();
        let mut declines = vec![(word, profile(32, false, true))];
        if matches!(
            operand.address.offset,
            crate::aarch64::sve::memory::Offset::Register { .. }
        ) {
            declines.push((word | REGISTER_OFFSET_XZR, profile(32, true, true)));
        }
        if operand.requires_sve2p1_or_sme2p1() {
            declines.push((word, profile(32, true, false)));
        }
        for (word, profile) in declines {
            let input = source(&[NOP, word, RET_X30]);
            let scan =
                memory_requirements(&input, GUEST_BASE, profile, TargetCpu::Baseline).unwrap_err();
            let compile =
                compile_for_profile(&input, GUEST_BASE, profile, TargetCpu::Baseline).unwrap_err();
            assert_eq!(scan.0, compile.0);
        }
    }
}

#[test]
fn structure_requirements_fold_the_complete_body() {
    let input = source(&[
        NOP,
        LD2B_IMMEDIATE | BASE_X5,
        LD2Q_IMMEDIATE | BASE_SP,
        RET_X30,
    ]);
    assert_eq!(
        memory_requirements(
            &input,
            GUEST_BASE,
            profile(16, true, true),
            TargetCpu::Baseline
        )
        .unwrap(),
        MemoryRequirements {
            required_flags: flags::SVE_PREDICATED | flags::TAG_CHECKED,
            required_host_caps: host_caps::ATOMIC_LOAD16,
            required_profile: profile_requirements::NATIVE_ACCESS
                | profile_requirements::TAG_GRANULES
                | profile_requirements::SCALABLE_TAG_CHECKS,
            required_sp_alignment: SpAlignmentRequirement::Enabled,
        }
    );
}
