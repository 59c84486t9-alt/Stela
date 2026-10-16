//! SVE load dispatch, source maps and requirements.
use super::*;
use crate::aarch64::sve::memory_load;
use crate::context::memory::{SpAlignmentRequirement, flags, host_caps, profile_requirements};
use alloc::vec;
use alloc::vec::Vec;

const RET_X30: u32 = 0xd65f_03c0;
const NOP: u32 = 0xd503_201f;
const BRANCH_PAST_LEAF: u32 = 0x1400_0002;
const LD1B_Z1_P0_X5: u32 = 0xa400_a0a1;
const LD1D_Z1_P0_X5: u32 = 0xa5e0_a0a1;
const LD1D_Z1_P0_SP: u32 = 0xa5e0_a3e1;
const RESERVED_LD1B_Z1_P0_X5_XZR: u32 = 0xa41f_40a1;
const GUEST_BASE: GuestAddress = GuestAddress(0x1000);
const WORDS: [u32; 66] = [
    0xa420a0a1, // ld1b_z_p_bi_u16
    0xa440a0a1, // ld1b_z_p_bi_u32
    0xa460a0a1, // ld1b_z_p_bi_u64
    0xa400a0a1, // ld1b_z_p_bi_u8
    0xa42040a1, // ld1b_z_p_br_u16
    0xa44040a1, // ld1b_z_p_br_u32
    0xa46040a1, // ld1b_z_p_br_u64
    0xa40040a1, // ld1b_z_p_br_u8
    0xa5e0a0a1, // ld1d_z_p_bi_u64
    0xa5e040a1, // ld1d_z_p_br_u64
    0xa4a0a0a1, // ld1h_z_p_bi_u16
    0xa4c0a0a1, // ld1h_z_p_bi_u32
    0xa4e0a0a1, // ld1h_z_p_bi_u64
    0xa4a040a1, // ld1h_z_p_br_u16
    0xa4c040a1, // ld1h_z_p_br_u32
    0xa4e040a1, // ld1h_z_p_br_u64
    0x8440a0a1, // ld1rb_z_p_bi_u16
    0x8440c0a1, // ld1rb_z_p_bi_u32
    0x8440e0a1, // ld1rb_z_p_bi_u64
    0x844080a1, // ld1rb_z_p_bi_u8
    0x85c0e0a1, // ld1rd_z_p_bi_u64
    0x84c0a0a1, // ld1rh_z_p_bi_u16
    0x84c0c0a1, // ld1rh_z_p_bi_u32
    0x84c0e0a1, // ld1rh_z_p_bi_u64
    0xa40020a1, // ld1rqb_z_p_bi_u8
    0xa40000a1, // ld1rqb_z_p_br_contiguous
    0xa58020a1, // ld1rqd_z_p_bi_u64
    0xa58000a1, // ld1rqd_z_p_br_contiguous
    0xa48020a1, // ld1rqh_z_p_bi_u16
    0xa48000a1, // ld1rqh_z_p_br_contiguous
    0xa50020a1, // ld1rqw_z_p_bi_u32
    0xa50000a1, // ld1rqw_z_p_br_contiguous
    0x85c0c0a1, // ld1rsb_z_p_bi_s16
    0x85c0a0a1, // ld1rsb_z_p_bi_s32
    0x85c080a1, // ld1rsb_z_p_bi_s64
    0x8540a0a1, // ld1rsh_z_p_bi_s32
    0x854080a1, // ld1rsh_z_p_bi_s64
    0x84c080a1, // ld1rsw_z_p_bi_s64
    0x8540c0a1, // ld1rw_z_p_bi_u32
    0x8540e0a1, // ld1rw_z_p_bi_u64
    0xa5c0a0a1, // ld1sb_z_p_bi_s16
    0xa5a0a0a1, // ld1sb_z_p_bi_s32
    0xa580a0a1, // ld1sb_z_p_bi_s64
    0xa5c040a1, // ld1sb_z_p_br_s16
    0xa5a040a1, // ld1sb_z_p_br_s32
    0xa58040a1, // ld1sb_z_p_br_s64
    0xa520a0a1, // ld1sh_z_p_bi_s32
    0xa500a0a1, // ld1sh_z_p_bi_s64
    0xa52040a1, // ld1sh_z_p_br_s32
    0xa50040a1, // ld1sh_z_p_br_s64
    0xa480a0a1, // ld1sw_z_p_bi_s64
    0xa48040a1, // ld1sw_z_p_br_s64
    0xa540a0a1, // ld1w_z_p_bi_u32
    0xa560a0a1, // ld1w_z_p_bi_u64
    0xa54040a1, // ld1w_z_p_br_u32
    0xa56040a1, // ld1w_z_p_br_u64
    0xa400e0a1, // ldnt1b_z_p_bi_contiguous
    0xa400c0a1, // ldnt1b_z_p_br_contiguous
    0xa580e0a1, // ldnt1d_z_p_bi_contiguous
    0xa580c0a1, // ldnt1d_z_p_br_contiguous
    0xa480e0a1, // ldnt1h_z_p_bi_contiguous
    0xa480c0a1, // ldnt1h_z_p_br_contiguous
    0xa500e0a1, // ldnt1w_z_p_bi_contiguous
    0xa500c0a1, // ldnt1w_z_p_br_contiguous
    0x858000a1, // ldr_p_bi_
    0x858040a1, // ldr_z_bi_
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
fn all_load_forms_dispatch_exact_bodies_and_source_maps_at_every_length() {
    for word in WORDS {
        let operand = memory_load::decode(word).unwrap().unwrap();
        assert_eq!(
            crate::aarch64::sve::decode(word),
            Some(Ok(crate::aarch64::sve::Operand::MemoryLoad(operand)))
        );
        for bytes in [16, 32, 64, 128, 256] {
            let profile = profile(bytes, true);
            let native = compile_for_profile(
                &source(&[word, RET_X30]),
                GUEST_BASE,
                profile,
                TargetCpu::Baseline,
            )
            .unwrap();
            let mut expected = Vec::new();
            x86_64::sve::memory_load::emit(
                &mut expected,
                operand,
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
                memory_requirements(
                    &source(&[word, RET_X30]),
                    GUEST_BASE,
                    profile,
                    TargetCpu::Baseline
                )
                .unwrap(),
                x86_64::sve::memory_load::requirements(operand),
            );
        }
    }
}

#[test]
fn requirements_cover_the_complete_body_and_explicit_pure_case() {
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
            &source(&[LD1B_Z1_P0_X5, LD1D_Z1_P0_SP, LD1D_Z1_P0_X5, RET_X30]),
            GUEST_BASE,
            profile,
            TargetCpu::Baseline,
        )
        .unwrap(),
        MemoryRequirements {
            required_pointer_arithmetic: None,
            required_address_checks: Default::default(),
            required_flags: flags::TAG_CHECKED | flags::SVE_PREDICATED,
            required_host_caps: host_caps::ATOMIC_LOAD16,
            required_profile: profile_requirements::NATIVE_ACCESS
                | profile_requirements::TAG_GRANULES
                | profile_requirements::SCALABLE_TAG_CHECKS,
            required_sp_alignment: SpAlignmentRequirement::Enabled,
        }
    );
}

#[test]
fn scan_and_compile_share_input_reserved_and_mode_declines() {
    for (source, base, profile) in [
        (Vec::new(), GUEST_BASE, profile(16, true)),
        (
            source(&[BRANCH_PAST_LEAF, RET_X30]),
            GUEST_BASE,
            profile(16, true),
        ),
        (vec![0; 3], GUEST_BASE, profile(16, true)),
        (
            source(&[RET_X30]),
            GuestAddress(GUEST_BASE.0 + 1),
            profile(16, true),
        ),
        (source(&[LD1B_Z1_P0_X5]), GUEST_BASE, profile(16, true)),
        (
            source(&[RESERVED_LD1B_Z1_P0_X5_XZR, RET_X30]),
            GUEST_BASE,
            profile(16, true),
        ),
        (
            source(&[LD1B_Z1_P0_X5, RET_X30]),
            GUEST_BASE,
            profile(16, false),
        ),
    ] {
        let scan = memory_requirements(&source, base, profile, TargetCpu::Baseline).unwrap_err();
        let compile = compile_for_profile(&source, base, profile, TargetCpu::Baseline).unwrap_err();
        assert_eq!(scan.0, compile.0);
    }
}
