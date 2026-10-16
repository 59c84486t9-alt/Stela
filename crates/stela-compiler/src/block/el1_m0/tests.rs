use super::*;
use crate::block::{BlockProfile, CompilationPlan, EL1_M0_INTEGER_BLOCK_ABI};
use alloc::vec::Vec;
const ADRP_X0: u32 = 0x9000_0000;
const ADD_X0: u32 = 0x9100_0000;
const LDR_X1: u32 = 0x5800_1bc1;
const BL: u32 = 0x9400_139f;
const RET: u32 = 0xd65f_03c0;
fn bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}
#[test]
fn generic_entry_plan_splits_before_ram_and_preserves_call_return() {
    for base in [0x100000, 0x200000, 0x4020000000] {
        let profile = BlockProfile::El1M0IntegerV1;
        assert_eq!(profile.abi(), EL1_M0_INTEGER_BLOCK_ABI);
        let plan = CompilationPlan::new(
            &bytes(&[ADRP_X0, ADD_X0, LDR_X1, BL]),
            GuestAddress(base),
            profile,
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(plan.source_bytes(), 8);
        assert!(
            plan.memory_requirements().is_none() && plan.el1_m0_intent() == Some(Intent::Registers)
        );
        assert_eq!(plan.compile().unwrap().native.source_map.len(), 2);
        let plan = CompilationPlan::new(
            &bytes(&[LDR_X1, BL]),
            GuestAddress(base + 8),
            profile,
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(plan.source_bytes(), 4);
        assert_eq!(
            plan.el1_m0_intent(),
            Some(Intent::LiteralRead64(LiteralRead64 {
                source_pc: GuestAddress(base + 8),
                address: base + 0x380,
                destination: Register::X(1)
            }))
        );
        let requirements = plan.memory_requirements().unwrap();
        assert_eq!(
            requirements.required_profile,
            profile_requirements::M0_DEVICE_RAM_READ64
        );
        assert_eq!(requirements.required_flags, 0);
        assert_eq!(requirements.required_host_caps, 0);
        assert_eq!(plan.compile().unwrap().native.source_map.len(), 1);
        for (word, pc) in [(BL, base + 12), (RET, base + 0x4e88)] {
            let plan = CompilationPlan::new(
                &word.to_le_bytes(),
                GuestAddress(pc),
                profile,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(plan.source_bytes(), 4);
            assert!(plan.memory_requirements().is_none());
            assert_eq!(plan.compile().unwrap().native.source_map.len(), 1);
        }
    }
}
#[test]
fn unadmitted_effects_decline_instead_of_using_direct_memory_or_services() {
    for word in [
        0xd5034fdf_u32,
        0xf9400020,
        0xf9000020,
        0x18000000,
        0x98000000,
        0x5c000000,
        0x54000000,
        0xd61f0000,
        0xd63f0000,
        0xd4000001,
        0x910003e0,
        0xb1000000,
    ] {
        assert!(
            CompilationPlan::new(
                &word.to_le_bytes(),
                GuestAddress(0x100000),
                BlockProfile::El1M0IntegerV1,
                TargetCpu::Baseline
            )
            .is_err(),
            "{word:08x}"
        );
    }
    let plan = CompilationPlan::new(
        &bytes(&[LDR_X1, 0xd5034fdf]),
        GuestAddress(0x100008),
        BlockProfile::El1M0IntegerV1,
        TargetCpu::Baseline,
    )
    .unwrap();
    assert_eq!(plan.source_bytes(), 4);
}
