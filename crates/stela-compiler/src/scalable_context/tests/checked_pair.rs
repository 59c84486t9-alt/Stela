//! Checked store-pair routing.
use super::*;
use crate::{
    block::{BlockProfile, CheckedMemoryProfile, CompilationPlan, Features},
    context::memory::{SpAlignmentRequirement, flags, host_caps},
};
use alloc::vec::Vec;

const BASE: GuestAddress = GuestAddress(0x1000);
const RET: u32 = 0xd65f_03c0;
const FORMS: [u32; 8] = [
    0x2900_0000,
    0x2980_0000,
    0x2880_0000,
    0xa900_0000,
    0xa980_0000,
    0xa880_0000,
    0x2800_0000,
    0xa800_0000,
];
const REGISTER_MASK: u32 = 31;
const BASE_SHIFT: u32 = 5;
const SECOND_DATA_SHIFT: u32 = 10;

fn word(form: u32, base: u32) -> u32 {
    form | (base << BASE_SHIFT) | (1 << SECOND_DATA_SHIFT)
}

#[test]
fn all_store_pair_forms_reach_checked_whole_plan_and_keep_source_intervals() {
    for recipe in [
        CheckedMemoryProfile::SpAlignmentEnabled,
        CheckedMemoryProfile::SpAlignmentDisabled,
    ] {
        for form in FORMS {
            for base in [2, REGISTER_MASK] {
                let instruction = Decoder.lift(BASE, word(form, base)).unwrap();
                let decoded = Decoded::checked_ordinary(instruction, recipe).unwrap();
                assert!(matches!(decoded, Decoded::MemoryPair(_)));
                let required = decoded.memory_requirements();
                assert_eq!(
                    required.required_flags & (flags::WRITE | flags::PAIR),
                    flags::WRITE | flags::PAIR
                );
                assert_eq!(required.required_flags & flags::ASIMD, 0);
                assert_eq!(
                    required.required_sp_alignment,
                    if base == REGISTER_MASK {
                        recipe.sp_requirement()
                    } else {
                        SpAlignmentRequirement::Any
                    }
                );
                if form >> 31 != 0 && recipe == CheckedMemoryProfile::SpAlignmentDisabled {
                    assert_eq!(required.required_host_caps, host_caps::CX16);
                }
                let source: Vec<_> = [word(form, base), RET]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect();
                for profile in [
                    BlockProfile::ORDINARY.with_checked_memory(recipe),
                    BlockProfile::new(Features::PROCESS_HELPERS).with_checked_memory(recipe),
                ] {
                    let plan = CompilationPlan::new(
                        &source,
                        BASE,
                        &crate::Options::new(profile, TargetCpu::Cx16),
                    )
                    .unwrap();
                    assert_eq!(plan.memory_requirements(), Some(required));
                    let compiled = plan.compile().unwrap();
                    assert_eq!(
                        compiled
                            .native
                            .source_map
                            .iter()
                            .map(|(pc, _)| *pc)
                            .collect::<Vec<_>>(),
                        [BASE, GuestAddress(BASE.0 + size_of::<u32>() as u64)]
                    );
                }
            }
        }
    }
}

#[test]
fn constrained_store_writeback_overlap_stays_decoder_nop_without_memory_requirements() {
    for form in [0x2980_0000, 0x2880_0000, 0xa980_0000, 0xa880_0000] {
        for recipe in [
            CheckedMemoryProfile::SpAlignmentEnabled,
            CheckedMemoryProfile::SpAlignmentDisabled,
        ] {
            // Rt is X0 and the base is X0. The decoder owns the source-permitted NOP.
            let instruction = Decoder.lift(BASE, word(form, 0)).unwrap();
            assert!(matches!(instruction.operation, Operation::Nop));
            let decoded = Decoded::checked_ordinary(instruction, recipe).unwrap();
            assert!(matches!(decoded, Decoded::Ordinary(_)));
            assert_eq!(decoded.memory_requirements(), Default::default());
        }
    }
}

#[test]
fn load_pairs_reach_checked_plans_without_store_or_asimd_permission() {
    let forms = [
        0x2940_0000,
        0x29c0_0000,
        0x28c0_0000,
        0xa940_0000,
        0xa9c0_0000,
        0xa8c0_0000,
        0x6940_0000,
        0x69c0_0000,
        0x68c0_0000,
        0x2840_0000,
        0xa840_0000,
    ];
    for recipe in [
        CheckedMemoryProfile::SpAlignmentEnabled,
        CheckedMemoryProfile::SpAlignmentDisabled,
    ] {
        for form in forms {
            for base in [2, REGISTER_MASK] {
                let load = word(form, base);
                let instruction = Decoder.lift(BASE, load).unwrap();
                let decoded = Decoded::checked_ordinary(instruction, recipe).unwrap();
                assert!(matches!(decoded, Decoded::MemoryPair(_)));
                let required = decoded.memory_requirements();
                assert_eq!(
                    required.required_flags & (flags::PAIR | flags::WRITE | flags::ASIMD),
                    flags::PAIR
                );
                assert_eq!(required.required_host_caps, host_caps::ATOMIC_LOAD16);
                let source: Vec<_> = [load, RET].into_iter().flat_map(u32::to_le_bytes).collect();
                for profile in [
                    BlockProfile::ORDINARY.with_checked_memory(recipe),
                    BlockProfile::new(Features::PROCESS_HELPERS).with_checked_memory(recipe),
                ] {
                    let plan = CompilationPlan::new(
                        &source,
                        BASE,
                        &crate::Options::new(profile, TargetCpu::AtomicLoad16),
                    )
                    .unwrap();
                    assert_eq!(plan.memory_requirements(), Some(required));
                    let compiled = plan.compile().unwrap();
                    assert_eq!(
                        compiled
                            .native
                            .source_map
                            .iter()
                            .map(|(pc, _)| *pc)
                            .collect::<Vec<_>>(),
                        [BASE, GuestAddress(BASE.0 + 4)]
                    );
                }
            }
        }
    }
}
