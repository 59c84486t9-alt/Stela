use super::*;
use alloc::vec::Vec;

#[test]
fn private_scratch_is_bounded_aligned_and_disjoint() {
    for vector_bytes in [16, 32, 64, 128, 256] {
        for registers in [2, 4] {
            let tuple_bytes = vector_bytes * registers;
            let scratch = Scratch::new(tuple_bytes);
            assert_eq!(scratch.bytes % STACK_ALIGNMENT, 0);
            assert!(scratch.data >= MASK_OFFSET + tuple_bytes.div_ceil(8) as u32);
            assert_eq!(scratch.bytes, scratch.data + tuple_bytes as u32);
            assert!(scratch.bytes <= 1200);
        }
    }
}

#[test]
fn one_callback_site_handles_all_lengths_and_restores_stack_on_each_exit() {
    for vector_bytes in [16, 32, 64, 128, 256] {
        let length = VectorLength::from_bytes(vector_bytes).unwrap();
        for word in [0xa040_0000, 0xa060_e001, 0xa03f_6000, 0xa040_03e0] {
            let operand = crate::aarch64::sve::memory_multi::decode(word)
                .unwrap()
                .unwrap();
            let mut code = Vec::new();
            emit(&mut code, &operand, length, TargetCpu::Baseline, 0x1000);
            let scratch = Scratch::new(usize::from(operand.registers) * vector_bytes);
            assert!(code.starts_with(SUB_RSP_IMM32));
            let cleanup = [ADD_RSP_IMM32, &scratch.bytes.to_le_bytes()].concat();
            assert_eq!(
                code.windows(cleanup.len())
                    .filter(|bytes| *bytes == cleanup)
                    .count(),
                1
            );
            assert_eq!(
                code.windows(3)
                    .filter(|bytes| *bytes == [0xff, 0x57, 8])
                    .count(),
                1
            );
            assert!(code.len() < 8192);
        }
    }
}

#[test]
fn descriptors_and_preentry_requirements_use_actual_element_widths() {
    use crate::aarch64::sve::memory_multi::decode;
    const LD1B_PAIR_X5: u32 = 0xa040_00a0;
    const LD1D_PAIR_X5: u32 = 0xa040_60a0;
    const LD1D_PAIR_SP: u32 = 0xa040_63e0;
    const LDNT1D_PAIR_SP_REGISTER: u32 = 0xa000_63e1;
    const ST1D_QUAD_X5: u32 = 0xa060_e0a0;
    for (word, descriptor, capabilities, profile) in [
        (
            LD1B_PAIR_X5,
            flags::TAG_CHECKED,
            0,
            profile_requirements::NATIVE_ACCESS | profile_requirements::TAG_GRANULES,
        ),
        (
            LD1D_PAIR_X5,
            flags::TAG_CHECKED,
            host_caps::ATOMIC_LOAD16,
            profile_requirements::NATIVE_ACCESS | profile_requirements::TAG_GRANULES,
        ),
        (LD1D_PAIR_SP, 0, 0, profile_requirements::NATIVE_ACCESS),
        (
            LDNT1D_PAIR_SP_REGISTER,
            flags::TAG_CHECKED | flags::NON_TEMPORAL,
            0,
            profile_requirements::NATIVE_ACCESS | profile_requirements::TAG_GRANULES,
        ),
        (
            ST1D_QUAD_X5,
            flags::TAG_CHECKED | flags::WRITE,
            0,
            profile_requirements::NATIVE_ACCESS | profile_requirements::TAG_GRANULES,
        ),
    ] {
        let operand = decode(word).unwrap().unwrap();
        assert_eq!(
            requirements(&operand),
            MemoryRequirements {
                required_pointer_arithmetic: None,
                required_address_checks: Default::default(),
                required_sp_alignment: if operand.address.base == Register::Sp {
                    SpAlignmentRequirement::Enabled
                } else {
                    SpAlignmentRequirement::Any
                },
                required_flags: descriptor,
                required_host_caps: capabilities,
                required_profile: profile
                    | if operand.tag_checked() {
                        profile_requirements::SCALABLE_TAG_CHECKS
                    } else {
                        0
                    },
            }
        );
        assert_eq!(
            access_flags(&operand) & (flags::SME | flags::SVE_PREDICATED),
            0
        );
    }
}
