use super::*;
use crate::aarch64::sve::memory_load;

const LD1B_Z1_P0_X5: u32 = 0xa400_a0a1;
const LD1D_Z1_P0_X5: u32 = 0xa5e0_a0a1;
const LD1D_Z1_P0_SP: u32 = 0xa5e0_a3e1;

fn decoded(word: u32) -> Operand {
    memory_load::decode(word).unwrap().unwrap()
}

#[test]
fn preflight_distinguishes_checked_bytes_generic_reads_and_aligned_sp() {
    let checked = flags::TAG_CHECKED | flags::SVE_PREDICATED;
    let checked_profile = profile_requirements::NATIVE_ACCESS
        | profile_requirements::TAG_GRANULES
        | profile_requirements::SCALABLE_TAG_CHECKS;
    assert_eq!(
        requirements(decoded(LD1B_Z1_P0_X5)),
        MemoryRequirements {
            required_pointer_arithmetic: None,
            required_address_checks: Default::default(),
            required_sp_alignment: SpAlignmentRequirement::Any,
            required_flags: checked,
            required_host_caps: 0,
            required_profile: checked_profile,
        }
    );
    assert_eq!(
        requirements(decoded(LD1D_Z1_P0_X5)),
        MemoryRequirements {
            required_pointer_arithmetic: None,
            required_address_checks: Default::default(),
            required_sp_alignment: SpAlignmentRequirement::Any,
            required_flags: checked,
            required_host_caps: host_caps::ATOMIC_LOAD16,
            required_profile: checked_profile,
        }
    );
    assert_eq!(
        requirements(decoded(LD1D_Z1_P0_SP)),
        MemoryRequirements {
            required_pointer_arithmetic: None,
            required_address_checks: Default::default(),
            required_sp_alignment: SpAlignmentRequirement::Enabled,
            required_flags: flags::SVE_PREDICATED,
            required_host_caps: 0,
            required_profile: profile_requirements::NATIVE_ACCESS,
        }
    );
}
