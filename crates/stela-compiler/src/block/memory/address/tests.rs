use super::*;
use crate::{
    GuestAddress, TargetCpu,
    block::{BlockProfile, CheckedMemoryProfile, CompilationPlan},
};

const SOURCE_PC: GuestAddress = GuestAddress(0x4000);
const RET_X30: u32 = 0xd65f_03c0;
const LDR_X0_X9_8: u32 = 0xf940_0520;
const STR_X0_X9_8: u32 = 0xf900_0520;
const LDR_X0_X9_PRE8: u32 = 0xf840_8d20;
const LDR_X0_X9_POST8: u32 = 0xf840_8520;
const STR_X0_X9_PRE8: u32 = 0xf800_8d20;
const STR_X0_X9_POST8: u32 = 0xf800_8520;
const LDTR_X1_X9_8: u32 = 0xf840_8921;
const STTR_X1_X9_8: u32 = 0xf800_8921;
const LDR_X0_X9_X10: u32 = 0xf86a_6920;
const LDP_X0_X1_X9_16: u32 = 0xa941_0520;
const STP_X0_X1_X9_16: u32 = 0xa901_0520;
const LDNP_X0_X1_X9_16: u32 = 0xa841_0520;
const LDR_D0_X9_8: u32 = 0xfd40_0520;
const STR_D0_X9_8: u32 = 0xfd00_0520;
const LDP_Q0_Q1_X9_32: u32 = 0xad41_0520;
const LDXR_X10_X9: u32 = 0xc85f_7d2a;

fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

#[test]
fn unchecked_specialization_preserves_every_adapter_body_and_retains_new_requirements() {
    let unchecked =
        EffectiveAddressChecks::new(AddressAddChecks::Disabled, AddressAddChecks::Disabled);
    for original in [
        CheckedMemoryProfile::SpAlignmentEnabled,
        CheckedMemoryProfile::SpAlignmentDisabled,
    ] {
        for word in [
            LDR_X0_X9_8,
            STR_X0_X9_8,
            LDR_X0_X9_PRE8,
            LDR_X0_X9_POST8,
            STR_X0_X9_PRE8,
            STR_X0_X9_POST8,
            LDTR_X1_X9_8,
            STTR_X1_X9_8,
            LDR_X0_X9_X10,
            LDP_X0_X1_X9_16,
            STP_X0_X1_X9_16,
            LDNP_X0_X1_X9_16,
            LDR_D0_X9_8,
            STR_D0_X9_8,
            LDP_Q0_Q1_X9_32,
            LDXR_X10_X9,
        ] {
            let bytes = source(&[word, RET_X30]);
            let legacy = CompilationPlan::new(
                &bytes,
                SOURCE_PC,
                BlockProfile::CheckedMemory(original),
                TargetCpu::Baseline,
            )
            .unwrap();
            assert!(
                legacy
                    .memory_requirements()
                    .unwrap()
                    .required_address_checks
                    .is_empty()
            );
            let selected = original.with_address_checks(AccessEl::El0, AccessEl::El0, unchecked);
            let specialized = CompilationPlan::new(
                &bytes,
                SOURCE_PC,
                BlockProfile::CheckedMemory(selected),
                TargetCpu::Baseline,
            )
            .unwrap();
            let required = specialized
                .memory_requirements()
                .unwrap()
                .required_address_checks;
            assert!(!required.is_empty());
            assert!(required.matches(unchecked, IncrementChoice::Unchecked));
            let legacy = legacy.compile().unwrap();
            let specialized = specialized.compile().unwrap();
            assert_eq!(legacy.source_bytes, bytes.len());
            assert_eq!(specialized.source_bytes, bytes.len());
            assert_eq!(legacy.native.x86_64_code, specialized.native.x86_64_code);
            assert_eq!(legacy.native.source_map, specialized.native.source_map);
        }
    }
}

#[test]
fn source_plan_keeps_normal_and_unprivileged_access_levels_in_one_block() {
    let effects =
        EffectiveAddressChecks::new(AddressAddChecks::Disabled, AddressAddChecks::Enabled);
    let profile = CheckedMemoryProfile::SpAlignmentDisabled.with_address_checks(
        AccessEl::El1,
        AccessEl::El0,
        effects,
    );
    let bytes = source(&[LDR_X0_X9_8, LDTR_X1_X9_8, RET_X30]);
    let plan = CompilationPlan::new(
        &bytes,
        SOURCE_PC,
        BlockProfile::CheckedMemory(profile),
        TargetCpu::Baseline,
    )
    .unwrap();
    let required = plan.memory_requirements().unwrap().required_address_checks;
    assert!(required.matches(effects, IncrementChoice::Unchecked));
    assert!(!required.matches(
        EffectiveAddressChecks::new(AddressAddChecks::Enabled, AddressAddChecks::Enabled),
        IncrementChoice::Unchecked,
    ));
    assert!(!required.matches(
        EffectiveAddressChecks::new(AddressAddChecks::Disabled, AddressAddChecks::Disabled),
        IncrementChoice::Unchecked,
    ));
    let compiled = plan.compile().unwrap();
    assert_eq!(compiled.source_bytes, bytes.len());
    assert_eq!(compiled.native.source_map.len(), 3);
}
