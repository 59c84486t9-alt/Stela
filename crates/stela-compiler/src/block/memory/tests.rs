use super::*;
use alloc::vec::Vec;
#[test]
fn checked_process_helpers_use_distinct_immutable_abi_and_exact_terminals() {
    use crate::block::{BlockProfile, CompilationPlan};
    let base = GuestAddress(0x1000);
    for recipe in [
        CheckedMemoryProfile::SpAlignmentEnabled,
        CheckedMemoryProfile::SpAlignmentDisabled,
    ] {
        let selected = BlockProfile::CheckedMemoryPauthClockThread(recipe);
        assert_ne!(selected.abi(), BlockProfile::CheckedMemory(recipe).abi());
        assert_ne!(
            selected.abi(),
            BlockProfile::AppleArm64eSoftwarePauthClockThreadV1.abi()
        );
        assert!(selected.supports_pointer_authentication());
        assert!(selected.supports_clock());
        assert!(selected.supports_thread_registers());
        assert!(!selected.supports_system());
        for terminal in [0xd503237fu32, 0xd53be040, 0xd5033fdf, 0xd53bd061] {
            // Original MOV X3,#0x44 prefix must survive before the helper.
            let source: Vec<_> = [0xd2800883u32, terminal, 0xd65f03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            let plan =
                CompilationPlan::new(&source, base, selected, crate::TargetCpu::Baseline).unwrap();
            assert_eq!(plan.source_bytes(), 8);
            assert!(plan.memory_requirements().is_some());
            let compiled = plan.compile().unwrap();
            assert_eq!(compiled.native.source_map.len(), 2);
            assert_eq!(compiled.native.source_map[1].0, GuestAddress(base.0 + 4));
            assert!(
                CompilationPlan::new(
                    &source,
                    base,
                    BlockProfile::CheckedMemory(recipe),
                    crate::TargetCpu::Baseline
                )
                .is_err()
            );
        }
        // Authenticated data loads still need the canonical helper reader.
        let load = 0xf8200400u32.to_le_bytes();
        assert!(CompilationPlan::new(&load, base, selected, crate::TargetCpu::Baseline).is_err());
    }
}
#[test]
fn checked_fixed_simd_load_store_routes_through_exact_plan_requirements() {
    use crate::context::memory::{SpAlignmentRequirement, flags, host_caps};
    for profile in [
        CheckedMemoryProfile::SpAlignmentEnabled,
        CheckedMemoryProfile::SpAlignmentDisabled,
    ] {
        for (word, write) in [(0xfd47_b520u32, false), (0xfc19_83a0, true)] {
            let source: Vec<_> = [word, 0xd65f_03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            let plan = crate::block::CompilationPlan::new(
                &source,
                GuestAddress(0x1000),
                crate::block::BlockProfile::CheckedMemoryPauthClockThread(profile),
                TargetCpu::Baseline,
            )
            .unwrap();
            let required = plan.memory_requirements().unwrap();
            assert_eq!(required.required_flags & flags::ASIMD, flags::ASIMD);
            assert_eq!(
                required.required_flags & flags::WRITE,
                if write { flags::WRITE } else { 0 }
            );
            assert_eq!(required.required_sp_alignment, SpAlignmentRequirement::Any);
            assert_eq!(
                required.required_host_caps,
                if write { 0 } else { host_caps::ATOMIC_LOAD16 }
            );
            let native = plan.compile().unwrap();
            assert_eq!(native.native.source_map.len(), 2);
        }
    }
}
#[test]
fn m0_staged_read_never_combines_with_process_helpers() {
    let source = 0xf940_0000u32.to_le_bytes();
    let selected = crate::block::BlockProfile::CheckedMemoryPauthClockThread(
        CheckedMemoryProfile::M0DeviceRamRead64Staged,
    );
    assert!(
        crate::block::CompilationPlan::new(
            &source,
            GuestAddress(0x1000),
            selected,
            TargetCpu::Baseline,
        )
        .is_err()
    );
}
#[test]
fn checked_exclusive_widths_preserve_source_quantity_and_host_requirements() {
    use crate::context::memory::{flags, host_caps, profile_requirements};
    const RET: u32 = 0xd65f_03c0;
    // Existing source decoder/emitter shapes, all with non-SP base X9.
    for (word, element_bytes, members, required_caps) in [
        (0x085f_7d2a_u32, 1, 1, 0),
        (0x485f_7d2a, 2, 1, host_caps::ATOMIC_LOAD16),
        (0x885f_7d2a, 4, 1, host_caps::ATOMIC_LOAD16),
        (0xc85f_7d2a, 8, 1, host_caps::ATOMIC_LOAD16),
        (0x887f_2d2a, 4, 2, host_caps::ATOMIC_LOAD16),
        (0xc87f_2d2a, 8, 2, host_caps::ATOMIC_LOAD16),
    ] {
        let operand = crate::aarch64::exclusive::decode(word).unwrap().unwrap();
        let crate::aarch64::exclusive::Operand::Transfer {
            element_bytes: actual,
            data,
            ..
        } = operand
        else {
            panic!("expected transfer");
        };
        assert_eq!(actual, element_bytes);
        assert_eq!(
            match data {
                crate::aarch64::exclusive::Data::Scalar(_) => 1,
                crate::aarch64::exclusive::Data::Pair(registers) => registers.len(),
            },
            members
        );
        let source: Vec<u8> = [word, RET].into_iter().flat_map(u32::to_le_bytes).collect();
        for recipe in [
            CheckedMemoryProfile::SpAlignmentEnabled,
            CheckedMemoryProfile::SpAlignmentDisabled,
        ] {
            let plan = crate::block::CompilationPlan::new(
                &source,
                GuestAddress(0x1000),
                crate::block::BlockProfile::CheckedMemory(recipe),
                TargetCpu::Baseline,
            )
            .unwrap();
            let requirements = plan
                .memory_requirements()
                .expect("checked body requirements");
            assert_eq!(requirements.required_host_caps, required_caps);
            assert_eq!(
                requirements.required_flags,
                flags::EXCLUSIVE | flags::TAG_CHECKED
            );
            assert_eq!(
                requirements.required_profile,
                profile_requirements::NATIVE_ACCESS | profile_requirements::TAG_GRANULES
            );
            // Actual emission must preserve the same consumed plan and source map.
            let native = plan.compile().unwrap();
            assert!(!native.native.x86_64_code.is_empty());
            assert_eq!(native.native.source_map.len(), 2);
        }
    }
}
fn m0_plan(words: &[u32]) -> Result<crate::block::CompilationPlan, CompileError> {
    let source: Vec<u8> = words.iter().copied().flat_map(u32::to_le_bytes).collect();
    crate::block::CompilationPlan::new(
        &source,
        GuestAddress(0x82eb_408c),
        crate::block::BlockProfile::CheckedMemory(CheckedMemoryProfile::M0DeviceRamRead64Staged),
        TargetCpu::Baseline,
    )
}
#[test]
fn m0_read64_plan_retains_source_flags_and_distinct_requirements() {
    use crate::context::memory::{flags, profile_requirements};
    for base in [0, 20, 30] {
        for data in [0, 22, 31] {
            for displacement in [0, 1, 4095] {
                let word = 0xf940_0000 | (displacement << 10) | (base << 5) | data;
                let plan = m0_plan(&[word]).unwrap();
                let requirements = plan.memory_requirements().unwrap();
                assert_eq!(plan.source_bytes(), size_of::<u32>());
                assert_eq!(requirements.required_flags, flags::TAG_CHECKED);
                assert_eq!(requirements.required_host_caps, 0);
                assert_eq!(
                    requirements.required_profile,
                    profile_requirements::M0_DEVICE_RAM_READ64
                );
                assert_eq!(
                    requirements.required_profile & profile_requirements::NATIVE_ACCESS,
                    0
                );
                assert_eq!(
                    requirements.required_sp_alignment,
                    crate::context::memory::SpAlignmentRequirement::Any
                );
            }
        }
    }
}
#[test]
fn m0_read64_plan_refuses_other_accesses_and_source_prefixes() {
    for word in [
        0xf900_0696, // STR X22,[X20,#8]
        0xb940_0696, // LDR W22,[X20,#4]
        0xf940_07f6, // SP base
        0xf840_8696, // post-index writeback
        0xf840_8e96, // pre-index writeback
        0xf840_0a96, // unprivileged access
        0xb980_0696, // LDRSW
        0xc85f_7d2a, // LDXR X10,[X9]
        0xa940_0696, // LDP
        0xd280_0015, // ordinary MOV prefix is not this one-operation profile
        0xd65f_03c0, // terminator
    ] {
        assert!(
            m0_plan(&[word]).is_err(),
            "unexpected M0 admission: {word:#010x}"
        );
    }
    assert!(m0_plan(&[0xf940_0696, 0xf940_0a97]).is_err());
    assert!(m0_plan(&[0xf940_0696, 0xd65f_03c0]).is_err());
}
#[test]
fn m0_identity_does_not_change_legacy_profile_or_context_layout() {
    assert!(
        CheckedMemoryProfile::M0DeviceRamRead64Staged
            .id()
            .contains("staged")
    );
    assert!(
        !CheckedMemoryProfile::M0DeviceRamRead64Staged
            .abi()
            .contains("normal-wb")
    );
    assert_eq!(crate::context::memory::MEMORY_CONTEXT_VERSION, 1);
    assert_eq!(crate::context::memory::MEMORY_CONTEXT_BYTES, 64);
    assert_eq!(crate::context::memory::MEMORY_REQUEST_BYTES, 32);
    assert_eq!(
        CheckedMemoryProfile::SpAlignmentEnabled.id(),
        "checked-gpr-memory-sa0-on-normal-wb-v3"
    );
    assert_eq!(
        CheckedMemoryProfile::SpAlignmentDisabled.id(),
        "checked-gpr-memory-sa0-off-normal-wb-v3"
    );
}
