//! Source descriptor and entry validation.
use super::BoundSource;
use crate::blocks::{BlockRuntime, ThreadState};
use stela_compiler::{
    GuestAddress, GuestState,
    block::{BlockProfile, CheckedMemoryProfile},
};
const BASE: GuestAddress = GuestAddress(0x4000);
const TARGET: GuestAddress = GuestAddress(0x4008);
const B_PLUS8: u32 = 0x1400_0002;
fn runtime(cache: &std::path::Path, profile: BlockProfile) -> BlockRuntime {
    let mut runtime = BlockRuntime::new_with_profile(73, cache.to_owned(), profile);
    runtime
        .register_code(BASE, B_PLUS8.to_le_bytes().to_vec())
        .unwrap();
    runtime
}
#[test]
fn exact_branch_bound_source_retains_none_and_canonical_target_without_entry() {
    let cache = tempfile::tempdir().unwrap();
    let mut runtime = runtime(cache.path(), BlockProfile::El1DirectBranchV1);
    let mut accounting = super::super::empty_accounting();
    runtime.load(BASE, &mut accounting).unwrap();
    let bound = BoundSource::new(&runtime, BASE).unwrap();
    assert_eq!(bound.direct_branch_target().unwrap(), TARGET);
    assert!(bound.memory_requirements().is_err());
    assert!(bound.block.prepared.manifest.memory_requirements.is_none());
    assert_eq!(bound.entry.source_bytes(), size_of::<u32>());
    assert_eq!(bound.source, B_PLUS8.to_le_bytes());
    assert_eq!(accounting.blocks_executed, 0);
}
#[test]
fn checked_memory_bound_source_keeps_some_and_cannot_be_el1_branch() {
    let cache = tempfile::tempdir().unwrap();
    let profile = BlockProfile::CheckedMemory(CheckedMemoryProfile::SpAlignmentEnabled);
    let mut runtime = runtime(cache.path(), profile);
    let mut accounting = super::super::empty_accounting();
    runtime.load(BASE, &mut accounting).unwrap();
    let bound = BoundSource::new(&runtime, BASE).unwrap();
    assert_eq!(
        Some(bound.memory_requirements().unwrap()),
        bound.block.prepared.manifest.memory_requirements
    );
    assert!(bound.direct_branch_target().is_err());
    assert_eq!(accounting.blocks_executed, 0);
}
#[test]
fn legacy_entry_refuses_typed_el1_branch_before_body_or_pc_effect() {
    let cache = tempfile::tempdir().unwrap();
    let mut runtime = runtime(cache.path(), BlockProfile::El1DirectBranchV1);
    let mut thread = ThreadState {
        registers: GuestState::default(),
        pc: BASE,
    };
    // SAFETY: owned B source and state with no RAM references. This profile
    // must be refused before any code is loaded or run.
    let returned = unsafe { runtime.run(&mut thread, Some(TARGET), 1) };
    assert!(returned.is_err());
    assert_eq!(thread.pc, BASE);
    assert_eq!(thread.registers, GuestState::default());
    assert!(runtime.loaded.is_empty());
}

#[test]
fn exact_platform_source_keeps_effect_free_and_memory_intent_requirements_distinct() {
    use stela_compiler::block::el1_platform::Intent;
    // Canonical branch, DAIFSet, LDR literal64 and STP X0,X1,[X2].
    for (word, memory) in [
        (B_PLUS8, false),
        (0xd5034fdf, false),
        (0x58000040, true),
        (0x18000040, true),
        (0x98000040, true),
        (0x39400020, true),
        (0xb9400020, true),
        (0x39000020, true),
        (0x79000020, true),
        (0xb9000020, true),
        (0xf9000020, true),
        (0xa9000440, true),
        (0xa9400440, true),
    ] {
        let cache = tempfile::tempdir().unwrap();
        let mut runtime = BlockRuntime::new_with_profile(
            73,
            cache.path().to_owned(),
            BlockProfile::El1PlatformV1,
        );
        runtime
            .register_code(BASE, word.to_le_bytes().to_vec())
            .unwrap();
        let mut accounting = super::super::empty_accounting();
        runtime.load(BASE, &mut accounting).unwrap();
        let bound = BoundSource::new(&runtime, BASE).unwrap();
        let intent = bound.el1_platform_intent().unwrap();
        assert_eq!(
            matches!(
                intent,
                Intent::LiteralRead64(_)
                    | Intent::ScalarLoad(_)
                    | Intent::ScalarStore(_)
                    | Intent::Write64Pair(_)
                    | Intent::Read64Pair(_)
            ),
            memory
        );
        assert_eq!(bound.memory_requirements().is_ok(), memory);
        assert_eq!(
            bound.block.prepared.manifest.memory_requirements.is_some(),
            memory
        );
        assert_eq!(accounting.blocks_executed, 0);
    }
}
