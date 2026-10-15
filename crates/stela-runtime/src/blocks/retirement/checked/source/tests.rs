//! Canonical descriptor/entry separation, without invoking guest native code.
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
    // SAFETY: own bounded immutable B source/state, no direct RAM references.
    // This selected profile MUST refuse before code loading or native execution;
    // the canonical retained owner is the only admissible entry route.
    let returned = unsafe { runtime.run(&mut thread, Some(TARGET), 1) };
    assert!(returned.is_err());
    assert_eq!(thread.pc, BASE);
    assert_eq!(thread.registers, GuestState::default());
    assert!(runtime.loaded.is_empty());
}
