use super::super::*;
use crate::machine::{
    engine::{NoDevices, tests::FakeHost},
    system::Register,
};
const PC: u64 = 0x4000;
const DATA: u64 = 0x14000;
const LEAF: u64 = 0x13020;
const BINDING: publication::WorkerBinding = publication::WorkerBinding {
    pe: 0,
    worker: publication::WorkerId(0),
};
pub(super) fn fixture() -> (Machine<FakeHost, NoDevices>, Arc<RegisteredSystemRam>) {
    let (mut machine, ram, events) = super::super::super::tests::machine();
    machine
        .install_shared_memory_for_processors(Arc::clone(&ram), &events)
        .unwrap();
    machine.cpu.pc = PC;
    let source: Vec<_> = [0x91000400u32, 0x17ffffff]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(DATA, &source) }.unwrap();
    (machine, ram)
}
fn prepare_artifact(
    machine: &mut Machine<FakeHost, NoDevices>,
    binding: publication::WorkerBinding,
) -> Result<Arc<Artifact>, MemoryStatus> {
    // Preparation only: no POSIX fixture enters a physical native frame.
    let bytes = source_window(machine.cpu.pc, &machine.breakpoints, &machine.traces);
    let run = prepare(
        &mut machine.cpu,
        binding,
        machine.current,
        &machine.profile,
        &machine.profile_missing,
        &machine.admit_table,
        PreparationBoundary {
            source_bytes: bytes,
            translation_generation: machine.translation_generation,
        },
    )
    .map_err(|failure| failure.status)?;
    Ok(Arc::clone(&run.artifact))
}
fn capture_controls(machine: &Machine<FakeHost, NoDevices>) -> Result<Controls, MemoryStatus> {
    Controls::capture(&machine.cpu, machine.profile.name, &machine.profile_missing)
}

fn prepare_failure(
    machine: &mut Machine<FakeHost, NoDevices>,
    binding: publication::WorkerBinding,
) -> PreparationFailure {
    let bytes = source_window(machine.cpu.pc, &machine.breakpoints, &machine.traces);
    match prepare(
        &mut machine.cpu,
        binding,
        machine.current,
        &machine.profile,
        &machine.profile_missing,
        &machine.admit_table,
        PreparationBoundary {
            source_bytes: bytes,
            translation_generation: machine.translation_generation,
        },
    ) {
        Ok(_) => panic!("preparation unexpectedly succeeded"),
        Err(failure) => failure,
    }
}

#[test]
fn preparation_refusal_preserves_source_and_owner_reason_without_execution() {
    use crate::machine::engine::{RequirementKind, Stop};
    let (mut machine, ram) = fixture();
    let state = machine.cpu.state.clone();
    let retired = machine.cpu.retired;
    let el = machine.cpu.pstate.el;
    let failure = prepare_failure(
        &mut machine,
        publication::WorkerBinding { pe: 1, ..BINDING },
    );
    assert_eq!(failure.status, MemoryStatus::Unsupported);
    let Stop::Unsupported(requirement) = failure.into_stop(0, 3) else {
        panic!()
    };
    assert_eq!((requirement.pc, requirement.el), (PC, el));
    let RequirementKind::NativePreparation(detail) = requirement.kind else {
        panic!()
    };
    assert!(detail.contains("worker/frame ownership"));
    assert!(detail.contains("PE=0"));
    assert!(!detail.contains("first_word="));

    // A failed executable walk must keep the original MMU cause.
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(LEAF, &0u64.to_le_bytes()) }.unwrap();
    let failure = prepare_failure(&mut machine, BINDING);
    let rendered = match failure.into_stop(0, 3) {
        Stop::Unsupported(requirement) => alloc::format!("{requirement}"),
        _ => panic!(),
    };
    assert!(rendered.contains("first instruction fetch"));
    assert!(rendered.contains("Fault("));
    assert_eq!(machine.cpu.state, state);
    assert_eq!(machine.cpu.pc, PC);
    assert_eq!(machine.cpu.retired, retired);
    assert_eq!(
        machine
            .cpu
            .canonical_memory
            .as_ref()
            .unwrap()
            .native_artifact_stats()
            .compiled,
        0
    );
}

#[test]
fn warm_controls_reuse_digest_but_observe_every_actual_id_profile_and_missing_input() {
    let (mut machine, _) = fixture();
    prepare_artifact(&mut machine, BINDING).unwrap();
    let original = capture_controls(&machine).unwrap();
    let repeated = capture_controls(&machine).unwrap();
    assert!(Arc::ptr_eq(
        &original.shared_identity(),
        &repeated.shared_identity()
    ));
    for register in [
        Register::ID_AA64DFR0_EL1,
        Register::ID_AA64DFR1_EL1,
        Register::ID_AA64DFR2_EL1,
        Register::ID_AA64ISAR0_EL1,
        Register::ID_AA64ISAR1_EL1,
        Register::ID_AA64ISAR3_EL1,
        Register::ID_AA64MMFR0_EL1,
        Register::ID_AA64MMFR2_EL1,
        Register::ID_AA64PFR1_EL1,
    ] {
        let value = machine.cpu.read(register);
        machine.cpu.registers.set_raw(register, 0, value ^ 1);
        if let Ok(changed) = capture_controls(&machine) {
            assert_ne!(original.identity(), changed.identity(), "{register:?}");
            assert!(!Arc::ptr_eq(
                &original.shared_identity(),
                &changed.shared_identity()
            ));
        }
        machine.cpu.registers.set_raw(register, 0, value);
        machine.profile_missing.push(register);
        assert!(capture_controls(&machine).is_err(), "{register:?}");
        machine.profile_missing.pop();
    }
    let changed = Controls::capture(
        &machine.cpu,
        "another-declared-machine",
        &machine.profile_missing,
    )
    .unwrap();
    assert_ne!(original.identity(), changed.identity());
    // Even an unrelated missing declaration changes the exact reuse key,
    // although it does not alter the established effective-control digest.
    machine.profile_missing.push(Register::TTBR0_EL1);
    let changed = capture_controls(&machine).unwrap();
    assert_eq!(original.identity(), changed.identity());
    assert!(!Arc::ptr_eq(
        &original.shared_identity(),
        &changed.shared_identity()
    ));
    machine.profile_missing.pop();
    assert!(Arc::ptr_eq(
        &original.shared_identity(),
        &capture_controls(&machine).unwrap().shared_identity()
    ));
}

#[test]
fn warm_controls_recheck_translation_requester_sp_permissions_and_debug_state() {
    let (mut machine, _) = fixture();
    prepare_artifact(&mut machine, BINDING).unwrap();
    let original = capture_controls(&machine).unwrap();
    for register in [Register::TTBR0_EL1, Register::TCR_EL1, Register::MAIR_EL1] {
        let value = machine.cpu.read(register);
        machine.cpu.registers.set_raw(register, 0, value ^ 0x1000);
        let changed = capture_controls(&machine).unwrap();
        assert_ne!(original.identity(), changed.identity(), "{register:?}");
        machine.cpu.registers.set_raw(register, 0, value);
    }
    let sctlr = machine.cpu.read(Register::SCTLR_EL1);
    machine
        .cpu
        .registers
        .set_raw(Register::SCTLR_EL1, 0, sctlr ^ (1 << 3));
    let changed = capture_controls(&machine).unwrap();
    assert_ne!(original.sp, changed.sp);
    assert_ne!(original.identity(), changed.identity());
    machine.cpu.registers.set_raw(Register::SCTLR_EL1, 0, sctlr);
    machine.cpu.pstate.pan = !machine.cpu.pstate.pan;
    let changed = capture_controls(&machine).unwrap();
    assert_ne!(original.requester, changed.requester);
    assert_ne!(original.identity(), changed.identity());
    machine.cpu.pstate.pan = !machine.cpu.pstate.pan;
    machine
        .cpu
        .registers
        .set_raw(Register::CPACR_EL1, 0, 3 << 20);
    machine
        .cpu
        .registers
        .set_raw(Register::CPTR_EL2, 0, 3 << 20);
    let enabled = capture_controls(&machine).unwrap();
    assert!(enabled.asimd);
    machine.cpu.registers.set_raw(Register::CPTR_EL2, 0, 0);
    let disabled = capture_controls(&machine).unwrap();
    assert!(!disabled.asimd);
    assert_ne!(enabled.identity(), disabled.identity());
    machine.cpu.pstate.ss = true;
    assert!(capture_controls(&machine).is_err());
}

#[test]
fn cached_controls_are_charged_at_exact_budget_and_tightening_or_reset_clears_them() {
    let (mut machine, _) = fixture();
    prepare_artifact(&mut machine, BINDING).unwrap();
    let controls = capture_controls(&machine).unwrap();
    let mut exact = ArtifactCache::default();
    let bytes = controls.retained_bytes() + exact.slot_bytes();
    exact.tighten(bytes);
    exact.remember_controls(&controls);
    assert_eq!(exact.stats().retained_bytes, bytes);
    assert!(exact.controls().is_some());
    assert!(exact.empty_like().controls().is_none());
    let mut denied = ArtifactCache::default();
    denied.tighten(bytes - 1);
    denied.remember_controls(&controls);
    assert!(denied.controls().is_none());
    exact.tighten(0);
    assert_eq!(exact.stats().retained_bytes, 0);
    assert!(exact.controls().is_none());
    exact.remember_controls(&controls);
    assert!(exact.controls().is_none());
    machine.tighten_native_artifact_cache_budget(0).unwrap();
    let uncached = capture_controls(&machine).unwrap();
    assert!(!Arc::ptr_eq(
        &controls.shared_identity(),
        &uncached.shared_identity()
    ));
}

#[test]
fn repeated_preparation_reuses_only_immutable_artifact_and_refetches_changed_source() {
    let (mut machine, ram) = fixture();
    let first = prepare_artifact(&mut machine, BINDING).unwrap();
    let second = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(first.source.len(), 8);
    // No frame was cached: each attempt still borrows current CPU state.
    machine.cpu.state.x[0] = 0x1234;
    let third = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(Arc::ptr_eq(&first, &third));
    assert_eq!(machine.cpu.state.x[0], 0x1234);
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(DATA, &0x91000800u32.to_le_bytes()) }.unwrap();
    let changed = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&first, &changed));
    assert_ne!(first.identity.source_sha256, changed.identity.source_sha256);
    assert_eq!(
        u32::from_le_bytes(changed.source[..4].try_into().unwrap()),
        0x91000800
    );
    let stats = machine
        .cpu
        .canonical_memory
        .as_ref()
        .unwrap()
        .native_artifact_stats();
    assert_eq!((stats.compiled, stats.reused, stats.entries), (2, 2, 1));
    assert!(stats.retained_bytes <= ARTIFACT_CACHE_BYTES);
}

#[test]
fn actual_return_shares_immutable_provenance_after_artifact_replacement() {
    let (mut machine, ram) = fixture();
    let bytes = source_window(machine.cpu.pc, &machine.breakpoints, &machine.traces);
    let run = prepare(
        &mut machine.cpu,
        BINDING,
        machine.current,
        &machine.profile,
        &machine.profile_missing,
        &machine.admit_table,
        PreparationBoundary {
            source_bytes: bytes,
            translation_generation: machine.translation_generation,
        },
    )
    .unwrap();
    let identity = Arc::clone(&run.artifact.identity);
    let returned = publication::NativeFrame::execute(run, &mut machine.host);
    let observation = returned.observation.as_ref().unwrap();
    // The unassigned test Host refuses entry, while the real frame path
    // constructs its observation from this exact prepared artifact.
    assert_eq!(observation.status, Err(MemoryStatus::Unsupported));
    assert!(Arc::ptr_eq(&identity, &observation.identity));
    let retained = Arc::clone(&observation.identity);
    drop(returned);
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(DATA, &0x91000800u32.to_le_bytes()) }.unwrap();
    let changed = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&retained, &changed.identity));
    assert_ne!(retained.source_sha256, changed.identity.source_sha256);
    assert_eq!(retained, identity);
    machine.tighten_native_artifact_cache_budget(0).unwrap();
    assert_eq!(retained, identity);
}

#[test]
fn warm_revalidation_reads_the_entire_maximum_compiler_window() {
    let (mut machine, ram) = fixture();
    let mut words = [0xd503201fu32; stela_compiler::block::MAX_BLOCK_INSTRUCTIONS];
    *words.last_mut().unwrap() = 0x14000000;
    let source: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(DATA, &source) }.unwrap();
    let first = prepare_artifact(&mut machine, BINDING).unwrap();
    assert_eq!(
        first.source.len(),
        super::super::super::super::MAX_BLOCK_BYTES as usize
    );
    assert!(Arc::ptr_eq(
        &first,
        &prepare_artifact(&mut machine, BINDING).unwrap()
    ));
    let changed_offset = source.len() - 8;
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(DATA + changed_offset as u64, &0x91000400u32.to_le_bytes()) }
        .unwrap();
    let changed = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&first, &changed));
    assert_ne!(first.identity.source_sha256, changed.identity.source_sha256);
    assert_eq!(
        &changed.source[changed_offset..changed_offset + 4],
        &0x91000400u32.to_le_bytes()
    );
}

#[test]
fn unchanged_source_requires_both_actual_chip_policies_and_withheld_features() {
    let (mut machine, _) = fixture();
    let first = prepare_artifact(&mut machine, BINDING).unwrap();
    let chip = machine.profile.chip;
    let table = Arc::clone(&machine.admit_table);
    machine.profile.chip = stela_contracts::Chip::AppleM2;
    let profile = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&first, &profile));
    assert_ne!(
        first.key.admission.profile_chip,
        profile.key.admission.profile_chip
    );
    assert_eq!(
        first.identity.controls_sha256,
        profile.identity.controls_sha256
    );
    assert_eq!(first.source, profile.source);
    machine.profile.chip = chip;
    machine.admit_table = Arc::new(
        stela_contracts::Chip::AppleM2
            .admit_table(table.withheld())
            .unwrap(),
    );
    let table_chip = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&first, &table_chip));
    assert_ne!(
        first.key.admission.table_chip,
        table_chip.key.admission.table_chip
    );
    assert_eq!(first.source, table_chip.source);
    let withheld = table.withheld() ^ (1 << stela_contracts::Feature::FEAT_WFxT as u64);
    machine.admit_table = Arc::new(table.chip().admit_table(withheld).unwrap());
    let features = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&first, &features));
    assert_ne!(
        first.key.admission.withheld,
        features.key.admission.withheld
    );
    assert_eq!(first.source, features.source);
    machine.admit_table = table;
    assert!(Arc::ptr_eq(
        &first,
        &prepare_artifact(&mut machine, BINDING).unwrap()
    ));
}

#[test]
fn unchanged_fp_source_cannot_reuse_admission_after_permission_is_revoked() {
    for word in [0x9e670000, 0x9e630100] {
        // FMOV D0,X0; UCVTF D0,X8
        let (mut machine, ram) = fixture();
        machine
            .cpu
            .registers
            .set_raw(Register::CPACR_EL1, 0, 3 << 20);
        machine
            .cpu
            .registers
            .set_raw(Register::CPTR_EL2, 0, 3 << 20);
        let source: Vec<_> = [0x91000400u32, word, 0x14000000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
        // registered.
        unsafe { ram.publish_physical(DATA, &source) }.unwrap();
        let enabled = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(enabled.key.admission.asimd);
        let expected_bytes = if word == 0x9e630100 { 8 } else { 12 };
        assert_eq!(enabled.source, source[..expected_bytes]);
        assert!(Arc::ptr_eq(
            &enabled,
            &prepare_artifact(&mut machine, BINDING).unwrap()
        ));
        machine.cpu.registers.set_raw(Register::CPTR_EL2, 0, 0);
        let denied = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!denied.key.admission.asimd);
        assert!(!Arc::ptr_eq(&enabled, &denied));
        // Current access controls cut the real GPR prefix before FP,
        // even when the exact canonical source was previously admitted.
        assert_eq!(denied.source, source[..4]);
        machine.cpu.pc = PC + 4;
        let state = machine.cpu.state.clone();
        assert_eq!(
            prepare_artifact(&mut machine, BINDING).err(),
            Some(MemoryStatus::Unsupported)
        );
        assert_eq!(machine.cpu.state, state);
    }
}

#[test]
fn changed_later_source_is_readmitted_before_any_cached_decoder_proof_is_reused() {
    let (mut machine, ram) = fixture();
    let source: Vec<_> = [0x91000400u32, 0x91000421, 0x14000000]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(DATA, &source) }.unwrap();
    let first = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(Arc::ptr_eq(
        &first,
        &prepare_artifact(&mut machine, BINDING).unwrap()
    ));
    // An unallocated nonzero top-level group is denied by AdmitTable,
    // rather than being mistaken for the existing artifact's admitted word.
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(DATA + 4, &0x02000000u32.to_le_bytes()) }.unwrap();
    let changed = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&first, &changed));
    assert_eq!(changed.source, source[..4]);
}
#[test]
fn new_host_points_cut_a_warm_artifact_before_the_observed_instruction() {
    for breakpoint in [false, true] {
        let (mut machine, _) = fixture();
        let full = prepare_artifact(&mut machine, BINDING).unwrap();
        assert_eq!(full.source.len(), 8);
        if breakpoint {
            machine.set_breakpoints(&[PC + 4]);
        } else {
            machine.set_traces(&[PC, PC + 1, PC + 4, PC + 8]);
        }
        let prefix = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&full, &prefix));
        assert_eq!(prefix.source, full.source[..4]);
        assert_eq!(prefix.source_map.len(), 1);
        assert!(Arc::ptr_eq(
            &prefix,
            &prepare_artifact(&mut machine, BINDING).unwrap()
        ));
        machine.set_breakpoints(&[]);
        machine.set_traces(&[]);
        // Removing a point may keep the shorter, still valid boundary.
        assert!(Arc::ptr_eq(
            &prefix,
            &prepare_artifact(&mut machine, BINDING).unwrap()
        ));
    }
}
#[test]
fn controls_worker_and_guarded_leaf_are_actual_cache_identity() {
    let (mut machine, ram) = fixture();
    let first = prepare_artifact(&mut machine, BINDING).unwrap();
    let worker = prepare_artifact(
        &mut machine,
        publication::WorkerBinding {
            worker: publication::WorkerId(7),
            ..BINDING
        },
    )
    .unwrap();
    assert!(!Arc::ptr_eq(&first, &worker));
    let sctlr = machine.cpu.read(Register::SCTLR_EL1);
    machine
        .cpu
        .registers
        .set_raw(Register::SCTLR_EL1, 0, sctlr | (1 << 3));
    let controls = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&first, &controls));
    assert_ne!(
        first.identity.controls_sha256,
        controls.identity.controls_sha256
    );
    machine.cpu.registers.set_raw(Register::SCTLR_EL1, 0, sctlr);
    let mut bytes = [0; 8];
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.read_physical(LEAF, &mut bytes) }.unwrap();
    let descriptor = u64::from_le_bytes(bytes);
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(LEAF, &(descriptor | (1 << 50)).to_le_bytes()) }.unwrap();
    let guarded = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&first, &guarded));
    assert_eq!(
        first.identity.controls_sha256,
        guarded.identity.controls_sha256
    );
    assert!(guarded.key.guarded);
    // Entry BTI validation is fresh even when a guarded artifact exists.
    machine.cpu.pstate.btype = 1;
    assert!(matches!(
        prepare_artifact(&mut machine, BINDING),
        Err(MemoryStatus::Unsupported)
    ));
}
#[test]
fn cached_code_never_bypasses_current_fetch_translation_or_execute_permission() {
    let (mut machine, ram) = fixture();
    let first = prepare_artifact(&mut machine, BINDING).unwrap();
    let mut bytes = [0; 8];
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.read_physical(LEAF, &mut bytes) }.unwrap();
    let descriptor = u64::from_le_bytes(bytes);
    for denied in [0, descriptor | (1 << 53) | (1 << 54)] {
        // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
        // registered.
        unsafe { ram.publish_physical(LEAF, &denied.to_le_bytes()) }.unwrap();
        assert!(matches!(
            prepare_artifact(&mut machine, BINDING),
            Err(MemoryStatus::Unsupported)
        ));
    }
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(LEAF, &descriptor.to_le_bytes()) }.unwrap();
    assert!(Arc::ptr_eq(
        &first,
        &prepare_artifact(&mut machine, BINDING).unwrap()
    ));
}
#[test]
fn retained_capacities_are_bounded_and_owner_budget_can_only_tighten() {
    let (mut machine, _) = fixture();
    let first = prepare_artifact(&mut machine, BINDING).unwrap();
    let mut cache = ArtifactCache::default();
    for index in 0..4 {
        let mut key = first.key.clone();
        key.pc += index * 4;
        cache.insert(Arc::new(Artifact {
                key, identity: first.identity.clone(),
                code: Arc::new(alloc::vec![0; if index == 3 { ARTIFACT_CACHE_BYTES } else { ARTIFACT_CACHE_BYTES / 2 }]),
                source_map: Vec::new(), source: first.source.clone(),
                requirements: first.requirements, branch_type: first.branch_type,
                #[cfg(feature = "native-profile")]
                profile: first.profile.clone(),
            }));
        assert!(cache.stats().retained_bytes <= ARTIFACT_CACHE_BYTES);
        assert_eq!(cache.stats().entries, 1);
    }
    assert_eq!(cache.stats().compiled, 4);
    machine.tighten_native_artifact_cache_budget(0).unwrap();
    let stats = machine
        .cpu
        .canonical_memory
        .as_ref()
        .unwrap()
        .native_artifact_stats();
    assert_eq!((stats.entries, stats.retained_bytes), (0, 0));
    // A later larger request cannot restore a limit already tightened.
    machine
        .tighten_native_artifact_cache_budget(ARTIFACT_CACHE_BYTES)
        .unwrap();
    let uncached = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&first, &uncached));
    assert_eq!(
        machine
            .cpu
            .canonical_memory
            .as_ref()
            .unwrap()
            .artifacts
            .byte_budget,
        0
    );
    let (cpu, profile, missing, _) = super::super::super::policy::tests::fixture();
    let reset = machine
        .cpu
        .canonical_memory
        .as_ref()
        .unwrap()
        .prepare_reset_peer(&cpu, 1, profile.name, &missing)
        .unwrap();
    assert_eq!(
        (
            reset.artifacts.byte_budget,
            reset.artifacts.stats().retained_bytes
        ),
        (0, 0)
    );
}

fn branch_artifacts(
    count: usize,
) -> (
    Machine<FakeHost, NoDevices>,
    Arc<RegisteredSystemRam>,
    Vec<Arc<Artifact>>,
) {
    let (mut machine, ram) = fixture();
    let source: Vec<_> = core::iter::repeat_n(0x14000000u32, count + 1)
        .flat_map(u32::to_le_bytes)
        .collect();
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(DATA, &source) }.unwrap();
    let artifacts = (0..count)
        .map(|index| {
            machine.cpu.pc = PC + index as u64 * 4;
            prepare_artifact(&mut machine, BINDING).unwrap()
        })
        .collect();
    (machine, ram, artifacts)
}

#[test]
fn validated_hot_source_survives_byte_budget_eviction() {
    for count in [3, 80] {
        let (mut machine, _, artifacts) = branch_artifacts(count);
        let initial = machine
            .cpu
            .canonical_memory
            .as_ref()
            .unwrap()
            .native_artifact_stats();
        machine
            .tighten_native_artifact_cache_budget(initial.retained_bytes)
            .unwrap();
        machine.cpu.pc = PC;
        assert!(Arc::ptr_eq(
            &artifacts[0],
            &prepare_artifact(&mut machine, BINDING).unwrap()
        ));
        let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
        assert!(Arc::ptr_eq(
            cache.recency_order().last().unwrap(),
            &artifacts[0]
        ));
        assert_eq!(cache.stats().retained_bytes, initial.retained_bytes);
        assert_eq!(cache.stats().reused, initial.reused + 1);
        assert_eq!(cache.stats().compiled, initial.compiled);

        machine.cpu.pc = PC + count as u64 * 4;
        let cold = prepare_artifact(&mut machine, BINDING).unwrap();
        let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
        assert_eq!(cache.entries.len(), count);
        assert!(cache.candidate(&artifacts[1].key).is_none());
        let (_, hot) = cache.candidate(&artifacts[0].key).unwrap();
        assert!(Arc::ptr_eq(&hot, &artifacts[0]));
        assert!(Arc::ptr_eq(cache.recency_order().last().unwrap(), &cold));
        assert!(cache.stats().retained_bytes <= cache.byte_budget);
    }
}

#[test]
fn cache_lookup_and_refused_source_do_not_refresh_recency() {
    let (mut machine, ram, artifacts) = branch_artifacts(3);
    let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
    let initial = cache.stats();
    assert!(cache.candidate(&artifacts[0].key).is_some());
    assert!(Arc::ptr_eq(cache.recency_order()[0], &artifacts[0]));
    machine.cpu.pc = PC;
    let mut descriptor = [0; 8];
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.read_physical(LEAF, &mut descriptor) }.unwrap();
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(LEAF, &0u64.to_le_bytes()) }.unwrap();
    assert_eq!(
        prepare_artifact(&mut machine, BINDING).err(),
        Some(MemoryStatus::Unsupported)
    );
    let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
    assert_eq!(cache.stats(), initial);
    for (entry, artifact) in cache.recency_order().into_iter().zip(&artifacts) {
        assert!(Arc::ptr_eq(entry, artifact));
    }
    // The first fetch now succeeds and finds the old key, but exact bytes
    // differ and the newly fetched instruction cannot pass admission.
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(LEAF, &descriptor) }.unwrap();
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(DATA, &0x02000000u32.to_le_bytes()) }.unwrap();
    assert_eq!(
        prepare_artifact(&mut machine, BINDING).err(),
        Some(MemoryStatus::Unsupported)
    );
    let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
    assert_eq!(cache.stats(), initial);
    for (entry, artifact) in cache.recency_order().into_iter().zip(&artifacts) {
        assert!(Arc::ptr_eq(entry, artifact));
    }
}

#[test]
fn changed_source_replaces_without_crediting_or_promoting_a_hit() {
    let (mut machine, ram, artifacts) = branch_artifacts(3);
    let initial = machine
        .cpu
        .canonical_memory
        .as_ref()
        .unwrap()
        .native_artifact_stats();
    machine.cpu.pc = PC;
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(DATA, &0x91000400u32.to_le_bytes()) }.unwrap();
    let changed = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&changed, &artifacts[0]));
    assert_eq!(&changed.source[..4], &0x91000400u32.to_le_bytes());
    let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
    assert_eq!(cache.stats().compiled, initial.compiled + 1);
    assert_eq!(cache.stats().reused, initial.reused);
    assert!(Arc::ptr_eq(cache.recency_order()[0], &artifacts[1]));
    assert!(Arc::ptr_eq(cache.recency_order()[1], &artifacts[2]));
    assert!(Arc::ptr_eq(cache.recency_order().last().unwrap(), &changed));
}

#[test]
fn changed_admission_key_does_not_refresh_an_older_artifact() {
    let (mut machine, _, artifacts) = branch_artifacts(3);
    let initial = machine
        .cpu
        .canonical_memory
        .as_ref()
        .unwrap()
        .native_artifact_stats();
    machine.cpu.pc = PC;
    machine.profile.chip = stela_contracts::Chip::AppleM2;
    let changed = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&changed, &artifacts[0]));
    let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
    assert_eq!(cache.stats().compiled, initial.compiled + 1);
    assert_eq!(cache.stats().reused, initial.reused);
    for (entry, artifact) in cache.recency_order().into_iter().zip(&artifacts) {
        assert!(Arc::ptr_eq(entry, artifact));
    }
    assert!(Arc::ptr_eq(cache.recency_order().last().unwrap(), &changed));
    // Equal-PC entries keep independent full keys. Revisit both variants
    // and a missing variant after insertion, without refreshing recency.
    let tickets: Vec<_> = cache.entries.iter().map(|entry| entry.recency).collect();
    assert!(Arc::ptr_eq(
        &cache.candidate(&artifacts[0].key).unwrap().1,
        &artifacts[0]
    ));
    assert!(Arc::ptr_eq(
        &cache.candidate(&changed.key).unwrap().1,
        &changed
    ));
    let mut missing = changed.key.clone();
    missing.worker = publication::WorkerId(1);
    assert!(cache.candidate(&missing).is_none());
    assert_eq!(
        cache
            .entries
            .iter()
            .map(|entry| entry.recency)
            .collect::<Vec<_>>(),
        tickets
    );
}

#[test]
fn shortened_observation_window_replaces_without_crediting_a_hit() {
    let (mut machine, _) = fixture();
    let full = prepare_artifact(&mut machine, BINDING).unwrap();
    machine.cpu.pc = PC + 4;
    let following = prepare_artifact(&mut machine, BINDING).unwrap();
    let initial = machine
        .cpu
        .canonical_memory
        .as_ref()
        .unwrap()
        .native_artifact_stats();
    machine.set_breakpoints(&[PC + 4]);
    machine.cpu.pc = PC;
    let prefix = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&prefix, &full));
    assert_eq!(prefix.source, full.source[..4]);
    let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
    assert_eq!(cache.stats().compiled, initial.compiled + 1);
    assert_eq!(cache.stats().reused, initial.reused);
    assert!(Arc::ptr_eq(cache.recency_order()[0], &following));
    assert!(Arc::ptr_eq(cache.recency_order().last().unwrap(), &prefix));
}

fn assert_accounting(cache: &ArtifactCache) {
    let payload: usize = cache
        .entries
        .iter()
        .map(|entry| entry.artifact.retained_bytes())
        .sum();
    assert_eq!(cache.retained_payload, payload);
    assert_eq!(
        cache.stats().retained_bytes,
        payload
            + cache.entries.capacity() * core::mem::size_of::<CacheEntry>()
            + cache.controls_bytes()
    );
    assert!(cache.stats().retained_bytes <= cache.byte_budget);
    assert!(
        cache
            .entries
            .windows(2)
            .all(|pair| pair[0].artifact.key.pc <= pair[1].artifact.key.pc)
    );
}

#[test]
fn indexed_cache_matches_reference_lru_without_moving_hits() {
    let (_, _, artifacts) = branch_artifacts(8);
    let mut cache = ArtifactCache::default();
    let mut reference: Vec<Arc<Artifact>> = Vec::new();
    for step in 0..200 {
        let artifact = &artifacts[(step * 5 + step / 7) % artifacts.len()];
        if let Some((index, candidate)) = cache.candidate(&artifact.key) {
            let positions: Vec<_> = cache
                .entries
                .iter()
                .map(|entry| entry.artifact.key.pc)
                .collect();
            let bytes = cache.stats().retained_bytes;
            assert!(Arc::ptr_eq(&candidate, artifact));
            cache.reuse(index);
            assert_eq!(
                cache
                    .entries
                    .iter()
                    .map(|entry| entry.artifact.key.pc)
                    .collect::<Vec<_>>(),
                positions
            );
            assert_eq!(cache.stats().retained_bytes, bytes);
            reference.retain(|entry| !Arc::ptr_eq(entry, artifact));
        } else {
            cache.insert(Arc::clone(artifact));
        }
        reference.push(Arc::clone(artifact));
        if step % 11 == 10 {
            cache.evict_oldest();
            reference.remove(0);
        }
        assert_eq!(cache.entries.len(), reference.len());
        for (actual, expected) in cache.recency_order().into_iter().zip(&reference) {
            assert!(Arc::ptr_eq(actual, expected));
        }
        assert_accounting(&cache);
    }
}

#[test]
fn recency_wrap_preserves_indices_order_and_eviction_after_counter_saturation() {
    let (_, _, artifacts) = branch_artifacts(4);
    let mut cache = ArtifactCache::default();
    for index in [2, 0, 3, 1] {
        cache.insert(Arc::clone(&artifacts[index]));
    }
    let (index, _) = cache.candidate(&artifacts[0].key).unwrap();
    let bytes = cache.stats().retained_bytes;
    cache.recency_clock = u64::MAX;
    cache.reused = u64::MAX;
    cache.reuse(index);
    assert_eq!(cache.reused, u64::MAX);
    assert_eq!(cache.candidate(&artifacts[0].key).unwrap().0, index);
    assert_eq!(cache.stats().retained_bytes, bytes);
    for (actual, expected) in cache.recency_order().into_iter().zip([2, 3, 1, 0]) {
        assert!(Arc::ptr_eq(actual, &artifacts[expected]));
    }
    cache.evict_oldest();
    assert!(cache.candidate(&artifacts[2].key).is_none());
    assert!(cache.candidate(&artifacts[0].key).is_some());
    assert_accounting(&cache);
}

#[test]
fn more_than_the_old_entry_limit_reuses_real_prepared_artifacts_and_reset_is_empty() {
    let (mut machine, _, artifacts) = branch_artifacts(129);
    let owner = machine.cpu.canonical_memory.as_ref().unwrap();
    assert_eq!(owner.artifacts.entries.len(), artifacts.len());
    assert_accounting(&owner.artifacts);
    let initial = owner.artifacts.stats();
    for (index, artifact) in artifacts.iter().enumerate() {
        machine.cpu.pc = PC + index as u64 * 4;
        assert!(Arc::ptr_eq(
            artifact,
            &prepare_artifact(&mut machine, BINDING).unwrap()
        ));
    }
    let owner = machine.cpu.canonical_memory.as_ref().unwrap();
    assert_eq!(owner.artifacts.stats().compiled, initial.compiled);
    assert_eq!(
        owner.artifacts.stats().reused,
        initial.reused + artifacts.len() as u64
    );
    assert_accounting(&owner.artifacts);
    let (cpu, profile, missing, _) = super::super::super::policy::tests::fixture();
    let reset = owner
        .prepare_reset_peer(&cpu, 1, profile.name, &missing)
        .unwrap();
    assert!(reset.artifacts.entries.is_empty());
    assert_eq!(reset.artifacts.entries.capacity(), 0);
    assert_eq!(reset.artifacts.byte_budget, owner.artifacts.byte_budget);
    assert!(Arc::ptr_eq(&owner.ram, &reset.ram));
}

#[test]
fn adaptive_growth_uses_spare_bytes_without_evicting_for_speculative_slots() {
    let (machine, _, artifacts) = branch_artifacts(5);
    let controls = capture_controls(&machine).unwrap();
    let mut cache = ArtifactCache::default();
    cache.remember_controls(&controls);
    for artifact in &artifacts[..4] {
        cache.insert(Arc::clone(artifact));
        assert_accounting(&cache);
    }
    let slots = core::mem::size_of::<CacheEntry>();
    assert_eq!(cache.entries.capacity(), 4);
    let budget = cache.retained_payload
        + controls.retained_bytes()
        + artifacts[4].retained_bytes()
        + 5 * slots;
    cache.tighten(budget);
    cache.insert(Arc::clone(&artifacts[4]));
    assert_eq!(cache.entries.capacity(), 5);
    assert_eq!(cache.entries.len(), 5);
    assert_eq!(cache.stats().retained_bytes, budget);
    assert_accounting(&cache);
    for (entry, artifact) in cache.recency_order().into_iter().zip(&artifacts) {
        assert!(Arc::ptr_eq(entry, artifact));
    }
}

#[test]
fn high_water_slots_release_for_tiny_artifact_and_zero_budget() {
    let (machine, _, artifacts) = branch_artifacts(129);
    let controls = capture_controls(&machine).unwrap();
    let slots = core::mem::size_of::<CacheEntry>();
    let mut cache = ArtifactCache::default();
    for artifact in &artifacts {
        cache.insert(Arc::clone(artifact));
    }
    assert!(cache.entries.capacity() >= artifacts.len());
    // Source/code capacities can make one artifact larger than the slot
    // allocation for this roster. Derive sufficient metadata pressure from
    // its charge rather than assuming a particular compiled size.
    let required = (artifacts[0].retained_bytes() + slots).div_ceil(slots);
    cache
        .reserve_slots(required.max(cache.entries.len()))
        .unwrap();
    assert_accounting(&cache);
    // Retaining only the old slot allocation fits exactly, but leaves no
    // payload room. Insertion must release it and regrow a smaller buffer.
    let high_water = cache.slot_bytes();
    assert!(high_water >= artifacts[0].retained_bytes() + slots);
    cache.tighten(high_water);
    assert!(cache.entries.is_empty());
    assert_eq!(cache.slot_bytes(), high_water);
    cache.insert(Arc::clone(&artifacts[0]));
    assert_eq!(cache.stats().entries, 1);
    assert_eq!(cache.entries.capacity(), 1);
    assert_accounting(&cache);
    let tiny = artifacts[0].retained_bytes() + slots;
    cache.tighten(tiny);
    assert_eq!(cache.stats().retained_bytes, tiny);
    cache.tighten(0);
    cache.remember_controls(&controls);
    cache.insert(Arc::clone(&artifacts[0]));
    assert_eq!(cache.stats().retained_bytes, 0);
    assert_eq!(cache.entries.capacity(), 0);
    assert!(cache.controls.is_none());
    assert_eq!(cache.empty_like().byte_budget, 0);
}

#[test]
fn oversized_slot_buffer_does_not_prevent_retaining_controls_after_eviction() {
    let (machine, _, _) = branch_artifacts(1);
    let controls = capture_controls(&machine).unwrap();
    let mut cache = ArtifactCache::default();
    let slots = controls
        .retained_bytes()
        .div_ceil(core::mem::size_of::<CacheEntry>());
    cache.reserve_slots(slots).unwrap();
    let budget = cache.slot_bytes();
    cache.tighten(budget);
    assert_eq!(cache.slot_bytes(), budget);
    cache.remember_controls(&controls);
    assert!(cache.controls.is_some());
    assert!(cache.entries.is_empty());
    assert_eq!(cache.entries.capacity(), 0);
    assert_eq!(cache.stats().retained_bytes, controls.retained_bytes());
    assert_accounting(&cache);
}

#[test]
fn varied_payload_capacity_replacement_and_controls_changes_charge_actual_storage() {
    let (mut machine, _, artifacts) = branch_artifacts(3);
    let original_controls = capture_controls(&machine).unwrap();
    let mut cache = ArtifactCache::default();
    cache.remember_controls(&original_controls);
    for (index, artifact) in artifacts.iter().enumerate() {
        // Vec::clone may discard spare capacity. Grow beyond the real
        // original charge so replacing this entry cannot require eviction.
        let mut code = artifact.code.as_ref().clone();
        code.reserve_exact(artifact.code.capacity() + (index + 1) * 37 - code.len());
        let mut source = artifact.source.clone();
        source.reserve_exact(artifact.source.capacity() + (index + 1) * 11 - source.len());
        let mut source_map = artifact.source_map.clone();
        source_map
            .reserve_exact(artifact.source_map.capacity() + (index + 1) * 3 - source_map.len());
        #[cfg(feature = "native-profile")]
        let profile = {
            let mut profile = artifact.profile.clone();
            // Metadata is another kept Vec: cloning can shrink its
            // spare capacity, so grow beyond its original charge too.
            profile.register_spans.reserve_exact(
                artifact.profile.register_spans.capacity() + index + 1
                    - profile.register_spans.len(),
            );
            profile
        };
        let enlarged = Arc::new(Artifact {
            key: artifact.key.clone(),
            identity: Arc::clone(&artifact.identity),
            code: Arc::new(code),
            source_map,
            source,
            requirements: artifact.requirements,
            branch_type: artifact.branch_type,
            #[cfg(feature = "native-profile")]
            profile,
        });
        assert!(enlarged.retained_bytes() > artifact.retained_bytes());
        cache.insert(enlarged);
        assert_accounting(&cache);
    }
    let initial_count = cache.entries.len();
    cache.tighten(cache.stats().retained_bytes);
    // Same-key replacement removes the old capacity charge exactly once.
    cache.insert(Arc::clone(&artifacts[1]));
    assert_eq!(cache.entries.len(), initial_count);
    assert!(Arc::ptr_eq(
        cache.recency_order().last().unwrap(),
        &artifacts[1]
    ));
    assert_accounting(&cache);
    cache.tighten(cache.stats().retained_bytes);
    // The kept missing-register slice is charged at host-word
    // alignment. One additional register may fit within its old charge.
    machine.profile_missing.extend([
        Register::TTBR0_EL1,
        Register::TTBR1_EL1,
        Register::TCR_EL1,
        Register::SCTLR_EL1,
    ]);
    let changed = capture_controls(&machine).unwrap();
    assert!(changed.retained_bytes() > original_controls.retained_bytes());
    cache.remember_controls(&changed);
    assert_eq!(cache.entries.len(), initial_count - 1);
    assert_eq!(cache.controls_bytes(), changed.retained_bytes());
    assert_accounting(&cache);
}

#[test]
fn growth_failure_returns_prepared_uncached_code_without_losing_valid_entries() {
    let (mut machine, _, artifacts) = branch_artifacts(4);
    let cache = &mut machine.cpu.canonical_memory.as_mut().unwrap().artifacts;
    assert_eq!(cache.entries.len(), cache.entries.capacity());
    let initial = cache.stats();
    cache.fail_next_growth = true;
    machine.cpu.pc = PC + artifacts.len() as u64 * 4;
    let uncached = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!uncached.code.is_empty());
    assert_eq!(uncached.source, 0x14000000u32.to_le_bytes());
    let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
    assert_eq!(cache.stats().compiled, initial.compiled + 1);
    assert_eq!(cache.stats().retained_bytes, initial.retained_bytes);
    assert_eq!(cache.stats().entries, initial.entries);
    assert!(cache.candidate(&uncached.key).is_none());
    for (entry, artifact) in cache.recency_order().into_iter().zip(&artifacts) {
        assert!(Arc::ptr_eq(entry, artifact));
    }
    assert_accounting(cache);
    let retry = prepare_artifact(&mut machine, BINDING).unwrap();
    assert!(!Arc::ptr_eq(&retry, &uncached));
    assert_accounting(&machine.cpu.canonical_memory.as_ref().unwrap().artifacts);
}

#[test]
fn growth_arithmetic_overflow_declines_without_mutating_retained_cache() {
    let (machine, _, _) = branch_artifacts(3);
    let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
    let initial = cache.stats();
    assert_eq!(cache.growth_capacity(usize::MAX), None);
    assert!(!cache.fits(usize::MAX));
    assert_eq!(cache.stats(), initial);
    assert_accounting(cache);
}

#[test]
fn immutable_code_arc_metadata_is_charged_at_the_exact_artifact_budget_boundary() {
    let (mut machine, _) = fixture();
    let artifact = prepare_artifact(&mut machine, BINDING).unwrap();
    let expected = core::mem::size_of::<Artifact>()
        + 2 * core::mem::size_of::<usize>()
        + core::mem::size_of::<Identity>()
        + 2 * core::mem::size_of::<usize>()
        + crate::machine::engine::installed_code::ARC_VEC_METADATA_BYTES
        + artifact.code.capacity()
        + artifact.source.capacity()
        + artifact.source_map.capacity()
            * core::mem::size_of::<(stela_compiler::GuestAddress, usize)>()
        + artifact.key.controls_sha256.len()
        + 2 * core::mem::size_of::<usize>()
        + artifact.identity.source_sha256.capacity()
        + artifact.identity.native_sha256.capacity()
        + artifact.identity.controls_sha256.capacity();
    #[cfg(feature = "native-profile")]
    let expected = expected + artifact.profile.retained_bytes().unwrap();
    assert_eq!(artifact.retained_bytes(), expected);
    let mut denied = ArtifactCache::default();
    let slots = core::mem::size_of::<CacheEntry>();
    denied.tighten(expected + slots - 1);
    denied.insert(Arc::clone(&artifact));
    assert!(denied.entries.is_empty());
    let mut exact = ArtifactCache::default();
    exact.tighten(expected + slots);
    exact.insert(artifact);
    assert_eq!(exact.stats().entries, 1);
    assert_eq!(exact.stats().retained_bytes, expected + slots);
}
#[test]
fn warm_epoch_probe_checks_reached_source_without_compiling_or_changing_identity() {
    let (mut machine, ram, artifacts) = branch_artifacts(3);
    machine.cpu.pc = PC;
    // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA, device
    // worker or other writer admitted.
    let run = unsafe { machine.shared_native_run(BINDING) }.unwrap();
    let before = run.memory.artifacts.stats();
    let execution = run.memory.memory.execution_session().unwrap();
    *run.pc = PC + 4;
    let (_, candidate) = run.warm_successor(&execution).unwrap().unwrap();
    assert!(Arc::ptr_eq(&candidate, &artifacts[1]));
    assert!(Arc::ptr_eq(&run.artifact, &artifacts[0]));
    // A valid but cold reached target yields; it never compiles on worker.
    *run.pc = PC + 12;
    assert!(matches!(
        run.warm_successor(&execution),
        Ok(Err(NativeEpochEnd::Cold))
    ));
    assert_eq!(run.memory.artifacts.stats(), before);
    // Source bytes can change through the real shared publication owner.
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(DATA + 4, &0x14000001u32.to_le_bytes()) }.unwrap();
    *run.pc = PC + 4;
    assert!(matches!(
        run.warm_successor(&execution),
        Ok(Err(NativeEpochEnd::Source))
    ));
    assert_eq!(run.memory.artifacts.stats(), before);
    assert!(Arc::ptr_eq(&run.artifact, &artifacts[0]));
    assert_eq!(run.executed_bodies, 0);
}

#[test]
fn warm_epoch_probe_rewalks_permissions_mapping_and_guarded_entry() {
    let (mut machine, ram, _) = branch_artifacts(2);
    machine.cpu.pc = PC;
    // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA, device
    // worker or other writer admitted.
    let run = unsafe { machine.shared_native_run(BINDING) }.unwrap();
    let execution = run.memory.memory.execution_session().unwrap();
    let mut descriptor = [0; 8];
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.read_physical(LEAF, &mut descriptor) }.unwrap();
    let descriptor = u64::from_le_bytes(descriptor);
    // Guarded BR target requires a compatible landing instruction.
    *run.btype = 3;
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(LEAF, &(descriptor | (1 << 50)).to_le_bytes()) }.unwrap();
    assert!(matches!(
        run.warm_successor(&execution),
        Ok(Err(NativeEpochEnd::Source))
    ));
    *run.btype = 0;
    // Same virtual PC and old cached bytes cannot confer execute rights.
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(LEAF, &0u64.to_le_bytes()) }.unwrap();
    assert!(matches!(
        run.warm_successor(&execution),
        Ok(Err(NativeEpochEnd::Source))
    ));
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(LEAF, &descriptor.to_le_bytes()) }.unwrap();
    assert!(matches!(run.warm_successor(&execution), Ok(Ok(_))));
}
