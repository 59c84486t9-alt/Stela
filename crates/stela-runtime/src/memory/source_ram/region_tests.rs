//! Authored storage/identity lifecycle checks, not firmware acceptance.
use super::*;
use crate::memory::{
    backing::AccessKind, domain::physical::PhysicalAddressSpace, stage1::PhysicalMemory,
};
const BASE: u64 = 0x1000;
const ALIAS: u64 = 0x3000;
const REGION_BYTES: u64 = 64;
const PREFIX: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const RWX: SourceRamPermissions = SourceRamPermissions {
    readable: true,
    writable: true,
    executable: true,
};
fn declaration() -> SourceRamDeclaration {
    SourceRamDeclaration {
        address_space: 701,
        target: TargetCpu::Baseline,
        declared_capacity: vec![
            PhysicalRamRange {
                source_pa: BASE,
                bytes: REGION_BYTES,
            },
            PhysicalRamRange {
                source_pa: ALIAS,
                bytes: REGION_BYTES,
            },
        ],
        initialized: Vec::new(),
    }
}
fn region() -> InitializedRamRegion {
    InitializedRamRegion {
        range: PhysicalRamRange {
            source_pa: BASE,
            bytes: REGION_BYTES,
        },
        file_prefix: PREFIX.to_vec(),
        file_sha256: stela_core::sha256(&PREFIX),
        permissions: RWX,
    }
}
fn config() -> SourceRamSystemConfig {
    SourceRamSystemConfig {
        reservation_granule_bytes: 16,
        reservation_stripe_count: 8,
    }
}
fn materialize() -> MaterializedSourceRam {
    materialize_source_ram_regions(declaration(), Vec::new(), vec![region()], config()).unwrap()
}
#[test]
fn full_region_cold_contents_keep_original_file_identity_and_absent_capacity() {
    let materialized = materialize();
    let view = materialized.test_view(BASE).unwrap();
    assert_eq!(view.bytes(), REGION_BYTES as usize);
    assert!(view.resolve(BASE + 60, 4, AccessKind::Execute).is_ok());
    assert!(view.resolve(BASE + 64, 1, AccessKind::Read).is_err());
    let (binding, immutable) = materialized.into_parts();
    assert!(immutable.is_empty());
    let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
    assert_eq!(
        physical.read_descriptor(BASE).unwrap(),
        u64::from_le_bytes(PREFIX)
    );
    assert_eq!(physical.read_descriptor(BASE + 8).unwrap(), 0);
    assert_eq!(physical.read_descriptor(BASE + 56).unwrap(), 0);
    assert!(physical.read_descriptor(BASE + 64).is_err());
    assert!(physical.read_descriptor(ALIAS).is_err()); // descriptive capacity is absent
    let layout = &physical.layout().initialized[0];
    assert_eq!(layout.file_prefix, Some((8, stela_core::sha256(&PREFIX))));
    let mut full = vec![0; REGION_BYTES as usize];
    full[..8].copy_from_slice(&PREFIX);
    assert_eq!(layout.source_sha256, stela_core::sha256(&full));
    // SAFETY: intentionally rejected writable backing, no rights are changed.
    assert!(unsafe { ImmutableCodeBacking::adopt(Arc::clone(view.backing())) }.is_err());
}
#[test]
fn invalid_regions_refuse_instead_of_granting_capacity_or_immutable_authority() {
    for kind in 0..5 {
        let mut input = region();
        match kind {
            0 => input.range.bytes = 7,
            1 => input.file_prefix.clear(),
            2 => input.file_sha256 = "wrong".into(),
            3 => input.range.source_pa = u64::MAX,
            4 => input.range.source_pa = BASE + REGION_BYTES,
            _ => unreachable!(),
        }
        assert!(
            materialize_source_ram_regions(declaration(), Vec::new(), vec![input], config())
                .is_err()
        );
    }
    assert!(
        materialize_source_ram_regions(
            declaration(),
            Vec::new(),
            vec![region(), region()],
            config()
        )
        .is_err()
    );
    let mut legacy = declaration();
    legacy.initialized.push(OwnedRamExtent {
        source_pa: BASE,
        bytes: PREFIX.to_vec(),
        permissions: RWX,
    });
    assert!(materialize_source_ram_with_zeroed(legacy, Vec::new(), config()).is_err());
}
#[test]
fn exact_owned_receipts_detect_aba_and_unaccounted_writers_on_actual_aliases() {
    let aliases = [SourceRamTestAlias {
        source_pa: ALIAS,
        initialized_source_pa: BASE,
        source_offset: 0,
        bytes: REGION_BYTES as usize,
        permissions: RWX,
    }];
    let materialized = materialize_source_ram_impl(
        declaration(),
        Vec::new(),
        vec![region()],
        config(),
        &aliases,
    )
    .unwrap();
    let view = materialized.test_view(BASE).unwrap();
    let alias = materialized.test_view(ALIAS).unwrap();
    assert!(Arc::ptr_eq(view.backing(), alias.backing()));
    let (binding, _) = materialized.into_parts();
    let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
    let generation = view.backing().instruction_generation();
    let foreign = MemorySystem::new(16, 8).unwrap();
    assert!(
        foreign
            .validate_owned_source_writes(view.backing(), generation, &[])
            .is_err()
    );
    // SAFETY: valid private staging; the foreign coherence owner is rejected
    // before any native byte effect or generation reservation.
    assert_eq!(
        unsafe { foreign.publish(view.backing(), view.backing_offset(), &PREFIX) }
            .unwrap_err()
            .completed,
        0
    );
    let mut receipts = Vec::new();
    let _service = physical.domain().service_loan().unwrap();
    // SAFETY: actual fresh source owner, current quiescent service and private
    // staging; both aliases use the original same-System tracked publisher.
    unsafe {
        physical.memory_system().publish_tracked(
            alias.backing(),
            alias.backing_offset(),
            &PREFIX,
            Some(&mut receipts),
        )
    }
    .unwrap();
    physical
        .memory_system()
        .validate_owned_source_writes(view.backing(), generation, &receipts)
        .unwrap();
    assert!(
        physical
            .memory_system()
            .validate_owned_source_writes(view.backing(), generation, &[])
            .is_err()
    );
    // SAFETY: identical owned writer and quiescent lifetime, private bytes.
    unsafe {
        physical.memory_system().publish_tracked(
            view.backing(),
            view.backing_offset(),
            &[0xaa; 8],
            Some(&mut receipts),
        )
    }
    .unwrap();
    // SAFETY: identical owned writer, restores original bytes but not history.
    unsafe {
        physical.memory_system().publish_tracked(
            view.backing(),
            view.backing_offset(),
            &PREFIX,
            Some(&mut receipts),
        )
    }
    .unwrap();
    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[0].bytes(), 8);
    physical
        .memory_system()
        .validate_owned_source_writes(view.backing(), generation, &receipts)
        .unwrap();
    assert!(
        !view
            .backing()
            .instruction_generation_current(generation.unwrap())
    );
}
#[test]
fn warm_prefix_reload_preserves_tail_and_refuses_active_outer() {
    let materialized = materialize();
    let view = materialized.test_view(BASE).unwrap();
    let (binding, _) = materialized.into_parts();
    let mut physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
    {
        let _service = physical.domain().service_loan().unwrap();
        // SAFETY: original storage/System plus quiescent service, private staging.
        unsafe {
            physical
                .memory_system()
                .publish(view.backing(), view.backing_offset(), &[0xab; 16])
        }
        .unwrap();
    }
    let generation = view.backing().instruction_generation();
    let outer = physical.initial_source_execution_loan().unwrap();
    assert!(physical.reload_original_region_prefixes().is_err());
    assert_eq!(view.backing().instruction_generation(), generation);
    drop(outer);
    let reset = physical.reload_original_region_prefixes().unwrap();
    assert_eq!(
        (
            reset.generation,
            reset.completed_bytes,
            reset.completed_regions
        ),
        (2, 8, 1)
    );
    assert_eq!(
        physical.read_descriptor(BASE).unwrap(),
        u64::from_le_bytes(PREFIX)
    );
    assert_eq!(
        physical.read_descriptor(BASE + 8).unwrap(),
        u64::from_le_bytes([0xab; 8])
    );
    assert!(
        !view
            .backing()
            .instruction_generation_current(generation.unwrap())
    );
}
#[test]
fn generation_exhaustion_precedes_byte_effect_and_unknown_attempt_fails_closed() {
    let materialized = materialize();
    let view = materialized.test_view(BASE).unwrap();
    let (binding, _) = materialized.into_parts();
    let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
    view.backing().exhaust_instruction_generation_for_test();
    let _service = physical.domain().service_loan().unwrap();
    // SAFETY: valid owned publisher, rejection is before target bytes change.
    let error = unsafe {
        physical
            .memory_system()
            .publish(view.backing(), view.backing_offset(), &[9; 8])
    }
    .unwrap_err();
    assert_eq!(error.completed, 0);
    drop(_service);
    assert_eq!(
        physical.read_descriptor(BASE).unwrap(),
        u64::from_le_bytes(PREFIX)
    );
    let materialized = materialize();
    let view = materialized.test_view(BASE).unwrap();
    let (binding, _) = materialized.into_parts();
    let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
    let mut attempt = physical
        .memory_system()
        .prepare_source_write(view.backing(), view.backing_offset(), 8)
        .unwrap();
    attempt.attempting();
    drop(attempt); // injected unknown host-effect outcome, never a false success
    assert!(physical.check_fetch_execution().is_err());
}
