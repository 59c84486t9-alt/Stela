use super::completion::{RamCompletionError, RamCompletionProgress};
use super::*;
use crate::memory::{
    policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
    source_ram::{
        OwnedRamExtent, PhysicalRamRange, SourceRamBuildError, SourceRamDeclaration,
        SourceRamPermissions, SourceRamSystemConfig, materialize_source_ram,
    },
};
use stela_compiler::{TargetCpu, context::memory::MemoryRequirements};

fn extent(source_pa: u64, bytes: Vec<u8>, executable: bool) -> OwnedRamExtent {
    OwnedRamExtent {
        source_pa,
        bytes,
        permissions: SourceRamPermissions {
            readable: true,
            writable: !executable,
            executable,
        },
    }
}

fn declaration(initialized: Vec<OwnedRamExtent>) -> SourceRamDeclaration {
    SourceRamDeclaration {
        address_space: 7,
        target: TargetCpu::Baseline,
        declared_capacity: vec![PhysicalRamRange {
            source_pa: 0x1000,
            bytes: 0x4000,
        }],
        initialized,
    }
}

fn config() -> SourceRamSystemConfig {
    SourceRamSystemConfig {
        reservation_granule_bytes: 16,
        reservation_stripe_count: 8,
    }
}

fn physical() -> PhysicalAddressSpace {
    let original: Vec<u8> = (0..29).collect();
    let materialized = materialize_source_ram(
        declaration(vec![
            extent(0x1003, original, false),
            extent(0x3000, vec![0xa5; 16], true),
        ]),
        config(),
    )
    .unwrap();
    let (binding, immutable_sources) = materialized.into_parts();
    assert_eq!(immutable_sources.len(), 1);
    assert!(
        !immutable_sources[0]
            .backing()
            .maximum_permissions()
            .writable
    );
    assert!(
        immutable_sources[0]
            .backing()
            .maximum_permissions()
            .executable
    );
    PhysicalAddressSpace::from_materialized(binding).unwrap()
}

#[test]
fn explicit_pa_materialization_pins_exact_initialized_bytes_and_alignment() {
    let physical = physical();
    let execution = physical.domain().execution_loan().unwrap();
    let pin = physical.resolve_ram8(&execution, 0x1008).unwrap();
    assert_eq!(pin.pointer() as usize & 7, 0);
    assert!(std::ptr::eq(
        pin.memory_system(),
        physical.memory_system().as_ref()
    ));
    pin.check_current().unwrap();
    // SAFETY: materialized source, an aligned readable quantity, and every
    // reached backing and view held through the read.
    let value = unsafe { access::read_part(pin.pointer(), 8, TargetCpu::Baseline) }.unwrap();
    assert_eq!(
        value as u64,
        u64::from_le_bytes([5, 6, 7, 8, 9, 10, 11, 12])
    );
    assert_eq!(
        physical.read_descriptor(0x3000).unwrap(),
        0xa5a5_a5a5_a5a5_a5a5
    );
    // Capacity holes, leading padding, rounded tails and out-of-capacity values
    // never become readable by retaining the surrounding allocation.
    for address in [0x1000, 0x1020, 0x2000, 0x3010, 0x6000] {
        assert!(physical.resolve_ram8(&execution, address).is_err());
    }
    assert!(matches!(
        physical.resolve_ram8(&execution, 0x1009),
        Err(PhysicalReadPlatformError::Alignment)
    ));
    assert_eq!(physical.layout().declared_capacity[0].bytes, 0x4000);
    assert_eq!(physical.layout().initialized[0].range.bytes, 29);
    assert_eq!(
        physical.layout().initialized[0].source_sha256,
        stela_core::sha256(&(0..29).collect::<Vec<u8>>())
    );
}

#[test]
fn physical_role_denies_generic_callbacks_and_survives_snapshot_publication() {
    let physical = physical();
    let policy = MemoryControls::new(
        LowerAddressProfile::new(44, false).unwrap(),
        false,
        false,
        false,
        TagCheckFaultMode::Ignore,
        false,
    );
    let mut thread = physical.domain().thread(policy);
    assert!(matches!(thread.profile(), Err(MemoryStatus::Unsupported)));
    assert!(matches!(
        thread.prepare(MemoryRequirements::default()),
        Err(MemoryStatus::Unsupported)
    ));
    let called = std::cell::Cell::new(false);
    // SAFETY: no native code or staging is invoked; the unsupported physical
    // role must decline before exposing a generic callback at all.
    assert_eq!(
        unsafe { thread.with_checked_view(|_| called.set(true)) },
        Err(MemoryStatus::Unsupported)
    );
    assert!(!called.get());
    let service = physical.domain.service_loan().unwrap();
    let snapshot = service.prepare(service.views().unwrap()).unwrap();
    service.commit(snapshot).unwrap();
    drop(service);
    assert!(physical.domain.is_source_physical_ram());
    assert!(matches!(thread.profile(), Err(MemoryStatus::Unsupported)));
    assert_eq!(thread.validate_execution(0), Err(MemoryStatus::Unsupported));
    let execution = thread.execution_loan().unwrap();
    assert_eq!(
        physical.check_execution_loan(&execution),
        Err(PhysicalReadPlatformError::Unavailable)
    );
}

#[test]
fn physical_binding_rejects_foreign_outer_and_retirement_while_pinned() {
    let first = physical();
    let other = physical();
    let foreign = other.domain().execution_loan().unwrap();
    assert!(matches!(
        first.check_execution_loan(&foreign),
        Err(PhysicalReadPlatformError::Domain(MemoryStatus::Domain))
    ));
    let execution = first.domain().execution_loan().unwrap();
    let pin = first.resolve_ram8(&execution, 0x1008).unwrap();
    let view = Arc::clone(pin.reached.first().view());
    assert_eq!(first.domain.retire(&view), Err(MemoryStatus::Domain));
    pin.check_current().unwrap();
    drop(pin);
    drop(execution);
    first.domain.retire(&view).unwrap();
    let execution = first.domain().execution_loan().unwrap();
    assert_eq!(
        first.check_execution_loan(&execution),
        Err(PhysicalReadPlatformError::Unavailable)
    );
}

#[test]
fn malformed_capacity_extents_and_write_execute_decline_without_binding() {
    let mut overlap = declaration(vec![
        extent(0x1000, vec![1; 16], false),
        extent(0x1008, vec![2; 16], false),
    ]);
    assert!(matches!(
        materialize_source_ram(overlap, config()),
        Err(SourceRamBuildError::Declaration(_))
    ));
    overlap = declaration(vec![extent(0x6000, vec![1; 8], false)]);
    assert!(matches!(
        materialize_source_ram(overlap, config()),
        Err(SourceRamBuildError::Declaration(_))
    ));
    let mut overflow = declaration(vec![extent(0x1000, vec![1; 8], false)]);
    overflow.declared_capacity[0] = PhysicalRamRange {
        source_pa: u64::MAX - 3,
        bytes: 8,
    };
    assert!(matches!(
        materialize_source_ram(overflow, config()),
        Err(SourceRamBuildError::Declaration(_))
    ));
    let mut writable_code = extent(0x1000, vec![1; 8], true);
    writable_code.permissions.writable = true;
    assert!(matches!(
        materialize_source_ram(declaration(vec![writable_code]), config()),
        Err(SourceRamBuildError::Declaration(_))
    ));
}

#[test]
fn metadata_fetch_check_never_mints_a_loan_and_initial_loan_excludes_service() {
    let physical = physical();
    let service = physical.domain.service_loan().unwrap();
    // The metadata check must succeed without a native borrow while the service
    // scope is held.
    physical.check_fetch_execution().unwrap();
    assert!(matches!(
        physical.initial_source_execution_loan(),
        Err(PhysicalReadPlatformError::Domain(MemoryStatus::Domain))
    ));
    physical.check_fetch_execution().unwrap();
    drop(service);
    let construction = physical.initial_source_execution_loan().unwrap();
    physical.check_execution_loan(&construction).unwrap();
    assert!(matches!(
        physical.domain.service_loan(),
        Err(MemoryStatus::Domain)
    ));
    drop(construction);
    physical.domain.service_loan().unwrap();
}

#[test]
fn actual_ram_completion_retains_same_order_owner_and_cannot_be_replayed() {
    let actual = physical();
    let outer = actual.domain().execution_loan().unwrap();
    let mut prepared = actual.prepare_ram_completion(&outer).unwrap();
    assert_eq!(prepared.progress(), RamCompletionProgress::Unattempted);
    // A second session cannot bypass the machine's serializer.
    assert!(matches!(
        actual.prepare_ram_completion(&outer),
        Err(RamCompletionError::Ordering(_))
    ));
    prepared.complete().unwrap();
    assert_eq!(prepared.progress(), RamCompletionProgress::Completed);
    assert!(matches!(
        prepared.complete(),
        Err(RamCompletionError::AlreadyAttempted(
            RamCompletionProgress::Completed
        ))
    ));
    // Completion keeps its borrows until settlement.
    assert!(matches!(
        actual.prepare_ram_completion(&outer),
        Err(RamCompletionError::Ordering(_))
    ));
    drop(prepared);
    drop(actual.prepare_ram_completion(&outer).unwrap());
}

#[test]
fn ram_completion_rejects_another_actual_domain_before_any_fence() {
    let actual = physical();
    let foreign = physical();
    let wrong_outer = foreign.domain().execution_loan().unwrap();
    assert!(matches!(
        actual.prepare_ram_completion(&wrong_outer),
        Err(RamCompletionError::Physical(_))
    ));
    let outer = actual.domain().execution_loan().unwrap();
    let mut prepared = actual.prepare_ram_completion(&outer).unwrap();
    prepared.complete().unwrap();
}

#[test]
fn scalar_pins_cover_only_exact_narrow_quantities_at_real_extent_end() {
    let space = physical();
    let outer = space.domain().execution_loan().unwrap();
    for bytes in [1_u8, 2, 4, 8] {
        let address = 0x1020 - u64::from(bytes);
        let pin = space.resolve_ram_scalar(&outer, address, bytes).unwrap();
        assert_eq!(pin.bytes(), usize::from(bytes));
        assert_eq!(pin.pointer() as usize & (usize::from(bytes) - 1), 0);
        pin.check_current().unwrap();
        let (footprint, width) = access::read_footprint(
            pin.pointer() as usize,
            usize::from(bytes),
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(
            (footprint, width),
            (pin.pointer() as usize, usize::from(bytes))
        );
        // Resolution and footprint checks issue no target read. The adjacent
        // uninitialized capacity is not admitted by the backing allocation.
        assert!(space.resolve_ram_scalar(&outer, 0x1020, bytes).is_err());
    }
    assert!(matches!(
        space.resolve_ram_scalar(&outer, 0x101f, 2),
        Err(PhysicalReadPlatformError::Alignment)
    ));
    assert!(matches!(
        space.resolve_ram_scalar(&outer, 0x101c, 3),
        Err(PhysicalReadPlatformError::Domain(
            MemoryStatus::InvalidRequest
        ))
    ));
    let foreign = physical();
    let foreign_outer = foreign.domain().execution_loan().unwrap();
    assert!(space.resolve_ram_scalar(&foreign_outer, 0x101f, 1).is_err());
}
