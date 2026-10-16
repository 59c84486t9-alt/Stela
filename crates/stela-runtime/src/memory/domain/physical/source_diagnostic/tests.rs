use super::*;
use crate::memory::source_ram::{
    OwnedRamExtent, PhysicalRamRange, SourceRamDeclaration, SourceRamPermissions,
    SourceRamSystemConfig, materialize_source_ram,
};
use stela_compiler::TargetCpu;

const ADDRESS_SPACE: u64 = 7;
const DATA_PA: u64 = 0x1000;
const BYTES: usize = 16;

fn physical(value: u8) -> PhysicalAddressSpace {
    let source = materialize_source_ram(
        SourceRamDeclaration {
            address_space: ADDRESS_SPACE,
            target: TargetCpu::Baseline,
            declared_capacity: vec![PhysicalRamRange {
                source_pa: DATA_PA,
                bytes: 0x1000,
            }],
            initialized: vec![OwnedRamExtent {
                source_pa: DATA_PA,
                bytes: vec![value; BYTES],
                permissions: SourceRamPermissions {
                    readable: false,
                    writable: false,
                    executable: true,
                },
            }],
        },
        SourceRamSystemConfig {
            reservation_granule_bytes: 16,
            reservation_stripe_count: 8,
        },
    )
    .unwrap();
    let (binding, original_sources) = source.into_parts();
    assert_eq!(original_sources.len(), 1);
    PhysicalAddressSpace::from_materialized(binding).unwrap()
}

#[test]
fn original_execute_only_bytes_are_observed_without_granting_guest_read() {
    let physical = physical(0x5a);
    assert_eq!(
        physical
            .source_diagnostic_snapshot_quiescent(DATA_PA, BYTES)
            .unwrap(),
        vec![0x5a; BYTES]
    );
    let ordinary = physical.domain.observation_loan().unwrap();
    assert_eq!(
        ordinary.snapshot(DATA_PA, BYTES),
        Err(MemoryStatus::Permission)
    );
    drop(ordinary);
    let service = physical.domain.service_loan().unwrap();
    assert_eq!(
        physical.source_diagnostic_snapshot_quiescent(DATA_PA, BYTES),
        Err(PhysicalReadPlatformError::Domain(MemoryStatus::Domain))
    );
    assert_eq!(
        physical
            .source_diagnostic_snapshot(&service, DATA_PA, BYTES)
            .unwrap(),
        vec![0x5a; BYTES]
    );
    assert!(physical.domain.execution_loan().is_err());
    assert!(physical.domain.service_loan().is_err());
    let views = service.views().unwrap();
    assert!(!views[0].0.permissions().readable);
    assert!(views[0].0.permissions().executable);
    assert!(!views[0].0.backing().maximum_permissions().readable);
    drop(service);
    let ordinary = physical.domain.observation_loan().unwrap();
    assert_eq!(
        ordinary.snapshot(DATA_PA, BYTES),
        Err(MemoryStatus::Permission)
    );
}

#[test]
fn foreign_same_number_service_refuses_original_source_snapshot() {
    let first = physical(0x11);
    let foreign = physical(0x22);
    assert_eq!(first.domain.address_space(), foreign.domain.address_space());
    let service = foreign.domain.service_loan().unwrap();
    assert_eq!(
        first.source_diagnostic_snapshot(&service, DATA_PA, BYTES),
        Err(PhysicalReadPlatformError::Domain(MemoryStatus::Domain))
    );
    assert_eq!(
        foreign
            .source_diagnostic_snapshot(&service, DATA_PA, BYTES)
            .unwrap(),
        vec![0x22; BYTES]
    );
}
