use super::*;
use crate::memory::{domain::physical::PhysicalAddressSpace, stage1::PhysicalMemory};

const CODE_PA: u64 = 0x1000;
const RAM_PA: u64 = 0x2000;
const RAM_BYTES: u64 = 24;
const ORIGINAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn declaration() -> SourceRamDeclaration {
    SourceRamDeclaration {
        address_space: 51,
        target: TargetCpu::Baseline,
        declared_capacity: vec![PhysicalRamRange {
            source_pa: CODE_PA,
            bytes: MAX_IMAGE_MEMORY_BYTES + 0x4000,
        }],
        initialized: vec![OwnedRamExtent {
            source_pa: CODE_PA,
            bytes: ORIGINAL.to_vec(),
            permissions: SourceRamPermissions {
                readable: true,
                writable: false,
                executable: true,
            },
        }],
    }
}

fn config() -> SourceRamSystemConfig {
    SourceRamSystemConfig {
        reservation_granule_bytes: 16,
        reservation_stripe_count: 8,
    }
}

fn zeroed(source_pa: u64, bytes: u64) -> ZeroedRamExtent {
    ZeroedRamExtent {
        source_pa,
        bytes,
        permissions: SourceRamPermissions {
            readable: true,
            writable: true,
            executable: false,
        },
    }
}

#[test]
fn explicit_zeroed_ram_preserves_original_code_and_unassigned_capacity_holes() {
    let materialized = materialize_source_ram_with_zeroed(
        declaration(),
        vec![zeroed(RAM_PA, RAM_BYTES)],
        config(),
    )
    .unwrap();
    let code = materialized.test_view(CODE_PA).unwrap();
    let ram = materialized.test_view(RAM_PA).unwrap();
    assert!(!code.permissions().writable);
    assert!(code.permissions().executable);
    assert!(ram.permissions().readable && ram.permissions().writable);
    assert!(!ram.permissions().executable);
    let (binding, original_sources) = materialized.into_parts();
    assert_eq!(original_sources.len(), 1);
    let layout = binding.layout();
    assert_eq!(layout.initialized.len(), 2);
    assert!(!layout.initialized[0].zero_initialized);
    assert_eq!(
        layout.initialized[0].source_sha256,
        crate::sha256(&ORIGINAL)
    );
    assert!(layout.initialized[1].zero_initialized);
    assert_eq!(
        layout.initialized[1].source_sha256,
        crate::sha256(&[0; RAM_BYTES as usize])
    );
    let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
    assert_eq!(
        physical.read_descriptor(CODE_PA).unwrap(),
        u64::from_le_bytes(ORIGINAL)
    );
    for offset in [0, 8, 16] {
        assert_eq!(physical.read_descriptor(RAM_PA + offset).unwrap(), 0);
    }
    assert!(physical.read_descriptor(CODE_PA + 8).is_err());
    assert!(physical.read_descriptor(RAM_PA + RAM_BYTES).is_err());
    assert!(physical.read_descriptor(0x1800).is_err());
}

#[test]
fn mixed_zeroed_ranges_reject_invalid_declarations_before_materialization() {
    for extent in [
        zeroed(CODE_PA + 4, 8),
        zeroed(RAM_PA, 0),
        zeroed(u64::MAX - 7, 16),
        zeroed(RAM_PA, MAX_IMAGE_MEMORY_BYTES),
        ZeroedRamExtent {
            permissions: SourceRamPermissions {
                readable: true,
                writable: false,
                executable: true,
            },
            ..zeroed(RAM_PA, 8)
        },
        ZeroedRamExtent {
            permissions: SourceRamPermissions {
                readable: false,
                writable: true,
                executable: false,
            },
            ..zeroed(RAM_PA, 8)
        },
    ] {
        assert!(materialize_source_ram_with_zeroed(declaration(), vec![extent], config()).is_err());
    }
    assert!(
        materialize_source_ram_with_zeroed(
            declaration(),
            vec![zeroed(RAM_PA, 16), zeroed(RAM_PA + 8, 16)],
            config(),
        )
        .is_err()
    );
}
