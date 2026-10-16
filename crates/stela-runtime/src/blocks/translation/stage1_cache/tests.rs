//! Stage-1 cache and walker behavior.
use super::*;
use stage1::{AsidBits, Controls, CpuProfile, Granule, GranuleSupport, PaBits, PhysicalReadError};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
const PAGE: u64 = 0x1000;
const ROOT: u64 = PAGE;
const LEAF: u64 = 4 * PAGE;
const VA: u64 = 0x100;
const FIRST_PA: u64 = 0x8000;
const NEXT_PA: u64 = 0x9000;
const AF: u64 = 1 << 10;
const READ_ONLY: u64 = 1 << 7;
struct Tables {
    values: RefCell<BTreeMap<u64, u64>>,
    reads: Cell<usize>,
}
impl PhysicalMemory for Tables {
    fn read_descriptor(&self, pa: u64) -> Result<u64, PhysicalReadError> {
        self.reads.set(self.reads.get() + 1);
        self.values
            .borrow()
            .get(&pa)
            .copied()
            .ok_or(PhysicalReadError::Platform("fixture hole"))
    }
}
fn config_for_asid(asid: u16) -> Config {
    Config::from_controls_for_cpu(
        Controls {
            sctlr_el1: 1 | (1 << 2) | (1 << 12),
            tcr_el1: 16 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (5 << 32) | (1 << 36),
            ttbr0_el1: ROOT | (u64::from(asid) << 48),
            ttbr1_el1: 0,
            mair_el1: 0xff,
        },
        CpuProfile {
            pa_max: PaBits::Bits48,
            asid_bits: AsidBits::Bits16,
            granules: GranuleSupport {
                kib4: true,
                kib16: true,
                kib64: false,
                lower_fallback: Granule::KiB4,
                upper_fallback: Granule::KiB4,
            },
            pauth: false,
            pan: false,
            pan3: false,
        },
    )
    .unwrap()
}
fn tables(attributes: u64) -> Tables {
    Tables {
        values: RefCell::new(BTreeMap::from([
            (ROOT, (2 * PAGE) | 3),
            (2 * PAGE, (3 * PAGE) | 3),
            (3 * PAGE, LEAF | 3),
            (LEAF, FIRST_PA | 3 | AF | attributes),
        ])),
        reads: Cell::new(0),
    }
}
fn access(kind: stage1::AccessKind) -> Access {
    Access {
        kind,
        exception_level: stage1::ExceptionLevel::El1,
        raw_virtual_address: VA,
        source_pc: 0x6000,
        pan: false,
        uao: false,
        aligned: true,
    }
}
#[test]
fn repeated_exact_access_retains_genuine_translation_after_pte_bytes_change() {
    let config = config_for_asid(7);
    let cache = CacheEntries::new(config);
    let tables = tables(0);
    let intent = access(stage1::AccessKind::Read);
    let first = cache.translate(&config, &tables, intent).unwrap();
    assert_eq!(first.physical_address(), FIRST_PA + VA);
    assert_eq!(first.walk().unwrap().asid, 7);
    assert_eq!(tables.reads.get(), 4);
    tables.values.borrow_mut().insert(LEAF, NEXT_PA | 3 | AF);
    assert_eq!(cache.translate(&config, &tables, intent).unwrap(), first);
    assert_eq!(tables.reads.get(), 4);
    assert_eq!(
        stage1::translate(&config, &tables, intent)
            .unwrap()
            .physical_address(),
        NEXT_PA + VA
    );
    // This is mathematical PTE mutation only. Actual TLBI/IC Retiring consumer
    // is not supplied by a private test-only cache clear or counter placeholder.
}
#[test]
fn cached_read_does_not_supply_write_or_different_source_provenance() {
    let config = config_for_asid(7);
    let cache = CacheEntries::new(config);
    let tables = tables(READ_ONLY);
    cache
        .translate(&config, &tables, access(stage1::AccessKind::Read))
        .unwrap();
    let write = access(stage1::AccessKind::Write);
    let expected = stage1::translate(&config, &tables, write);
    assert!(matches!(
        expected,
        Err(TranslationError::Fault(stage1::Fault {
            kind: stage1::FaultKind::Permission,
            ..
        }))
    ));
    assert_eq!(cache.translate(&config, &tables, write), expected);
    let mut changed = access(stage1::AccessKind::Read);
    changed.source_pc += 4;
    assert_eq!(
        cache.translate(&config, &tables, changed).unwrap().access(),
        changed
    );
}
#[test]
fn faults_are_not_cached_and_changed_asid_config_cannot_reuse_cells() {
    let config = config_for_asid(7);
    let cache = CacheEntries::new(config);
    let tables = tables(0);
    tables.values.borrow_mut().insert(LEAF, FIRST_PA | 3);
    let intent = access(stage1::AccessKind::Fetch);
    assert!(matches!(
        cache.translate(&config, &tables, intent),
        Err(TranslationError::Fault(stage1::Fault {
            kind: stage1::FaultKind::AccessFlag,
            ..
        }))
    ));
    tables.values.borrow_mut().insert(LEAF, FIRST_PA | 3 | AF);
    assert!(cache.translate(&config, &tables, intent).is_ok());
    assert!(matches!(
        cache.translate(&config_for_asid(8), &tables, intent),
        Err(TranslationError::Unsupported(stage1::Unsupported::Control(
            _
        )))
    ));
}
#[test]
fn poisoned_cache_preserves_platform_failure_without_walk_or_repair() {
    let config = config_for_asid(7);
    let cache = CacheEntries::new(config);
    let tables = tables(0);
    let _ = std::panic::catch_unwind(|| {
        let _held = cache.cells.lock().unwrap();
        panic!("fixture poison");
    });
    assert!(matches!(
        cache.translate(&config, &tables, access(stage1::AccessKind::Read)),
        Err(TranslationError::Unsupported(
            stage1::Unsupported::PhysicalPlatform(_)
        ))
    ));
    assert_eq!(tables.reads.get(), 0);
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn concrete_cache_refill_rejects_foreign_physical_and_outer_even_on_hot_hit() {
    use crate::memory::source_ram::{
        OwnedRamExtent, PhysicalRamRange, SourceRamDeclaration, SourceRamPermissions,
        SourceRamSystemConfig, materialize_source_ram,
    };
    use stela_compiler::TargetCpu;
    fn physical() -> PhysicalAddressSpace {
        let initialized = [
            (ROOT, (2 * PAGE) | 3),
            (2 * PAGE, (3 * PAGE) | 3),
            (3 * PAGE, LEAF | 3),
            (LEAF, FIRST_PA | 3 | AF),
        ]
        .into_iter()
        .map(|(source_pa, value)| OwnedRamExtent {
            source_pa,
            bytes: value.to_le_bytes().to_vec(),
            permissions: SourceRamPermissions {
                readable: true,
                writable: true,
                executable: false,
            },
        })
        .collect();
        let materialized = materialize_source_ram(
            SourceRamDeclaration {
                address_space: 713,
                target: TargetCpu::Baseline,
                declared_capacity: vec![PhysicalRamRange {
                    source_pa: ROOT,
                    bytes: 0x10000,
                }],
                initialized,
            },
            SourceRamSystemConfig {
                reservation_granule_bytes: 16,
                reservation_stripe_count: 8,
            },
        )
        .unwrap();
        let (binding, _) = materialized.into_parts();
        PhysicalAddressSpace::from_materialized(binding).unwrap()
    }
    let first = physical();
    let other = physical();
    let config = config_for_asid(7);
    let cache = Stage1Cache::new(config, &first);
    let original = first.initial_source_execution_loan().unwrap();
    let foreign = other.initial_source_execution_loan().unwrap();
    let intent = access(stage1::AccessKind::Read);
    let hot = cache.translate(&config, &first, &original, intent).unwrap();
    assert_eq!(hot.physical_address(), FIRST_PA + VA);
    for (space, outer) in [(&other, &foreign), (&first, &foreign), (&other, &original)] {
        assert!(matches!(
            cache.translate(&config, space, outer, intent),
            Err(TranslationError::Unsupported(
                stage1::Unsupported::PhysicalPlatform(_)
            ))
        ));
    }
    assert_eq!(
        cache.translate(&config, &first, &original, intent).unwrap(),
        hot
    );
}
