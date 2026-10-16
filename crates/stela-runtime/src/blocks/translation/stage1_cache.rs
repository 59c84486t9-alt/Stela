//! Cache of successful stage-1 translation walks.
use crate::memory::domain::{MemoryDomain, MemoryExecutionLoan, physical::PhysicalAddressSpace};
use crate::memory::stage1::{self, Access, Config, PhysicalMemory, Translation, TranslationError};
use crate::platform::sync::Mutex;
use alloc::sync::Arc;

const CACHE_CELLS: usize = 128;

pub(super) struct Stage1Cache {
    domain: Arc<MemoryDomain>,
    entries: CacheEntries,
}
impl Stage1Cache {
    pub(super) fn new(config: Config, physical: &PhysicalAddressSpace) -> Self {
        Self {
            domain: Arc::clone(physical.domain()),
            entries: CacheEntries::new(config),
        }
    }
    /// Refill requires the installed storage and outer object.
    pub(super) fn translate(
        &self,
        config: &Config,
        physical: &PhysicalAddressSpace,
        execution: &MemoryExecutionLoan,
        access: Access,
    ) -> Result<Translation, TranslationError> {
        if !Arc::ptr_eq(&self.domain, physical.domain()) {
            return Err(TranslationError::Unsupported(
                stage1::Unsupported::PhysicalPlatform(
                    "translation cache uses a different original physical domain",
                ),
            ));
        }
        let descriptors = physical.borrow_descriptors(execution).map_err(|_| {
            TranslationError::Unsupported(stage1::Unsupported::PhysicalPlatform(
                "translation cache original physical/outer binding unavailable",
            ))
        })?;
        let result = self.entries.translate(config, &descriptors, access);
        physical.check_execution_loan(execution).map_err(|_| {
            TranslationError::Unsupported(stage1::Unsupported::PhysicalPlatform(
                "translation cache original physical/outer binding became unavailable",
            ))
        })?;
        result
    }
}

// The cache algorithm, reachable in production only through the wrapper above.
// Tests may use table models directly.
struct CacheEntries {
    config: Config,
    cells: Mutex<[Option<Translation>; CACHE_CELLS]>,
}
impl CacheEntries {
    fn new(config: Config) -> Self {
        Self {
            config,
            cells: Mutex::new([None; CACHE_CELLS]),
        }
    }
    /// The caller holds the installed context, controls, source, physical
    /// memory and outer borrows. Only the walker creates entries, faults are
    /// never cached, and a colliding entry may be evicted.
    fn translate(
        &self,
        config: &Config,
        memory: &(impl PhysicalMemory + ?Sized),
        access: Access,
    ) -> Result<Translation, TranslationError> {
        if *config != self.config || config.asid().is_none() {
            return Err(TranslationError::Unsupported(stage1::Unsupported::Control(
                "translation cache differs from enabled installed controls",
            )));
        }
        let mut cells = self.cells.lock().map_err(|_| {
            TranslationError::Unsupported(stage1::Unsupported::PhysicalPlatform(
                "installed translation cache is poisoned",
            ))
        })?;
        let index = cell_index(access);
        if let Some(hit) = cells[index]
            && hit.access() == access
        {
            return Ok(hit);
        }
        let reached = stage1::translate(config, memory, access)?;
        // A successful enabled ordinary walk must carry its authentic leaf and
        // ASID. Do not turn a flat diagnostic result into a cached translation.
        if reached
            .walk()
            .is_none_or(|walk| Some(walk.asid) != config.asid())
        {
            return Err(TranslationError::Unsupported(stage1::Unsupported::Control(
                "enabled canonical result has no current ASID walk provenance",
            )));
        }
        cells[index] = Some(reached);
        Ok(reached)
    }
}

fn cell_index(access: Access) -> usize {
    let mixed = access.raw_virtual_address.rotate_right(2)
        ^ access.source_pc.rotate_left(17)
        ^ (access.kind as u64).rotate_left(7)
        ^ (access.exception_level as u64).rotate_left(9)
        ^ u64::from(access.pan).rotate_left(11)
        ^ u64::from(access.uao).rotate_left(13)
        ^ u64::from(access.aligned).rotate_left(15);
    (mixed ^ (mixed >> 32)) as usize & (CACHE_CELLS - 1)
}

#[cfg(test)]
mod tests {
    //! Stage-1 cache and walker behavior.
    use super::*;
    use stage1::{
        AsidBits, Controls, CpuProfile, Granule, GranuleSupport, PaBits, PhysicalReadError,
    };
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
}
