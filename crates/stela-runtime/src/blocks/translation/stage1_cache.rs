//! Bounded successful stage1 results in the ORIGINAL installed context.
//! This cache is not an address-access, source, native or retirement authority.
use crate::memory::domain::{MemoryDomain, MemoryExecutionLoan, physical::PhysicalAddressSpace};
use crate::memory::stage1::{self, Access, Config, PhysicalMemory, Translation, TranslationError};
use std::sync::{Arc, Mutex};

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
    /// Concrete original storage and outer are required at the refill entry.
    /// A copied Config and arbitrary PhysicalMemory cannot publish cache cells.
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

// Private algorithm core; only the concrete original-owner wrapper above can
// call it in production. Descendant tests may supply mathematical table models.
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
    /// Caller retains actual installed/controls/source/physical/outer loans.
    /// Only the unchanged canonical walker creates results. Faults never enter
    /// this cache, and a colliding entry may be evicted without guest effects.
    fn translate(
        &self,
        config: &Config,
        memory: &(impl PhysicalMemory + ?Sized),
        access: Access,
    ) -> Result<Translation, TranslationError> {
        if *config != self.config || config.asid().is_none() {
            return Err(TranslationError::Unsupported(stage1::Unsupported::Control(
                "translation cache differs from actual enabled installed controls",
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
#[path = "stage1_cache/tests.rs"]
mod tests;
