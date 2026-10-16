//! Fresh physical region source authority and prefix-only warm RAM reload.
//! This is storage lifecycle, not an architectural CPU reset or migration.
use super::{PhysicalAddressSpace, PhysicalReadPlatformError};
use crate::memory::{backing::MemoryBacking, domain::PublicationFault};
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::Ordering;

pub(in crate::memory) struct RegionReload {
    backing: Arc<MemoryBacking>,
    offset: usize,
    original_prefix: Box<[u8]>,
}
impl RegionReload {
    pub(in crate::memory) fn new(
        backing: Arc<MemoryBacking>,
        offset: usize,
        original_prefix: Box<[u8]>,
    ) -> Self {
        Self {
            backing,
            offset,
            original_prefix,
        }
    }
}
#[derive(Debug)]
pub(crate) struct RegionResetObservation {
    pub(crate) generation: u64,
    pub(crate) completed_bytes: usize,
    pub(crate) completed_regions: usize,
}
#[derive(Debug)]
pub(crate) enum RegionResetFailure {
    Unavailable(PhysicalReadPlatformError),
    Publication {
        fault: PublicationFault,
        observation: RegionResetObservation,
    },
}
impl core::fmt::Display for RegionResetFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unavailable(error) => write!(f, "RAM prefix reload unavailable: {error}"),
            Self::Publication { fault, observation } => write!(
                f,
                "RAM prefix reload generation{} failed after{} bytes/{} regions: {fault}",
                observation.generation, observation.completed_bytes, observation.completed_regions
            ),
        }
    }
}
impl core::error::Error for RegionResetFailure {}
impl PhysicalAddressSpace {
    pub(crate) fn owns_mutable_instruction_sources(&self) -> bool {
        self.binding.has_mutable_instruction_sources()
    }

    /// Only a mutable borrow of the real physical owner can request this storage
    /// reset. The service loan excludes every original native/outer participant.
    /// The caller must retire its derived source/RX cache before re-entry; fresh
    /// fetch also rejects every old mutation generation. No PE is reconstructed.
    pub(crate) fn reload_original_region_prefixes(
        &mut self,
    ) -> Result<RegionResetObservation, RegionResetFailure> {
        self.check_source_binding()
            .map_err(RegionResetFailure::Unavailable)?;
        let _service = self.domain.service_loan().map_err(|status| {
            RegionResetFailure::Unavailable(PhysicalReadPlatformError::Domain(status))
        })?;
        let next =
            self.binding
                .reset_generation
                .checked_add(1)
                .ok_or(RegionResetFailure::Unavailable(
                    PhysicalReadPlatformError::Unavailable,
                ))?;
        let mut observation = RegionResetObservation {
            generation: next,
            completed_bytes: 0,
            completed_regions: 0,
        };
        for reload in &self.binding.reloads {
            // SAFETY: the sole region factory retained original private prefix,
            // actual RW backing and same System. Quiescent service excludes all
            // native effects/rights changes; every fragment uses tracked writer.
            let result = unsafe {
                self.domain
                    .system
                    .publish(&reload.backing, reload.offset, &reload.original_prefix)
            };
            match result {
                Ok(()) => {
                    observation.completed_bytes += reload.original_prefix.len();
                    observation.completed_regions += 1;
                }
                Err(fault) => {
                    observation.completed_bytes += fault.completed;
                    self.domain.system.failed.store(true, Ordering::Release);
                    return Err(RegionResetFailure::Publication { fault, observation });
                }
            }
        }
        self.binding.reset_generation = next;
        Ok(observation)
    }
}
