//! Architectural data translations, not a cache of current PTE bytes or RAM.
//! Valid mappings may remain stale until guest maintenance. Fetches still walk
//! and compare actual source bytes; all data hits still resolve actual RAM.
use super::{DataPart, mmu};
use alloc::{boxed::Box, vec};

const PAGE_BYTES: u64 = 4096;
const PAGE_MASK: u64 = PAGE_BYTES - 1;
const CELLS: usize = 128;

#[derive(Clone, Copy)]
struct Entry {
    page: u64,
    translation: mmu::Translation,
}

#[cfg(feature = "native-profile")]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Statistics {
    pub hits: u64,
    pub misses: u64,
    pub bypasses: u64,
    pub permission_misses: u64,
    pub walks: u64,
    pub descriptor_reads: u64,
    pub fills: u64,
    pub replacements: u64,
    pub generation_flushes: u64,
    pub control_flushes: u64,
    pub cells: usize,
    pub retained_bytes: usize,
}

#[derive(Default)]
pub(super) struct DataTlb {
    // None until actual Machine preparation; stopped helpers disable reuse.
    generation: Option<u64>,
    // Lazy, bounded allocation; no table-sized array on a native callback stack.
    cells: Box<[Option<Entry>]>,
    #[cfg(feature = "native-profile")]
    statistics: Statistics,
}

impl DataTlb {
    pub(super) fn refresh(&mut self, generation: u64, controls_changed: bool) {
        let generation_changed = self.generation != Some(generation);
        if generation_changed || controls_changed {
            self.cells.fill(None);
            #[cfg(feature = "native-profile")]
            {
                self.statistics.generation_flushes = self
                    .statistics
                    .generation_flushes
                    .saturating_add(u64::from(generation_changed));
                self.statistics.control_flushes = self
                    .statistics
                    .control_flushes
                    .saturating_add(u64::from(controls_changed));
            }
        }
        self.generation = Some(generation);
    }

    pub(super) fn disable(&mut self) {
        self.generation = None;
        self.cells.fill(None);
    }

    fn contained(part: DataPart) -> bool {
        matches!(part.bytes, 1 | 2 | 4 | 8)
            && part.address.is_multiple_of(part.bytes as u64)
            && (part.address & PAGE_MASK) + part.bytes as u64 <= PAGE_BYTES
    }

    fn index(address: u64) -> usize {
        (address / PAGE_BYTES) as usize % CELLS
    }

    pub(super) fn lookup(&mut self, part: DataPart, eligible: bool) -> Option<mmu::Translation> {
        if self.generation.is_none() || !eligible || !Self::contained(part) {
            #[cfg(feature = "native-profile")]
            {
                self.statistics.bypasses = self.statistics.bypasses.saturating_add(1);
            }
            return None;
        }
        let entry = self.cells.get(Self::index(part.address)).copied().flatten();
        if let Some(entry) = entry.filter(|entry| entry.page == part.address & !PAGE_MASK) {
            let permitted = match part.kind {
                crate::memory::backing::AccessKind::Read => entry.translation.readable,
                crate::memory::backing::AccessKind::Write => entry.translation.writable,
                crate::memory::backing::AccessKind::Execute => false,
            };
            if permitted {
                let mut translation = entry.translation;
                translation.physical |= part.address & PAGE_MASK;
                #[cfg(feature = "native-profile")]
                {
                    self.statistics.hits = self.statistics.hits.saturating_add(1);
                }
                return Some(translation);
            }
            #[cfg(feature = "native-profile")]
            {
                self.statistics.permission_misses =
                    self.statistics.permission_misses.saturating_add(1);
            }
        }
        #[cfg(feature = "native-profile")]
        {
            self.statistics.misses = self.statistics.misses.saturating_add(1);
        }
        None
    }

    pub(super) fn fill(&mut self, part: DataPart, mut translation: mmu::Translation) {
        if self.generation.is_none()
            || !Self::contained(part)
            || translation.memory != mmu::MemoryType::Normal
            || translation.attributes == mmu::attributes::TAGGED
            || translation.alignment.device
            || !translation.size.is_power_of_two()
            || translation.size < PAGE_BYTES
            || (translation.physical & PAGE_MASK) != part.address & PAGE_MASK
        {
            return;
        }
        if self.cells.is_empty() {
            self.cells = vec![None; CELLS].into_boxed_slice();
        }
        let index = Self::index(part.address);
        #[cfg(feature = "native-profile")]
        {
            self.statistics.fills = self.statistics.fills.saturating_add(1);
            if self.cells[index].is_some() {
                self.statistics.replacements = self.statistics.replacements.saturating_add(1);
            }
        }
        translation.physical &= !PAGE_MASK;
        self.cells[index] = Some(Entry {
            page: part.address & !PAGE_MASK,
            translation,
        });
    }

    pub(super) fn record_walk(&mut self, #[cfg(feature = "native-profile")] reads: u64) {
        #[cfg(feature = "native-profile")]
        {
            self.statistics.walks = self.statistics.walks.saturating_add(1);
            self.statistics.descriptor_reads =
                self.statistics.descriptor_reads.saturating_add(reads);
        }
    }

    #[cfg(feature = "native-profile")]
    pub(super) fn statistics(&self) -> Statistics {
        Statistics {
            cells: self.cells.len(),
            retained_bytes: size_of::<Self>() + size_of_val(self.cells.as_ref()),
            ..self.statistics
        }
    }
}

#[cfg(test)]
mod tests;
