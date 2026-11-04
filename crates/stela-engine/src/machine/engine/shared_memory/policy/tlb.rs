//! Architectural data translations, not a cache of current PTE bytes or RAM.
//! Valid mappings may remain stale until guest maintenance. Fetches still walk
//! and compare source bytes; all data hits still resolve RAM.
use super::{DataPart, mmu};
use crate::memory::backing::AccessKind;
use alloc::{boxed::Box, vec};

const PAGE_BYTES: u64 = 4096;
const PAGE_MASK: u64 = PAGE_BYTES - 1;
const CELLS: usize = 128;
const LARGE_LEAVES: usize = 4;
const READ: u64 = 1;
const WRITE: u64 = 2;

#[derive(Clone, Copy)]
struct Entry {
    page: u64,
    // Page-aligned physical base with data permissions in its low bits.
    physical_rights: u64,
}

impl Entry {
    const EMPTY: Self = Self {
        page: u64::MAX,
        physical_rights: 0,
    };
}

#[derive(Clone, Copy)]
struct LargeEntry {
    base: u64,
    mask: u64,
    physical_rights: u64,
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
    // None until Machine preparation; stopped helpers disable reuse.
    generation: Option<u64>,
    // Lazy, bounded allocation; no table-sized array on a native callback stack.
    cells: Box<[Entry]>,
    // Recent large leaves back the 4 KiB hot cache without expanding a
    // block into thousands of entries. Check these only on a page miss.
    large: [Option<LargeEntry>; LARGE_LEAVES],
    next_large: usize,
    #[cfg(feature = "native-profile")]
    statistics: Statistics,
}

impl DataTlb {
    pub(super) fn refresh(&mut self, generation: u64, controls_changed: bool) {
        let generation_changed = self.generation != Some(generation);
        if generation_changed || controls_changed {
            self.clear();
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
        self.clear();
    }

    fn clear(&mut self) {
        self.cells.fill(Entry::EMPTY);
        self.large.fill(None);
        self.next_large = 0;
    }

    fn contained(part: DataPart) -> bool {
        // These naturally aligned widths all divide a page.
        matches!(part.bytes, 1 | 2 | 4 | 8) && part.address & (part.bytes as u64 - 1) == 0
    }

    fn index(address: u64) -> usize {
        (address / PAGE_BYTES) as usize % CELLS
    }

    pub(super) fn lookup(&mut self, part: DataPart, eligible: bool) -> Option<u64> {
        if self.generation.is_none() || !eligible || !Self::contained(part) {
            #[cfg(feature = "native-profile")]
            {
                self.statistics.bypasses = self.statistics.bypasses.saturating_add(1);
            }
            return None;
        }
        let page = part.address & !PAGE_MASK;
        let index = Self::index(page);
        let hot = self.cells.get(index).copied();
        let hot = hot.filter(|entry| entry.page == page);
        let entry = hot.or_else(|| {
            let leaf = self
                .large
                .iter()
                .flatten()
                .find(|leaf| part.address & !leaf.mask == leaf.base)?;
            Some(Entry {
                page,
                physical_rights: leaf.physical_rights | (page & leaf.mask),
            })
        });
        if let Some(entry) = entry {
            let required = match part.kind {
                AccessKind::Read => READ,
                AccessKind::Write => WRITE,
                AccessKind::Execute => 0,
            };
            if entry.physical_rights & required != 0 {
                if hot.is_none() {
                    self.cells[index] = entry;
                }
                #[cfg(feature = "native-profile")]
                {
                    self.statistics.hits = self.statistics.hits.saturating_add(1);
                }
                return Some((entry.physical_rights & !PAGE_MASK) | (part.address & PAGE_MASK));
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

    pub(super) fn fill(&mut self, part: DataPart, translation: mmu::Translation) {
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
            self.cells = vec![Entry::EMPTY; CELLS].into_boxed_slice();
        }
        let index = Self::index(part.address);
        #[cfg(feature = "native-profile")]
        {
            self.statistics.fills = self.statistics.fills.saturating_add(1);
            if self.cells[index].page != Entry::EMPTY.page {
                self.statistics.replacements = self.statistics.replacements.saturating_add(1);
            }
        }
        let rights =
            (u64::from(translation.readable) * READ) | (u64::from(translation.writable) * WRITE);
        let mask = translation.size - 1;
        if mask > PAGE_MASK && translation.physical & mask == part.address & mask {
            let base = part.address & !mask;
            let entry = Some(LargeEntry {
                base,
                mask,
                physical_rights: (translation.physical & !mask) | rights,
            });
            if let Some(existing) = self.large.iter_mut().find(|existing| {
                existing.is_some_and(|leaf| leaf.base == base && leaf.mask == mask)
            }) {
                *existing = entry;
            } else {
                self.large[self.next_large] = entry;
                self.next_large = (self.next_large + 1) % LARGE_LEAVES;
            }
        }
        self.cells[index] = Entry {
            page: part.address & !PAGE_MASK,
            physical_rights: (translation.physical & !PAGE_MASK) | rights,
        };
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
