//! The rules of the host's page window: the rest of the first 512 GiB of the
//! engine's window, past its image, stacks and MMIO aperture, inside the same
//! top-level entry and so in every root the engine builds. Scattered pages get
//! a contiguous CPU view there in the cache attribute their use needs, which the
//! aperture's uncached leaves cannot give: `vmap`, a GPU's write-combined BAR1,
//! and the buffers NVK maps.
//!
//! Pure functions over addresses and leaf values, and the allocator of the
//! window's pages.
use alloc::collections::BTreeMap;

pub const PAGE: u64 = 4096;
/// Bytes one paging-structure entry's level covers, from the leaf up.
const DIRECTORY_BYTES: u64 = PAGE << 9;
const DIRECTORY_POINTER_BYTES: u64 = DIRECTORY_BYTES << 9;
const ENTRIES: u64 = 512;
/// The window's offset in the engine's: past `layout`'s fixed parts.
const OFFSET: u64 = 0x10_0000_0000;

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const WRITE_THROUGH: u64 = 1 << 3;
const CACHE_DISABLE: u64 = 1 << 4;
/// PAT's selector bit in a 4 KiB leaf.
const PAT: u64 = 1 << 7;
const ACCESSED_DIRTY: u64 = 0x60;
const NO_EXECUTE: u64 = 1 << 63;

/// The IA32_PAT encoding of write-combining (Intel SDM Vol. 3A 12.12.2, AMD
/// APM Vol. 2 7.8.1 give the same table).
const WRITE_COMBINING: u64 = 1;
/// The PAT entry the window's write-combining leaves select. Nothing maps
/// through it at reset, as its entry mirrors one the lower four already offer.
pub const WRITE_COMBINING_INDEX: u32 = 5;

/// `pat` with [`WRITE_COMBINING_INDEX`] made write-combining. Every other
/// entry stays as firmware left it, so no existing mapping changes type.
pub fn with_write_combining(pat: u64) -> u64 {
    let shift = 8 * WRITE_COMBINING_INDEX;
    pat & !(0xff << shift) | WRITE_COMBINING << shift
}

/// How a window page is cached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cache {
    WriteBack,
    WriteCombining,
    Uncached,
}

/// The leaf that maps `physical`, writable and never executable.
pub fn leaf(physical: u64, cache: Cache) -> u64 {
    let attribute = match cache {
        Cache::WriteBack => 0,
        // PAT, PCD and PWT of 1, 0 and 1 select PAT entry 5.
        Cache::WriteCombining => PAT | WRITE_THROUGH,
        // Of 0, 1 and 1, entry 3, which firmware leaves uncached.
        Cache::Uncached => CACHE_DISABLE | WRITE_THROUGH,
    };
    physical | PRESENT | WRITABLE | NO_EXECUTE | ACCESSED_DIRTY | attribute
}

/// The leaf that maps `physical` write-back, writable and executable: generated
/// code, which its generator writes in place.
pub fn code_leaf(physical: u64) -> u64 {
    leaf(physical, Cache::WriteBack) & !NO_EXECUTE
}

/// The cache attribute of a page Linux's page protection `prot` asks for, in
/// the PWT and PCD bits its `pgprot_writecombine` and `pgprot_noncached` set.
pub fn cache_of(prot: u64) -> Cache {
    if prot & CACHE_DISABLE != 0 {
        Cache::Uncached
    } else if prot & WRITE_THROUGH != 0 {
        Cache::WriteCombining
    } else {
        Cache::WriteBack
    }
}

/// A window address's index in its directory-pointer, directory and page
/// tables.
pub fn indices(address: u64) -> [usize; 3] {
    [
        (address / DIRECTORY_POINTER_BYTES % ENTRIES) as usize,
        (address / DIRECTORY_BYTES % ENTRIES) as usize,
        (address / PAGE % ENTRIES) as usize,
    ]
}

/// The page window of the engine's window at `base`: the rest of the
/// directory-pointer table its fixed parts start.
pub fn span(base: u64) -> core::ops::Range<u64> {
    base + OFFSET..base + DIRECTORY_POINTER_BYTES * ENTRIES
}

/// The window's free pages, as runs by their first address. An unmapped run
/// comes back merged with its neighbours, so long-lived small mappings cannot
/// fragment the window into uselessness.
pub struct Free {
    runs: BTreeMap<u64, u64>,
}

impl Free {
    pub fn new(span: core::ops::Range<u64>) -> Self {
        let mut runs = BTreeMap::new();
        if span.end > span.start {
            runs.insert(span.start, (span.end - span.start) / PAGE);
        }
        Self { runs }
    }

    /// The first run of `pages` pages, lowest first so tables stay few.
    pub fn take(&mut self, pages: u64) -> Option<u64> {
        if pages == 0 {
            return None;
        }
        let (&start, &length) = self.runs.iter().find(|(_, length)| **length >= pages)?;
        self.runs.remove(&start);
        if length > pages {
            self.runs.insert(start + pages * PAGE, length - pages);
        }
        Some(start)
    }

    pub fn give(&mut self, start: u64, pages: u64) {
        let (mut start, mut pages) = (start, pages);
        if let Some((&before, &length)) = self.runs.range(..start).next_back()
            && before + length * PAGE == start
        {
            self.runs.remove(&before);
            start = before;
            pages += length;
        }
        if let Some(&length) = self.runs.get(&(start + pages * PAGE)) {
            self.runs.remove(&(start + pages * PAGE));
            pages += length;
        }
        self.runs.insert(start, pages);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    #[test]
    fn only_the_write_combining_entry_changes() {
        // The reset value: WB, WT, UC-, UC twice over.
        let reset = 0x0007_0406_0007_0406;
        assert_eq!(with_write_combining(reset), 0x0007_0106_0007_0406);
        assert_eq!(
            with_write_combining(with_write_combining(reset)),
            0x0007_0106_0007_0406
        );
    }

    #[test]
    fn leaves_select_their_pat_entry() {
        let index = |leaf: u64| (leaf >> 3 & 1) | (leaf >> 4 & 1) << 1 | (leaf >> 7 & 1) << 2;
        assert_eq!(index(leaf(0x1000, Cache::WriteBack)), 0);
        assert_eq!(index(leaf(0x1000, Cache::Uncached)), 3);
        assert_eq!(
            index(leaf(0x1000, Cache::WriteCombining)),
            u64::from(WRITE_COMBINING_INDEX)
        );
        let value = leaf(0x7000, Cache::WriteBack);
        assert_eq!(value & 0x000f_ffff_ffff_f000, 0x7000);
        assert_eq!(
            value & (PRESENT | WRITABLE | NO_EXECUTE),
            PRESENT | WRITABLE | NO_EXECUTE
        );
    }

    #[test]
    fn only_code_leaves_run() {
        let code = code_leaf(0x7000);
        assert_eq!(code & NO_EXECUTE, 0);
        assert_eq!(code | NO_EXECUTE, leaf(0x7000, Cache::WriteBack));
    }

    #[test]
    fn linux_protections_choose_the_cache() {
        assert_eq!(cache_of(0), Cache::WriteBack);
        assert_eq!(cache_of(WRITE_THROUGH), Cache::WriteCombining);
        assert_eq!(cache_of(CACHE_DISABLE), Cache::Uncached);
        assert_eq!(cache_of(CACHE_DISABLE | WRITE_THROUGH), Cache::Uncached);
    }

    #[test]
    fn the_window_fills_the_rest_of_its_table() {
        let window = span(0xffff_8000_0000_0000);
        assert_eq!(window.start, 0xffff_8000_0000_0000 + 64 * GIB);
        assert_eq!(window.end, 0xffff_8080_0000_0000);
        assert_eq!(indices(window.start)[0], 64);
        assert_eq!(
            indices(window.start + (GIB + 2 * (1 << 21) + 5 * PAGE)),
            [65, 2, 5]
        );
    }

    #[test]
    fn runs_split_and_merge() {
        let mut free = Free::new(0x10000..0x18000);
        assert_eq!(free.take(0), None);
        assert_eq!(free.take(9), None);
        let first = free.take(2).unwrap();
        let second = free.take(2).unwrap();
        let third = free.take(2).unwrap();
        assert_eq!([first, second, third], [0x10000, 0x12000, 0x14000]);
        // The hole is too small until its neighbour joins it.
        free.give(second, 2);
        assert_eq!(free.take(3), None);
        free.give(first, 2);
        assert_eq!(free.take(4), Some(0x10000));
        free.give(0x10000, 4);
        free.give(third, 2);
        assert_eq!(free.take(8), Some(0x10000));
    }
}
