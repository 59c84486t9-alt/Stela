//! Sets of fetch pages a board compiles in a variant of their own: the
//! tagged variant (`Machine::learn_tagged_page`) and the two-sided range
//! check at EL0 (`Machine::learn_two_sided_page`). One set for every PE of
//! the board, so the first PE that needs the variant switches the page for
//! all of them, and the page's blocks are forgotten once. Fetches read it
//! without a lock: an open-addressed table of physical frame numbers,
//! filled by compare-and-swap, never emptied.
use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The most pages a set takes; past them an access keeps its engine path.
pub(super) const CAPACITY: usize = 1 << 14;
/// Slots: twice the capacity, so probes stay short.
const SLOTS: usize = CAPACITY * 2;
/// The page size the set keys by (the fetch page).
const PAGE_SHIFT: u32 = 12;

/// What [`PageSet::insert`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Inserted {
    /// The page is new to the set.
    New,
    /// Another PE (or this one) put it there before.
    Present,
    /// The set is full and does not hold it.
    Full,
}

pub(super) struct PageSet {
    /// Frame number plus one; 0 is an empty slot.
    slots: Box<[AtomicU64]>,
    /// Pages held, read first so a board with none pays one load.
    count: AtomicUsize,
}

impl Default for PageSet {
    fn default() -> Self {
        Self {
            slots: (0..SLOTS)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            count: AtomicUsize::new(0),
        }
    }
}

impl PageSet {
    fn key(physical: u64) -> u64 {
        (physical >> PAGE_SHIFT) + 1
    }

    fn start(key: u64) -> usize {
        (key.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 32) as usize % SLOTS
    }

    /// Put the page holding `physical` in the set.
    pub(super) fn insert(&self, physical: u64) -> Inserted {
        let key = Self::key(physical);
        let mut at = Self::start(key);
        for _ in 0..SLOTS {
            let slot = &self.slots[at];
            match slot.load(Ordering::Acquire) {
                held if held == key => return Inserted::Present,
                0 => {
                    if self.count.load(Ordering::Relaxed) >= CAPACITY {
                        return Inserted::Full;
                    }
                    match slot.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                        Ok(_) => {
                            self.count.fetch_add(1, Ordering::Release);
                            return Inserted::New;
                        }
                        Err(held) if held == key => return Inserted::Present,
                        // Another page took the slot: probe on.
                        Err(_) => {}
                    }
                }
                _ => {}
            }
            at = (at + 1) % SLOTS;
        }
        Inserted::Full
    }

    /// Whether the page holding `physical` is in the set.
    pub(super) fn contains(&self, physical: u64) -> bool {
        if self.count.load(Ordering::Acquire) == 0 {
            return false;
        }
        let key = Self::key(physical);
        let mut at = Self::start(key);
        for _ in 0..SLOTS {
            match self.slots[at].load(Ordering::Acquire) {
                0 => return false,
                held if held == key => return true,
                _ => at = (at + 1) % SLOTS,
            }
        }
        false
    }

    /// Pages held.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_go_in_once_and_the_set_stops_at_its_capacity() {
        let pages = PageSet::default();
        assert!(!pages.contains(0x1000));
        assert_eq!(pages.insert(0x1234), Inserted::New);
        // Keyed by the 4 KiB page.
        assert_eq!(pages.insert(0x1ff8), Inserted::Present);
        assert!(pages.contains(0x1000) && !pages.contains(0x2000) && !pages.contains(0));
        assert_eq!(pages.insert(0), Inserted::New);
        assert!(pages.contains(0x0fff));
        for page in 2..CAPACITY as u64 {
            assert_eq!(pages.insert(page << PAGE_SHIFT), Inserted::New);
        }
        assert_eq!(pages.len(), CAPACITY);
        assert_eq!(pages.insert(1 << 40), Inserted::Full);
        assert!(!pages.contains(1 << 40));
        assert_eq!(pages.insert(0x5000), Inserted::Present);
        assert!((0..CAPACITY as u64).all(|page| pages.contains(page << PAGE_SHIFT)));
    }

    #[test]
    fn pes_racing_on_one_page_see_one_new_insert() {
        let pages = std::sync::Arc::new(PageSet::default());
        for round in 0..64u64 {
            let page = round << PAGE_SHIFT;
            let threads: Vec<_> = (0..4)
                .map(|_| {
                    let pages = std::sync::Arc::clone(&pages);
                    std::thread::spawn(move || pages.insert(page))
                })
                .collect();
            let new = threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .filter(|inserted| *inserted == Inserted::New)
                .count();
            assert_eq!(new, 1, "round {round}");
        }
    }
}
