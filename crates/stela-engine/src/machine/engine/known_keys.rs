//! The page keys of fetch pages a board's PEs read, shared by all of them:
//! a page read again whose bytes give the check it had
//! ([`super::stored::page_check`]) takes its key instead of being hashed,
//! whichever PE read it before. The check of the bytes just read is what
//! keeps a key valid: a page written with or without IC maintenance checks
//! differently and is hashed again. An IC IVAU forgets its page's key, and
//! a discard of the board's code all of them, as each PE's own table did.
//!
//! The table is two-way set associative by frame, a slot a sequence lock of
//! atomic words: a reader never waits, a writer that finds its slot taken
//! leaves it, and a read racing a write misses. Its size is the store's
//! ([`super::stored::Translations::known_pages`]), at most [`MAX_SLOTS`].
use crate::translations::Digest;
use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering, fence};

/// The most slots: 2^18 of 56 bytes, 14.7 MB, room for twice the distinct
/// code pages a desktop boot reads (about 146 thousand).
pub(super) const MAX_SLOTS: usize = 1 << 18;
/// Slots without a store's size: what a machine without one keeps.
#[cfg(not(test))]
pub(super) const DEFAULT_SLOTS: usize = 1 << 15;
#[cfg(test)]
pub(super) const DEFAULT_SLOTS: usize = 1 << 4;
/// The fewest slots.
const MIN_SLOTS: usize = 1 << 4;

/// The frame word's low bits, below the 4 KiB frame: the slot holds a key,
/// the store held no record for it, and the table's generation then.
const VALID: u64 = 1;
const ABSENT: u64 = 2;
const GENERATION_SHIFT: u32 = 2;
const GENERATION_MASK: u64 = 0x3ff;
const FRAME_MASK: u64 = !0xfff;

#[derive(Default)]
struct Slot {
    /// Odd while a writer writes.
    sequence: AtomicU64,
    frame: AtomicU64,
    check: AtomicU64,
    key: [AtomicU64; 4],
}

/// What the table knows of a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Known {
    pub(super) key: Digest,
    pub(super) absent: bool,
}

/// A board's known page keys, allocated at the first use.
pub(super) struct KnownKeys {
    slots: AtomicPtr<Vec<Slot>>,
    /// Advances when every key is forgotten: slots of another generation
    /// hold none.
    generation: AtomicU64,
}

impl Default for KnownKeys {
    fn default() -> Self {
        Self {
            slots: AtomicPtr::new(core::ptr::null_mut()),
            generation: AtomicU64::new(0),
        }
    }
}

impl Drop for KnownKeys {
    fn drop(&mut self) {
        let slots = *self.slots.get_mut();
        if !slots.is_null() {
            // SAFETY: allocated by `table` from a `Box` and never freed
            // elsewhere; `&mut self` excludes every other use.
            drop(unsafe { Box::from_raw(slots) });
        }
    }
}

impl KnownKeys {
    /// The slots, allocated at the first call with about `slots` of them.
    fn table(&self, slots: usize) -> &[Slot] {
        let mut table = self.slots.load(Ordering::Acquire);
        if table.is_null() {
            let count = 1 << slots.clamp(MIN_SLOTS, MAX_SLOTS).ilog2();
            let fresh = Box::into_raw(Box::new((0..count).map(|_| Slot::default()).collect()));
            table = match self.slots.compare_exchange(
                core::ptr::null_mut(),
                fresh,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => fresh,
                Err(won) => {
                    // SAFETY: `fresh` was never shared.
                    drop(unsafe { Box::from_raw(fresh) });
                    won
                }
            };
        }
        // SAFETY: set once, freed only by `drop`.
        unsafe { &*table }
    }

    /// The slots in use, if any.
    fn allocated(&self) -> Option<&[Slot]> {
        let table = self.slots.load(Ordering::Acquire);
        // SAFETY: as in `table`.
        (!table.is_null()).then(|| unsafe { (&*table).as_slice() })
    }

    /// The two slots of `frame`'s set.
    fn set(table: &[Slot], frame: u64) -> [&Slot; 2] {
        let number = frame >> 12;
        let mixed = number.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 20;
        let first = (mixed as usize) & (table.len() - 1) & !1;
        [&table[first], &table[first + 1]]
    }

    fn tag(&self, frame: u64) -> u64 {
        let generation = self.generation.load(Ordering::Relaxed) & GENERATION_MASK;
        (frame & FRAME_MASK) | generation << GENERATION_SHIFT | VALID
    }

    /// A consistent copy of `slot`: its frame word, check and key.
    fn read(slot: &Slot) -> Option<(u64, u64, Digest)> {
        let before = slot.sequence.load(Ordering::Acquire);
        if before & 1 != 0 {
            return None;
        }
        let frame = slot.frame.load(Ordering::Relaxed);
        let check = slot.check.load(Ordering::Relaxed);
        let mut key = [0u8; 32];
        for (bytes, word) in key.as_chunks_mut::<8>().0.iter_mut().zip(&slot.key) {
            *bytes = word.load(Ordering::Relaxed).to_le_bytes();
        }
        fence(Ordering::Acquire);
        (slot.sequence.load(Ordering::Relaxed) == before).then_some((frame, check, Digest(key)))
    }

    /// Write `slot` unless another writer holds it.
    fn write(slot: &Slot, frame: u64, check: u64, key: &Digest) {
        let sequence = slot.sequence.load(Ordering::Relaxed);
        if sequence & 1 != 0
            || slot
                .sequence
                .compare_exchange(sequence, sequence + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        fence(Ordering::Release);
        slot.frame.store(frame, Ordering::Relaxed);
        slot.check.store(check, Ordering::Relaxed);
        for (bytes, word) in key.0.as_chunks::<8>().0.iter().zip(&slot.key) {
            word.store(u64::from_le_bytes(*bytes), Ordering::Relaxed);
        }
        slot.sequence.store(sequence + 2, Ordering::Release);
    }

    /// The key of the page at `frame` whose bytes check `check`, if a PE
    /// read it so before.
    pub(super) fn get(&self, slots: usize, frame: u64, check: u64) -> Option<Known> {
        let tag = self.tag(frame);
        Self::set(self.table(slots), frame)
            .into_iter()
            .filter_map(Self::read)
            .find(|&(word, held, _)| word & !ABSENT == tag && held == check)
            .map(|(word, _, key)| Known {
                key,
                absent: word & ABSENT != 0,
            })
    }

    /// Keep `known` as the key of the page at `frame` whose bytes check
    /// `check`: in the slot that holds the frame, else an empty one, else
    /// the one the check picks.
    pub(super) fn put(&self, slots: usize, frame: u64, check: u64, known: Known) {
        let tag = self.tag(frame);
        let set = Self::set(self.table(slots), frame);
        let held = set.map(|slot| Self::read(slot).map(|(word, ..)| word));
        let way = (0..2)
            .find(|&way| held[way].is_some_and(|word| word & FRAME_MASK == frame & FRAME_MASK))
            .or_else(|| (0..2).find(|&way| held[way].is_some_and(|word| word & VALID == 0)))
            .unwrap_or((check & 1) as usize);
        let word = tag | if known.absent { ABSENT } else { 0 };
        Self::write(set[way], word, check, &known.key);
    }

    /// Forget the key of the page at `frame`.
    pub(super) fn forget(&self, frame: u64) {
        let Some(table) = self.allocated() else {
            return;
        };
        for slot in Self::set(table, frame) {
            if Self::read(slot).is_some_and(|(word, ..)| word & FRAME_MASK == frame & FRAME_MASK) {
                Self::write(slot, 0, 0, &Digest([0; 32]));
            }
        }
    }

    /// Forget every key.
    pub(super) fn forget_all(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(n: u8, absent: bool) -> Known {
        Known {
            key: Digest([n; 32]),
            absent,
        }
    }

    #[test]
    fn a_key_is_found_by_its_frame_and_check_until_forgotten() {
        let keys = KnownKeys::default();
        assert_eq!(keys.get(16, 0x1000, 7), None);
        keys.put(16, 0x1000, 7, known(1, false));
        keys.put(16, 0x2000, 8, known(2, true));
        assert_eq!(keys.get(16, 0x1000, 7), Some(known(1, false)));
        assert_eq!(keys.get(16, 0x2000, 8), Some(known(2, true)));
        // Other bytes check differently.
        assert_eq!(keys.get(16, 0x1000, 9), None);
        // The same frame's new key replaces its old one.
        keys.put(16, 0x1000, 9, known(3, false));
        assert_eq!(keys.get(16, 0x1000, 7), None);
        assert_eq!(keys.get(16, 0x1000, 9), Some(known(3, false)));
        keys.forget(0x1000);
        assert_eq!(keys.get(16, 0x1000, 9), None);
        assert_eq!(keys.get(16, 0x2000, 8), Some(known(2, true)));
        keys.forget_all();
        assert_eq!(keys.get(16, 0x2000, 8), None);
    }

    #[test]
    fn a_full_table_keeps_the_keys_put_last() {
        let keys = KnownKeys::default();
        for frame in 0..64u64 {
            keys.put(16, frame << 12, frame, known(frame as u8, false));
        }
        let held = (0..64u64)
            .filter(|&frame| keys.get(16, frame << 12, frame).is_some())
            .count();
        assert!(held > 0 && held <= 16, "{held}");
        assert_eq!(keys.get(16, 63 << 12, 63), Some(known(63, false)));
    }

    #[test]
    fn threads_reading_and_writing_see_whole_keys() {
        let keys = std::sync::Arc::new(KnownKeys::default());
        let threads: Vec<_> = (0..4u64)
            .map(|thread| {
                let keys = keys.clone();
                std::thread::spawn(move || {
                    for round in 0..20_000u64 {
                        let frame = (round % 64) << 12;
                        let n = ((round + thread) % 251) as u8;
                        keys.put(64, frame, u64::from(n), known(n, false));
                        if let Some(found) = keys.get(64, frame, u64::from(n)) {
                            assert_eq!(found.key, Digest([n; 32]));
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }
}
