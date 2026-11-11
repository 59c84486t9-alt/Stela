//! The lookup contexts of one half of the address space ([`Space`]), by
//! key, from the last change of its translations no control value shows,
//! up to a bound, the least recently used dropped first.
//!
//! A context names a translation regime's inputs as a TLB tags its
//! entries, so its ITLB entries stay valid until a TLBI that reaches them
//! (`code_cache.rs`): a process that runs again after hundreds of others
//! finds its pages. A context's number is never reused, and it names its
//! slot here, so whether an ITLB entry's context is live is one load.

use super::*;

/// The contexts the lower half keeps: one per address space, EL and SPRR
/// permission value its fetches ran with, for every process a desktop runs
/// (about 500 on macOS) with room to spare. An ITLB of 16 Ki entries holds
/// the working sets of a few hundred of them at most.
pub(super) const LOWER_CONTEXTS: usize = 2048;
/// The upper half's: the kernel's, one per EL, GL and SPRR_PERM_EL1 value
/// (and one per ASID while one of its fetches was non-global).
pub(super) const UPPER_CONTEXTS: usize = 256;
/// The bits of a context number above its salt that name its slot.
const SLOT_BITS: u32 = 12;
const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;
const _: () = assert!(LOWER_CONTEXTS <= 1 << SLOT_BITS && UPPER_CONTEXTS <= 1 << SLOT_BITS);
/// No slot, in the recency list.
const NONE: u32 = u32::MAX;

/// What tells one context of a half from another: with the half's
/// [`Frame`], the inputs [`Machine::half_inputs`] gives, and the EL (with
/// the guarded level) and variant fetches run in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Key {
    /// TTBR0's value as the half's inputs keep it (the upper half keeps
    /// at most its ASID).
    pub(super) ttbr0: u64,
    /// The one SPRR permission register the fetch reads: SPRR_PERM_EL0 at
    /// EL0, SPRR_PERM_EL1 above.
    pub(super) permissions: u64,
    /// The other inputs, by their number in [`Machine::context_frames`].
    pub(super) frame: u32,
    pub(super) el: u8,
    pub(super) variant: Variant,
}

/// One lookup context: its key, its number (which ITLB entries hold), and
/// what TLBIs select contexts by.
#[derive(Debug, Clone, Copy)]
pub(super) struct Space {
    pub(super) key: Key,
    pub(super) number: u64,
    /// The ASID of its non-global translations ([`mmu::current_asid`]).
    pub(super) asid: u16,
    pub(super) regime: mmu::Regime,
}

/// A half's contexts.
#[derive(Debug, Default)]
pub(super) struct Contexts {
    /// By slot; a slot without a context holds number 0.
    spaces: Vec<Space>,
    free: Vec<u32>,
    keys: BTreeMap<Key, u32>,
    /// The recency list: each slot's older and newer neighbour.
    older: Vec<u32>,
    newer: Vec<u32>,
    oldest: u32,
    newest: u32,
    capacity: usize,
}

/// The slot a context number names.
pub(super) fn number_slot(number: u64) -> usize {
    ((number >> chain::LOOKUP_SALT_BITS) & SLOT_MASK) as usize
}

/// The number of the context made `made`-th, in `slot`, with `salt`.
pub(super) fn context_number(made: u64, slot: usize, salt: u64) -> u64 {
    ((made << SLOT_BITS | slot as u64) << chain::LOOKUP_SALT_BITS) | salt
}

impl Contexts {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            oldest: NONE,
            newest: NONE,
            capacity,
            ..Self::default()
        }
    }

    pub(super) fn len(&self) -> usize {
        self.keys.len()
    }

    /// The live context numbered `number`.
    pub(super) fn live(&self, number: u64) -> Option<&Space> {
        self.spaces
            .get(number_slot(number))
            .filter(|space| space.number == number && number != 0)
    }

    /// The number of the context of `key`, which becomes the most recently
    /// used.
    pub(super) fn find(&mut self, key: &Key) -> Option<u64> {
        let slot = *self.keys.get(key)?;
        self.touch(slot);
        Some(self.spaces[slot as usize].number)
    }

    /// Make a context of `key`, numbered by `number` from its slot: the
    /// most recently used. Past the capacity the least recently used goes
    /// first, which this returns.
    pub(super) fn insert(
        &mut self,
        key: Key,
        asid: u16,
        regime: mmu::Regime,
        number: impl FnOnce(usize) -> u64,
    ) -> (u64, Option<Space>) {
        debug_assert!(!self.keys.contains_key(&key));
        let evicted = (self.len() == self.capacity).then(|| {
            let oldest = self.oldest;
            let space = self.spaces[oldest as usize];
            self.remove(oldest);
            space
        });
        let slot = match self.free.pop() {
            Some(slot) => slot,
            None => {
                self.spaces.push(Space {
                    key,
                    number: 0,
                    asid,
                    regime,
                });
                self.older.push(NONE);
                self.newer.push(NONE);
                (self.spaces.len() - 1) as u32
            }
        };
        let number = number(slot as usize);
        debug_assert_eq!(number_slot(number), slot as usize);
        self.spaces[slot as usize] = Space {
            key,
            number,
            asid,
            regime,
        };
        self.keys.insert(key, slot);
        self.link_newest(slot);
        (number, evicted)
    }

    /// Keep the contexts `keep` names: how many went.
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&Space) -> bool) -> usize {
        let gone: Vec<u32> = self
            .keys
            .values()
            .copied()
            .filter(|&slot| !keep(&self.spaces[slot as usize]))
            .collect();
        for &slot in &gone {
            self.remove(slot);
        }
        gone.len()
    }

    pub(super) fn clear(&mut self) {
        let capacity = self.capacity;
        *self = Self::new(capacity);
    }

    /// The live contexts.
    pub(super) fn iter(&self) -> impl Iterator<Item = &Space> {
        self.keys.values().map(|&slot| &self.spaces[slot as usize])
    }

    fn remove(&mut self, slot: u32) {
        let space = &mut self.spaces[slot as usize];
        self.keys.remove(&space.key);
        space.number = 0;
        self.unlink(slot);
        self.free.push(slot);
    }

    fn touch(&mut self, slot: u32) {
        if self.newest != slot {
            self.unlink(slot);
            self.link_newest(slot);
        }
    }

    fn unlink(&mut self, slot: u32) {
        let (older, newer) = (self.older[slot as usize], self.newer[slot as usize]);
        match older {
            NONE => self.oldest = newer,
            older => self.newer[older as usize] = newer,
        }
        match newer {
            NONE => self.newest = older,
            newer => self.older[newer as usize] = older,
        }
        self.older[slot as usize] = NONE;
        self.newer[slot as usize] = NONE;
    }

    fn link_newest(&mut self, slot: u32) {
        self.older[slot as usize] = self.newest;
        self.newer[slot as usize] = NONE;
        match self.newest {
            NONE => self.oldest = slot,
            newest => self.newer[newest as usize] = slot,
        }
        self.newest = slot;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(ttbr0: u64) -> Key {
        Key {
            ttbr0,
            permissions: 0,
            frame: 0,
            el: 0,
            variant: super::super::tests::machine(&[]).current_variant(false, false),
        }
    }

    fn insert(contexts: &mut Contexts, ttbr0: u64, made: &mut u64) -> (u64, Option<Space>) {
        *made += 1;
        let made = *made;
        contexts.insert(key(ttbr0), 0, mmu::Regime::El20, |slot| {
            context_number(made, slot, ttbr0 % chain::LOOKUP_SALTS as u64)
        })
    }

    /// Numbers name their slot and are never reused; the least recently
    /// used goes at the capacity, and a lookup makes a context recent.
    #[test]
    fn contexts_go_least_recently_used_first_and_numbers_stay_unique() {
        let mut contexts = Contexts::new(3);
        let mut made = 0;
        let numbers: Vec<u64> = (1..=3)
            .map(|table| insert(&mut contexts, table, &mut made).0)
            .collect();
        for &number in &numbers {
            assert_eq!(
                contexts.live(number).map(|space| space.number),
                Some(number)
            );
        }
        assert_eq!(contexts.find(&key(1)), Some(numbers[0]));
        let (fourth, evicted) = insert(&mut contexts, 4, &mut made);
        assert_eq!(evicted.map(|space| space.key.ttbr0), Some(2));
        assert!(contexts.live(numbers[1]).is_none());
        assert_eq!(number_slot(fourth), number_slot(numbers[1]));
        assert!(!numbers.contains(&fourth));
        assert_eq!(contexts.find(&key(2)), None);
        assert_eq!(contexts.retain(|space| space.key.ttbr0 != 1), 1);
        assert!(contexts.live(numbers[0]).is_none());
        assert_eq!(contexts.len(), 2);
        // The order survives removals: 3 is now the oldest.
        insert(&mut contexts, 5, &mut made);
        let (_, evicted) = insert(&mut contexts, 6, &mut made);
        assert_eq!(evicted.map(|space| space.key.ttbr0), Some(3));
        contexts.clear();
        assert_eq!(contexts.len(), 0);
        assert!(contexts.live(fourth).is_none());
        assert!(contexts.live(0).is_none());
    }
}
