//! Why the board compiles code it had compiled before, for the heartbeat
//! (`PES CODE churn=`): a ghost of each block that leaves the index (its
//! identity, why it went, the ring generation then and a byte of its source
//! hash), and at each install whether the block's ghost is there. The table
//! is direct-mapped by a hash of the block's PC, frame address and variant,
//! so a slot keeps the latest ghost hashed to it and the counts are close,
//! not exact. It changes only under the board's code lock, where blocks
//! leave the index and are installed, and a compile reads it without the
//! lock to choose its block's generation ([`Churn::promotes`]); a fetch
//! never reads it.
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

/// Why a block left the index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Gone {
    /// Its ring part was taken away as the ring went round.
    Ring = 0,
    /// An IC IVAU of its page.
    Invalidated = 1,
    /// Its part went early, for want of a block slot.
    Slot = 2,
    /// A discard of every block, or a host's reclaim.
    Other = 3,
}

/// Ghosts: one per block slot, between 2^15 and 2^21 (16 MiB), which a
/// board of 1.6M live blocks retiring a part at a time keeps for about a
/// turn of its ring.
fn ghost_slots(slots: u32) -> usize {
    (slots as usize).next_power_of_two().clamp(1 << 15, 1 << 21)
}

/// Ring generations a ghost keeps.
const GENERATION_BITS: u32 = 30;
const GENERATION_MASK: u64 = (1 << GENERATION_BITS) - 1;

/// What [`Churn`] counted: installs never in the index before (as far as
/// the table tells), and those of a block that left it, by [`Gone`]; of
/// those, the IC IVAU ones whose bytes were the same; the age of a
/// re-install in ring generations since its block left: within one turn
/// of the ring, four, or more. `aliases` are installs whose frame offset
/// held a block of another PC already, `variants` of the same PC in
/// another variant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChurnCounts {
    pub installs: u64,
    pub new: u64,
    pub again: [u64; 4],
    pub same_bytes: u64,
    pub ages: [u64; 3],
    pub aliases: u64,
    pub variants: u64,
}

impl ChurnCounts {
    /// The counts since `was`.
    pub fn since(&self, was: &Self) -> Self {
        let less = |now: u64, was: u64| now.saturating_sub(was);
        Self {
            installs: less(self.installs, was.installs),
            new: less(self.new, was.new),
            again: core::array::from_fn(|at| less(self.again[at], was.again[at])),
            same_bytes: less(self.same_bytes, was.same_bytes),
            ages: core::array::from_fn(|at| less(self.ages[at], was.ages[at])),
            aliases: less(self.aliases, was.aliases),
            variants: less(self.variants, was.variants),
        }
    }
}

pub(super) struct Churn {
    /// Per slot: a 24-bit tag of the identity, the cause, a byte of the
    /// source hash and the generation it left in; 0 for none.
    ghosts: Box<[AtomicU64]>,
}

/// The hash of a block's identity: its PC, frame address and variant.
pub(super) fn identity(pc: u64, physical: u64, variant: u32) -> u64 {
    let mut hash = pc.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    hash ^= physical.rotate_left(17).wrapping_mul(0xc2b2_ae3d_27d4_eb4f);
    hash ^= u64::from(variant).wrapping_mul(0x1656_67b1_9e37_79f9);
    (hash ^ hash >> 31).wrapping_mul(0xbf58_476d_1ce4_e5b9) ^ hash >> 29
}

/// A nonzero 24-bit tag of `identity`, apart from the bits that pick its
/// slot.
fn tag(identity: u64) -> u64 {
    (identity >> 40) | 1
}

impl Churn {
    pub(super) fn new(slots: u32) -> Self {
        Self {
            ghosts: (0..ghost_slots(slots)).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    fn slot(&self, identity: u64) -> usize {
        identity as usize & (self.ghosts.len() - 1)
    }

    /// A block of `identity` with source hash `source` left the index in
    /// ring generation `generation`, for `cause`.
    pub(super) fn gone(&self, identity: u64, source: u64, generation: u32, cause: Gone) {
        let ghost = tag(identity) << 40
            | (cause as u64) << 38
            | (source & 0xff) << GENERATION_BITS
            | u64::from(generation) & GENERATION_MASK;
        self.ghosts[self.slot(identity)].store(ghost, Ordering::Relaxed);
    }

    /// Whether a block of `identity` compiled in generation `generation`
    /// belongs in the tenured generation: the ring took its block away
    /// within [`super::board::AGE_TURNS`] turns of `parts`. No lock.
    pub(super) fn promotes(&self, identity: u64, generation: u32, parts: u32) -> bool {
        let ghost = self.ghosts[self.slot(identity)].load(Ordering::Relaxed);
        let cause = (ghost >> 38) & 3;
        let left = (ghost & GENERATION_MASK) as u32;
        let age = generation.wrapping_sub(left) & GENERATION_MASK as u32;
        ghost >> 40 == tag(identity)
            && (cause == Gone::Ring as u64 || cause == Gone::Slot as u64)
            && age <= super::board::AGE_TURNS * parts
    }

    /// A block of `identity` with source hash `source` is installed in
    /// generation `generation`; `shared` says whether its frame offset held
    /// a block of another PC (`Some(true)`) or of its PC in another variant
    /// (`Some(false)`).
    pub(super) fn installed(
        &self,
        counts: &mut ChurnCounts,
        identity: u64,
        source: u64,
        generation: u32,
        shared: Option<bool>,
        parts: u32,
    ) {
        counts.installs += 1;
        match shared {
            Some(true) => counts.aliases += 1,
            Some(false) => counts.variants += 1,
            None => {}
        }
        let slot = &self.ghosts[self.slot(identity)];
        let ghost = slot.load(Ordering::Relaxed);
        if ghost >> 40 != tag(identity) {
            counts.new += 1;
            return;
        }
        slot.store(0, Ordering::Relaxed);
        let cause = (ghost >> 38) as usize & 3;
        counts.again[cause] += 1;
        if cause == Gone::Invalidated as usize && (ghost >> GENERATION_BITS) & 0xff == source & 0xff
        {
            counts.same_bytes += 1;
        }
        let left = (ghost & GENERATION_MASK) as u32;
        let age = generation.wrapping_sub(left) & GENERATION_MASK as u32;
        let parts = parts.max(1);
        counts.ages[if age <= parts {
            0
        } else if age <= 4 * parts {
            1
        } else {
            2
        }] += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reinstall_counts_why_its_block_went_and_how_long_ago() {
        let (churn, mut counts) = (Churn::new(1 << 16), ChurnCounts::default());
        let (a, b, c) = (
            identity(0x1000, 0x8000, 0),
            identity(0x1004, 0x8004, 0),
            identity(0x1000, 0x8000, 1),
        );
        assert_ne!(a, c);
        churn.installed(&mut counts, a, 7, 0, None, 32);
        churn.gone(a, 7, 3, Gone::Ring);
        churn.gone(b, 9, 3, Gone::Invalidated);
        // A block the ring took within four turns goes to the tenured
        // generation; one an IC IVAU took, or one long gone, does not.
        assert!(churn.promotes(a, 40, 32));
        assert!(!churn.promotes(a, 3 + 4 * 32 + 1, 32));
        assert!(!churn.promotes(b, 4, 32));
        assert!(!churn.promotes(c, 4, 32));
        // Another variant of the same PC is new, and counted as one.
        churn.installed(&mut counts, c, 7, 4, Some(false), 32);
        churn.installed(&mut counts, a, 7, 40, Some(true), 32);
        churn.installed(&mut counts, b, 9, 300, None, 32);
        // A ghost counts once.
        churn.installed(&mut counts, a, 7, 41, None, 32);
        assert_eq!(counts.installs, 5);
        assert_eq!(counts.new, 3);
        assert_eq!(counts.again, [1, 1, 0, 0]);
        assert_eq!(counts.same_bytes, 1);
        assert_eq!(counts.ages, [0, 1, 1]);
        assert_eq!((counts.aliases, counts.variants), (1, 1));
        assert_eq!(counts.since(&counts), ChurnCounts::default());
    }

    #[test]
    fn new_bytes_after_an_invalidation_are_not_the_same() {
        let (churn, mut counts) = (Churn::new(1 << 16), ChurnCounts::default());
        let a = identity(0x2000, 0x9000, 2);
        churn.gone(a, 0x11, 5, Gone::Invalidated);
        churn.installed(&mut counts, a, 0x12, 5, None, 32);
        assert_eq!(counts.again[Gone::Invalidated as usize], 1);
        assert_eq!(counts.same_bytes, 0);
        assert_eq!(counts.ages, [1, 0, 0]);
    }
}
