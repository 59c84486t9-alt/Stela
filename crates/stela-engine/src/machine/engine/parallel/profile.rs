//! Bounded broadcast observations. No observation grants quiescence authority.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastKind {
    Tlb,
    Code,
    Power,
}
impl BroadcastKind {
    pub const ALL: [Self; 3] = [Self::Tlb, Self::Code, Self::Power];
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Whole broadcast duration includes posting and processing incoming mail.
/// Counts saturate; they are retained observations, never completion receipts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BroadcastCounts {
    pub started: u64,
    /// Calls that returned, including errors, rather than architectural receipts.
    pub completed: u64,
    pub recipients: u64,
    pub elapsed_ticks: u64,
    pub maximum_ticks: u64,
    pub polls: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BroadcastProfile {
    pub kinds: [BroadcastCounts; 3],
    pub active: Option<BroadcastKind>,
    /// Raw owner counter at entry; meaningful only while active is Some.
    pub active_start: u64,
    /// At least one update was lost; counters then provide only lower bounds.
    pub dropped_updates: bool,
}

#[derive(Default)]
struct AtomicCounts {
    started: AtomicU64,
    completed: AtomicU64,
    recipients: AtomicU64,
    elapsed_ticks: AtomicU64,
    maximum_ticks: AtomicU64,
    polls: AtomicU64,
}
impl AtomicCounts {
    fn read(&self) -> BroadcastCounts {
        BroadcastCounts {
            started: self.started.load(Ordering::SeqCst),
            completed: self.completed.load(Ordering::SeqCst),
            recipients: self.recipients.load(Ordering::SeqCst),
            elapsed_ticks: self.elapsed_ticks.load(Ordering::SeqCst),
            maximum_ticks: self.maximum_ticks.load(Ordering::SeqCst),
            polls: self.polls.load(Ordering::SeqCst),
        }
    }
}

#[derive(Default)]
pub(super) struct Slot {
    sequence: AtomicU64,
    kinds: [AtomicCounts; 3],
    active: AtomicU64,
    start: AtomicU64,
    dropped: AtomicBool,
}

pub(super) struct Active {
    kind: BroadcastKind,
    start: u64,
}

impl Slot {
    fn dropped(&self) {
        self.dropped.store(true, Ordering::Relaxed);
    }

    /// A single nonblocking attempt; anomalous overlapping publishers drop.
    fn update(&self, write: impl FnOnce()) -> bool {
        let before = self.sequence.load(Ordering::SeqCst);
        let Some(after) = before.checked_add(2).filter(|_| before & 1 == 0) else {
            self.dropped();
            return false;
        };
        if self
            .sequence
            .compare_exchange(before, before + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            self.dropped();
            return false;
        }
        write();
        self.sequence.store(after, Ordering::SeqCst);
        true
    }

    fn add(field: &AtomicU64, value: u64) {
        let current = field.load(Ordering::SeqCst);
        field.store(current.saturating_add(value), Ordering::SeqCst);
    }

    pub(super) fn begin(
        &self,
        kind: BroadcastKind,
        start: u64,
        recipients: usize,
    ) -> Option<Active> {
        let mut admitted = false;
        let published = self.update(|| {
            if self.active.load(Ordering::SeqCst) != 0 {
                self.dropped();
                return;
            }
            let counts = &self.kinds[kind.index()];
            Self::add(&counts.started, 1);
            Self::add(&counts.recipients, recipients as u64);
            self.start.store(start, Ordering::SeqCst);
            self.active.store(kind.index() as u64 + 1, Ordering::SeqCst);
            admitted = true;
        });
        (published && admitted).then_some(Active { kind, start })
    }

    pub(super) fn finish(&self, active: Active, elapsed: u64, polls: u64) {
        self.update(|| {
            if self.active.load(Ordering::SeqCst) != active.kind.index() as u64 + 1
                || self.start.load(Ordering::SeqCst) != active.start
            {
                self.dropped();
                return;
            }
            let counts = &self.kinds[active.kind.index()];
            Self::add(&counts.completed, 1);
            Self::add(&counts.elapsed_ticks, elapsed);
            let maximum = counts.maximum_ticks.load(Ordering::SeqCst).max(elapsed);
            counts.maximum_ticks.store(maximum, Ordering::SeqCst);
            Self::add(&counts.polls, polls);
            self.active.store(0, Ordering::SeqCst);
        });
    }

    pub(super) fn read(&self) -> Option<BroadcastProfile> {
        for _ in 0..3 {
            let before = self.sequence.load(Ordering::SeqCst);
            if before & 1 != 0 {
                continue;
            }
            let kinds = core::array::from_fn(|kind| self.kinds[kind].read());
            let active = self.active.load(Ordering::SeqCst);
            let active_start = self.start.load(Ordering::SeqCst);
            if before == self.sequence.load(Ordering::SeqCst) {
                return Some(BroadcastProfile {
                    kinds,
                    active: active
                        .checked_sub(1)
                        .and_then(|kind| BroadcastKind::ALL.get(kind as usize).copied()),
                    active_start,
                    dropped_updates: self.dropped.load(Ordering::Relaxed),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_reader_never_combines_partial_boundary_updates() {
        use std::sync::{Arc, atomic::AtomicBool};
        let slot = Arc::new(Slot::default());
        let done = Arc::new(AtomicBool::new(false));
        let producer = Arc::clone(&slot);
        let ended = Arc::clone(&done);
        let writer = std::thread::spawn(move || {
            for index in 0..10_000 {
                let active = producer.begin(BroadcastKind::Tlb, index * 64, 2).unwrap();
                producer.finish(active, 7, 3);
            }
            ended.store(true, Ordering::Release);
        });
        let check = |snapshot: BroadcastProfile| {
            let counts = snapshot.kinds[0];
            assert_eq!(
                counts.started,
                counts.completed + u64::from(snapshot.active.is_some())
            );
            assert_eq!(counts.recipients, counts.started * 2);
            assert_eq!(counts.elapsed_ticks, counts.completed * 7);
            assert_eq!(counts.polls, counts.completed * 3);
            assert!(!snapshot.dropped_updates);
            if snapshot.active.is_some() {
                assert_eq!(snapshot.active_start, counts.completed * 64);
            }
        };
        while !done.load(Ordering::Acquire) {
            if let Some(snapshot) = slot.read() {
                check(snapshot);
            }
            std::thread::yield_now();
        }
        writer.join().unwrap();
        let final_snapshot = slot.read().unwrap();
        check(final_snapshot);
        assert_eq!(final_snapshot.kinds[0].completed, 10_000);
    }

    #[test]
    fn records_started_completed_and_whole_elapsed_by_kind() {
        let slot = Slot::default();
        let active = slot.begin(BroadcastKind::Tlb, 10, 7).unwrap();
        let entered = slot.read().unwrap();
        assert_eq!(
            (entered.active, entered.active_start),
            (Some(BroadcastKind::Tlb), 10)
        );
        assert_eq!(
            (entered.kinds[0].started, entered.kinds[0].completed),
            (1, 0)
        );
        slot.finish(active, 30, 41);
        let active = slot.begin(BroadcastKind::Tlb, 50, 2).unwrap();
        slot.finish(active, 20, 3);
        let active = slot.begin(BroadcastKind::Code, 90, 1).unwrap();
        slot.finish(active, 7, 0);
        let observed = slot.read().unwrap();
        assert_eq!(observed.active, None);
        assert_eq!(
            observed.kinds[0],
            BroadcastCounts {
                started: 2,
                completed: 2,
                recipients: 9,
                elapsed_ticks: 50,
                maximum_ticks: 30,
                polls: 44
            }
        );
        assert_eq!(
            (observed.kinds[1].started, observed.kinds[1].maximum_ticks),
            (1, 7)
        );
        assert_eq!(observed.kinds[2], BroadcastCounts::default());
    }

    #[test]
    fn overlapping_and_busy_publishers_drop_without_spinning() {
        let slot = Slot::default();
        let active = slot.begin(BroadcastKind::Tlb, 1, 1).unwrap();
        assert!(slot.begin(BroadcastKind::Code, 2, 1).is_none());
        slot.finish(active, 3, 4);
        assert!(slot.read().unwrap().dropped_updates);
        slot.sequence.store(5, Ordering::SeqCst);
        assert!(slot.begin(BroadcastKind::Power, 5, 1).is_none());
        assert!(slot.read().is_none());
        assert!(slot.dropped.load(Ordering::Relaxed));
    }

    #[test]
    fn exhausted_publication_retains_observation_and_counts_saturate() {
        let slot = Slot::default();
        slot.kinds[0]
            .elapsed_ticks
            .store(u64::MAX - 1, Ordering::SeqCst);
        let active = slot.begin(BroadcastKind::Tlb, 1, 0).unwrap();
        slot.finish(active, 9, 0);
        assert_eq!(slot.read().unwrap().kinds[0].elapsed_ticks, u64::MAX);
        slot.sequence.store(u64::MAX - 1, Ordering::SeqCst);
        assert!(slot.begin(BroadcastKind::Tlb, 1, 0).is_none());
        assert_eq!(slot.read().unwrap().kinds[0].completed, 1);
    }
}
