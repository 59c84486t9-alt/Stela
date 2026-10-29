//! Retained callback wall time, distinct from queued command latency.
use core::sync::atomic::{AtomicU64, Ordering};

/// One callback generation observed active between the sample's counter reads.
/// This is diagnostic metadata, not a completion or quiescence receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveCallback {
    pub sequence: u64,
    pub started_ticks: u64,
}

/// Independently sampled callback kinds; not a coherent view across owners.
/// None means idle or raced. A sampled callback can finish immediately afterward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallbackActivity {
    pub observed_before_ticks: u64,
    pub observed_after_ticks: u64,
    pub advance: Option<ActiveCallback>,
    pub direct: Option<ActiveCallback>,
}

#[derive(Default)]
pub(super) struct Activity {
    pub advance: Active,
    pub direct: Active,
}

#[derive(Default)]
pub(super) struct Active {
    sequence: AtomicU64,
    started: AtomicU64,
}

impl Active {
    pub(super) fn enter(&self, started: u64) -> Guard<'_> {
        debug_assert_eq!(self.sequence.load(Ordering::SeqCst) & 1, 0);
        self.started.store(started, Ordering::SeqCst);
        self.sequence.fetch_add(1, Ordering::SeqCst);
        Guard(self)
    }

    pub(super) fn snapshot(&self) -> Option<ActiveCallback> {
        let sequence = self.sequence.load(Ordering::SeqCst);
        if sequence & 1 == 0 {
            return None;
        }
        let started_ticks = self.started.load(Ordering::SeqCst);
        // The shared total order prevents a newer start from validating
        // against an older generation, including the idle gap between calls.
        (self.sequence.load(Ordering::SeqCst) == sequence).then_some(ActiveCallback {
            sequence,
            started_ticks,
        })
    }
}

pub(super) struct Guard<'a>(&'a Active);

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.sequence.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallbackCounts {
    pub calls: u64,
    pub elapsed_ticks: u64,
    pub maximum_ticks: u64,
    /// Queued provider start attempts and returned completions, including errors.
    /// Direct callbacks do not expose their internal command count here.
    pub starts: u64,
    pub finishes: u64,
    pub maximum_starts: u64,
    pub maximum_finishes: u64,
}

/// Direct execution can be nested inside advance for a synchronous provider.
/// The two elapsed categories must not be added together as CPU time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallbackStats {
    pub advance: CallbackCounts,
    pub direct: CallbackCounts,
}

#[derive(Default)]
pub(super) struct Work {
    pub starts: u64,
    pub finishes: u64,
}

impl CallbackCounts {
    pub(super) fn record(&mut self, elapsed: u64, work: Work) {
        self.calls = self.calls.saturating_add(1);
        self.elapsed_ticks = self.elapsed_ticks.saturating_add(elapsed);
        self.maximum_ticks = self.maximum_ticks.max(elapsed);
        self.starts = self.starts.saturating_add(work.starts);
        self.finishes = self.finishes.saturating_add(work.finishes);
        self.maximum_starts = self.maximum_starts.max(work.starts);
        self.maximum_finishes = self.maximum_finishes.max(work.finishes);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::block::{BlockDevice, BlockError, Command, Identity, RamDisk, Shared};
    use alloc::{boxed::Box, rc::Rc, vec::Vec};
    use core::cell::RefCell;

    #[test]
    fn disabled_activity_reads_no_clock_and_enabled_samples_are_bracketed() {
        let _clock = crate::test_clock::virtualize();
        let disk = Shared::new(Box::new(RamDisk::new("activity", 8, 512)));
        let first = crate::Clock::ticks();
        let step = crate::Clock::ticks().wrapping_sub(first);
        let before = crate::Clock::ticks();
        assert!(disk.callback_activity().is_none());
        assert_eq!(crate::Clock::ticks().wrapping_sub(before), step);
        disk.set_callback_profile(true);
        let sample = disk.callback_activity().unwrap();
        assert_eq!(
            sample
                .observed_after_ticks
                .wrapping_sub(sample.observed_before_ticks),
            step
        );
        assert!(sample.advance.is_none() && sample.direct.is_none());
        disk.set_callback_profile(false);
        let before = crate::Clock::ticks();
        assert!(disk.callback_activity().is_none());
        assert_eq!(crate::Clock::ticks().wrapping_sub(before), step);
    }

    struct Observing {
        disk: RamDisk,
        owner: Rc<RefCell<Option<Shared>>>,
        samples: Rc<RefCell<Vec<CallbackActivity>>>,
    }

    impl BlockDevice for Observing {
        fn identity(&self) -> &Identity {
            self.disk.identity()
        }
        fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
            self.disk.read(lba, buffer)
        }
        fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
            let owner = self.owner.borrow();
            let owner = owner.as_ref().unwrap();
            assert!(
                owner.callback_stats().is_none(),
                "the callback holds the disk lock"
            );
            self.samples
                .borrow_mut()
                .push(owner.callback_activity().unwrap());
            self.disk.write(lba, data)
        }
    }

    #[test]
    fn actual_nested_callbacks_publish_without_acquiring_the_held_disk_lock() {
        let _clock = crate::test_clock::virtualize();
        let owner = Rc::new(RefCell::new(None));
        let samples = Rc::new(RefCell::new(Vec::new()));
        let disk = Shared::new(Box::new(Observing {
            disk: RamDisk::new("nested", 8, 512),
            owner: owner.clone(),
            samples: samples.clone(),
        }));
        *owner.borrow_mut() = Some(disk.clone());
        disk.set_callback_profile(true);
        let mut window = disk.whole();
        let ticket = window
            .start(Command::Write {
                lba: 0,
                data: alloc::vec![0x7e; 512],
                fua: false,
            })
            .unwrap();
        let sample = samples.borrow()[0];
        let advance = sample.advance.unwrap();
        let direct = sample.direct.unwrap();
        assert_eq!((advance.sequence, direct.sequence), (1, 1));
        assert!(advance.started_ticks <= direct.started_ticks);
        assert!(direct.started_ticks <= sample.observed_before_ticks);
        assert!(sample.observed_before_ticks < sample.observed_after_ticks);
        let idle = disk.callback_activity().unwrap();
        assert!(idle.advance.is_none() && idle.direct.is_none());
        assert_eq!(window.finish(ticket), Some(Ok(None)));
        assert_eq!(disk.stats().callbacks.unwrap().direct.calls, 1);
        // Break the fixture's observer cycle; production metadata owns no disk handles.
        owner.borrow_mut().take();
    }

    #[test]
    fn nested_kind_lifetimes_leave_the_outer_generation_active() {
        let activity = Activity::default();
        let outer = activity.advance.enter(0);
        let first = activity.advance.snapshot().unwrap();
        {
            let _inner = activity.direct.enter(7);
            assert_eq!(activity.advance.snapshot(), Some(first));
            assert_eq!(activity.direct.snapshot().unwrap().started_ticks, 7);
        }
        assert!(activity.direct.snapshot().is_none());
        assert_eq!(activity.advance.snapshot(), Some(first));
        drop(outer);
        assert!(activity.advance.snapshot().is_none());
        let _next = activity.advance.enter(9);
        assert_eq!(
            activity.advance.snapshot().unwrap().sequence,
            first.sequence + 2
        );
    }

    #[test]
    fn concurrent_samples_keep_generation_and_start_together() {
        let active = Active::default();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let first = active.enter(1);
                barrier.wait();
                barrier.wait();
                drop(first);
                for index in 1..1000 {
                    let _call = active.enter(2 * index + 1);
                    std::thread::yield_now();
                }
            });
            barrier.wait();
            let first = active.snapshot();
            barrier.wait();
            assert_eq!(first.unwrap().started_ticks, 1);
            for _ in 0..1000 {
                if let Some(sample) = active.snapshot() {
                    assert_eq!(sample.sequence, sample.started_ticks);
                }
                std::thread::yield_now();
            }
        });
        assert!(active.snapshot().is_none());
    }
}
