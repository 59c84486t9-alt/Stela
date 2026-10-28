//! The host disk under ANS's namespaces.
//!
//! A host transfer takes as long as the host's storage does. Each I/O
//! command's transfer is submitted where the guest rings the doorbell, as
//! many at once as the guest queues, through the block layer
//! ([`Submission`]), which runs them on the disk as it has room. The
//! controller completes each command once the disk has completed its
//! transfer, in whatever order that happens, as a real controller completes
//! commands once its media has. It looks once the disk has posted a
//! completion. A disk that signals its completions wakes the core that
//! looks, so it looks otherwise only for a lost signal; for one that does
//! not, it looks after half the disk's recent latency, then more often
//! (Linux's hybrid polling). Nothing waits for the disk and nothing wakes
//! while no transfer runs. A disk that runs nothing queued completes each
//! transfer at once, the PE that rang waiting.
use alloc::{boxed::Box, vec::Vec};
use stela_drivers::block::{BlockDevice, BlockError, Finished, Identity, Request, Submission};

/// The latency assumed before any transfer completed: 100 us of the 24 MHz
/// counter.
const FIRST_LATENCY: u64 = 2_400;
/// The shortest wait between two looks: 10 us.
const SHORTEST_POLL: u64 = 240;
/// How long a signalling disk's transfer may go unsignalled before a look
/// finds a lost completion: 1 ms.
const LOST_SIGNAL: u64 = 24_000;

pub(super) struct HostDisk {
    device: Box<dyn BlockDevice>,
    /// The running transfers: each one's key, when it was submitted in
    /// counter ticks, and its commands.
    running: Vec<(u32, u64, Submission)>,
    /// What a transfer took, a moving average in counter ticks.
    latency: u64,
}

impl HostDisk {
    pub(super) fn new(device: Box<dyn BlockDevice>) -> Self {
        Self {
            device,
            running: Vec::new(),
            latency: FIRST_LATENCY,
        }
    }

    pub(super) fn identity(&self) -> &Identity {
        self.device.identity()
    }

    /// The host disk has a volatile write cache, so a write is durable
    /// only after a flush.
    pub(super) fn write_cache(&self) -> bool {
        self.identity().features.write_cache
    }

    /// Deallocating host blocks leaves them reading as zeros for good: the
    /// disk's Write Zeroes may deallocate.
    pub(super) fn deallocates_zeroed(&self) -> bool {
        self.identity()
            .features
            .write_zeroes
            .is_some_and(|zeroes| zeroes.unmap)
    }

    #[cfg(test)]
    pub(super) fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.device.read(address, buffer)
    }
    #[cfg(test)]
    pub(super) fn write(&mut self, address: u64, data: &[u8]) -> Result<(), BlockError> {
        self.device.write(address, data)
    }

    pub(super) fn flush(&mut self) -> Result<(), BlockError> {
        self.device.flush()
    }

    /// Submit `requests`, one after another, under `key` at counter `now`:
    /// their result at once from a disk that runs nothing queued, else
    /// `None` until [`Self::poll`] gives it.
    pub(super) fn submit(
        &mut self,
        key: u32,
        requests: Vec<Request>,
        now: u64,
    ) -> Option<Finished> {
        let mut submission = match Submission::batch(requests, self.device.identity()) {
            Ok(submission) => submission,
            Err(error) => return Some(Err(error)),
        };
        if let Some(done) = submission.poll(&mut *self.device) {
            return Some(done);
        }
        self.running.push((key, now, submission));
        None
    }

    /// The transfers the disk has completed by counter `now`, by key; never
    /// waits.
    pub(super) fn poll(&mut self, now: u64) -> Vec<(u32, Finished)> {
        let mut done = Vec::new();
        let mut index = 0;
        while index < self.running.len() {
            let Some(finished) = self.running[index].2.poll(&mut *self.device) else {
                index += 1;
                continue;
            };
            let (key, started, _) = self.running.swap_remove(index);
            let took = now.saturating_sub(started);
            self.latency = (self.latency * 7 + took) / 8;
            done.push((key, finished));
        }
        done
    }

    /// Whether a running transfer's completion is posted, ready for
    /// [`Self::poll`]; a look at memory alone.
    pub(super) fn posted(&self) -> bool {
        !self.running.is_empty() && self.device.posted()
    }

    /// When to look for the running transfers' completions next, at counter
    /// `now`: half the latency after the oldest began, then more often; for
    /// a disk that signals them, only once a signal is overdue.
    pub(super) fn next_look(&self, now: u64) -> u64 {
        let oldest = self.running.iter().map(|(_, started, _)| *started).min();
        if self.device.signals() {
            let overdue = (self.latency * 4).max(LOST_SIGNAL);
            let due = oldest.unwrap_or(now).saturating_add(overdue);
            return if now < due {
                due
            } else {
                now.saturating_add(LOST_SIGNAL)
            };
        }
        let half = oldest.unwrap_or(now).saturating_add(self.latency / 2);
        if now < half {
            half
        } else {
            now.saturating_add((self.latency / 8).max(SHORTEST_POLL))
        }
    }
}
