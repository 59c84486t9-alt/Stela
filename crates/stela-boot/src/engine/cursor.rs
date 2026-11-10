//! How the guest's pointer follows the host's in real time: the rate of the
//! display's presents that moved a layer (a pointer moves its layer whole),
//! and the time from a host pointer report to the first such present after
//! it, both on the host's clock. The display paces itself on the guest's
//! counter, so its own rate (`DCP PACING`) is per guest second.
//!
//! The service notes the host read of the first pointer report a present
//! has not yet answered ([`motion`]); the boot PE looks at the display's
//! count of moved presents after each slice ([`Cursor::look`]), so a
//! latency is late by one slice at most.

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use stela_soc::dcp::iomfb::moved_presents;

/// When the host read the oldest pointer report no moved present followed
/// yet, in TSC ticks; zero for none.
static MOTION_AT: AtomicU64 = AtomicU64::new(0);

/// The host read a pointer report at TSC `now`.
pub(super) fn motion(now: u64) {
    let _ = MOTION_AT.compare_exchange(0, now.max(1), Ordering::Relaxed, Ordering::Relaxed);
}

/// The moved presents and latencies since the last report.
pub(super) struct Cursor {
    seen: u64,
    since: u64,
    moved: u64,
    samples: u64,
    total: u64,
    longest: u64,
}

impl Cursor {
    pub(super) fn new(now: u64) -> Self {
        Self {
            seen: moved_presents(),
            since: now,
            moved: 0,
            samples: 0,
            total: 0,
            longest: 0,
        }
    }

    /// Note the moved presents since the last look, at TSC `now`.
    pub(super) fn look(&mut self, now: u64) {
        let seen = moved_presents();
        if seen == self.seen {
            return;
        }
        self.moved += seen.wrapping_sub(self.seen);
        self.seen = seen;
        let at = MOTION_AT.swap(0, Ordering::Relaxed);
        if at != 0 {
            let latency = now.saturating_sub(at);
            self.samples += 1;
            self.total += latency;
            self.longest = self.longest.max(latency);
        }
    }

    /// The window's line, and a new window from TSC `now`.
    pub(super) fn report(&mut self, now: u64, tsc_hz: u64) -> String {
        let tsc_hz = u128::from(tsc_hz.max(1));
        let millis = |ticks: u64| u128::from(ticks) * 1000 / tsc_hz;
        let wall = now.saturating_sub(self.since).max(1);
        let per_ten = u128::from(self.moved) * 10 * tsc_hz / u128::from(wall);
        let pending = MOTION_AT.load(Ordering::Relaxed);
        let line = alloc::format!(
            "CURSOR moved_per_wall_second={}.{} input_to_present_ms={}/{} samples={} unanswered_ms={}\n",
            per_ten / 10,
            per_ten % 10,
            millis(self.total / self.samples.max(1)),
            millis(self.longest),
            self.samples,
            if pending == 0 {
                0
            } else {
                millis(now.saturating_sub(pending))
            },
        );
        *self = Self {
            seen: self.seen,
            since: now,
            moved: 0,
            samples: 0,
            total: 0,
            longest: 0,
        };
        line
    }
}
