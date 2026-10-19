//! The system counter the PEs observe: the host's counter, held back by
//! what the PEs could not have done in the time it shows.
//!
//! The PEs of a board run concurrently on hardware but take turns on the
//! host, and a translated PE runs far slower than the core it stands for.
//! Software times hardware work against the counter: XNU 26A434 panics once
//! a mutex interlock stays held for 12,582,912 counts (`lock_mtx.c` 326,
//! about 0.5 s at 24 MHz) or a ticket spinlock for 3,000,000
//! (`lock_ticket.c`, 125 ms). A holder that needs a few milliseconds of a
//! real core, while the other PEs spin out their slices, can take that long
//! in host time, and the guest panics although nothing is wrong.
//!
//! So a time slice may advance the counter by at most [`TICKS_PER_BLOCK`]
//! for each block it runs, shared among the PEs that could run with it:
//! over a round of slices every runnable PE then gets a block done for each
//! `TICKS_PER_BLOCK` counts, as on a slow but concurrent machine. A slice
//! that shows more is charged as lag when it ends, and the counter holds at
//! the last value read until the host's catches up, so it never runs
//! backwards (Arm ARM D12.1.2, the count is monotonically increasing).
//! While every PE waits nothing has to progress, and the counter follows
//! the host's. When the host is fast enough, no slice exceeds its bound and
//! the counter is the host's minus the lag of earlier slow stretches.
//!
//! With idle skip (`Machine::set_idle_skip`), a wait of every PE ends at
//! once: the counter leaps to the next deadline, as if the host had waited
//! that long, so the guest's sleeps cost no host time. Nothing outside the
//! board changes the machine meanwhile, so it observes the same sequence of
//! events; time of day then runs ahead of the host's by the leaps.
//!
//! The architecture requires a constant counter frequency, not a match
//! with wall time; time of day drifts behind by the accumulated lag, as on
//! a machine whose counter was paused, and ahead by any idle leaps.

/// The most counts one block may account for: one count at 24 MHz is
/// 42 ns, a PE at least ~1/12 the speed of an M2 core. XNU drivers time
/// work against fixed timeouts (IOUSBDeviceFamily's function registration,
/// IOKit start waits), so a slower apparent PE fails them although nothing
/// is wrong. The longest real critical section XNU guards with a timeout
/// runs far below 3,000,000 blocks, the ticket spinlock bound at this rate.
pub(super) const TICKS_PER_BLOCK: u64 = 1;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Clock {
    /// Host counts the guest is behind.
    lag: u64,
    /// Counts the guest leapt ahead over idle waits.
    lead: u64,
    /// The last count read, which no later read precedes.
    last: u64,
    /// The running slice, when a PE runs: its start count, start block
    /// count and the PEs sharing the round.
    slice: Option<Slice>,
}

#[derive(Debug, Clone, Copy)]
struct Slice {
    count: u64,
    blocks: u64,
    share: u64,
}

impl Clock {
    /// The count at host counter value `host`.
    pub(super) fn read(&mut self, host: u64) -> u64 {
        self.last = host
            .saturating_add(self.lead)
            .saturating_sub(self.lag)
            .max(self.last);
        self.last
    }

    /// The host counter value at which the count reaches `count`.
    pub(super) fn host_deadline(&self, count: u64) -> u64 {
        count.saturating_add(self.lag).saturating_sub(self.lead)
    }

    /// `counts` of host time passed with no PE running and nothing in the
    /// guest's world happening: the count does not show it.
    pub(super) fn exclude(&mut self, counts: u64) {
        self.lag += counts;
    }

    /// While every PE waits at host counter value `host`, the count leaps to
    /// `deadline` if it is still before it.
    pub(super) fn skip_to(&mut self, host: u64, deadline: u64) {
        let count = self.read(host);
        self.lead += deadline.saturating_sub(count);
        self.last = self.last.max(deadline);
    }

    /// A slice starts at host counter value `host` and block count `blocks`,
    /// with `share` PEs (at least one) able to run in the round.
    pub(super) fn start_slice(&mut self, host: u64, blocks: u64, share: u64) {
        let count = self.read(host);
        self.slice = Some(Slice {
            count,
            blocks,
            share: share.max(1),
        });
    }

    /// The running slice ends at `host` and `blocks`: the counts it showed
    /// beyond its blocks' bound become lag.
    pub(super) fn end_slice(&mut self, host: u64, blocks: u64) {
        let count = self.read(host);
        let Some(slice) = self.slice.take() else {
            return;
        };
        let allowed = blocks
            .saturating_sub(slice.blocks)
            .saturating_mul(TICKS_PER_BLOCK)
            / slice.share;
        let shown = count - slice.count;
        self.lag += shown.saturating_sub(allowed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_advance_by_their_blocks_and_waits_by_the_host() {
        // The blocks that account for `counts` counts.
        let blocks = |counts: u64| counts / TICKS_PER_BLOCK;
        let mut clock = Clock::default();
        clock.start_slice(1000, 0, 2);
        // Within a slice the host's counter shows through.
        assert_eq!(clock.read(1500), 1500);
        // Blocks shared by two PEs account for 200 counts, so the 800 more
        // the slice showed become lag and the count holds.
        clock.end_slice(2000, blocks(400));
        assert_eq!(clock.read(2000), 2000);
        assert_eq!(clock.read(2500), 2000);
        assert_eq!(clock.read(2900), 2100);
        assert_eq!(clock.host_deadline(2200), 3000);
        // A slice within its bound adds no lag.
        clock.start_slice(3000, blocks(400), 1);
        clock.end_slice(3200, blocks(800));
        assert_eq!(clock.read(3300), 2500);
        // Waiting outside a slice follows the host.
        assert_eq!(clock.read(10_000), 9200);
        clock.end_slice(11_000, blocks(800));
        assert_eq!(clock.read(11_000), 10_200);
    }

    #[test]
    fn excluded_host_time_never_reaches_the_count() {
        let mut clock = Clock::default();
        assert_eq!(clock.read(100), 100);
        clock.exclude(900);
        assert_eq!(clock.read(1000), 100);
        assert_eq!(clock.read(1010), 110);
    }

    #[test]
    fn idle_skips_leap_to_the_deadline_and_keep_counting_from_there() {
        let mut clock = Clock::default();
        assert_eq!(clock.read(100), 100);
        clock.skip_to(150, 5_000);
        assert_eq!(clock.read(150), 5_000);
        assert_eq!(clock.read(200), 5_050);
        assert_eq!(clock.host_deadline(6_000), 1_150);
        // A deadline already reached leaps nowhere.
        clock.skip_to(300, 10);
        assert_eq!(clock.read(300), 5_150);
        // Lag from a slow slice still holds the count back: 90 of the 100
        // counts it showed, until the host catches up.
        clock.start_slice(300, 0, 1);
        clock.end_slice(400, 10 / TICKS_PER_BLOCK);
        assert_eq!(clock.read(490), 5_250);
        assert_eq!(clock.read(500), 5_260);
    }
}
