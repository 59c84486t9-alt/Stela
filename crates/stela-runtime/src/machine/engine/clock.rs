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
//! The architecture requires a constant counter frequency, not a match
//! with wall time; time of day drifts behind by the accumulated lag, as on
//! a machine whose counter was paused.

/// The most counts one block may account for: 4 counts at 24 MHz is
/// 167 ns, a PE at least ~1/50 the speed of an M2 core. The longest real
/// critical section XNU guards with a timeout runs far below 750,000
/// blocks, the 3,000,000-count ticket spinlock bound at this rate.
pub(super) const TICKS_PER_BLOCK: u64 = 4;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Clock {
    /// Host counts the guest is behind.
    lag: u64,
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
        self.last = host.saturating_sub(self.lag).max(self.last);
        self.last
    }

    /// The host counter value at which the count reaches `count`.
    pub(super) fn host_deadline(&self, count: u64) -> u64 {
        count.saturating_add(self.lag)
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
        let mut clock = Clock::default();
        clock.start_slice(1000, 0, 2);
        // Within a slice the host's counter shows through.
        assert_eq!(clock.read(1500), 1500);
        // 100 blocks shared by two PEs account for 200 counts, so the 800
        // more the slice showed become lag and the count holds.
        clock.end_slice(2000, 100);
        assert_eq!(clock.read(2000), 2000);
        assert_eq!(clock.read(2500), 2000);
        assert_eq!(clock.read(2900), 2100);
        assert_eq!(clock.host_deadline(2200), 3000);
        // A slice within its bound adds no lag.
        clock.start_slice(3000, 100, 1);
        clock.end_slice(3200, 200);
        assert_eq!(clock.read(3300), 2500);
        // Waiting outside a slice follows the host.
        assert_eq!(clock.read(10_000), 9200);
        clock.end_slice(11_000, 200);
        assert_eq!(clock.read(11_000), 10_200);
    }
}
