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
//! So a time slice accounts for at most [`TICKS_PER_BLOCK`] counts
//! for each block it runs, shared among the PEs that could run with it:
//! over a round of slices every runnable PE then gets a block done for each
//! `TICKS_PER_BLOCK` counts, as on a slow but concurrent machine. A slice
//! that takes more host time is charged as lag when it ends, and the counter
//! holds at the last value read until the adjusted host count catches up, so it never runs
//! backwards (Arm ARM D12.1.2, the count is monotonically increasing).
//! While every PE waits nothing has to progress, and the counter follows
//! the host's. When the host is fast enough, no slice exceeds its bound and
//! the counter is the host's minus the lag of earlier slow stretches.
//! The monotonic clamp can retain a slice's already observed overshoot, but
//! cannot cancel the lag charged for a later slice: lag measures elapsed
//! host time, independently of how long an earlier count remains held.
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
//!
//! A machine that is one thread of a hosted process follows the host's
//! counter instead ([`Clock::follow_host`]): there the guest is an ordinary
//! process, which no kernel timeout constrains, and its threads, each on its
//! own machine, must read one clock.

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
    /// The running slice, when a PE runs: its host start, start block
    /// count and the PEs sharing the round.
    slice: Option<Slice>,
    /// Charge no slice lag: the count is the host's ([`Clock::follow_host`]).
    follows_host: bool,
}

#[derive(Debug, Clone, Copy)]
struct Slice {
    host: u64,
    lag: u64,
    blocks: u64,
    share: u64,
}

impl Clock {
    /// Charge no slice lag, so the count is the host's counter (plus any
    /// idle leap). A hosted process runs one machine per thread, and its
    /// threads read one clock, as an OS process's do: a count held back by
    /// the lag of one thread's slow slices would order another thread's
    /// reads before it.
    pub(super) fn follow_host(&mut self) {
        self.follows_host = true;
        self.lag = 0;
    }

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
        if deadline > count {
            // Advance the underlying count, not only the monotonic clamp:
            // an earlier slice may still hold `count` above host minus lag.
            let adjusted = host.saturating_add(self.lead).saturating_sub(self.lag);
            self.lead += deadline - adjusted;
            self.last = deadline;
        }
    }

    /// A slice starts at host counter value `host` and block count `blocks`,
    /// with `share` PEs (at least one) able to run in the round.
    pub(super) fn start_slice(&mut self, host: u64, blocks: u64, share: u64) {
        self.read(host);
        self.slice = Some(Slice {
            host,
            lag: self.lag,
            blocks,
            share: share.max(1),
        });
    }

    /// The running slice ends at `host` and `blocks`: elapsed host counts
    /// beyond its blocks' bound become lag. Explicitly excluded host work
    /// was already charged and must not be charged twice. The monotonic
    /// count can still be held by an earlier read; it does not measure this
    /// slice's elapsed time.
    pub(super) fn end_slice(&mut self, host: u64, blocks: u64) {
        self.read(host);
        let Some(slice) = self.slice.take() else {
            return;
        };
        let allowed = blocks
            .saturating_sub(slice.blocks)
            .saturating_mul(TICKS_PER_BLOCK)
            / slice.share;
        let elapsed = host
            .saturating_sub(slice.host)
            .saturating_sub(self.lag.saturating_sub(slice.lag));
        if !self.follows_host {
            self.lag += elapsed.saturating_sub(allowed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_slow_slices_charge_their_full_host_duration() {
        let mut clock = Clock::default();
        let mut previous = 0;
        // Four concurrent PEs get ten counts per forty blocks. Each slice
        // takes 100 host counts: after the initial overshoot, work must
        // advance the count by ten, not by a share of the host's slowdown.
        for slice in 0..100 {
            clock.start_slice(slice * 100, slice * 40, 4);
            let during = clock.read(slice * 100 + 50);
            assert!(during >= previous);
            clock.end_slice((slice + 1) * 100, (slice + 1) * 40);
            let after = clock.read((slice + 1) * 100);
            assert!(after >= during);
            assert_eq!(after, 100 + slice * 10);
            previous = after;
        }
        // The final read's bounded overshoot holds briefly, then ordinary
        // idle time reaches the translated deadline exactly.
        assert_eq!(clock.read(10_089), 1090);
        assert_eq!(clock.read(10_100), 1100);
        assert_eq!(clock.host_deadline(2000), 11_000);
        assert_eq!(clock.read(10_999), 1999);
        assert_eq!(clock.read(11_000), 2000);
    }

    #[test]
    fn host_work_excluded_mid_slice_is_not_charged_again() {
        let mut clock = Clock::default();
        for slice in 0..100 {
            clock.start_slice(slice * 100, slice * 10, 1);
            // Eighty counts were host-only work; the other twenty ran ten
            // blocks. Only ten more counts become slice lag.
            clock.exclude(80);
            clock.end_slice((slice + 1) * 100, (slice + 1) * 10);
            assert_eq!(clock.read((slice + 1) * 100), 20 + slice * 10);
        }
        assert_eq!(clock.host_deadline(2000), 11_000);
        assert_eq!(clock.read(11_000), 2000);
    }

    #[test]
    fn idle_leaps_from_a_held_count_keep_deadlines_and_host_following_coherent() {
        let mut clock = Clock::default();
        clock.start_slice(1000, 0, 1);
        clock.end_slice(2000, 100);
        assert_eq!(clock.read(2000), 2000);
        // The observed count is held above the host minus lag. Leaping to
        // 5000 must advance that underlying count too, so it can continue
        // from 5000 and translate the very next deadline correctly.
        clock.skip_to(2000, 5000);
        assert_eq!(clock.read(2000), 5000);
        assert_eq!(clock.host_deadline(5001), 2001);
        assert_eq!(clock.read(2001), 5001);
        clock.start_slice(2001, 100, 1);
        clock.end_slice(2101, 120);
        assert_eq!(clock.read(2101), 5101);
        assert_eq!(clock.host_deadline(6000), 3080);
        assert_eq!(clock.read(3079), 5999);
        assert_eq!(clock.read(3080), 6000);
        clock.exclude(500);
        assert_eq!(clock.read(3580), 6000);
        clock.follow_host();
        assert_eq!(clock.read(3580), 7480);
        clock.start_slice(3580, 120, 4);
        clock.end_slice(4580, 124);
        assert_eq!(clock.read(4580), 8480);
        assert_eq!(clock.host_deadline(9000), 5100);
    }

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
    fn a_clock_following_the_host_charges_no_lag() {
        let mut clock = Clock::default();
        clock.start_slice(1000, 0, 1);
        clock.end_slice(2000, 0);
        // The slow slice's lag holds the count.
        assert_eq!(clock.read(2500), 2000);
        clock.follow_host();
        assert_eq!(clock.read(2600), 2600);
        // A slice that shows more than its blocks' bound keeps the host's.
        clock.start_slice(2600, 0, 2);
        clock.end_slice(9000, 10);
        assert_eq!(clock.read(9000), 9000);
        // Two such clocks read alike whatever their slices did.
        let mut other = Clock::default();
        other.follow_host();
        other.start_slice(0, 0, 1);
        other.end_slice(5000, 1);
        assert_eq!(other.read(9500), clock.read(9500));
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
