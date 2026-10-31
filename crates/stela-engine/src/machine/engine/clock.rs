//! The system counter the PEs observe: the host's counter, held back by
//! what the PEs could not have done in the time it shows.
//!
//! A translated PE runs far slower than the core it stands for, and the
//! host also stops it for work of its own: compiling, serving devices,
//! waiting for other PEs to apply a broadcast. Software times hardware work
//! against the counter: XNU 26A434 panics once a mutex interlock stays held
//! for 12,582,912 counts (`lock_mtx.c` 326, about 0.5 s at 24 MHz) or a
//! ticket spinlock for 3,000,000 (`lock_ticket.c`, 125 ms). A holder that
//! needs a few microseconds of a real core, but is stopped by the host for
//! longer, would make the guest panic although nothing is wrong. So the
//! count only advances as far as every PE that could run has progressed:
//! guest timeouts measure guest work, whatever the host's speed.
//!
//! **Serialized PEs** take turns on one host core. A time slice accounts
//! for at most [`TICKS_PER_BLOCK`] counts for each block it runs, shared
//! among the PEs that could run with it: over a round of slices every
//! runnable PE then gets a block done for each `TICKS_PER_BLOCK` counts, as
//! on a slow but concurrent machine. A slice that takes more host time is
//! charged as lag when it ends, and the counter holds at the last value
//! read until the adjusted host count catches up, so it never runs
//! backwards (Arm ARM D12.1.2, the count is monotonically increasing).
//! While every PE waits nothing has to progress, and the counter follows
//! the host's. With idle skip (`Machine::set_idle_skip`), a wait of every
//! PE ends at once: the counter leaps to the next deadline, as if the host
//! had waited that long, so the guest's sleeps cost no host time.
//!
//! **Parallel PEs** each run on a host core of their own and read one
//! [`SharedClock`], as the cores of a Mac read one system counter (Linux
//! KVM likewise keeps one counter offset for a whole arm64 VM, so its
//! vCPUs agree). Each running PE publishes a horizon at its slice
//! boundaries: the count it has earned at its [`Pace`], never more than the
//! lookahead past the present. The count stops at the lowest horizon of the
//! PEs that run. A PE the host stopped (compiling, serving the host,
//! waiting on a broadcast, or descheduled) runs no blocks and publishes
//! nothing, so the count stops within the lookahead of its last boundary,
//! whatever stopped it, and resumes from there, the time held becoming lag.
//! A PE that runs keeps the count at the host's pace unless it runs slower
//! than [`PACE_BLOCKS_PER_SECOND`]; then the count slows with it, so a guest
//! second always holds that much work per running PE, on any host. A PE
//! waiting in WFI or WFE, held in reset or powered down holds nothing, so an
//! idle guest's time follows the host's. This is conservative synchronization
//! with bounded lookahead, as parallel full-system simulators keep their
//! cores' time, and QEMU's `-icount shift=auto` keeps a guest's. Only the
//! count waits: a PE that is ahead keeps running.
//!
//! The architecture requires a constant counter frequency, not a match
//! with wall time; time of day drifts behind by the accumulated lag, as on
//! a machine whose counter was paused, and ahead by any idle leaps.

use super::processors::QUANTUM_HZ;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering, fence};
use stela_compiler::x86_64::register_read::{Count, CountState};

/// The most counts one block may account for: one count at 24 MHz is
/// 42 ns, a PE at least ~1/12 the speed of an M2 core. XNU drivers time
/// work against fixed timeouts (IOUSBDeviceFamily's function registration,
/// IOKit start waits), so a slower apparent PE fails them although nothing
/// is wrong. The longest real critical section XNU guards with a timeout
/// runs far below 3,000,000 blocks, the ticket spinlock bound at this rate.
pub(super) const TICKS_PER_BLOCK: u64 = 1;

/// The slowest a running parallel PE may execute blocks while the count
/// keeps the host's pace, about 150 MIPS. A slower PE slows the count, so
/// its timeouts still measure its work: the 60 s XNU allows the registry to
/// come to rest (`IOService.cpp` 6140) held some 34 G instructions of launching
/// driver extensions in a 26A434 boot, 570 MIPS across the four or so PEs
/// that run. The slowest PE that runs sets the count and every guest sleep
/// lasts as much longer, so a floor much above this makes a boot's timed
/// waits take several times their length.
pub(super) const PACE_BLOCKS_PER_SECOND: u64 = 2_000_000;

/// Slice periods ([`QUANTUM_HZ`]) a running PE's horizon may lie past the
/// present: several, so that only a PE stopped for longer than a few slices
/// holds the count, never one merely between two boundaries.
const LOOKAHEAD_SLICES: u64 = 4;

/// How a [`SharedClock`]'s horizons advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Pace {
    /// The counts each block a PE runs earns its horizon.
    pub per_block: u64,
    /// The counts a running PE's horizon may lie past the present.
    pub lookahead: u64,
}

impl Pace {
    /// The pace of a counter of `frequency` Hz.
    pub(super) fn new(frequency: u64) -> Self {
        Self {
            per_block: (frequency / PACE_BLOCKS_PER_SECOND).max(1),
            lookahead: frequency * LOOKAHEAD_SLICES / QUANTUM_HZ,
        }
    }
}

/// A horizon that holds nothing: the PE waits or does not run.
const UNBOUNDED: u64 = u64::MAX;

/// The host's counter, read fresh at each call.
pub(super) trait Counter: FnMut() -> u64 {}
impl<F: FnMut() -> u64> Counter for F {}

/// The count every parallel PE reads, and the horizons that hold it.
#[derive(Debug)]
pub struct SharedClock {
    state: CountState,
    /// Each PE's horizon, [`UNBOUNDED`] while it holds nothing. Changed only
    /// with `state.sequence` odd.
    horizons: Box<[AtomicU64]>,
    /// [`Pace::per_block`] and [`Pace::lookahead`].
    per_block: AtomicU64,
    lookahead: AtomicU64,
}

/// What a PE did since its last publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Progress {
    /// Ran this many blocks, or starts running after a wait.
    Ran(u64),
    /// Waits, or stopped running guest code.
    Waits,
}

/// A [`SharedClock`]'s count, and the PE whose horizon holds it with that
/// horizon, if one does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockStatus {
    pub count: u64,
    pub holder: Option<(usize, u64)>,
}

impl SharedClock {
    /// A clock for `pes` PEs, none holding it, following the host's count.
    pub fn new(pes: usize) -> Self {
        let state = CountState::default();
        state.ceiling.store(UNBOUNDED, Ordering::Relaxed);
        Self {
            state,
            horizons: (0..pes).map(|_| AtomicU64::new(UNBOUNDED)).collect(),
            per_block: AtomicU64::new(1),
            lookahead: AtomicU64::new(0),
        }
    }

    /// Continue from a count of `offset` past the host's at `pace`.
    fn seed(&self, offset: u64, pace: Pace) {
        let sequence = self.lock();
        self.state.offset.store(offset, Ordering::Relaxed);
        self.per_block.store(pace.per_block, Ordering::Relaxed);
        self.lookahead.store(pace.lookahead, Ordering::Relaxed);
        self.unlock(sequence);
    }

    /// The count now, with the host's counter sampled while one published
    /// state holds.
    fn read(&self, counter: &mut impl Counter) -> u64 {
        loop {
            let sequence = self.state.sequence.load(Ordering::Acquire);
            if sequence & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let offset = self.state.offset.load(Ordering::Relaxed);
            let ceiling = self.state.ceiling.load(Ordering::Relaxed);
            let host = sampled(counter);
            fence(Ordering::Acquire);
            if self.state.sequence.load(Ordering::Relaxed) == sequence {
                return host.wrapping_add(offset).min(ceiling);
            }
        }
    }

    /// The host count at which the count reaches `count` if no horizon holds
    /// it meanwhile; a waiter that wakes before it reads the count again.
    fn host_deadline(&self, count: u64) -> u64 {
        let offset = self.state.offset.load(Ordering::Acquire);
        count.saturating_add_signed((offset as i64).wrapping_neg())
    }

    /// When a PE waiting at host counter `host` for the count to reach
    /// `count` looks again: as it does, or, while a horizon holds the count
    /// below it, a lookahead later, by when the holder normally published
    /// again. Read outside the sequence: a stale answer only wakes early.
    fn wake_at(&self, count: u64, host: u64) -> u64 {
        if count > self.state.ceiling.load(Ordering::Acquire) {
            return host.saturating_add(self.lookahead.load(Ordering::Relaxed).max(1));
        }
        self.host_deadline(count)
    }

    /// Record PE `pe`'s `progress`. A count held at a lower horizon becomes
    /// lag, so the count continues from where it was held when it rises.
    fn publish(&self, pe: usize, progress: Progress, counter: &mut impl Counter) {
        let sequence = self.lock();
        let host = sampled(counter);
        let offset = self.state.offset.load(Ordering::Relaxed);
        let ceiling = self.state.ceiling.load(Ordering::Relaxed);
        let count = host.wrapping_add(offset).min(ceiling);
        let lookahead = count.saturating_add(self.lookahead.load(Ordering::Relaxed));
        let previous = self.horizons[pe].load(Ordering::Relaxed);
        let horizon = match progress {
            Progress::Waits => UNBOUNDED,
            Progress::Ran(_) if previous == UNBOUNDED => lookahead,
            Progress::Ran(blocks) => previous
                .saturating_add(blocks.saturating_mul(self.per_block.load(Ordering::Relaxed)))
                .min(lookahead),
        };
        self.horizons[pe].store(horizon, Ordering::Relaxed);
        let lowest = self
            .horizons
            .iter()
            .map(|horizon| horizon.load(Ordering::Relaxed))
            .min()
            .unwrap_or(UNBOUNDED);
        let ceiling = if lowest == UNBOUNDED {
            UNBOUNDED
        } else {
            lowest.max(count)
        };
        self.state
            .offset
            .store(count.wrapping_sub(host), Ordering::Relaxed);
        self.state.ceiling.store(ceiling, Ordering::Relaxed);
        self.unlock(sequence);
    }

    /// The count now, and the PE whose horizon holds it, if one does.
    pub fn status(&self, mut counter: impl Counter) -> ClockStatus {
        let count = self.read(&mut counter);
        let ceiling = self.state.ceiling.load(Ordering::Acquire);
        let holder = (count >= ceiling)
            .then(|| {
                self.horizons
                    .iter()
                    .map(|horizon| horizon.load(Ordering::Relaxed))
                    .enumerate()
                    .min_by_key(|&(_, horizon)| horizon)
            })
            .flatten();
        ClockStatus { count, holder }
    }

    /// Make the sequence odd, waiting for another writer to finish; the even
    /// sequence it had. The following host sample is ordered after it.
    fn lock(&self) -> u64 {
        loop {
            let sequence = self.state.sequence.load(Ordering::Relaxed);
            if sequence & 1 == 0
                && self
                    .state
                    .sequence
                    .compare_exchange_weak(
                        sequence,
                        sequence + 1,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                fence(Ordering::SeqCst);
                return sequence;
            }
            core::hint::spin_loop();
        }
    }

    fn unlock(&self, sequence: u64) {
        self.state.sequence.store(sequence + 2, Ordering::Release);
    }
}

/// The host's counter, sampled after every earlier load and before every
/// later one (`lfence`, Intel SDM Vol. 2B RDTSC), so that a seqlock read
/// brackets it.
fn sampled(counter: &mut impl Counter) -> u64 {
    lfence();
    let host = counter();
    lfence();
    host
}

fn lfence() {
    // SAFETY: `lfence` is SSE2, which every x86-64 processor implements.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_lfence()
    };
}

/// This PE's place in a [`SharedClock`].
#[derive(Debug)]
struct Attachment {
    clock: Arc<SharedClock>,
    pe: usize,
    /// Its block count at its last publication.
    blocks: u64,
    /// Whether its last publication was a wait.
    waiting: bool,
}

#[derive(Debug)]
pub(super) struct Clock {
    /// Host counts the guest is behind.
    lag: u64,
    /// Counts the guest leapt ahead over idle waits.
    lead: u64,
    /// The serialized count, `lead` less `lag` and no ceiling, where native
    /// count reads find it while no [`SharedClock`] is attached.
    own: CountState,
    /// This reader's last count, which no later read precedes, and its
    /// TSC scale (`register_read::count_thunk`).
    count: Count,
    /// The running slice, when a serialized PE runs: its host start, start
    /// block count and the PEs sharing the round.
    slice: Option<Slice>,
    shared: Option<Attachment>,
}

impl Default for Clock {
    fn default() -> Self {
        let own = CountState::default();
        own.ceiling.store(UNBOUNDED, Ordering::Relaxed);
        Self {
            lag: 0,
            lead: 0,
            own,
            count: Count::default(),
            slice: None,
            shared: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Slice {
    host: u64,
    lag: u64,
    blocks: u64,
    share: u64,
}

impl Clock {
    /// Read `clock` as PE `pe` from now on, from the count this clock last
    /// read. The PE holds nothing until its first slice starts.
    pub(super) fn attach(&mut self, clock: Arc<SharedClock>, pe: usize, blocks: u64) {
        self.shared = Some(Attachment {
            clock,
            pe,
            blocks,
            waiting: true,
        });
    }

    /// Hand this serialized clock's count, as at the host counter `host`, on
    /// to `clock`, which continues it at `pace`.
    pub(super) fn seed(&mut self, clock: &SharedClock, host: u64, pace: Pace) {
        let count = self.read_at(host);
        clock.seed(count.wrapping_sub(host), pace);
    }

    /// The count now.
    pub(super) fn read(&mut self, mut counter: impl Counter) -> u64 {
        let count = match &self.shared {
            Some(attachment) => attachment.clock.read(&mut counter),
            None => return self.read_at(counter()),
        };
        self.count.last = count.max(self.count.last);
        self.count.last
    }

    /// The serialized count at host counter value `host`.
    fn read_at(&mut self, host: u64) -> u64 {
        self.count.last = host
            .saturating_add(self.lead)
            .saturating_sub(self.lag)
            .max(self.count.last);
        self.count.last
    }

    /// The host counter value at which the count reaches `count`. Attached,
    /// a PE that wakes there finds whether a horizon held the count.
    pub(super) fn host_deadline(&self, count: u64) -> u64 {
        match &self.shared {
            Some(attachment) => attachment.clock.host_deadline(count),
            None => count.saturating_add(self.lag).saturating_sub(self.lead),
        }
    }

    /// The host counter value at which a PE waiting at host counter `host`
    /// for the count to reach `count` looks at the count again.
    pub(super) fn wake_at(&self, count: u64, host: u64) -> u64 {
        match &self.shared {
            Some(attachment) => attachment.clock.wake_at(count, host),
            None => self.host_deadline(count),
        }
    }

    /// `counts` of host time passed with no PE running and nothing in the
    /// guest's world happening: the count does not show it. Attached, the
    /// horizons already hold the count while this PE runs no guest code.
    pub(super) fn exclude(&mut self, counts: u64) {
        if self.shared.is_none() {
            self.lag += counts;
            self.sync();
        }
    }

    /// While every PE waits at host counter value `host`, the count leaps to
    /// `deadline` if it is still before it. Parallel PEs do not leap
    /// (`Machine::set_idle_skip`).
    pub(super) fn skip_to(&mut self, host: u64, deadline: u64) {
        debug_assert!(self.shared.is_none(), "an attached clock never leaps");
        let count = self.read_at(host);
        if deadline > count {
            // Advance the underlying count, not only the monotonic clamp:
            // an earlier slice may still hold `count` above host minus lag.
            let adjusted = host.saturating_add(self.lead).saturating_sub(self.lag);
            self.lead += deadline - adjusted;
            self.count.last = deadline;
            self.sync();
        }
    }

    /// A slice starts at block count `blocks`, with `share` PEs (at least
    /// one) able to run in the round. Attached, a PE that waited holds the
    /// count again from here.
    pub(super) fn start_slice(&mut self, mut counter: impl Counter, blocks: u64, share: u64) {
        if let Some(attachment) = &mut self.shared {
            if attachment.waiting {
                attachment.waiting = false;
                attachment.blocks = blocks;
                let (clock, pe) = (Arc::clone(&attachment.clock), attachment.pe);
                clock.publish(pe, Progress::Ran(0), &mut counter);
            }
            return;
        }
        let host = counter();
        self.read_at(host);
        self.slice = Some(Slice {
            host,
            lag: self.lag,
            blocks,
            share: share.max(1),
        });
    }

    /// The running slice ends at block count `blocks`. Serialized, elapsed
    /// host counts beyond its blocks' bound become lag; explicitly excluded
    /// host work was already charged and is not charged twice, and the
    /// monotonic count, which an earlier read can still hold, does not
    /// measure this slice's elapsed time. Attached, the blocks become the
    /// PE's horizon.
    pub(super) fn end_slice(&mut self, mut counter: impl Counter, blocks: u64) {
        if let Some(attachment) = &mut self.shared {
            if !attachment.waiting {
                let ran = blocks.saturating_sub(attachment.blocks);
                attachment.blocks = blocks;
                let (clock, pe) = (Arc::clone(&attachment.clock), attachment.pe);
                clock.publish(pe, Progress::Ran(ran), &mut counter);
            }
            return;
        }
        let host = counter();
        self.read_at(host);
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
        self.lag += elapsed.saturating_sub(allowed);
        self.sync();
    }

    /// The running PE waits or stops running guest code: attached, it no
    /// longer holds the count.
    pub(super) fn wait(&mut self, mut counter: impl Counter) {
        if let Some(attachment) = &mut self.shared
            && !attachment.waiting
        {
            attachment.waiting = true;
            let (clock, pe) = (Arc::clone(&attachment.clock), attachment.pe);
            clock.publish(pe, Progress::Waits, &mut counter);
        }
    }

    /// The last count read.
    pub(super) fn last(&self) -> u64 {
        self.count.last
    }

    /// Native count reads at the host counter `((tsc - base) * per_tsc) >>
    /// 64` ([`super::Host::tsc_counter`]): where they find this reader.
    pub(super) fn native(&mut self, (base, per_tsc): (u64, u64)) -> u64 {
        self.count.base = base;
        self.count.per_tsc = per_tsc;
        self.count.state = match &self.shared {
            Some(attachment) => &attachment.clock.state as *const CountState as u64,
            None => &self.own as *const CountState as u64,
        };
        &self.count as *const Count as u64
    }

    fn sync(&mut self) {
        self.own
            .offset
            .store(self.lead.wrapping_sub(self.lag), Ordering::Relaxed);
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
            clock.start_slice(|| slice * 100, slice * 40, 4);
            let during = clock.read(|| slice * 100 + 50);
            assert!(during >= previous);
            clock.end_slice(|| (slice + 1) * 100, (slice + 1) * 40);
            let after = clock.read(|| (slice + 1) * 100);
            assert!(after >= during);
            assert_eq!(after, 100 + slice * 10);
            previous = after;
        }
        // The final read's bounded overshoot holds briefly, then ordinary
        // idle time reaches the translated deadline exactly.
        assert_eq!(clock.read(|| 10_089), 1090);
        assert_eq!(clock.read(|| 10_100), 1100);
        assert_eq!(clock.host_deadline(2000), 11_000);
        assert_eq!(clock.read(|| 10_999), 1999);
        assert_eq!(clock.read(|| 11_000), 2000);
    }

    #[test]
    fn host_work_excluded_mid_slice_is_not_charged_again() {
        let mut clock = Clock::default();
        for slice in 0..100 {
            clock.start_slice(|| slice * 100, slice * 10, 1);
            // Eighty counts were host-only work; the other twenty ran ten
            // blocks. Only ten more counts become slice lag.
            clock.exclude(80);
            clock.end_slice(|| (slice + 1) * 100, (slice + 1) * 10);
            assert_eq!(clock.read(|| (slice + 1) * 100), 20 + slice * 10);
        }
        assert_eq!(clock.host_deadline(2000), 11_000);
        assert_eq!(clock.read(|| 11_000), 2000);
    }

    #[test]
    fn idle_leaps_from_a_held_count_keep_deadlines_coherent() {
        let mut clock = Clock::default();
        clock.start_slice(|| 1000, 0, 1);
        clock.end_slice(|| 2000, 100);
        assert_eq!(clock.read(|| 2000), 2000);
        // The observed count is held above the host minus lag. Leaping to
        // 5000 must advance that underlying count too, so it can continue
        // from 5000 and translate the very next deadline correctly.
        clock.skip_to(2000, 5000);
        assert_eq!(clock.read(|| 2000), 5000);
        assert_eq!(clock.host_deadline(5001), 2001);
        assert_eq!(clock.read(|| 2001), 5001);
        clock.start_slice(|| 2001, 100, 1);
        clock.end_slice(|| 2101, 120);
        assert_eq!(clock.read(|| 2101), 5101);
        assert_eq!(clock.host_deadline(6000), 3080);
        assert_eq!(clock.read(|| 3079), 5999);
        assert_eq!(clock.read(|| 3080), 6000);
        clock.exclude(500);
        assert_eq!(clock.read(|| 3580), 6000);
    }

    #[test]
    fn slices_advance_by_their_blocks_and_waits_by_the_host() {
        // The blocks that account for `counts` counts.
        let blocks = |counts: u64| counts / TICKS_PER_BLOCK;
        let mut clock = Clock::default();
        clock.start_slice(|| 1000, 0, 2);
        // Within a slice the host's counter shows through.
        assert_eq!(clock.read(|| 1500), 1500);
        // Blocks shared by two PEs account for 200 counts, so the 800 more
        // the slice showed become lag and the count holds.
        clock.end_slice(|| 2000, blocks(400));
        assert_eq!(clock.read(|| 2000), 2000);
        assert_eq!(clock.read(|| 2500), 2000);
        assert_eq!(clock.read(|| 2900), 2100);
        assert_eq!(clock.host_deadline(2200), 3000);
        // A slice within its bound adds no lag.
        clock.start_slice(|| 3000, blocks(400), 1);
        clock.end_slice(|| 3200, blocks(800));
        assert_eq!(clock.read(|| 3300), 2500);
        // Waiting outside a slice follows the host.
        assert_eq!(clock.read(|| 10_000), 9200);
        clock.end_slice(|| 11_000, blocks(800));
        assert_eq!(clock.read(|| 11_000), 10_200);
    }

    #[test]
    fn excluded_host_time_never_reaches_the_count() {
        let mut clock = Clock::default();
        assert_eq!(clock.read(|| 100), 100);
        clock.exclude(900);
        assert_eq!(clock.read(|| 1000), 100);
        assert_eq!(clock.read(|| 1010), 110);
    }

    #[test]
    fn idle_skips_leap_to_the_deadline_and_keep_counting_from_there() {
        let mut clock = Clock::default();
        assert_eq!(clock.read(|| 100), 100);
        clock.skip_to(150, 5_000);
        assert_eq!(clock.read(|| 150), 5_000);
        assert_eq!(clock.read(|| 200), 5_050);
        assert_eq!(clock.host_deadline(6_000), 1_150);
        // A deadline already reached leaps nowhere.
        clock.skip_to(300, 10);
        assert_eq!(clock.read(|| 300), 5_150);
        // Lag from a slow slice still holds the count back: 90 of the 100
        // counts it showed, until the host catches up.
        clock.start_slice(|| 300, 0, 1);
        clock.end_slice(|| 400, 10 / TICKS_PER_BLOCK);
        assert_eq!(clock.read(|| 490), 5_250);
        assert_eq!(clock.read(|| 500), 5_260);
    }

    #[test]
    fn a_24_mhz_pace_earns_half_a_microsecond_a_block_and_looks_ahead_four_slices() {
        assert_eq!(
            Pace::new(24_000_000),
            Pace {
                per_block: 12,
                lookahead: 192_000
            }
        );
    }

    /// Two PEs reading one shared clock, continuing a serialized count of
    /// 1000 at host 1000, each block earning one count, with a lookahead of
    /// 100 counts.
    fn pair() -> (Arc<SharedClock>, Clock, Clock) {
        let shared = Arc::new(SharedClock::new(2));
        let mut serialized = Clock::default();
        serialized.seed(
            &shared,
            1000,
            Pace {
                per_block: 1,
                lookahead: 100,
            },
        );
        let (mut first, mut second) = (Clock::default(), Clock::default());
        first.attach(Arc::clone(&shared), 0, 0);
        second.attach(Arc::clone(&shared), 1, 0);
        (shared, first, second)
    }

    #[test]
    fn a_shared_count_follows_the_host_while_every_pe_waits() {
        let (shared, mut first, mut second) = pair();
        assert_eq!(first.read(|| 1500), 1500);
        assert_eq!(second.read(|| 9000), 9000);
        assert_eq!(first.host_deadline(12_000), 12_000);
        assert_eq!(
            shared.status(|| 9000),
            ClockStatus {
                count: 9000,
                holder: None
            }
        );
    }

    #[test]
    fn a_stopped_pe_holds_the_count_within_its_lookahead_and_resumes_without_a_jump() {
        let (shared, mut first, mut second) = pair();
        first.start_slice(|| 1000, 0, 1);
        second.start_slice(|| 1000, 0, 1);
        assert_eq!(first.read(|| 1050), 1050);
        // The second PE ran far more blocks than counts passed: its horizon
        // is the present plus the lookahead, never more.
        second.end_slice(|| 1050, 10_000);
        // The first PE publishes nothing, as if the host stopped it: the
        // count stops at its horizon, 1100, for both PEs.
        assert_eq!(second.read(|| 1200), 1100);
        assert_eq!(first.read(|| 4000), 1100);
        // A waiter for a count past the hold looks again a lookahead later,
        // not at a host deadline the hold has already passed.
        assert_eq!(second.wake_at(1150, 4000), 4100);
        assert_eq!(
            shared.status(|| 4000),
            ClockStatus {
                count: 1100,
                holder: Some((0, 1100))
            }
        );
        // The first PE ran 100 blocks: its horizon rises to 1200, while the
        // second PE's last one, 1150, now holds. The 3900 host counts held
        // became lag, so the count continues from 1100.
        first.end_slice(|| 5000, 100);
        assert_eq!(second.read(|| 5000), 1100);
        assert_eq!(second.read(|| 5040), 1140);
        assert_eq!(first.read(|| 5060), 1150);
        assert_eq!(shared.status(|| 5060).holder, Some((1, 1150)));
        second.end_slice(|| 5060, 20_000);
        assert_eq!(second.read(|| 5100), 1190);
        assert_eq!(first.read(|| 5110), 1200);
        // Waiting, the first PE holds nothing; the count runs to the
        // second's horizon, 1250, and the deadline translates from there.
        first.wait(|| 5110);
        assert_eq!(first.read(|| 5150), 1240);
        assert_eq!(first.host_deadline(1245), 5155);
        assert_eq!(first.wake_at(1245, 5150), 5155);
        assert_eq!(second.read(|| 5300), 1250);
    }

    #[test]
    fn a_slow_pe_advances_the_count_by_its_blocks() {
        let (_, mut first, mut second) = pair();
        first.start_slice(|| 1000, 0, 1);
        second.start_slice(|| 1000, 0, 1);
        // Every 1000 host counts the first PE runs 10 blocks; the second PE
        // waits. The count gains ten per slice once the lookahead is spent.
        second.wait(|| 1000);
        let mut previous = 0;
        for slice in 1..=5 {
            let host = 1000 + slice * 1000;
            first.end_slice(|| host, slice * 10);
            let count = second.read(|| host);
            assert!(count >= previous);
            assert_eq!(count, 1100 + (slice - 1) * 10);
            previous = count;
        }
    }

    #[test]
    fn readers_of_one_shared_count_never_disagree_backwards() {
        let (_, mut first, mut second) = pair();
        first.start_slice(|| 1000, 0, 1);
        second.start_slice(|| 1000, 0, 1);
        let mut seen = 0;
        for step in 0..200u64 {
            let host = 1000 + step * 37;
            if step % 3 == 0 {
                first.end_slice(|| host, step * 5);
            }
            if step % 7 == 0 {
                second.end_slice(|| host, step * 50);
            }
            for clock in [&mut first, &mut second] {
                let count = clock.read(|| host);
                assert!(count >= seen, "step {step}: {count} after {seen}");
                seen = count;
            }
        }
    }
}
