// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2006, Red Hat, Inc., Ingo Molnar
//! Arithmetic of each AP's TSC synchronization with the BSP, after Linux's
//! `arch/x86/kernel/tsc_sync.c`: how long a round reads, which way a warp
//! moves the AP's counter, and the counter base an AP corrected in software
//! counts from, and the bounded rendezvous the two cores take turns at;
//! and the one device counter that every core reads and that never goes
//! back ([`Monotonic`]).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// The most a rendezvous point, or the turn lock of a round, waits for the
/// other core beyond a round: far above the microseconds between the two
/// on working cores, so only a core that stopped (an NMI, a machine check,
/// an SMI that never returns) misses it.
pub const POINT_MILLIS: u64 = 100;

/// The most an AP waits at its first point, while the BSP synchronizes the
/// APs that reached theirs before it, one at a time: rounds of 20 ms at
/// most eight times each, for every other processor of a large PC.
pub const FIRST_POINT_MILLIS: u64 = 30_000;

/// The points two cores meet at, each needing both. A wait that runs out
/// abandons the rendezvous, and every later arrival of either core fails
/// too, so that neither goes on alone with the other's half missing.
pub struct Rendezvous {
    arrivals: AtomicU32,
}

const ABANDONED: u32 = 1 << 31;

impl Default for Rendezvous {
    fn default() -> Self {
        Self::new()
    }
}

impl Rendezvous {
    pub const fn new() -> Self {
        Self {
            arrivals: AtomicU32::new(0),
        }
    }

    /// Arrive at `point`, counted from one, and wait for the other core
    /// until `expired` says the wait is over: whether both met.
    pub fn meet(&self, point: u32, mut expired: impl FnMut() -> bool) -> bool {
        if self.arrivals.fetch_add(1, Ordering::AcqRel) & ABANDONED != 0 {
            return false;
        }
        loop {
            let now = self.arrivals.load(Ordering::Acquire);
            if now & ABANDONED != 0 {
                return false;
            }
            if now >= 2 * point {
                return true;
            }
            // Abandon only while the other core is still missing: an
            // arrival in between makes the exchange fail and is seen next.
            if expired()
                && self
                    .arrivals
                    .compare_exchange(now, now | ABANDONED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return false;
            }
            core::hint::spin_loop();
        }
    }

    /// Give up from outside a point, as a core that cannot take its turn
    /// does: the other core fails its next point.
    pub fn abandon(&self) {
        self.arrivals.fetch_or(ABANDONED, Ordering::AcqRel);
    }

    pub fn abandoned(&self) -> bool {
        self.arrivals.load(Ordering::Acquire) & ABANDONED != 0
    }
}

/// Linux's `loop_timeout`: 2 ms when a CPU of the AP's package already
/// synchronized, whose counters the package's own clock already keeps
/// together, else 20 ms for a new package or module.
pub fn round_millis(package: u32, synchronized: impl IntoIterator<Item = u32>) -> u64 {
    if synchronized.into_iter().any(|other| other == package) {
        2
    } else {
        20
    }
}

/// What to add to the AP's counter after a round with warps: the most the
/// shared value went back as the AP saw it (the AP ran behind), else as the
/// BSP saw it, negated (the AP ran ahead).
pub fn correction(seen_here: u64, seen_by_bsp: u64) -> i64 {
    let clamp = |warp: u64| warp.min(i64::MAX as u64) as i64;
    if seen_here != 0 {
        clamp(seen_here)
    } else {
        -clamp(seen_by_bsp)
    }
}

/// How one round of an AP's synchronization moves its counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Move {
    /// Through `IA32_TSC_ADJUST`, which moves the counter itself.
    Adjust,
    /// In software: an offset added to every value the AP reads.
    Software,
}

/// How round `round` (from one) of an AP's synchronization moves its
/// counter: through `IA32_TSC_ADJUST` while the AP has it and the round
/// is before `rounds`, else in software. An AP without `IA32_TSC_ADJUST`,
/// as every AMD processor, moves it in software from the first round and
/// never writes `IA32_TIME_STAMP_COUNTER`: on Zen 2 a written counter went
/// back to its own count within seconds, so the cores were apart again by
/// what the write had removed and macOS met non-monotonic time. Linux never
/// writes the counter either; it marks it unstable and takes another clock,
/// where the guest's count here keeps the TSC through the offset.
pub fn correction_move(adjustable: bool, round: u32, rounds: u32) -> Move {
    if adjustable && round < rounds {
        Move::Adjust
    } else {
        Move::Software
    }
}

/// The base an AP whose counter reads `offset` ticks from the BSP's, and
/// which corrects that in software, counts its 24 MHz counter from, so that
/// it reads the same count as the BSP at the same instant: a raw value
/// `offset` behind the BSP's pairs with a base `offset` behind `tsc_base`.
pub fn corrected_base(tsc_base: u64, offset: i64) -> u64 {
    tsc_base.wrapping_sub(offset as u64)
}

/// The BSP's counter as an AP reads it: its raw value `raw`, which reads
/// `offset` ticks behind the BSP's, moved by that offset. Every counter
/// value one core stores and another compares is taken this way.
pub fn shared_tsc(raw: u64, offset: i64) -> u64 {
    raw.wrapping_add(offset as u64)
}

/// The most a counter read may trail the last value handed out and still
/// count as behind it, rather than as far ahead after a wrap: half a
/// revolution, as the drivers' deadlines tell the two apart.
const BEHIND_LIMIT: u64 = 1 << 63;

/// One counter that every core reads and that never goes back: the
/// drivers' clock, whose times and deadlines one core takes and another
/// compares (the network stack's, a disk's, a USB4 fabric's). Each read
/// answers the later of the core's own counter and the last value any core
/// was given, as Linux's `sched_clock_remote` takes the later of two CPUs'
/// clocks with a compare-exchange, and as its timekeeping counts a
/// clocksource read that went back as no time passed (`clocksource_delta`).
///
/// A core whose counter trails another's only by what synchronization
/// leaves (a few cycles) is held for that long. One whose counter moved
/// after its synchronization (firmware rewrote it, its offset went stale)
/// is held until it catches up, which [`Self::longest_behind`] shows,
/// instead of handing a time before one another core already took: a
/// consumer that refuses a regression (the network stack, the USB4
/// transport) would stop for good.
pub struct Monotonic {
    last: AtomicU64,
    longest_behind: AtomicU64,
}

impl Default for Monotonic {
    fn default() -> Self {
        Self::new()
    }
}

impl Monotonic {
    pub const fn new() -> Self {
        Self {
            last: AtomicU64::new(0),
            longest_behind: AtomicU64::new(0),
        }
    }

    /// The counter, given this core's read `now`: `now`, or the last value
    /// any core was given when `now` trails it. Only a read that moves the
    /// counter on writes it. The first read is taken as it is.
    pub fn read(&self, now: u64) -> u64 {
        let mut last = self.last.load(Ordering::Acquire);
        loop {
            let behind = last.wrapping_sub(now);
            if last != 0 && behind < BEHIND_LIMIT {
                if behind > self.longest_behind.load(Ordering::Relaxed) {
                    self.longest_behind.fetch_max(behind, Ordering::Relaxed);
                }
                return last;
            }
            match self
                .last
                .compare_exchange_weak(last, now, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return now,
                Err(newer) => last = newer,
            }
        }
    }

    /// The most a core's read trailed the counter, in ticks.
    pub fn longest_behind(&self) -> u64 {
        self.longest_behind.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_core_of_a_synchronized_package_reads_for_2_ms() {
        assert_eq!(round_millis(0, [0]), 2);
        assert_eq!(round_millis(1, [0, 0, 1]), 2);
        assert_eq!(round_millis(1, [0]), 20);
        assert_eq!(round_millis(0, []), 20);
    }

    #[test]
    fn warps_move_the_ap_toward_the_bsp() {
        assert_eq!(correction(500, 0), 500);
        assert_eq!(correction(0, 700), -700);
        assert_eq!(correction(500, 700), 500);
        assert_eq!(correction(0, 0), 0);
        assert_eq!(correction(u64::MAX, 0), i64::MAX);
    }

    #[test]
    fn two_cores_meet_at_each_point() {
        let rendezvous = Rendezvous::new();
        std::thread::scope(|scope| {
            scope.spawn(|| assert!((1..=3).all(|point| rendezvous.meet(point, || false))));
            assert!((1..=3).all(|point| rendezvous.meet(point, || false)));
        });
        assert!(!rendezvous.abandoned());
    }

    #[test]
    fn a_core_that_never_arrives_ends_the_wait_and_the_rendezvous() {
        let rendezvous = Rendezvous::new();
        let mut polls = 0;
        assert!(!rendezvous.meet(1, || {
            polls += 1;
            polls == 50
        }));
        assert_eq!(polls, 50);
        assert!(rendezvous.abandoned());
        // The late core fails at once, at that point and every later one.
        assert!(!rendezvous.meet(1, || panic!("no wait")));
        assert!(!rendezvous.meet(2, || panic!("no wait")));
        let other = Rendezvous::new();
        other.abandon();
        assert!(!other.meet(1, || panic!("no wait")));
    }

    #[test]
    fn a_software_correction_gives_the_bsps_count() {
        let base = 1_000_000;
        for (bsp_now, offset) in [(5_000_000u64, 12_345i64), (5_000_000, -9_876), (base, 0)] {
            // The AP's raw counter reads `offset` behind the BSP's.
            let ap_raw = bsp_now.wrapping_sub(offset as u64);
            let ap_base = corrected_base(base, offset);
            assert_eq!(ap_raw.wrapping_sub(ap_base), bsp_now - base);
            // Its shared value is the BSP's, and counts as the native base.
            assert_eq!(shared_tsc(ap_raw, offset), bsp_now);
            assert_eq!(
                shared_tsc(ap_raw, offset).wrapping_sub(base),
                ap_raw.wrapping_sub(ap_base)
            );
        }
    }

    #[test]
    fn a_core_without_tsc_adjust_never_writes_its_counter() {
        for round in 1..=8 {
            assert_eq!(correction_move(false, round, 4), Move::Software);
        }
        assert_eq!(correction_move(true, 1, 4), Move::Adjust);
        assert_eq!(correction_move(true, 3, 4), Move::Adjust);
        assert_eq!(correction_move(true, 4, 4), Move::Software);
    }

    #[test]
    fn a_read_behind_the_last_value_given_gets_that_value() {
        let counter = Monotonic::new();
        assert_eq!(counter.read(1_000), 1_000);
        assert_eq!(counter.read(990), 1_000);
        assert_eq!(counter.read(1_000), 1_000);
        assert_eq!(counter.longest_behind(), 10);
        assert_eq!(counter.read(1_500), 1_500);
        assert_eq!(counter.read(1_200), 1_500);
        assert_eq!(counter.longest_behind(), 300);
        // A read past a wrap of the raw counter is ahead, not behind.
        let wrapping = Monotonic::new();
        assert_eq!(wrapping.read(u64::MAX - 5), u64::MAX - 5);
        assert_eq!(wrapping.read(3), 3);
        assert_eq!(wrapping.read(u64::MAX - 1), 3);
        assert_eq!(wrapping.longest_behind(), 5);
    }

    /// Issue 144 (Ryzen 5 5600H at 3,293,805,211 Hz): the network stack,
    /// polled by whichever processor served the host, read 33,727,068 us
    /// and then 31,188,428 us and refused every later request. Two cores
    /// whose counters are that far apart take turns at a consumer that
    /// refuses any time before the last, as the stack's `now` does: through
    /// raw reads it fails at the first turn, through [`Monotonic`] never,
    /// and the counter still follows the core that is ahead.
    #[test]
    fn issue_144s_cores_apart_take_turns_at_one_clock_that_never_goes_back() {
        use std::sync::{
            Mutex,
            atomic::{AtomicU64, AtomicUsize},
        };
        const TICKS_PER_MICROSECOND: u64 = 3_293;
        const APART: u64 = (33_727_068 - 31_188_428) * TICKS_PER_MICROSECOND;
        const TURNS: usize = 2_000;
        // Ticks since the BSP's counter started: each read moves it on by a
        // microsecond, so time passes between every two turns.
        let wall = AtomicU64::new(100_000_000_000);
        let turn = AtomicUsize::new(0);
        // The consumer: its last time and the first regression it met.
        let consumer = Mutex::new((0u64, None::<(u64, u64)>));
        let run = |monotonic: Option<&Monotonic>| {
            turn.store(0, Ordering::Relaxed);
            *consumer.lock().unwrap() = (0, None);
            std::thread::scope(|scope| {
                for (core, behind) in [(0usize, 0u64), (1, APART)] {
                    let (wall, turn, consumer) = (&wall, &turn, &consumer);
                    scope.spawn(move || {
                        for _ in 0..TURNS {
                            while turn.load(Ordering::Acquire) % 2 != core {
                                core::hint::spin_loop();
                            }
                            let raw =
                                wall.fetch_add(TICKS_PER_MICROSECOND, Ordering::Relaxed) - behind;
                            let ticks = monotonic.map_or(raw, |counter| counter.read(raw));
                            let now = ticks / TICKS_PER_MICROSECOND;
                            let mut state = consumer.lock().unwrap();
                            if now < state.0 && state.1.is_none() {
                                state.1 = Some((state.0, now));
                            }
                            state.0 = state.0.max(now);
                            drop(state);
                            turn.fetch_add(1, Ordering::Release);
                        }
                    });
                }
            });
            consumer.lock().unwrap().1
        };
        let (previous, current) = run(None).expect("raw reads of cores apart go back");
        assert_eq!(previous - current, APART / TICKS_PER_MICROSECOND - 1);
        let counter = Monotonic::new();
        assert_eq!(run(Some(&counter)), None);
        assert!(counter.longest_behind() >= APART - 2 * TICKS_PER_MICROSECOND);
        // The core ahead set the pace: the last value is its last read, the
        // second last of all.
        let last = counter.read(0);
        assert_eq!(
            last,
            wall.load(Ordering::Relaxed) - 2 * TICKS_PER_MICROSECOND
        );
    }

    /// Issue 78 (Ryzen 5 4600H): slots 1-5 read 13,518,328,135 ticks ahead
    /// of the BSP at 2,994,376,808 Hz. A core that keeps its own count
    /// through a software offset gives the BSP's count across the 4.5 s
    /// macOS later saw between `invoke` and `runnable`.
    #[test]
    fn issue_78s_seconds_apart_cores_share_one_count() {
        let (base, bsp) = (100_000_000_000u64, 140_000_000_000u64);
        let ahead = 13_518_328_135i64;
        let ap_raw = bsp.wrapping_add(ahead as u64);
        // The AP ran ahead: the BSP saw the shared value go back.
        let offset = correction(0, ahead as u64);
        assert_eq!(offset, -ahead);
        let ap_base = corrected_base(base, offset);
        for later in [0u64, 1, 2_994_376_808, 30 * 2_994_376_808] {
            assert_eq!(shared_tsc(ap_raw + later, offset), bsp + later);
            assert_eq!((ap_raw + later).wrapping_sub(ap_base), (bsp + later) - base);
        }
    }
}
