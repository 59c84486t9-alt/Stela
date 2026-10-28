//! Each AP's time-stamp counter, brought into agreement with the BSP's
//! before the AP takes work, after Linux's `arch/x86/kernel/tsc_sync.c`.
//!
//! The engine and the drivers measure intervals as differences of counter
//! reads that may be taken on different cores: a deadline started on one
//! PE's core and checked on another's. Firmware may leave the cores'
//! counters apart. As `check_tsc_sync_source` and `check_tsc_sync_target`
//! do, the BSP and the AP take turns reading their counters under one lock
//! for [`ROUND_MILLIS`], each noting the most the shared last value went
//! back. A clean round ends it. Otherwise the AP moves its own counter by
//! the warp through `IA32_TSC_ADJUST`, forward when it saw the counter go
//! back and so ran behind, else back, and tries again. Linux finds the
//! sync mechanism's own overhead leaves at most a third round needed; an AP
//! whose counter still differs after [`ROUNDS`], or which has no
//! `IA32_TSC_ADJUST` to correct it with, is refused.
use crate::cpu::msr::TSC_ADJUST;
use core::{
    arch::{
        asm,
        x86_64::{__cpuid_count, _rdtsc},
    },
    sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering},
};

/// `IA32_TSC_ADJUST`.
/// Linux's `loop_timeout` for cores of different packages or modules.
const ROUND_MILLIS: u64 = 20;
const ROUNDS: u32 = 4;
const BSP: usize = 0;
const AP: usize = 1;

/// One AP's synchronization with the BSP.
pub(super) struct Sync {
    round_ticks: u64,
    /// Arrivals at the rendezvous points; each point needs both cores.
    arrivals: AtomicU32,
    lock: AtomicBool,
    last: AtomicU64,
    /// The most the shared counter value went back, as the BSP and as the
    /// AP saw it.
    warps: [AtomicU64; 2],
    /// Set by the AP when it has decided, before the last rendezvous.
    finished: AtomicBool,
    /// What the AP added to its `IA32_TSC_ADJUST`, and its rounds.
    adjusted: AtomicI64,
    rounds: AtomicU32,
}

/// The counter, read after every earlier load and store, as Linux's
/// `rdtsc_ordered`.
fn ordered() -> u64 {
    // SAFETY: fences and RDTSC have no effect beyond ordering.
    unsafe { asm!("mfence", "lfence", options(nostack, preserves_flags)) };
    // SAFETY: RDTSC has no side effects; x86-64 always has it.
    unsafe { _rdtsc() }
}

impl Sync {
    pub(super) fn new(tsc_hz: u64) -> Self {
        Self {
            round_ticks: tsc_hz / 1000 * ROUND_MILLIS,
            arrivals: AtomicU32::new(0),
            lock: AtomicBool::new(false),
            last: AtomicU64::new(0),
            warps: [AtomicU64::new(0), AtomicU64::new(0)],
            finished: AtomicBool::new(false),
            adjusted: AtomicI64::new(0),
            rounds: AtomicU32::new(0),
        }
    }

    /// Wait until both cores reach rendezvous `point`, counted from one.
    fn meet(&self, point: u32) {
        self.arrivals.fetch_add(1, Ordering::AcqRel);
        while self.arrivals.load(Ordering::Acquire) < 2 * point {
            core::hint::spin_loop();
        }
    }

    /// Read the counter in turn with the other core for a round, noting
    /// the most the shared value went back as `side` saw it.
    fn measure(&self, side: usize) {
        let started = ordered();
        loop {
            while self
                .lock
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let previous = self.last.load(Ordering::Relaxed);
            let now = ordered();
            self.last.store(now, Ordering::Relaxed);
            self.lock.store(false, Ordering::Release);
            if now < previous {
                self.warps[side].fetch_max(previous - now, Ordering::Relaxed);
            }
            if now.wrapping_sub(started) >= self.round_ticks {
                return;
            }
        }
    }

    /// The BSP's part: every round the AP asks for.
    pub(super) fn source(&self) {
        let mut point = 0;
        loop {
            point += 1;
            self.meet(point);
            self.measure(BSP);
            point += 1;
            self.meet(point);
            point += 1;
            self.meet(point);
            if self.finished.load(Ordering::Acquire) {
                return;
            }
        }
    }

    /// The AP's part, on the AP: rounds until its counter agrees with the
    /// BSP's, correcting it between them.
    pub(super) fn target(&self) -> Result<(), &'static str> {
        // CPUID.(EAX=7,ECX=0):EBX[1] enumerates IA32_TSC_ADJUST.
        let adjustable = __cpuid_count(0, 0).eax >= 7 && __cpuid_count(7, 0).ebx & 1 << 1 != 0;
        // SAFETY: enumerated above, and read only then.
        let base = adjustable.then(|| unsafe { TSC_ADJUST.read() });
        let mut adjusted = 0i64;
        let mut point = 0;
        for round in 1..=ROUNDS {
            self.last.store(0, Ordering::Relaxed);
            for warp in &self.warps {
                warp.store(0, Ordering::Relaxed);
            }
            point += 1;
            self.meet(point);
            self.measure(AP);
            point += 1;
            self.meet(point);
            let seen_by_bsp = self.warps[BSP].load(Ordering::Relaxed);
            let seen_here = self.warps[AP].load(Ordering::Relaxed);
            let outcome = match base {
                _ if seen_by_bsp == 0 && seen_here == 0 => Some(Ok(())),
                None => Some(Err(
                    "AP TSC differs from the BSP's and has no IA32_TSC_ADJUST",
                )),
                Some(_) if round == ROUNDS => {
                    Some(Err("AP TSC still differs from the BSP's after adjustment"))
                }
                Some(base) => {
                    // Behind when this core saw the counter go back, else
                    // ahead.
                    adjusted += if seen_here != 0 {
                        seen_here as i64
                    } else {
                        -(seen_by_bsp as i64)
                    };
                    // SAFETY: enumerated; Linux writes the same register.
                    unsafe { TSC_ADJUST.write(base.wrapping_add(adjusted as u64)) };
                    None
                }
            };
            if let Some(outcome) = outcome {
                self.adjusted.store(adjusted, Ordering::Relaxed);
                self.rounds.store(round, Ordering::Relaxed);
                self.finished.store(true, Ordering::Release);
                point += 1;
                self.meet(point);
                return outcome;
            }
            point += 1;
            self.meet(point);
        }
        unreachable!("the last round decides")
    }

    /// What the AP added to its `IA32_TSC_ADJUST` and in how many rounds,
    /// once [`Self::source`] returned.
    pub(super) fn outcome(&self) -> (i64, u32) {
        (
            self.adjusted.load(Ordering::Relaxed),
            self.rounds.load(Ordering::Relaxed),
        )
    }
}
