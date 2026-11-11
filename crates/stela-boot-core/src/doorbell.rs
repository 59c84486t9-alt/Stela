//! A word a waiting CPU monitors, so that another CPU wakes it with a store
//! instead of an interrupt: Linux's `TIF_POLLING_NRFLAG` with
//! `mwait_idle_with_hints`. `stela-boot`'s idle wait arms MONITOR on
//! [`Doorbell::word`] between [`Doorbell::prepare`] and
//! [`Doorbell::finish`] and waits only while [`Doorbell::unchanged`].
//!
//! Tiers, chosen per CPU from CPUID ([`hint`]): MWAIT C1 on the doorbell,
//! else HLT ended by the ringer's interrupt. WAITPKG's UMWAIT would serve
//! as well but only in C0.1/C0.2 and bounded by IA32_UMWAIT_CONTROL; at CPL0
//! MWAIT is preferred.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// CPUID.01H:ECX[3], MONITOR/MWAIT.
const MWAIT: u32 = 1 << 3;

/// A value on a cache line of its own.
#[repr(align(64))]
struct Own<T>(T);

pub struct Doorbell {
    word: Own<AtomicU64>,
    monitoring: Own<AtomicBool>,
}

impl Default for Doorbell {
    fn default() -> Self {
        Self::new()
    }
}

impl Doorbell {
    pub const fn new() -> Self {
        Self {
            word: Own(AtomicU64::new(0)),
            monitoring: Own(AtomicBool::new(false)),
        }
    }

    /// The word MONITOR arms.
    pub fn word(&self) -> *const AtomicU64 {
        &self.word.0
    }

    /// Wake the CPU if it waits on this doorbell: whether the store did, so
    /// that no interrupt is needed. Ordered after the caller's stores that
    /// tell the CPU why, against the waiter's store in [`Self::prepare`].
    pub fn ring(&self) -> bool {
        if !self.monitoring.0.load(Ordering::SeqCst) {
            return false;
        }
        self.word.0.fetch_add(1, Ordering::SeqCst);
        true
    }

    /// The waiter, before it arms MONITOR: the word as it was before it
    /// said it monitors. A ring that sees `monitoring` stores after this
    /// read, so [`Self::unchanged`] or the armed monitor sees it.
    pub fn prepare(&self) -> u64 {
        let seen = self.word.0.load(Ordering::SeqCst);
        self.monitoring.0.store(true, Ordering::SeqCst);
        seen
    }

    /// The waiter, after it armed MONITOR: whether it may wait.
    pub fn unchanged(&self, seen: u64) -> bool {
        self.word.0.load(Ordering::SeqCst) == seen
    }

    /// The waiter, after its wait: ringers interrupt it again.
    pub fn finish(&self) {
        self.monitoring.0.store(false, Ordering::SeqCst);
    }
}

/// The CPUID facts that choose a CPU's doorbell tier ([`hint`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct Cpuid {
    pub max_leaf: u32,
    /// "GenuineIntel".
    pub intel: bool,
    pub leaf1_eax: u32,
    pub leaf1_ecx: u32,
    pub leaf5_ecx: u32,
    pub leaf5_edx: u32,
}

/// Intel family 6 models whose MONITOR misses stores to the armed line, so
/// that only an interrupt reliably ends MWAIT: Linux `X86_BUG_MONITOR`
/// (`arch/x86/kernel/cpu/intel.c`), Goldmont (Apollo Lake, erratum APL30)
/// and Lunar Lake.
const BROKEN_MONITOR_MODELS: [u32; 2] = [0x5c, 0xbd];

/// Whether stores to a monitored line wake MWAIT on this CPU.
fn monitor_wakes(cpu: &Cpuid) -> bool {
    let family = (cpu.leaf1_eax >> 8) & 0xf;
    let model = (cpu.leaf1_eax >> 4) & 0xf | (cpu.leaf1_eax >> 12) & 0xf0;
    !(cpu.intel && family == 6 && BROKEN_MONITOR_MODELS.contains(&model))
}

/// The MWAIT hint of a C1 wait on a doorbell from CPUID: MONITOR and MWAIT
/// (leaf 1 ECX[3]), leaf 5 present with its extensions and interrupts as
/// break events (ECX[1:0], as the wait sets ECX[0]), at least one C1
/// sub-state (EDX[7:4]), and a MONITOR that stores wake ([`monitor_wakes`]);
/// `None` for the fallback tier, HLT ended by an interrupt.
pub fn hint(cpu: Cpuid) -> Option<u32> {
    (cpu.leaf1_ecx & MWAIT != 0
        && cpu.max_leaf >= 5
        && cpu.leaf5_ecx & 3 == 3
        && (cpu.leaf5_edx >> 4) & 0xf != 0
        && monitor_wakes(&cpu))
    .then_some(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{Arc, atomic::AtomicU64},
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn mwait_is_chosen_only_with_a_c1_substate() {
        // AMD Zen 5 (family 1Ah): leaf 5 ECX = 3, EDX = 0x11.
        let zen = Cpuid {
            max_leaf: 0x10,
            intel: false,
            leaf1_eax: 0x00b4_0f40,
            leaf1_ecx: MWAIT,
            leaf5_ecx: 3,
            leaf5_edx: 0x11,
        };
        assert_eq!(hint(zen), Some(0));
        let no = |change: fn(&mut Cpuid)| {
            let mut cpu = zen;
            change(&mut cpu);
            hint(cpu)
        };
        assert_eq!(no(|cpu| cpu.leaf1_ecx = 0), None, "no MONITOR/MWAIT");
        assert_eq!(no(|cpu| cpu.max_leaf = 4), None, "no leaf 5");
        assert_eq!(no(|cpu| cpu.leaf5_ecx = 2), None, "no extensions");
        assert_eq!(no(|cpu| cpu.leaf5_ecx = 1), None, "no interrupt break");
        assert_eq!(no(|cpu| cpu.leaf5_edx = 0x01), None, "no C1 sub-state");
        // Intel: Alder Lake (06_97h) waits on the doorbell; Apollo Lake
        // (06_5Ch) and Lunar Lake (06_BDh) have X86_BUG_MONITOR and halt.
        let intel = |leaf1_eax| Cpuid {
            intel: true,
            leaf1_eax,
            ..zen
        };
        assert_eq!(hint(intel(0x0009_0672)), Some(0), "Alder Lake");
        assert_eq!(hint(intel(0x0005_06c9)), None, "Apollo Lake");
        assert_eq!(hint(intel(0x000b_06d1)), None, "Lunar Lake");
        // The same model numbers on another vendor are not the erratum.
        assert_eq!(
            hint(Cpuid {
                intel: false,
                ..intel(0x0005_06c9)
            }),
            Some(0)
        );
    }

    /// No lost wake: a waiter that finds no reason (`reason` unchanged)
    /// prepares, checks the word and "waits" (spins until the word changes or
    /// an interrupt flag is set, as MWAIT ends on a monitored store or an
    /// interrupt); the ringer sets the reason, then rings or interrupts.
    /// Every wait is bounded; a lost wake fails the test.
    #[test]
    fn a_ring_racing_a_wait_always_ends_it() {
        let bell = Arc::new(Doorbell::new());
        let reason = Arc::new(AtomicU64::new(0));
        let interrupt = Arc::new(AtomicU64::new(0));
        let woken = Arc::new(AtomicU64::new(0));
        let ringer = {
            let (bell, reason, interrupt, woken) = (
                Arc::clone(&bell),
                Arc::clone(&reason),
                Arc::clone(&interrupt),
                Arc::clone(&woken),
            );
            thread::spawn(move || {
                for round in 1..=20_000u64 {
                    while woken.load(Ordering::SeqCst) != round - 1 {
                        core::hint::spin_loop();
                    }
                    for _ in 0..round % 97 {
                        core::hint::spin_loop();
                    }
                    reason.store(round, Ordering::SeqCst);
                    if !bell.ring() {
                        interrupt.store(round, Ordering::SeqCst);
                    }
                }
            })
        };
        for round in 1..=20_000u64 {
            loop {
                if reason.load(Ordering::SeqCst) == round {
                    break;
                }
                // As `Hub::sleep` checks its epoch before the halt, whose
                // wait then prepares the doorbell.
                let seen = bell.prepare();
                if bell.unchanged(seen) {
                    let started = Instant::now();
                    while bell.unchanged(seen) && interrupt.load(Ordering::SeqCst) != round {
                        assert!(
                            started.elapsed() < Duration::from_secs(2),
                            "lost wake in round {round}"
                        );
                        core::hint::spin_loop();
                    }
                }
                bell.finish();
            }
            woken.store(round, Ordering::SeqCst);
        }
        ringer.join().unwrap();
    }
}
