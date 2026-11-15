//! The Linux task step watchdog's decisions. The host's Linux environment
//! runs driver work in bounded steps on the boot processor; a step that
//! never returns would leave the PC hanging with no stop record. While that
//! processor is the only one running (the GPU's start, before the other
//! processors start), a core cycle counter armed to overflow after
//! [`LIMIT_SECONDS`] raises an NMI there. Each step that returns, or the
//! dispatcher going idle, puts the counter back once a second at most
//! ([`next_rearm`]): the NMI comes only when nothing returned for the
//! whole limit, and its handler names the stuck step ([`attribute`],
//! [`message`]) with the interrupted instruction pointer.
//!
//! The counter counts unhalted core cycles, whose rate follows the core's
//! clock: [`start_value`] counts [`CLOCK_FACTOR`] times the time-stamp
//! counter's rate, so the NMI never comes before the limit, and comes at
//! most `CLOCK_FACTOR` times later on a core that runs at its base clock.
//!
//! Once the other processors run, the counter is off (`--profile` may use
//! it) and they watch instead: each of them, between two slices of its
//! guest code, reads which step the boot processor runs ([`look`]). A step
//! that every look finds running for the whole limit, by the watcher's own
//! clock (the processors' time-stamp counters may differ by seconds), is
//! stuck: the watcher sends the boot processor an NMI, whose handler names
//! the step ([`caught`]) with the instruction pointer it interrupted. The
//! boot processor itself pays nothing more than the step's own stores: no
//! NMI goes to a processor that runs no Linux step, as a guest's or a
//! parked one does not.
use alloc::{format, string::String};

/// How long no step may return before the watchdog stops the boot: half of
/// the GPU start's whole budget (60 s), far past nouveau's longest wait
/// inside one step (its 2 s register and firmware polls), and far below
/// the five minutes a reporter waited at a black screen.
pub const LIMIT_SECONDS: u64 = 30;

/// How often at most a returned step puts the counter back.
pub const REARM_SECONDS: u64 = 1;

/// The core clock's bound as a multiple of the time-stamp counter's rate:
/// a turbo clock stays below three times the nominal one.
pub const CLOCK_FACTOR: u64 = 3;

/// The value a `width`-bit up-counter starts from to overflow after the
/// limit's cycles at [`CLOCK_FACTOR`] times `tsc_hz`; `None` when the
/// count does not fit or the rate is unknown.
pub fn start_value(tsc_hz: u64, width: u32) -> Option<u64> {
    if tsc_hz == 0 || !(32..=64).contains(&width) {
        return None;
    }
    let cycles = tsc_hz
        .checked_mul(LIMIT_SECONDS)?
        .checked_mul(CLOCK_FACTOR)?;
    let mask = u64::MAX >> (64 - width);
    if cycles == 0 || cycles > mask {
        return None;
    }
    Some((mask - cycles).wrapping_add(1) & mask)
}

/// When a step returning at `now` next puts the counter back.
pub fn next_rearm(now: u64, tsc_hz: u64) -> u64 {
    now.saturating_add(tsc_hz.saturating_mul(REARM_SECONDS).max(1))
}

/// What the NMI handler reads on the watched processor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Observation {
    /// The counter is armed on this processor.
    pub armed: bool,
    /// When the counter was last put back.
    pub armed_at: u64,
    /// When the running step's switch began, 0 between steps.
    pub step_began: u64,
    pub task: u64,
    pub sequence: u64,
    pub now: u64,
    pub tsc_hz: u64,
}

/// The step the watchdog found running.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Step {
    pub task: u64,
    pub sequence: u64,
    pub running_ms: u64,
}

/// A watchdog stop: how long nothing returned, and the step running then,
/// if one was.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stuck {
    pub quiet_ms: u64,
    pub step: Option<Step>,
}

fn millis(ticks: u64, tsc_hz: u64) -> u64 {
    (u128::from(ticks) * 1000 / u128::from(tsc_hz.max(1))) as u64
}

/// Whether an NMI is the watchdog's: the counter was armed and nothing put
/// it back for the whole limit, the soonest it can overflow. Any other NMI
/// (a platform's, or one before the limit) is not, and keeps the plain
/// exception report.
pub fn attribute(observation: &Observation) -> Option<Stuck> {
    let Observation {
        armed,
        armed_at,
        step_began,
        task,
        sequence,
        now,
        tsc_hz,
    } = *observation;
    let quiet = now.checked_sub(armed_at)?;
    if !armed || tsc_hz == 0 || quiet < tsc_hz.checked_mul(LIMIT_SECONDS)? {
        return None;
    }
    let step = (step_began != 0)
        .then(|| now.checked_sub(step_began))
        .flatten()
        .map(|running| Step {
            task,
            sequence,
            running_ms: millis(running, tsc_hz),
        });
    Some(Stuck {
        quiet_ms: millis(quiet, tsc_hz),
        step,
    })
}

/// What the watching processors last saw of the boot processor's step: the
/// step's own start, by the boot processor's counter, which identifies it,
/// and when a watcher first saw it, by the watchers' shared count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sighting {
    pub began: u64,
    pub seen_at: u64,
}

/// What one look finds ([`look`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Look {
    /// No step runs, or the count's rate is unknown.
    Idle,
    /// A step no look saw before: remember it.
    New(Sighting),
    /// The step the last look saw, still within the limit.
    Running,
    /// The step the last look saw, running for the whole limit since: send
    /// the NMI.
    Overdue { quiet_ms: u64 },
}

/// One watcher's look at the boot processor's step (`began`, 0 between
/// steps) at `now` of a count at `counter_hz`, given the `last` sighting.
/// Each step has its own start, so an unchanged one is the same step.
pub fn look(last: Option<Sighting>, began: u64, now: u64, counter_hz: u64) -> Look {
    if began == 0 || counter_hz == 0 {
        return Look::Idle;
    }
    match last {
        Some(last) if last.began == began => {
            let quiet = now.saturating_sub(last.seen_at);
            if quiet >= counter_hz.saturating_mul(LIMIT_SECONDS) {
                Look::Overdue {
                    quiet_ms: millis(quiet, counter_hz),
                }
            } else {
                Look::Running
            }
        }
        _ => Look::New(Sighting {
            began,
            seen_at: now,
        }),
    }
}

/// What the boot processor's NMI handler finds once a watcher sent the NMI
/// for the step that began at `sent` ([`caught`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Caught {
    /// The step still runs: it never returned.
    Stuck(Stuck),
    /// The step returned between the watcher's look and the NMI, after
    /// running for the whole limit: the guest's processors waited for the
    /// boot processor all that time, so the boot stops all the same.
    Returned,
}

/// Whether an NMI on the boot processor is the watchers': one was sent
/// (`sent`, the step's start, 0 when none was), and what the step running
/// now (`observation`, read on the boot processor's own counter) says.
pub fn caught(sent: u64, observation: &Observation) -> Option<Caught> {
    if sent == 0 {
        return None;
    }
    let Observation {
        step_began,
        task,
        sequence,
        now,
        tsc_hz,
        ..
    } = *observation;
    if step_began != sent {
        return Some(Caught::Returned);
    }
    let running = millis(now.saturating_sub(step_began), tsc_hz);
    Some(Caught::Stuck(Stuck {
        quiet_ms: running,
        step: Some(Step {
            task,
            sequence,
            running_ms: running,
        }),
    }))
}

/// The stop's reason for a watchers' NMI ([`caught`]).
pub fn caught_message(stage: &str, caught: &Caught) -> String {
    match caught {
        Caught::Stuck(stuck) => message(stage, stuck),
        Caught::Returned => format!(
            "a Linux task step ran past {LIMIT_SECONDS} s ({stage}) and returned only as the \
             step watchdog's NMI came, the guest's processors waiting for this one all that \
             time; the step watchdog stopped it"
        ),
    }
}

/// The stop's reason, before the handler's instruction pointer and stack:
/// what the boot was doing (`stage`) and the step that never returned.
pub fn message(stage: &str, stuck: &Stuck) -> String {
    match stuck.step {
        Some(step) => format!(
            "a Linux task step did not return within {LIMIT_SECONDS} s ({stage}): task {} \
             job {} ran {} ms; the step watchdog stopped it",
            step.task, step.sequence, step.running_ms
        ),
        None => format!(
            "Linux's work did not return to its dispatcher within {LIMIT_SECONDS} s ({stage}), \
             outside any task step, for {} ms; the step watchdog stopped it",
            stuck.quiet_ms
        ),
    }
}

/// How long the boot processor's dispatcher may wait idle, while it runs
/// alone, with neither its timer interrupt nor a raised wake: the timer's
/// heartbeat fires every millisecond, so a second without it is a lost
/// interrupt, not a late one. A halted processor counts no cycles, so the
/// counter's limit never ends such a wait; the dispatcher then polls the
/// time-stamp counter instead of halting, and stops the boot past this.
pub const IDLE_LIMIT_MS: u64 = 1000;

/// Whether an idle wait entered at `entered` has gone [`IDLE_LIMIT_MS`]
/// without a wake at `now`, both by the time-stamp counter at `tsc_hz`.
/// Never with no known rate.
pub fn idle_overdue(entered: u64, now: u64, tsc_hz: u64) -> bool {
    tsc_hz != 0 && millis(now.wrapping_sub(entered), tsc_hz) >= IDLE_LIMIT_MS
}

/// The local APIC registers an idle stop names: the timer's entry and
/// counts, the task priority, and the in-service and requested vectors
/// (eight 32-bit registers each, vector 0 in bit 0 of the first).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdleApic {
    pub lvt_timer: u32,
    pub initial: u32,
    pub current: u32,
    pub tpr: u32,
    pub in_service: [u32; 8],
    pub requested: [u32; 8],
}

/// The highest vector set in an ISR or IRR image.
fn highest(bits: &[u32; 8]) -> Option<u32> {
    bits.iter()
        .enumerate()
        .rev()
        .find(|(_, word)| **word != 0)
        .map(|(index, word)| index as u32 * 32 + 31 - word.leading_zeros())
}

fn vector(vector: Option<u32>) -> String {
    vector.map_or_else(|| String::from("none"), |vector| format!("{vector:#x}"))
}

/// The stop's reason when the dispatcher's idle wait outlived
/// [`IDLE_LIMIT_MS`] (`waited_ms`) during `stage`.
pub fn idle_message(stage: &str, waited_ms: u64, apic: &IdleApic) -> String {
    format!(
        "the boot processor's timer interrupt did not arrive for {waited_ms} ms while Linux's \
         work waited idle ({stage}): LVT timer {:#x}{}, count {} of {}, TPR {:#x}, highest \
         vector in service {}, highest requested {}",
        apic.lvt_timer,
        if apic.lvt_timer & 1 << 16 != 0 {
            " (masked)"
        } else {
            ""
        },
        apic.current,
        apic.initial,
        apic.tpr,
        vector(highest(&apic.in_service)),
        vector(highest(&apic.requested)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_wait_is_overdue_only_after_the_limit_by_the_counter() {
        let entered = u64::MAX - HZ / 2;
        assert!(!idle_overdue(entered, entered + HZ / 1000, HZ));
        assert!(!idle_overdue(entered, entered.wrapping_add(HZ - 1), HZ));
        // Across the counter's wrap, a whole second later.
        assert!(idle_overdue(entered, entered.wrapping_add(HZ), HZ));
        assert!(!idle_overdue(entered, entered.wrapping_add(10 * HZ), 0));
    }

    #[test]
    fn an_idle_stop_names_the_timer_and_the_vectors_that_block_it() {
        let mut apic = IdleApic {
            lvt_timer: 0x20,
            initial: 2400,
            current: 0,
            tpr: 0,
            ..IdleApic::default()
        };
        apic.in_service[1] = 1 << 17;
        apic.requested[1] = 1;
        apic.requested[6] = 1 << 3;
        assert_eq!(
            idle_message("the GPU's probe", 1000, &apic),
            "the boot processor's timer interrupt did not arrive for 1000 ms while Linux's work \
             waited idle (the GPU's probe): LVT timer 0x20, count 0 of 2400, TPR 0x0, highest \
             vector in service 0x31, highest requested 0xc3"
        );
        apic.lvt_timer |= 1 << 16;
        apic.in_service = [0; 8];
        assert!(idle_message("Linux driver work", 1200, &apic).contains(
            "LVT timer 0x10020 (masked), count 0 of 2400, TPR 0x0, highest vector in service none"
        ));
    }

    const HZ: u64 = 2_400_000_000;

    #[test]
    fn the_counter_overflows_after_the_limit_at_the_bounded_clock() {
        let start = start_value(HZ, 48).unwrap();
        assert_eq!((1u64 << 48) - start, HZ * LIMIT_SECONDS * CLOCK_FACTOR);
        let start = start_value(HZ, 64).unwrap();
        assert_eq!(start.wrapping_neg(), HZ * LIMIT_SECONDS * CLOCK_FACTOR);
        // A 32-bit counter cannot hold 216 G cycles; no rate, no counter.
        assert_eq!(start_value(HZ, 32), None);
        assert_eq!(start_value(0, 48), None);
        assert_eq!(start_value(HZ, 16), None);
        assert_eq!(start_value(u64::MAX / 2, 64), None);
    }

    #[test]
    fn a_returned_step_puts_the_counter_back_once_a_second_at_most() {
        assert_eq!(next_rearm(10, HZ), 10 + HZ);
        assert_eq!(next_rearm(u64::MAX - 1, HZ), u64::MAX);
        assert_eq!(next_rearm(10, 0), 11);
    }

    fn observed(quiet_seconds: u64, step_seconds: Option<u64>) -> Observation {
        let now = 1000 * HZ;
        Observation {
            armed: true,
            armed_at: now - quiet_seconds * HZ,
            step_began: step_seconds.map_or(0, |seconds| now - seconds * HZ),
            task: 7,
            sequence: 42,
            now,
            tsc_hz: HZ,
        }
    }

    #[test]
    fn only_an_nmi_after_the_whole_limit_on_an_armed_counter_is_the_watchdogs() {
        // Before the limit, the counter cannot have overflowed: another NMI.
        assert_eq!(attribute(&observed(LIMIT_SECONDS - 1, Some(40))), None);
        let unarmed = Observation {
            armed: false,
            ..observed(LIMIT_SECONDS + 5, Some(40))
        };
        assert_eq!(attribute(&unarmed), None);
        let no_rate = Observation {
            tsc_hz: 0,
            ..observed(LIMIT_SECONDS + 5, Some(40))
        };
        assert_eq!(attribute(&no_rate), None);
        // A put-back time after the NMI's own reading is no overflow either.
        let ahead = Observation {
            armed_at: 1001 * HZ,
            ..observed(LIMIT_SECONDS, None)
        };
        assert_eq!(attribute(&ahead), None);
        assert_eq!(
            attribute(&observed(LIMIT_SECONDS, Some(40))),
            Some(Stuck {
                quiet_ms: LIMIT_SECONDS * 1000,
                step: Some(Step {
                    task: 7,
                    sequence: 42,
                    running_ms: 40_000
                }),
            })
        );
        assert_eq!(
            attribute(&observed(LIMIT_SECONDS + 3, None)),
            Some(Stuck {
                quiet_ms: (LIMIT_SECONDS + 3) * 1000,
                step: None,
            })
        );
    }

    #[test]
    fn another_processor_finds_a_step_stuck_once_it_saw_it_run_for_the_limit() {
        const COUNT_HZ: u64 = 1_000_000_000;
        let at = |seconds: u64| 5 * COUNT_HZ + seconds * COUNT_HZ;
        // Nothing runs: nothing to watch, whatever was seen before.
        assert_eq!(look(None, 0, at(0), COUNT_HZ), Look::Idle);
        let seen = Sighting {
            began: 77,
            seen_at: at(0),
        };
        assert_eq!(look(Some(seen), 0, at(40), COUNT_HZ), Look::Idle);
        assert_eq!(look(None, 77, at(0), 0), Look::Idle);
        // A step first seen is remembered, by the watcher's own count.
        assert_eq!(look(None, 77, at(0), COUNT_HZ), Look::New(seen));
        // The same step, within the limit, and past it.
        assert_eq!(
            look(Some(seen), 77, at(LIMIT_SECONDS) - 1, COUNT_HZ),
            Look::Running
        );
        assert_eq!(
            look(Some(seen), 77, at(LIMIT_SECONDS + 2), COUNT_HZ),
            Look::Overdue {
                quiet_ms: (LIMIT_SECONDS + 2) * 1000
            }
        );
        // Another step since, however long the watch: a new sighting.
        assert_eq!(
            look(Some(seen), 78, at(LIMIT_SECONDS + 2), COUNT_HZ),
            Look::New(Sighting {
                began: 78,
                seen_at: at(LIMIT_SECONDS + 2)
            })
        );
        // A count that went back (another watcher's earlier reading) is
        // no overdue.
        assert_eq!(
            look(Some(seen), 77, at(0) - COUNT_HZ, COUNT_HZ),
            Look::Running
        );
    }

    #[test]
    fn only_an_nmi_a_watcher_sent_is_attributed_and_a_late_return_still_stops() {
        let observation = observed(0, Some(LIMIT_SECONDS + 1));
        // No NMI sent: a platform's, with the plain exception report.
        assert_eq!(caught(0, &observation), None);
        let stuck = caught(observation.step_began, &observation).unwrap();
        assert_eq!(
            stuck,
            Caught::Stuck(Stuck {
                quiet_ms: (LIMIT_SECONDS + 1) * 1000,
                step: Some(Step {
                    task: 7,
                    sequence: 42,
                    running_ms: (LIMIT_SECONDS + 1) * 1000
                }),
            })
        );
        let text = caught_message("Linux driver work", &stuck);
        assert!(text.contains("(Linux driver work)"), "{text}");
        assert!(text.contains("task 7 job 42 ran 31000 ms"), "{text}");
        // The step returned between the look and the NMI, or another runs.
        let returned = Observation {
            step_began: 0,
            ..observation
        };
        assert_eq!(
            caught(observation.step_began, &returned),
            Some(Caught::Returned)
        );
        let next = Observation {
            step_began: observation.step_began + 5,
            ..observation
        };
        assert_eq!(
            caught(observation.step_began, &next),
            Some(Caught::Returned)
        );
        assert!(caught_message("x", &Caught::Returned).contains("returned only as"));
    }

    #[test]
    fn the_stop_names_the_stage_and_the_step() {
        let stuck = attribute(&observed(LIMIT_SECONDS, Some(31))).unwrap();
        let text = message("the GPU's probe", &stuck);
        assert!(text.contains("(the GPU's probe)"), "{text}");
        assert!(text.contains("task 7 job 42 ran 31000 ms"), "{text}");
        let stuck = attribute(&observed(LIMIT_SECONDS, None)).unwrap();
        assert!(message("Linux's first tasks", &stuck).contains("outside any task step"));
    }
}
