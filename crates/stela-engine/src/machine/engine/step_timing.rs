//! `--profile`: where a run's host time goes between translated blocks, by
//! phase of the engine's step loop and by the exit kind the engine handles.
//! The host supplies the clock ([`super::Host::profile_ticks`]); while off,
//! each phase boundary costs one branch.

/// A phase of the step loop ([`super::Machine::run_blocks`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Phase {
    /// Choosing the PE to run, ending slices and waiting.
    Schedule,
    /// Due device work and interrupt delivery before each step.
    Devices,
    /// Finding the next block, compiling and installing it when new.
    Fetch,
    /// Translated code, chained blocks included.
    Native,
    /// Handling the exit translated code returned with, by kind.
    Exit,
}

impl Phase {
    pub const COUNT: usize = Self::Exit as usize + 1;
    pub const ALL: [Self; Self::COUNT] = [
        Self::Schedule,
        Self::Devices,
        Self::Fetch,
        Self::Native,
        Self::Exit,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Schedule => "schedule",
            Self::Devices => "devices",
            Self::Fetch => "fetch",
            Self::Native => "native",
            Self::Exit => "exit",
        }
    }
}

/// The exits [`StepTiming::exits`] counts: each `ExitKind`, then faults.
pub const EXIT_SLOTS: usize = 14;
/// [`StepTiming::exits`]' slot for a native fault (a device access, say).
pub const FAULT_SLOT: usize = EXIT_SLOTS - 1;

/// One completed phase's largest observed profile-clock interval.
///
/// The CPU fields are a materialized snapshot after the phase, not a precise
/// fault PC or an attribution to one guest instruction. Fetch includes finding,
/// compiling and installing code; every phase can include host descheduling.
/// These observations are diagnostics, never architectural latency bounds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Maximum {
    pub ticks: u64,
    /// The same profile-clock sample used to close this interval.
    pub finished_ticks: u64,
    pub pc_after: u64,
    pub el_after: u8,
    pub daif_after: u8,
}

impl Maximum {
    #[inline]
    pub(super) fn observe(
        &mut self,
        ticks: u64,
        finished_ticks: u64,
        pc_after: u64,
        el_after: u8,
        daif_after: u8,
    ) {
        if ticks > self.ticks {
            *self = Self {
                ticks,
                finished_ticks,
                pc_after,
                el_after,
                daif_after,
            };
        }
    }
}

/// Host ticks spent so far, by phase and by exit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StepTiming {
    pub phases: [u64; Phase::COUNT],
    /// Lifetime maxima since timing was enabled or reset. A zero interval
    /// has no witness. These are retained, not subtracted, by [`Self::since`].
    pub lifetime_maxima: [Maximum; Phase::COUNT],
    /// Exits handled and the ticks handling them, by `ExitKind` value, with
    /// faults in [`FAULT_SLOT`].
    pub exits: [(u64, u64); EXIT_SLOTS],
}

impl StepTiming {
    /// Cumulative phase/exit totals spent since `earlier`, retaining the
    /// current lifetime maximum snapshots. An interval maximum cannot be
    /// derived by subtracting maxima.
    pub fn since(&self, earlier: &Self) -> Self {
        let mut delta = *self;
        for (now, then) in delta.phases.iter_mut().zip(earlier.phases) {
            *now = now.wrapping_sub(then);
        }
        for (now, then) in delta.exits.iter_mut().zip(earlier.exits) {
            *now = (now.0.wrapping_sub(then.0), now.1.wrapping_sub(then.1));
        }
        delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delta_subtracts_each_phase_and_exit() {
        let mut earlier = StepTiming::default();
        earlier.phases[Phase::Exit as usize] = 5;
        earlier.exits[FAULT_SLOT] = (1, 10);
        earlier.lifetime_maxima[Phase::Exit as usize].observe(5, 50, 0x1000, 1, 2);
        let mut now = earlier;
        now.phases[Phase::Exit as usize] = 12;
        now.exits[FAULT_SLOT] = (3, 40);
        now.lifetime_maxima[Phase::Exit as usize].observe(9, 90, 0x2000, 2, 3);
        let delta = now.since(&earlier);
        assert_eq!(delta.phases[Phase::Exit as usize], 7);
        assert_eq!(delta.exits[FAULT_SLOT], (2, 30));
        assert_eq!(delta.phases[Phase::Native as usize], 0);
        assert_eq!(delta.lifetime_maxima, now.lifetime_maxima);
        let later_delta = now.since(&now);
        assert_eq!(later_delta.phases, [0; Phase::COUNT]);
        assert_eq!(later_delta.lifetime_maxima, now.lifetime_maxima);
    }

    #[test]
    fn completed_phase_maxima_keep_their_materialized_witness_and_clock_samples() {
        let mut machine = super::super::tests::machine(&[]);
        machine.set_step_timing(true);
        let reads = machine.host.counter_reads;
        machine.host.now = 100;
        machine.cpu.pc = 0x4000;
        machine.cpu.pstate.el = 1;
        machine.cpu.pstate.daif = 2;
        assert_eq!(machine.timing_charge(Phase::Fetch, 90), 100);
        let first = Maximum {
            ticks: 10,
            finished_ticks: 100,
            pc_after: 0x4000,
            el_after: 1,
            daif_after: 2,
        };
        assert_eq!(
            machine.step_timing().unwrap().lifetime_maxima[Phase::Fetch as usize],
            first
        );
        machine.host.now = 115;
        machine.cpu.pc = 0x5000;
        machine.timing_charge(Phase::Fetch, 110);
        machine.host.now = 125;
        machine.timing_charge(Phase::Fetch, 115);
        // Smaller and tied intervals preserve the original witness.
        assert_eq!(
            machine.step_timing().unwrap().lifetime_maxima[Phase::Fetch as usize],
            first
        );
        machine.host.now = 200;
        machine.cpu.pstate.el = 2;
        machine.cpu.pstate.daif = 15;
        machine.timing_charge(Phase::Fetch, 150);
        let timing = machine.step_timing().unwrap();
        assert_eq!(timing.phases[Phase::Fetch as usize], 75);
        assert_eq!(
            timing.lifetime_maxima[Phase::Fetch as usize],
            Maximum {
                ticks: 50,
                finished_ticks: 200,
                pc_after: 0x5000,
                el_after: 2,
                daif_after: 15
            }
        );
        // Exit/fault accounting uses its existing sample too, including wrap.
        machine.host.now = 4;
        machine.timing_exit(FAULT_SLOT, u64::MAX - 8);
        let timing = machine.step_timing().unwrap();
        assert_eq!(timing.exits[FAULT_SLOT], (1, 13));
        assert_eq!(timing.phases[Phase::Exit as usize], 13);
        assert_eq!(
            timing.lifetime_maxima[Phase::Exit as usize],
            Maximum {
                ticks: 13,
                finished_ticks: 4,
                pc_after: 0x5000,
                el_after: 2,
                daif_after: 15
            }
        );
        assert_eq!(machine.host.counter_reads - reads, 5);
    }

    #[test]
    fn resetting_timing_clears_maxima_and_disabled_timing_reads_no_clock() {
        let mut machine = super::super::tests::machine(&[]);
        let reads = machine.host.counter_reads;
        assert_eq!(machine.timing_start(), 0);
        assert_eq!(machine.timing_charge(Phase::Fetch, 0), 0);
        machine.timing_exit(FAULT_SLOT, 0);
        assert_eq!(machine.host.counter_reads, reads);
        machine.set_step_timing(true);
        machine.host.now = 20;
        machine.timing_charge(Phase::Native, 10);
        assert_eq!(
            machine.step_timing().unwrap().lifetime_maxima[Phase::Native as usize].ticks,
            10
        );
        let reads = machine.host.counter_reads;
        machine.set_step_timing(true);
        assert_eq!(machine.step_timing(), Some(&StepTiming::default()));
        machine.set_step_timing(false);
        assert!(machine.step_timing().is_none());
        machine.timing_exit(FAULT_SLOT, 0);
        assert_eq!(machine.host.counter_reads, reads);
    }
}
