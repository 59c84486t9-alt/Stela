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

/// The exits [`StepTiming::exits`] counts: each `ExitKind`, then native
/// faults by cause ([`fault_slot`]).
pub const EXIT_SLOTS: usize = FAULT_SLOTS + 5;
/// [`StepTiming::exits`]' first native-fault slot.
const FAULT_SLOTS: usize = 13;
/// The slot of native faults that reached a device ([`fault_slot`]).
pub const DEVICE_FAULT_SLOT: usize = FAULT_SLOTS + 1;

/// A native fault's slot in [`StepTiming::exits`], by cause: the guest's
/// translation, a device, a native check, a watched or tag-checked page,
/// or translation the engine does not implement.
pub fn fault_slot(cause: &super::FaultCause) -> usize {
    use super::FaultCause;
    FAULT_SLOTS
        + match cause {
            FaultCause::Guest(_) => 0,
            FaultCause::Device { .. } => DEVICE_FAULT_SLOT - FAULT_SLOTS,
            FaultCause::NonCanonical | FaultCause::InvalidOpcode => 2,
            FaultCause::Watched | FaultCause::TagChecked => 3,
            FaultCause::Translation(_) => 4,
        }
}

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
    /// has no witness. These are held, not subtracted, by [`Self::since`].
    pub lifetime_maxima: [Maximum; Phase::COUNT],
    /// Exits handled and the ticks handling them, by `ExitKind` value, then
    /// native faults by cause ([`fault_slot`]).
    pub exits: [(u64, u64); EXIT_SLOTS],
}

impl StepTiming {
    /// Cumulative phase/exit totals spent since `earlier`, keeping the
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

    const FAULT_SLOT: usize = FAULT_SLOTS + 1;

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
    fn a_device_faults_ticks_go_to_the_register_it_reached() {
        const REGISTER: u64 = 0x2_3520_0018;
        let mut machine = super::super::tests::machine(&[]);
        machine.set_step_timing(true);
        machine.count_device_access(REGISTER);
        machine.host.now = 30;
        machine.timing_exit(DEVICE_FAULT_SLOT, 10);
        // Another exit's ticks are not the register's, even after an
        // access it did not fault for.
        machine.count_device_access(REGISTER);
        machine.host.now = 100;
        machine.timing_exit(FAULT_SLOTS, 40);
        machine.host.now = 120;
        machine.timing_exit(DEVICE_FAULT_SLOT, 110);
        assert_eq!(
            machine.device_registers()[&REGISTER],
            super::super::DeviceRegister {
                accesses: 2,
                ticks: 20
            }
        );
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
