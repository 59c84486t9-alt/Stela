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

/// Host ticks spent so far, by phase and by exit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StepTiming {
    pub phases: [u64; Phase::COUNT],
    /// Exits handled and the ticks handling them, by `ExitKind` value, with
    /// faults in [`FAULT_SLOT`].
    pub exits: [(u64, u64); EXIT_SLOTS],
}

impl StepTiming {
    /// What was spent since `earlier`.
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
        let mut now = earlier;
        now.phases[Phase::Exit as usize] = 12;
        now.exits[FAULT_SLOT] = (3, 40);
        let delta = now.since(&earlier);
        assert_eq!(delta.phases[Phase::Exit as usize], 7);
        assert_eq!(delta.exits[FAULT_SLOT], (2, 30));
        assert_eq!(delta.phases[Phase::Native as usize], 0);
    }
}
