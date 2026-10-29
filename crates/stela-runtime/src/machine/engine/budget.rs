//! Block and host-time limits for one dispatch call.

/// Either limit ends a run with `Stop::Budget` at an engine boundary.
/// Native chains and host callbacks already entered may overrun the time limit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunBudget {
    /// Absolute executed-block limit, with zero meaning unlimited.
    pub blocks: u64,
    /// Duration in `Host::counter` ticks; independent of the guest clock.
    pub host_ticks: Option<u64>,
}

#[derive(Clone, Copy)]
pub(super) struct Deadline {
    started: u64,
    ticks: u64,
}

impl Deadline {
    pub(super) fn new(started: u64, ticks: u64) -> Self {
        Self { started, ticks }
    }

    pub(super) fn remaining(self, now: u64) -> Option<u64> {
        self.ticks
            .checked_sub(now.wrapping_sub(self.started))
            .filter(|left| *left != 0)
    }

    /// Shorten an existing host timer using relative durations, including
    /// a counter wrap between the start and this observation.
    pub(super) fn timer(self, now: u64, until: u64) -> Option<u64> {
        let left = self.remaining(now)?;
        Some(now.wrapping_add(until.saturating_sub(now).min(left)))
    }
}

#[cfg(test)]
mod tests;
