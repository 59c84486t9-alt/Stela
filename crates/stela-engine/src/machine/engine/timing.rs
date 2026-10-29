//! Step-loop timing, host-time exclusion, idle skipping and wait limits.

use super::*;

impl<H: Host, D: Devices> Machine<H, D> {
    /// Run host-side work on the devices, such as an external peer's
    /// computation, between steps: the host time it takes is not guest
    /// time, so the system counter does not advance across it.
    pub fn exclude_host_time<T>(&mut self, work: impl FnOnce(&mut D) -> T) -> T {
        let before = self.host.counter();
        let result = work(&mut self.devices);
        let after = self.host.counter();
        self.clock.exclude(after.saturating_sub(before));
        result
    }

    /// End every wait of all PEs at once by leaping the system counter to
    /// the next deadline instead of waiting on the host: guest sleeps cost no
    /// host time, and time of day runs ahead of the host's (`clock`).
    /// Parallel machines share host time; advancing just one PE would
    /// disagree with the counters the other PEs observe.
    pub fn set_idle_skip(&mut self, skip: bool) -> Result<(), &'static str> {
        if skip && self.parallel.is_some() {
            return Err("idle skipping requires all PEs to share one scheduler");
        }
        self.idle_skip = skip;
        Ok(())
    }

    /// Time the step loop's phases and exits from now on ([`step_timing`]).
    pub fn set_step_timing(&mut self, on: bool) {
        self.step_timing = on.then(step_timing::StepTiming::default);
    }

    /// The step loop's timing so far, while it is on.
    pub fn step_timing(&self) -> Option<&step_timing::StepTiming> {
        self.step_timing.as_ref()
    }

    /// The profile clock, while timing is on.
    #[inline]
    pub(super) fn timing_start(&mut self) -> u64 {
        match self.step_timing {
            Some(_) => self.host.profile_ticks(),
            None => 0,
        }
    }

    /// Charge the ticks since `since` to `phase`; the profile clock now.
    #[inline]
    pub(super) fn timing_charge(&mut self, phase: step_timing::Phase, since: u64) -> u64 {
        if self.step_timing.is_none() {
            return 0;
        }
        let now = self.host.profile_ticks();
        if let Some(timing) = &mut self.step_timing {
            let spent = now.wrapping_sub(since);
            timing.phases[phase as usize] += spent;
            timing.lifetime_maxima[phase as usize].observe(
                spent,
                now,
                self.cpu.pc,
                self.cpu.pstate.el,
                self.cpu.pstate.daif,
            );
        }
        now
    }

    /// Charge the ticks since `since` to handling an exit in `slot`.
    #[inline]
    pub(super) fn timing_exit(&mut self, slot: usize, since: u64) {
        if self.step_timing.is_none() {
            return;
        }
        let now = self.host.profile_ticks();
        if let Some(timing) = &mut self.step_timing {
            let spent = now.wrapping_sub(since);
            timing.phases[step_timing::Phase::Exit as usize] += spent;
            timing.lifetime_maxima[step_timing::Phase::Exit as usize].observe(
                spent,
                now,
                self.cpu.pc,
                self.cpu.pstate.el,
                self.cpu.pstate.daif,
            );
            if let Some(exit) = timing.exits.get_mut(slot) {
                *exit = (exit.0 + 1, exit.1 + spent);
            }
        }
    }

    /// The architectural system count and each generic timer's `(CTL, CVAL)`
    /// in [`timer::CHANNELS`] order, sampled at that count, of the bank that
    /// counts it: the Apple generic timer's from the M3 on, where the kernel
    /// keeps its timer (`timer::agt`). Diagnostics must use this count,
    /// including slice lag and idle leaps, just as guest register reads and
    /// timer delivery do; the host counter can differ.
    pub fn timer_snapshot(&mut self) -> (u64, [(u64, u64); 4]) {
        let now = self.now();
        let bank = timer::system_bank(&self.cpu);
        let timers = timer::CHANNELS.map(|channel| {
            (
                channel.read_control(&self.cpu, bank, now),
                timer::value(&self.cpu, bank, channel.compare),
            )
        });
        (now, timers)
    }

    /// Bound the waits of every PE on the host in one `run` to `limit`
    /// system counter ticks in all, after which it returns [`Stop::Waiting`]
    /// so the host can take inputs that reach the board from outside it,
    /// such as its power button. In all, so that a guest whose timers end
    /// each wait early still returns. The counter keeps following the
    /// host's meanwhile; an idle skip, which leaps to a deadline at once, is
    /// not bounded. Without a limit a wait lasts until a deadline.
    pub fn set_wait_limit(&mut self, limit: Option<u64>) {
        self.wait_limit = limit.map(|limit| limit.max(1));
    }
}
