//! Sparse, jittered, owner-local timing. No allocation or execution authority.
use stela_runtime::machine::engine::NativeTimingPhase as Phase;

const INITIAL_JITTER: u64 = 0x19d5_65c8_d843_ba71;
const MIN_INTERVAL: u64 = 2048;
const INTERVAL_MASK: u64 = 4095;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Snapshot {
    pub rounds: u64,
    pub samples: u64,
    pub complete: u64,
    pub partial: u64,
    pub sampled_ticks: u64,
    pub complete_ticks: u64,
    /// Interval ending at each phase; these sum to complete_ticks only.
    pub phase_ticks: [u64; Phase::COUNT],
    pub installed_hits: u64,
    pub installed_misses: u64,
    pub installed_bytes: u64,
    pub exit_kinds: [u64; 13],
    pub timestamp_pair_min: u64,
    pub board_refreshes: u64,
    pub sampled_board_refreshes: u64,
    /// Inclusive across ALL sampled rounds, including partial rounds.
    pub sampled_board_ticks: u64,
}

pub(crate) struct Profile {
    snapshot: Snapshot,
    jitter: u64,
    remaining: u64,
    active: bool,
    valid: bool,
    last_phase: usize,
    started: u64,
    last: u64,
    pending: [u64; Phase::COUNT],
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            snapshot: Snapshot::default(),
            jitter: INITIAL_JITTER,
            remaining: 0,
            active: false,
            valid: false,
            last_phase: 0,
            started: 0,
            last: 0,
            pending: [0; Phase::COUNT],
        }
    }
}

impl Profile {
    pub(crate) fn board_start(&mut self, clock: impl FnOnce() -> u64) -> Option<u64> {
        self.snapshot.board_refreshes = self.snapshot.board_refreshes.saturating_add(1);
        if self.active {
            self.snapshot.sampled_board_refreshes =
                self.snapshot.sampled_board_refreshes.saturating_add(1);
            Some(clock())
        } else {
            None
        }
    }

    pub(crate) fn board_end(&mut self, started: u64, now: u64) {
        self.snapshot.sampled_board_ticks = self
            .snapshot
            .sampled_board_ticks
            .saturating_add(now.wrapping_sub(started));
    }

    pub(crate) fn needs_calibration(&self) -> bool {
        self.snapshot.timestamp_pair_min == 0
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    pub(crate) fn calibrate(&mut self, mut clock: impl FnMut() -> u64) {
        let mut minimum = u64::MAX;
        for _ in 0..32 {
            let start = clock();
            minimum = minimum.min(clock().wrapping_sub(start));
        }
        self.snapshot.timestamp_pair_min = minimum;
    }

    /// Unsampled checkpoints never read the clock. Partial/error paths retain
    /// whole-round time separately and cannot pollute complete phase totals.
    pub(crate) fn event(&mut self, phase: Phase, clock: impl FnOnce() -> u64) {
        if phase == Phase::Begin {
            self.snapshot.rounds = self.snapshot.rounds.saturating_add(1);
            if self.remaining != 0 {
                self.remaining -= 1;
                self.active = false;
                return;
            }
            self.jitter ^= self.jitter << 13;
            self.jitter ^= self.jitter >> 7;
            self.jitter ^= self.jitter << 17;
            self.remaining = MIN_INTERVAL + (self.jitter & INTERVAL_MASK);
            self.active = true;
            self.valid = true;
            self.pending = [0; Phase::COUNT];
            self.started = clock();
            self.last = self.started;
            self.last_phase = 0;
            return;
        }
        if !self.active {
            return;
        }
        let now = clock();
        let index = phase as usize;
        self.valid &= index == self.last_phase + 1;
        self.pending[index] = self.pending[index].saturating_add(now.wrapping_sub(self.last));
        self.last = now;
        self.last_phase = index;
        if phase == Phase::End {
            self.active = false;
            let ticks = now.wrapping_sub(self.started);
            let snapshot = &mut self.snapshot;
            snapshot.samples = snapshot.samples.saturating_add(1);
            snapshot.sampled_ticks = snapshot.sampled_ticks.saturating_add(ticks);
            if self.valid {
                snapshot.complete = snapshot.complete.saturating_add(1);
                snapshot.complete_ticks = snapshot.complete_ticks.saturating_add(ticks);
                for (total, pending) in snapshot.phase_ticks.iter_mut().zip(self.pending) {
                    *total = total.saturating_add(pending);
                }
            } else {
                snapshot.partial = snapshot.partial.saturating_add(1);
            }
        }
    }

    pub(crate) fn installed(&mut self, hit: bool) {
        let count = if hit {
            &mut self.snapshot.installed_hits
        } else {
            &mut self.snapshot.installed_misses
        };
        *count = count.saturating_add(1);
    }

    pub(crate) fn copied(&mut self, bytes: usize) {
        self.snapshot.installed_bytes = self.snapshot.installed_bytes.saturating_add(bytes as u64);
    }

    pub(crate) fn exit(&mut self, kind: u64) {
        if let Some(count) = self.snapshot.exit_kinds.get_mut(kind as usize) {
            *count = count.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PHASES: [Phase; Phase::COUNT] = [
        Phase::Begin,
        Phase::SchedulerReady,
        Phase::Prepared,
        Phase::CpuVerified,
        Phase::CodeInstalled,
        Phase::MemoryPrepared,
        Phase::BodyReturned,
        Phase::Recovered,
        Phase::End,
    ];

    #[test]
    fn complete_phases_partition_the_sample_and_unsampled_rounds_read_no_clock() {
        let mut profile = Profile::default();
        for (index, phase) in PHASES.into_iter().enumerate() {
            profile.event(phase, || 100 + index as u64 * 10);
        }
        let result = profile.snapshot();
        assert_eq!((result.samples, result.complete, result.partial), (1, 1, 0));
        assert_eq!(result.complete_ticks, 80);
        assert_eq!(result.phase_ticks.iter().sum::<u64>(), 80);
        for phase in PHASES {
            profile.event(phase, || panic!("unsampled clock read"));
        }
        assert_eq!(profile.snapshot().rounds, 2);
        assert_eq!(profile.snapshot().samples, 1);
    }

    #[test]
    fn skipped_phases_and_counter_wrap_preserve_partial_time_only() {
        let mut profile = Profile::default();
        profile.event(Phase::Begin, || u64::MAX - 10);
        profile.event(Phase::End, || 9);
        let result = profile.snapshot();
        assert_eq!((result.samples, result.complete, result.partial), (1, 0, 1));
        assert_eq!(result.sampled_ticks, 20);
        assert_eq!(result.complete_ticks, 0);
        assert_eq!(result.phase_ticks, [0; Phase::COUNT]);
    }

    #[test]
    fn cache_and_exit_counts_are_separate_from_sampled_phase_time() {
        let mut profile = Profile::default();
        profile.installed(true);
        profile.installed(false);
        profile.copied(4096);
        profile.exit(0);
        profile.exit(12);
        profile.exit(u64::MAX);
        let mut clock = 0;
        profile.calibrate(|| {
            clock += 7;
            clock
        });
        assert!(!profile.needs_calibration());
        let result = profile.snapshot();
        assert_eq!(
            (
                result.installed_hits,
                result.installed_misses,
                result.installed_bytes
            ),
            (1, 1, 4096)
        );
        assert_eq!(result.exit_kinds.iter().sum::<u64>(), 2);
        assert_eq!(result.timestamp_pair_min, 7);
        assert_eq!(result.samples, 0);
    }

    #[test]
    fn countdown_resamples_and_partial_state_cannot_leak_into_a_complete_sample() {
        let mut profile = Profile::default();
        assert_eq!(profile.board_start(|| panic!("inactive clock")), None);
        profile.event(Phase::Begin, || 100);
        let start = profile.board_start(|| 110).unwrap();
        profile.board_end(start, 130);
        profile.event(Phase::End, || 200);
        let skip = profile.remaining;
        assert!((MIN_INTERVAL..=MIN_INTERVAL + INTERVAL_MASK).contains(&skip));
        for _ in 0..skip {
            for phase in PHASES {
                profile.event(phase, || panic!("unsampled clock"));
            }
        }
        for (index, phase) in PHASES.into_iter().enumerate() {
            profile.event(phase, || 1000 + index as u64 * 10);
        }
        let result = profile.snapshot();
        assert_eq!((result.samples, result.complete, result.partial), (2, 1, 1));
        assert_eq!(result.complete_ticks, 80);
        assert_eq!(result.phase_ticks.iter().sum::<u64>(), 80);
        assert_eq!(result.board_refreshes, 2);
        assert_eq!(result.sampled_board_refreshes, 1);
        assert_eq!(result.sampled_board_ticks, 20);
    }
}
