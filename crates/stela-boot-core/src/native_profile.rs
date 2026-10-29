//! Sparse, jittered, owner-local timing. Staging is allocated before sampled
//! Begin timestamps; no sample buffer grows during actual epoch execution.
use alloc::vec::Vec;
use stela_engine::machine::engine::MAX_NATIVE_EPOCH_BODIES;
use stela_engine::machine::engine::NativeTimingPhase as Phase;
use stela_engine::machine::engine::NativeTimingWork as Work;
pub mod words;

const INITIAL_JITTER: u64 = 0x19d5_65c8_d843_ba71;
const MIN_INTERVAL: u64 = 2048;
const INTERVAL_MASK: u64 = 4095;

/// Inclusive intervals; NativeCall is nested in CheckedBody, and every
/// interval lies inside one of the outer disjoint phases. Never sum these.
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkSnapshot {
    pub calls: u64,
    pub sampled_calls: u64,
    pub sampled_ticks: u64,
    /// By the outer interval ending at each NativeTimingPhase. Work spans
    /// close before any phase checkpoint, so helper calls remain separable
    /// from native calls inside BodyReturned. Includes partial sampled rounds.
    pub phase_ticks: [u64; Phase::COUNT],
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Snapshot {
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
    pub words: words::Summary,
    pub capture_bytes: usize,
    /// Indexed by NativeTimingWork in its declared order.
    pub work: [WorkSnapshot; Work::COUNT],
}

pub struct Profile {
    snapshot: Snapshot,
    jitter: u64,
    remaining: u64,
    active: bool,
    valid: bool,
    last_phase: usize,
    started: u64,
    last: u64,
    pending: [u64; Phase::COUNT],
    words: words::Histogram,
    pending_words: Vec<words::Captured>,
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
            words: words::Histogram::default(),
            pending_words: Vec::new(),
        }
    }
}

impl Profile {
    pub fn work_start(&mut self, work: Work, clock: impl FnOnce() -> u64) -> Option<u64> {
        let count = &mut self.snapshot.work[work as usize];
        count.calls = count.calls.saturating_add(1);
        if self.active {
            count.sampled_calls = count.sampled_calls.saturating_add(1);
        }
        if work == Work::DeviceLines {
            return self.board_start(clock);
        }
        self.active.then(clock)
    }

    pub fn work_end(&mut self, work: Work, started: u64, now: u64) {
        let count = &mut self.snapshot.work[work as usize];
        let elapsed = now.wrapping_sub(started);
        count.sampled_ticks = count.sampled_ticks.saturating_add(elapsed);
        let phase = (self.last_phase + 1).min(Phase::COUNT - 1);
        count.phase_ticks[phase] = count.phase_ticks[phase].saturating_add(elapsed);
        if work == Work::DeviceLines {
            self.board_end(started, now);
        }
    }

    pub fn board_start(&mut self, clock: impl FnOnce() -> u64) -> Option<u64> {
        self.snapshot.board_refreshes = self.snapshot.board_refreshes.saturating_add(1);
        if self.active {
            self.snapshot.sampled_board_refreshes =
                self.snapshot.sampled_board_refreshes.saturating_add(1);
            Some(clock())
        } else {
            None
        }
    }

    pub fn board_end(&mut self, started: u64, now: u64) {
        self.snapshot.sampled_board_ticks = self
            .snapshot
            .sampled_board_ticks
            .saturating_add(now.wrapping_sub(started));
    }

    pub fn needs_calibration(&self) -> bool {
        self.snapshot.timestamp_pair_min == 0
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            words: self.words.summary,
            ..self.snapshot
        }
    }

    pub fn instructions(
        &mut self,
        sample: stela_engine::machine::engine::NativeInstructionSample<'_>,
    ) {
        if !self.active {
            return;
        }
        if self.pending_words.len() >= MAX_NATIVE_EPOCH_BODIES
            || self.pending_words.len() == self.pending_words.capacity()
        {
            self.words.summary.dropped_bodies = self.words.summary.dropped_bodies.saturating_add(1);
            return;
        }
        if let Some(captured) = words::Captured::new(sample) {
            self.pending_words.push(captured);
        } else {
            self.words.summary.invalid_samples =
                self.words.summary.invalid_samples.saturating_add(1);
        }
    }

    pub fn top_words(&self, ranking: words::Ranking) -> [Option<words::Weight>; words::TOP] {
        self.words.top_by(ranking)
    }

    pub fn calibrate(&mut self, mut clock: impl FnMut() -> u64) {
        let mut minimum = u64::MAX;
        for _ in 0..32 {
            let start = clock();
            minimum = minimum.min(clock().wrapping_sub(start));
        }
        self.snapshot.timestamp_pair_min = minimum;
    }

    /// Unsampled checkpoints never read the clock. Partial/error paths retain
    /// whole-round time separately and cannot pollute complete phase totals.
    pub fn event(&mut self, phase: Phase, clock: impl FnOnce() -> u64) {
        if phase == Phase::Begin {
            self.words.summary.dropped_bodies = self
                .words
                .summary
                .dropped_bodies
                .saturating_add(self.pending_words.len() as u64);
            self.pending_words.clear();
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
            // Allocate only for an actual sampled owner, before clock(). A
            // failed reservation remains explicit drops; it cannot grow later.
            if self.pending_words.capacity() < MAX_NATIVE_EPOCH_BODIES {
                let _ = self
                    .pending_words
                    .try_reserve_exact(MAX_NATIVE_EPOCH_BODIES);
            }
            self.snapshot.capture_bytes =
                self.pending_words.capacity() * core::mem::size_of::<words::Captured>();
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
            for captured in self.pending_words.drain(..) {
                self.words.merge(captured);
            }
        }
    }

    pub fn installed(&mut self, hit: bool) {
        let count = if hit {
            &mut self.snapshot.installed_hits
        } else {
            &mut self.snapshot.installed_misses
        };
        *count = count.saturating_add(1);
    }

    pub fn copied(&mut self, bytes: usize) {
        self.snapshot.installed_bytes = self.snapshot.installed_bytes.saturating_add(bytes as u64);
    }

    pub fn exit(&mut self, kind: u64) {
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

    fn instruction() -> stela_engine::machine::engine::NativeInstructionSample<'static> {
        stela_engine::machine::engine::NativeInstructionSample {
            source: &[1, 0, 0, 0],
            source_map: &[(stela_compiler::GuestAddress(0x4000), 3)],
            native_bytes: 12,
            register_spans: &[],
            retired: 1,
            faulting: false,
            deferred_terminal: false,
        }
    }

    #[test]
    fn instruction_aggregation_follows_end_and_unsampled_rounds_ignore_metadata() {
        let mut profile = Profile::default();
        profile.event(Phase::Begin, || 100);
        profile.instructions(instruction());
        assert_eq!(profile.snapshot().words.bodies, 0);
        assert!(
            profile
                .top_words(words::Ranking::Frequency)
                .iter()
                .all(Option::is_none)
        );
        profile.instructions(instruction());
        assert_eq!(profile.snapshot().words.dropped_bodies, 0);
        for (index, phase) in PHASES.into_iter().enumerate().skip(1) {
            profile.event(phase, || 100 + index as u64 * 10);
        }
        let result = profile.snapshot();
        assert_eq!(result.complete_ticks, 80);
        assert_eq!(
            (
                result.words.bodies,
                result.words.retired_words,
                result.words.wrapper_bytes
            ),
            (2, 2, 6)
        );
        profile.event(Phase::Begin, || panic!("unsampled clock"));
        let mut invalid = instruction();
        invalid.source_map = &[];
        profile.instructions(invalid);
        assert_eq!(profile.snapshot().words.invalid_samples, 0);
        assert!(profile.pending_words.is_empty());
    }

    #[test]
    fn abandoned_sample_is_counted_and_does_not_leak_into_the_next_round() {
        let mut profile = Profile::default();
        profile.event(Phase::Begin, || 100);
        profile.instructions(instruction());
        profile.event(Phase::Begin, || panic!("unsampled clock"));
        assert_eq!(profile.snapshot().words.dropped_bodies, 1);
        assert_eq!(profile.snapshot().words.bodies, 0);
        profile.remaining = 0;
        for (index, phase) in PHASES.into_iter().enumerate() {
            profile.event(phase, || 1000 + index as u64 * 10);
        }
        assert_eq!(profile.snapshot().words.bodies, 0);
        assert_eq!(profile.snapshot().complete_ticks, 80);
    }

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
    #[test]
    fn entire_bounded_epoch_is_captured_and_overflow_is_explicit() {
        let mut profile = Profile::default();
        profile.event(Phase::Begin, || 100);
        let allocation = profile.pending_words.as_ptr();
        for _ in 0..MAX_NATIVE_EPOCH_BODIES {
            profile.instructions(instruction());
        }
        profile.instructions(instruction());
        assert_eq!(profile.pending_words.as_ptr(), allocation);
        assert_eq!(profile.snapshot().words.dropped_bodies, 1);
        for (index, phase) in PHASES.into_iter().enumerate().skip(1) {
            profile.event(phase, || 100 + index as u64 * 10);
        }
        assert_eq!(
            profile.snapshot().words.bodies,
            MAX_NATIVE_EPOCH_BODIES as u64
        );
        assert_eq!(
            profile.snapshot().words.retired_words,
            MAX_NATIVE_EPOCH_BODIES as u64
        );
        assert_eq!(profile.snapshot().complete_ticks, 80);
        assert_eq!(profile.pending_words.as_ptr(), allocation);
        assert_eq!(
            profile.snapshot().capture_bytes,
            profile.pending_words.capacity() * core::mem::size_of::<words::Captured>()
        );
    }
    #[test]
    fn inclusive_work_separates_body_native_calls_from_stopped_helpers() {
        let mut profile = Profile::default();
        assert_eq!(
            profile.work_start(Work::WarmSource, || panic!("inactive clock")),
            None
        );
        for (index, phase) in PHASES.into_iter().enumerate().take(6) {
            profile.event(phase, || 100 + index as u64 * 10);
        }
        let checked = profile.work_start(Work::CheckedBody, || 160).unwrap();
        let native = profile.work_start(Work::NativeCall, || 170).unwrap();
        profile.work_end(Work::NativeCall, native, 190);
        profile.work_end(Work::CheckedBody, checked, 200);
        profile.event(Phase::BodyReturned, || 210);
        profile.event(Phase::Recovered, || 220);
        let helper = profile.work_start(Work::NativeCall, || 225).unwrap();
        profile.work_end(Work::NativeCall, helper, 235);
        profile.event(Phase::End, || 240);
        let snapshot = profile.snapshot();
        assert_eq!(snapshot.complete, 1);
        assert_eq!(snapshot.partial, 0);
        let native = snapshot.work[Work::NativeCall as usize];
        assert_eq!(
            (native.calls, native.sampled_calls, native.sampled_ticks),
            (2, 2, 30)
        );
        assert_eq!(native.phase_ticks[Phase::BodyReturned as usize], 20);
        assert_eq!(native.phase_ticks[Phase::End as usize], 10);
        assert_eq!(native.phase_ticks.iter().sum::<u64>(), native.sampled_ticks);
        let checked = snapshot.work[Work::CheckedBody as usize];
        assert_eq!(checked.sampled_ticks, 40);
        assert_eq!(checked.phase_ticks[Phase::BodyReturned as usize], 40);
        let source = snapshot.work[Work::WarmSource as usize];
        assert_eq!(
            (source.calls, source.sampled_calls, source.sampled_ticks),
            (1, 0, 0)
        );
    }
}
