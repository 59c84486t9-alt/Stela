//! Retained callback wall time, distinct from queued command latency.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallbackCounts {
    pub calls: u64,
    pub elapsed_ticks: u64,
    pub maximum_ticks: u64,
    /// Queued provider start attempts and returned completions, including errors.
    /// Direct callbacks do not expose their internal command count here.
    pub starts: u64,
    pub finishes: u64,
    pub maximum_starts: u64,
    pub maximum_finishes: u64,
}

/// Direct execution can be nested inside advance for a synchronous provider.
/// The two elapsed categories must not be added together as CPU time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallbackStats {
    pub advance: CallbackCounts,
    pub direct: CallbackCounts,
}

#[derive(Default)]
pub(super) struct Work {
    pub starts: u64,
    pub finishes: u64,
}

impl CallbackCounts {
    pub(super) fn record(&mut self, elapsed: u64, work: Work) {
        self.calls = self.calls.saturating_add(1);
        self.elapsed_ticks = self.elapsed_ticks.saturating_add(elapsed);
        self.maximum_ticks = self.maximum_ticks.max(elapsed);
        self.starts = self.starts.saturating_add(work.starts);
        self.finishes = self.finishes.saturating_add(work.finishes);
        self.maximum_starts = self.maximum_starts.max(work.starts);
        self.maximum_finishes = self.maximum_finishes.max(work.finishes);
    }
}
