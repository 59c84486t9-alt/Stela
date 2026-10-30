//! Opt-in execute-translation counters, independent of data-TLB statistics.
use core::cell::Cell;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Statistics {
    pub first_word_fetches: u64,
    pub full_source_fetches: u64,
    /// Execute MMU resolution calls; M=0 can resolve without descriptors.
    pub resolutions: u64,
    pub descriptor_reads: u64,
    pub requested_bytes: u64,
    /// Full successful private staging reads, not DRAM traffic or partial reads.
    pub successful_bytes: u64,
    pub declined_fetches: u64,
}
pub(super) enum Fetch {
    FirstWord,
    FullSource,
}
#[derive(Default)]
pub(super) struct Profile(Cell<Statistics>);
impl Profile {
    pub(super) fn statistics(&self) -> Statistics {
        self.0.get()
    }
    pub(super) fn record(
        &self,
        kind: Fetch,
        resolutions: u64,
        reads: u64,
        bytes: usize,
        success: bool,
    ) {
        let mut stats = self.0.get();
        let calls = match kind {
            Fetch::FirstWord => &mut stats.first_word_fetches,
            Fetch::FullSource => &mut stats.full_source_fetches,
        };
        *calls = calls.saturating_add(1);
        stats.resolutions = stats.resolutions.saturating_add(resolutions);
        stats.descriptor_reads = stats.descriptor_reads.saturating_add(reads);
        stats.requested_bytes = stats.requested_bytes.saturating_add(bytes as u64);
        if success {
            stats.successful_bytes = stats.successful_bytes.saturating_add(bytes as u64);
        }
        stats.declined_fetches = stats.declined_fetches.saturating_add(u64::from(!success));
        self.0.set(stats);
    }
}
