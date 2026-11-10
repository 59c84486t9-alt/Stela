//! Where retired command buffers' time went, from their GPU timestamps.
//!
//! A command buffer's latency, from its commit until the device saw it
//! complete, is the wait for the GPU to start it, the GPU's own time, and the
//! wait until the device looked. Its timestamps give the GPU's time on the GPU
//! clock; a calibration now and then maps that clock to the platform's ticks,
//! which the commit and the look are timed in, so the other two can be told
//! apart. The report says which one a slow screen waits on.
use alloc::{string::String, vec::Vec};

/// Retirements between calibrations of the GPU clock.
const CALIBRATE_EVERY: u32 = 32;

/// The retired command buffers' times since the last report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GpuTimes {
    /// Command buffers retired with timestamps.
    pub timed: u64,
    /// Their GPU time, start to end, in GPU nanoseconds.
    pub busy_ns: u64,
    pub longest_ns: u64,
    /// GPU nanoseconds between one command buffer's end and the next one's
    /// start, when the next started later.
    pub idle_ns: u64,
    /// GPU nanoseconds command buffers overlapped the one before.
    pub overlap_ns: u64,
    /// Command buffers whose start and end the calibration placed in the
    /// platform's ticks, and for them: ticks from commit to the GPU's start,
    /// and from the GPU's end until the device saw it complete.
    pub placed: u64,
    pub queued_ticks: u64,
    pub longest_queued_ticks: u64,
    pub noticed_ticks: u64,
    pub longest_noticed_ticks: u64,
    /// Committed command buffers that wait on an event.
    pub waiting: u64,
    /// The longest command buffer's serial and its pipelines' entry points.
    pub longest_serial: u64,
    pub longest_entries: String,
    /// The longest span between two of a command buffer's marks (its start,
    /// the ends of its first passes and dispatches, its end): GPU
    /// nanoseconds, the command buffer, the span's index among its spans,
    /// and the entry points of the pipelines it bound.
    pub span_ns: u64,
    pub span_serial: u64,
    pub span_index: usize,
    pub span_count: usize,
    pub span_entries: String,
}

/// Entry points without their function constants, each once.
pub(super) fn names(entries: impl IntoIterator<Item = String>) -> String {
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        // A bracketed note, such as a span's shape, stays whole.
        let name = if entry.starts_with('[') {
            entry.as_str()
        } else {
            entry.split('[').next().unwrap_or_default()
        };
        if !names.iter().any(|seen| seen == name) {
            names.push(String::from(name));
        }
    }
    names.join("+")
}

/// One reading of both clocks: platform ticks, GPU nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Reading {
    ticks: u64,
    gpu_ns: u64,
}

/// The GPU clock against the platform's, and what is counted for the report.
#[derive(Debug, Default)]
pub(super) struct GpuClock {
    first: Option<Reading>,
    last: Option<Reading>,
    /// Retirements since the last reading.
    since: u32,
    /// The device cannot read both clocks at once.
    unavailable: bool,
    /// The newest retired command buffer's end, in GPU nanoseconds.
    previous_end: Option<u64>,
    times: GpuTimes,
}

impl GpuClock {
    /// Whether a new reading is due before more retirements are placed.
    pub(super) fn due(&self) -> bool {
        !self.unavailable && (self.last.is_none() || self.since >= CALIBRATE_EVERY)
    }

    /// Notes a reading of both clocks: `before` and `after` bracket the read.
    pub(super) fn calibrate(&mut self, before: u64, after: u64, gpu_ns: u64) {
        let reading = Reading {
            ticks: before + after.wrapping_sub(before) / 2,
            gpu_ns,
        };
        self.first.get_or_insert(reading);
        self.last = Some(reading);
        self.since = 0;
    }

    pub(super) fn disable(&mut self) {
        self.unavailable = true;
    }

    /// Platform ticks at GPU time `gpu_ns`, once two readings are far enough
    /// apart to give the rate.
    fn ticks_at(&self, gpu_ns: u64) -> Option<u64> {
        let (first, last) = (self.first?, self.last?);
        let span_ns = last.gpu_ns.checked_sub(first.gpu_ns)?;
        // A tenth of a second keeps a reading's error well below a percent.
        if span_ns < 100_000_000 {
            return None;
        }
        let span_ticks = i128::from(last.ticks.wrapping_sub(first.ticks));
        let offset = i128::from(gpu_ns) - i128::from(last.gpu_ns);
        let ticks = i128::from(last.ticks) + offset * span_ticks / i128::from(span_ns);
        u64::try_from(ticks).ok()
    }

    /// Counts a committed command buffer that waits on an event.
    pub(super) fn waits(&mut self) {
        self.times.waiting += 1;
    }

    /// Counts a retired command buffer: committed at `committed` and seen
    /// complete at `seen`, platform ticks, run from `start` to `end`, GPU
    /// nanoseconds. `entries` names its pipelines when it is the longest;
    /// `spans` are the GPU nanoseconds between its marks with the entry
    /// points each span bound.
    pub(super) fn retire(
        &mut self,
        serial: u64,
        committed: u64,
        seen: u64,
        [start, end]: [u64; 2],
        entries: impl FnOnce() -> Vec<String>,
        spans: impl ExactSizeIterator<Item = (u64, Vec<String>)>,
    ) {
        let count = spans.len();
        for (index, (took, entries)) in spans.enumerate() {
            let times = &mut self.times;
            if took > times.span_ns {
                times.span_ns = took;
                times.span_serial = serial;
                times.span_index = index;
                times.span_count = count;
                times.span_entries = names(entries);
            }
        }
        self.since = self.since.saturating_add(1);
        let times = &mut self.times;
        let busy = end.saturating_sub(start);
        times.timed += 1;
        times.busy_ns += busy;
        if busy > times.longest_ns {
            times.longest_ns = busy;
            times.longest_serial = serial;
            times.longest_entries = names(entries());
        }
        if let Some(previous) = self.previous_end {
            if start >= previous {
                times.idle_ns += start - previous;
            } else {
                times.overlap_ns += previous - start;
            }
        }
        self.previous_end = Some(self.previous_end.map_or(end, |previous| previous.max(end)));
        let (Some(started), Some(ended)) = (self.ticks_at(start), self.ticks_at(end)) else {
            return;
        };
        let times = &mut self.times;
        let queued = started.saturating_sub(committed);
        let noticed = seen.saturating_sub(ended);
        times.placed += 1;
        times.queued_ticks += queued;
        times.longest_queued_ticks = times.longest_queued_ticks.max(queued);
        times.noticed_ticks += noticed;
        times.longest_noticed_ticks = times.longest_noticed_ticks.max(noticed);
    }

    /// What was counted since the last call.
    pub(super) fn take(&mut self) -> GpuTimes {
        core::mem::take(&mut self.times)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn splits_latency_into_queue_gpu_and_notice() {
        let mut clock = GpuClock::default();
        assert!(clock.due());
        // Two ticks per GPU nanosecond, GPU time 1000 at tick 5000.
        clock.calibrate(4_990, 5_010, 1_000);
        clock.calibrate(400_004_990, 400_005_010, 200_001_000);
        // Committed at tick 400_005_000 (GPU 200_001_000); started 10 ns
        // later, ran 100 ns; seen 30 ticks after its end.
        clock.retire(
            7,
            400_005_000,
            400_005_250,
            [200_001_010, 200_001_110],
            || {
                vec![
                    String::from("a[1=00]"),
                    String::from("b"),
                    String::from("a[1=01]"),
                ]
            },
            vec![
                (30, vec![String::from("a[1=00]")]),
                (
                    70,
                    vec![
                        String::from("b"),
                        String::from("c[2=01]"),
                        String::from("[8x8 draws=1]"),
                    ],
                ),
            ]
            .into_iter(),
        );
        let times = clock.take();
        assert_eq!(times.timed, 1);
        assert_eq!(times.busy_ns, 100);
        assert_eq!(times.longest_entries, "a+b");
        assert_eq!(times.placed, 1);
        assert_eq!(times.queued_ticks, 20);
        assert_eq!(times.noticed_ticks, 30);
        assert_eq!(times.span_ns, 70);
        assert_eq!((times.span_index, times.span_count), (1, 2));
        assert_eq!(times.span_entries, "b+c+[8x8 draws=1]");
        assert_eq!(clock.take(), GpuTimes::default());
    }

    #[test]
    fn counts_gaps_and_overlaps_between_command_buffers() {
        let mut clock = GpuClock::default();
        clock.retire(1, 0, 0, [100, 200], Vec::new, core::iter::empty());
        clock.retire(2, 0, 0, [250, 300], Vec::new, core::iter::empty());
        clock.retire(3, 0, 0, [280, 400], Vec::new, core::iter::empty());
        let times = clock.take();
        assert_eq!(times.idle_ns, 50);
        assert_eq!(times.overlap_ns, 20);
        assert_eq!(times.busy_ns, 270);
        assert_eq!(times.longest_serial, 3);
        // Without two readings nothing is placed.
        assert_eq!(times.placed, 0);
    }
}
