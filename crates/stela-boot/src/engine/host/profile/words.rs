//! Bounded space-saving histogram. Frequency bounds apply to the sampled
//! population only; attributed bytes exclude Rust helpers and are not uops.
use stela_engine::machine::engine::NativeInstructionSample;

const CAPACITY: usize = 256;
pub(crate) const TOP: usize = 16;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Ranking {
    Frequency,
    ObservedBytes,
    MaximumBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    Retired,
    FaultAttempt,
    DeferredService,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Weight {
    pub word: u32,
    pub event: Event,
    pub upper: u64,
    pub error: u64,
    /// Bytes observed for this key since its most recent insertion. Unlike
    /// upper/error these do not inherit the evicted key's count or work.
    pub observed_bytes: u64,
    pub max_bytes: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Summary {
    pub bodies: u64,
    pub retired_words: u64,
    pub fault_attempts: u64,
    pub deferred_services: u64,
    pub replacements: u64,
    pub invalid_samples: u64,
    pub dropped_bodies: u64,
    pub wrapper_bytes: u64,
    pub saturated: bool,
    pub registers: RegisterSummary,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RegisterSummary {
    pub covered_retired_words: u64,
    pub uncovered_retired_words: u64,
    /// Included in uncovered_retired_words, not an additional population.
    pub partial_span_words: u64,
    pub traffic: stela_compiler::block::profile::RegisterTraffic,
}

impl RegisterSummary {
    fn capture(
        spans: &[stela_compiler::block::profile::RegisterSpan],
        retired: usize,
        count: usize,
    ) -> Option<Self> {
        let mut summary = Self::default();
        let mut previous_end = 0;
        for span in spans {
            if span.source_start < previous_end
                || span.source_start >= span.source_end
                || span.source_end > count
            {
                return None;
            }
            previous_end = span.source_end;
            if span.source_end <= retired {
                summary.covered_retired_words += (span.source_end - span.source_start) as u64;
                if summary.traffic.accumulate(span.traffic) {
                    return None;
                }
            } else if span.source_start < retired {
                summary.partial_span_words += (retired - span.source_start) as u64;
            }
        }
        summary.uncovered_retired_words = retired as u64 - summary.covered_retired_words;
        Some(summary)
    }

    fn accumulate(&mut self, other: Self) -> bool {
        let mut saturated = self
            .covered_retired_words
            .checked_add(other.covered_retired_words)
            .is_none()
            || self
                .uncovered_retired_words
                .checked_add(other.uncovered_retired_words)
                .is_none()
            || self
                .partial_span_words
                .checked_add(other.partial_span_words)
                .is_none();
        self.covered_retired_words = self
            .covered_retired_words
            .saturating_add(other.covered_retired_words);
        self.uncovered_retired_words = self
            .uncovered_retired_words
            .saturating_add(other.uncovered_retired_words);
        self.partial_span_words = self
            .partial_span_words
            .saturating_add(other.partial_span_words);
        saturated |= self.traffic.accumulate(other.traffic);
        saturated
    }
}

const MAX_WORDS: usize = stela_compiler::block::MAX_BLOCK_INSTRUCTIONS;

/// A small immutable copy made while the actual source owner is borrowed.
/// Histogram searches wait until after the phase End timestamp.
pub(crate) struct Captured {
    words: [u32; MAX_WORDS],
    bytes: [u32; MAX_WORDS],
    end: usize,
    retired: usize,
    faulting: bool,
    deferred: bool,
    wrapper_bytes: u64,
    registers: RegisterSummary,
}

impl Captured {
    pub fn new(sample: NativeInstructionSample<'_>) -> Option<Self> {
        let count = sample.source.len() / 4;
        let retired = usize::try_from(sample.retired).ok();
        let valid = !sample.source.is_empty()
            && sample.source.len().is_multiple_of(4)
            && sample.source_map.len() == count
            && retired.is_some_and(|retired| {
                retired <= count
                    && (!(sample.faulting || sample.deferred_terminal) || retired < count)
                    && (!sample.deferred_terminal || retired + 1 == count)
            })
            && !(sample.faulting && sample.deferred_terminal)
            && sample
                .source_map
                .iter()
                .enumerate()
                .all(|(index, (pc, offset))| {
                    sample.source_map[0].0.0.checked_add(index as u64 * 4) == Some(pc.0)
                        && *offset <= sample.native_bytes
                        && sample
                            .source_map
                            .get(index + 1)
                            .is_none_or(|(_, next)| offset <= next)
                });
        if !valid || count > MAX_WORDS {
            return None;
        }
        let retired = retired.unwrap();
        let end = retired + usize::from(sample.faulting || sample.deferred_terminal);
        let mut captured = Self {
            words: [0; MAX_WORDS],
            bytes: [0; MAX_WORDS],
            end,
            retired,
            faulting: sample.faulting,
            deferred: sample.deferred_terminal,
            wrapper_bytes: sample.source_map[0].1 as u64,
            registers: RegisterSummary::capture(sample.register_spans, retired, count)?,
        };
        for index in 0..end {
            captured.words[index] =
                u32::from_le_bytes(sample.source[index * 4..index * 4 + 4].try_into().ok()?);
            let next = sample
                .source_map
                .get(index + 1)
                .map_or(sample.native_bytes, |(_, at)| *at);
            captured.bytes[index] = u32::try_from(next - sample.source_map[index].1).ok()?;
        }
        Some(captured)
    }
}

pub(crate) struct Histogram {
    entries: [Option<Weight>; CAPACITY],
    pub summary: Summary,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            entries: [None; CAPACITY],
            summary: Summary::default(),
        }
    }
}

impl Histogram {
    fn record(&mut self, word: u32, event: Event, bytes: u64) {
        let existing = self
            .entries
            .iter()
            .position(|slot| slot.is_some_and(|entry| entry.word == word && entry.event == event));
        let index = existing
            .or_else(|| self.entries.iter().position(Option::is_none))
            .unwrap_or_else(|| {
                self.entries
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, slot)| slot.unwrap().upper)
                    .unwrap()
                    .0
            });
        let entry = &mut self.entries[index];
        if existing.is_none() {
            let error = entry.map_or(0, |old| old.upper);
            if entry.is_some() {
                self.summary.replacements = self.summary.replacements.saturating_add(1);
            }
            *entry = Some(Weight {
                word,
                event,
                upper: error,
                error,
                observed_bytes: 0,
                max_bytes: 0,
            });
        }
        let entry = entry.as_mut().unwrap();
        self.summary.saturated |= entry.upper.checked_add(1).is_none()
            || entry.observed_bytes.checked_add(bytes).is_none();
        entry.upper = entry.upper.saturating_add(1);
        entry.observed_bytes = entry.observed_bytes.saturating_add(bytes);
        entry.max_bytes = entry.max_bytes.max(bytes);
    }

    pub fn merge(&mut self, captured: Captured) {
        self.summary.saturated |= self.summary.registers.accumulate(captured.registers);
        self.summary.bodies = self.summary.bodies.saturating_add(1);
        self.summary.retired_words = self
            .summary
            .retired_words
            .saturating_add(captured.retired as u64);
        self.summary.wrapper_bytes = self
            .summary
            .wrapper_bytes
            .saturating_add(captured.wrapper_bytes);
        for index in 0..captured.end {
            let event = if index < captured.retired {
                Event::Retired
            } else if captured.faulting {
                Event::FaultAttempt
            } else {
                Event::DeferredService
            };
            self.record(
                captured.words[index],
                event,
                u64::from(captured.bytes[index]),
            );
        }
        self.summary.fault_attempts = self
            .summary
            .fault_attempts
            .saturating_add(u64::from(captured.faulting));
        self.summary.deferred_services = self
            .summary
            .deferred_services
            .saturating_add(u64::from(captured.deferred));
    }

    #[cfg(test)]
    fn sample(&mut self, sample: NativeInstructionSample<'_>) {
        match Captured::new(sample) {
            Some(captured) => self.merge(captured),
            None => self.summary.invalid_samples = self.summary.invalid_samples.saturating_add(1),
        }
    }

    pub fn top_by(&self, ranking: Ranking) -> [Option<Weight>; TOP] {
        let key = |entry: Weight| match ranking {
            Ranking::Frequency => entry.upper,
            Ranking::ObservedBytes => entry.observed_bytes,
            Ranking::MaximumBytes => entry.max_bytes,
        };
        let mut output: [Option<Weight>; TOP] = [None; TOP];
        for entry in self.entries.iter().flatten() {
            if let Some(index) = output
                .iter()
                .position(|slot| slot.is_none_or(|old| key(old) < key(*entry)))
            {
                output[index..].rotate_right(1);
                output[index] = Some(*entry);
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::GuestAddress;

    #[test]
    fn register_coverage_never_credits_unretired_callbacks_or_partial_integer_spans() {
        use stela_compiler::block::profile::{RegisterRecipe, RegisterSpan, RegisterTraffic};
        let spans = [
            RegisterSpan {
                source_start: 0,
                source_end: 4,
                recipe: RegisterRecipe::Allocated,
                traffic: RegisterTraffic {
                    gpr_frame_loads: 1,
                    gpr_boundary_stores: 1,
                    resident_source_uses: 3,
                    ..Default::default()
                },
            },
            RegisterSpan {
                source_start: 4,
                source_end: 5,
                recipe: RegisterRecipe::ScalarCallback,
                traffic: RegisterTraffic {
                    gpr_frame_loads: 1,
                    gpr_direct_stores: 1,
                    ..Default::default()
                },
            },
        ];
        let partial = RegisterSummary::capture(&spans, 2, 6).unwrap();
        assert_eq!(
            (
                partial.covered_retired_words,
                partial.uncovered_retired_words,
                partial.partial_span_words
            ),
            (0, 2, 2)
        );
        assert_eq!(partial.traffic.gpr_frame_loads, 0);
        let before_callback = RegisterSummary::capture(&spans, 4, 6).unwrap();
        assert_eq!(
            (
                before_callback.covered_retired_words,
                before_callback.uncovered_retired_words
            ),
            (4, 0)
        );
        assert_eq!(before_callback.traffic.gpr_direct_stores, 0);
        let complete = RegisterSummary::capture(&spans, 6, 6).unwrap();
        assert_eq!(
            (
                complete.covered_retired_words,
                complete.uncovered_retired_words
            ),
            (5, 1)
        );
        assert_eq!(
            (
                complete.traffic.gpr_frame_loads,
                complete.traffic.gpr_direct_stores
            ),
            (2, 1)
        );
        let overlap = [
            spans[0],
            RegisterSpan {
                source_start: 3,
                ..spans[1]
            },
        ];
        assert!(RegisterSummary::capture(&overlap, 6, 6).is_none());
        assert!(RegisterSummary::capture(&spans, 6, 4).is_none());
    }

    #[test]
    fn retired_prefix_fault_attempt_and_deferred_service_never_share_retirement_credit() {
        let source = [1u32, 2, 3].map(u32::to_le_bytes).concat();
        let map = [
            (GuestAddress(0x4000), 13),
            (GuestAddress(0x4004), 20),
            (GuestAddress(0x4008), 30),
        ];
        let mut histogram = Histogram::default();
        histogram.sample(NativeInstructionSample {
            source: &source,
            source_map: &map,
            register_spans: &[],
            native_bytes: 40,
            retired: 1,
            faulting: true,
            deferred_terminal: false,
        });
        histogram.sample(NativeInstructionSample {
            source: &source,
            source_map: &map,
            register_spans: &[],
            native_bytes: 40,
            retired: 2,
            faulting: false,
            deferred_terminal: true,
        });
        assert_eq!(histogram.summary.retired_words, 3);
        assert_eq!(
            (
                histogram.summary.fault_attempts,
                histogram.summary.deferred_services
            ),
            (1, 1)
        );
        let rows: alloc::vec::Vec<_> = histogram
            .top_by(Ranking::Frequency)
            .into_iter()
            .flatten()
            .collect();
        let first = rows.iter().find(|r| r.word == 1).unwrap();
        assert_eq!((first.upper, first.error, first.observed_bytes), (2, 0, 14));
        assert_eq!(rows.iter().filter(|r| r.word == 2).count(), 2);
        assert!(
            !rows
                .iter()
                .any(|r| r.word == 3 && r.event == Event::Retired)
        );
    }

    #[test]
    fn replacement_frequency_bounds_hold_without_inheriting_evicted_byte_weights() {
        let mut histogram = Histogram::default();
        for word in 0..CAPACITY as u32 {
            histogram.record(word, Event::Retired, 100);
        }
        histogram.record(999, Event::Retired, 7);
        let row = histogram
            .entries
            .iter()
            .flatten()
            .find(|r| r.word == 999)
            .unwrap();
        assert_eq!(
            (row.upper, row.error, row.observed_bytes, row.max_bytes),
            (2, 1, 7, 7)
        );
        for _ in 0..100 {
            histogram.record(999, Event::Retired, 5);
        }
        let top = histogram.top_by(Ranking::Frequency)[0].unwrap();
        assert_eq!(
            (top.word, top.upper, top.error, top.observed_bytes),
            (999, 102, 1, 507)
        );
        assert_eq!(histogram.summary.replacements, 1);
    }

    #[test]
    fn each_ranking_uses_its_own_weight_and_overflow_is_explicit() {
        let mut histogram = Histogram::default();
        histogram.record(1, Event::Retired, 100);
        for _ in 0..3 {
            histogram.record(2, Event::Retired, 40);
        }
        for _ in 0..5 {
            histogram.record(3, Event::Retired, 1);
        }
        assert_eq!(histogram.top_by(Ranking::Frequency)[0].unwrap().word, 3);
        assert_eq!(histogram.top_by(Ranking::ObservedBytes)[0].unwrap().word, 2);
        assert_eq!(histogram.top_by(Ranking::MaximumBytes)[0].unwrap().word, 1);
        let entry = histogram
            .entries
            .iter_mut()
            .flatten()
            .find(|row| row.word == 1)
            .unwrap();
        entry.upper = u64::MAX;
        entry.observed_bytes = u64::MAX;
        histogram.record(1, Event::Retired, 1);
        assert!(histogram.summary.saturated);
        assert_eq!(
            histogram.top_by(Ranking::Frequency)[0].unwrap().upper,
            u64::MAX
        );
    }

    #[test]
    fn invalid_fault_and_deferred_prefixes_and_unordered_maps_are_rejected() {
        let source = [0; 8];
        let map = [(GuestAddress(0x4000), 3), (GuestAddress(0x4004), 7)];
        let base = NativeInstructionSample {
            source: &source,
            source_map: &map,
            register_spans: &[],
            native_bytes: 12,
            retired: 2,
            faulting: false,
            deferred_terminal: false,
        };
        assert!(Captured::new(base).is_some());
        assert!(
            Captured::new(NativeInstructionSample {
                faulting: true,
                ..base
            })
            .is_none()
        );
        assert!(
            Captured::new(NativeInstructionSample {
                retired: 0,
                deferred_terminal: true,
                ..base
            })
            .is_none()
        );
        assert!(
            Captured::new(NativeInstructionSample {
                retired: 1,
                deferred_terminal: true,
                faulting: true,
                ..base
            })
            .is_none()
        );
        let reversed = [(GuestAddress(0x4000), 7), (GuestAddress(0x4004), 3)];
        assert!(
            Captured::new(NativeInstructionSample {
                source_map: &reversed,
                ..base
            })
            .is_none()
        );
        let wrong_pc = [(GuestAddress(0x4000), 3), (GuestAddress(0x4008), 7)];
        assert!(
            Captured::new(NativeInstructionSample {
                source_map: &wrong_pc,
                ..base
            })
            .is_none()
        );
        assert!(
            Captured::new(NativeInstructionSample {
                register_spans: &[],
                native_bytes: 6,
                ..base
            })
            .is_none()
        );
    }

    #[test]
    fn invalid_source_metadata_changes_no_word_or_body_count() {
        let mut histogram = Histogram::default();
        histogram.sample(NativeInstructionSample {
            source: &[0; 4],
            source_map: &[],
            register_spans: &[],
            native_bytes: 10,
            retired: 1,
            faulting: false,
            deferred_terminal: false,
        });
        assert_eq!(
            (
                histogram.summary.invalid_samples,
                histogram.summary.bodies,
                histogram.summary.retired_words
            ),
            (1, 0, 0)
        );
        assert!(
            histogram
                .top_by(Ranking::Frequency)
                .iter()
                .all(Option::is_none)
        );
    }
}
