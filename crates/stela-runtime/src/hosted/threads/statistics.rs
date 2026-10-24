//! Completed-thread diagnostics. Word counts reuse the engine's existing
//! service-exit accounting; no new work is added to a translated hot path.
use crate::machine;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Statistics {
    engine: machine::Statistics,
    words: Option<BTreeMap<u32, u64>>,
}

impl Statistics {
    pub(super) fn new(serviced_words: bool) -> Self {
        Self {
            words: serviced_words.then(BTreeMap::new),
            ..Self::default()
        }
    }

    pub(super) fn record(
        &mut self,
        engine: machine::Statistics,
        words: impl FnOnce() -> BTreeMap<u32, u64>,
    ) {
        self.engine += engine;
        if let Some(total) = &mut self.words {
            for (word, count) in words() {
                let entry = total.entry(word).or_default();
                *entry = entry.saturating_add(count);
            }
        }
    }

    pub(super) fn snapshot(&self) -> (machine::Statistics, BTreeMap<u32, u64>) {
        (self.engine, self.words.clone().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_threads_merge_repeated_words_without_collecting_when_disabled() {
        let mut disabled = Statistics::default();
        disabled.record(machine::Statistics::default(), || {
            panic!("profiling disabled")
        });
        assert!(disabled.snapshot().1.is_empty());

        let mut enabled = Statistics::new(true);
        for (blocks, words) in [
            (7, BTreeMap::from([(0x1e20_2820, 11), (0xd65f_0fff, 3)])),
            (13, BTreeMap::from([(0x1e20_2820, 19), (0xd503_3fdf, 5)])),
        ] {
            enabled.record(
                machine::Statistics {
                    blocks,
                    ..Default::default()
                },
                || words,
            );
        }
        let (engine, words) = enabled.snapshot();
        assert_eq!(engine.blocks, 20);
        assert_eq!(
            words,
            BTreeMap::from([(0x1e20_2820, 30), (0xd65f_0fff, 3), (0xd503_3fdf, 5),])
        );
        assert_eq!(
            enabled.snapshot().1,
            words,
            "snapshot does not drain evidence"
        );
    }
}
