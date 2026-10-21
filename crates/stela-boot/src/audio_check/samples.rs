//! Deterministic PCM and bounded position/descriptor observations.
extern crate alloc;
use alloc::vec::Vec;

pub(crate) const PERIOD_BYTES: usize = 4096;
pub(crate) const PERIODS: usize = 4;
pub(crate) const RING_BYTES: usize = PERIOD_BYTES * PERIODS;
const REQUIRED_WRAPS: u32 = 5;
/// Position observations are evidence of progression, not an exact byte or
/// period count: complete rings can pass between polls. Polling is bounded to
/// less than one ring's duration; excessive gaps fail rather than infer wraps.
#[derive(Default)]
pub(crate) struct Progress {
    previous: u32,
    pub(crate) changes: u32,
    pub(crate) wraps: u32,
    pub(crate) completions: u32,
}

impl Progress {
    pub(crate) fn observe(&mut self, position: u32, completed: bool) {
        self.changes += u32::from(position != self.previous);
        self.wraps += u32::from(position < self.previous);
        self.completions += u32::from(completed);
        self.previous = position;
    }

    pub(crate) fn passed(&self) -> bool {
        self.wraps >= REQUIRED_WRAPS && self.completions >= REQUIRED_WRAPS * PERIODS as u32
    }
}

pub(crate) fn pcm() -> Vec<u8> {
    (0..RING_BYTES / 4)
        .flat_map(|frame| {
            let left = ((frame * 73 + 123) % 20_001) as i16 - 10_000;
            let right = -left;
            let [l0, l1] = left.to_le_bytes();
            let [r0, r1] = right.to_le_bytes();
            [l0, l1, r0, r1]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stagnant_positions_or_completion_bits_do_not_establish_wraps() {
        let mut progress = Progress::default();
        for _ in 0..100 {
            progress.observe(0, true);
        }
        assert!(!progress.passed());
        assert_eq!(progress.wraps, 0);
    }

    #[test]
    fn wraps_require_both_positions_and_descriptor_completion() {
        let mut without_completions = Progress::default();
        for _ in 0..REQUIRED_WRAPS {
            for position in [4096, 8192, 12288, 0] {
                without_completions.observe(position, false);
            }
        }
        assert!(!without_completions.passed());
        let mut progress = Progress::default();
        for _ in 0..REQUIRED_WRAPS {
            for position in [4096, 8192, 12288, 0] {
                progress.observe(position, true);
            }
        }
        assert!(progress.passed());
        assert_eq!(progress.wraps, REQUIRED_WRAPS);
        assert_eq!(pcm().len(), RING_BYTES);
        assert_ne!(&pcm()[..128], &[0; 128]);
    }
}
