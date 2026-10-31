//! CPM power-register placement, independently of kept controller state.
//! T8112 `enableThrottler` uses the four common full-width controls and a
//! performance-cluster control. `restoreHW` and CLPC's cluster samplers use
//! the counter block's enable word, and CLPC its two counter banks.
use alloc::vec::Vec;

pub const T8112_OFFSET: u64 = 0x40000;
pub const COUNTER_ENABLE: u64 = 0x40f8;
pub const THROTTLERS: [u64; 4] = [0x250, 0x270, 0x8400, 0x8408];
pub const P_THROTTLER: u64 = 0x8b30;

/// The cluster counter slots, each a count and then its event selector.
const CLUSTER_COUNTERS: u64 = 0x4000;
const CLUSTER_STRIDE: u64 = 0x10;
const CLUSTER_SLOTS: u64 = 8;
/// The uncore counters: both banks of a slot, and the control words.
const UNCORE_COUNTS: u64 = 0x4100;
const UNCORE_COUNT_STRIDE: u64 = 0x10;
const UNCORE_SHADOWS: u64 = 0x4248;
const UNCORE_SLOTS: u64 = 8;
const UNCORE_CONTROL: u64 = 0x4180;
const UNCORE_CONTROLS: u64 = 10;
const WORD: u64 = 8;

/// The complete described register offsets in their established iteration
/// order. Describing a word does not perform or complete its operation.
pub fn offsets(performance: bool) -> Vec<u64> {
    let mut offsets = THROTTLERS.to_vec();
    offsets.push(COUNTER_ENABLE);
    if performance {
        offsets.push(P_THROTTLER);
    }
    for slot in 0..CLUSTER_SLOTS {
        let count = CLUSTER_COUNTERS + slot * CLUSTER_STRIDE;
        offsets.extend([count, count + WORD]);
    }
    for slot in 0..UNCORE_SLOTS {
        offsets.push(UNCORE_COUNTS + slot * UNCORE_COUNT_STRIDE);
        offsets.push(UNCORE_SHADOWS + slot * WORD);
    }
    offsets.extend((0..UNCORE_CONTROLS).map(|word| UNCORE_CONTROL + word * WORD));
    offsets
}
