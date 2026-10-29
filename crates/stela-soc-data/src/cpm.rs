//! CPM power-register placement, independently of kept controller state.
//! T8112 `enableThrottler` uses the four common full-width controls and a
//! performance-cluster control. `restoreHW` uses the separate restore word.
use alloc::vec::Vec;

pub const T8112_OFFSET: u64 = 0x40000;
pub const RESTORE: u64 = 0x40f8;
pub const THROTTLERS: [u64; 4] = [0x250, 0x270, 0x8400, 0x8408];
pub const P_THROTTLER: u64 = 0x8b30;

/// The complete described register offsets in their established iteration
/// order. Describing a word does not perform or complete its operation.
pub fn offsets(performance: bool) -> Vec<u64> {
    let mut offsets = THROTTLERS.to_vec();
    offsets.push(RESTORE);
    if performance {
        offsets.push(P_THROTTLER);
    }
    offsets
}
