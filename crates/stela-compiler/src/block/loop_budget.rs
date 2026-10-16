//! Per-invocation iteration budget for resident blocks.

pub const RESIDENT_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v2-block-exit-direct-ram-resident-budget-v1";

/// Native code counts the basic blocks it completes, including internal back
/// edges. The caller keeps this context alive until native return.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopBudget {
    remaining: u64,
}

impl LoopBudget {
    pub const fn new(remaining: usize) -> Self {
        Self {
            remaining: remaining as u64,
        }
    }

    pub const fn remaining(self) -> u64 {
        self.remaining
    }

    /// Reject a counter that increased, and return the number of completed
    /// blocks.
    pub fn consumed(self, initial: usize) -> Option<usize> {
        let consumed = (initial as u64).checked_sub(self.remaining)?;
        usize::try_from(consumed).ok()
    }
}

pub(crate) const REMAINING_OFFSET: usize = core::mem::offset_of!(LoopBudget, remaining);
