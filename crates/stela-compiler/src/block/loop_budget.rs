//! Invocation-local accounting for the versioned ordinary resident-block ABI.
//! This counter is not a CPU, memory or asynchronous-delivery permission.

pub const RESIDENT_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v2-block-exit-direct-ram-resident-budget-v1";

/// Native code consumes original basic blocks, including internal backedges.
/// The caller retains this exact context until canonical native return.
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

    /// Reject an increased counter and return only actual completed blocks.
    pub fn consumed(self, initial: usize) -> Option<usize> {
        let consumed = (initial as u64).checked_sub(self.remaining)?;
        usize::try_from(consumed).ok()
    }
}

pub(crate) const REMAINING_OFFSET: usize = core::mem::offset_of!(LoopBudget, remaining);
