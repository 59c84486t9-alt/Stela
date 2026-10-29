//! Rejection-only quarantine of one canonical Machine execution domain.
//! The first raw failure is held before low-level recovery releases a frame.
use crate::{
    machine::{NativeCode, NativeFault},
    platform::sync::Mutex,
};
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::machine::engine) struct FailureCapture {
    pub pe: usize,
    pub pc: u64,
    pub retired: u64,
    pub code: NativeCode,
    pub fault: NativeFault,
}
/// Created only with Machine's real canonical-memory identity. No public
/// constructor, capture setter or replacement token grants execution permission.
pub(in crate::machine::engine) struct ExecutionDomain {
    rejected: AtomicBool,
    first: Mutex<Option<FailureCapture>>,
}
impl core::fmt::Debug for ExecutionDomain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExecutionDomain")
            .field("quarantined", &self.quarantined())
            .finish_non_exhaustive()
    }
}
impl ExecutionDomain {
    pub(in crate::machine::engine) fn new() -> Self {
        Self {
            rejected: AtomicBool::new(false),
            first: Mutex::new(None),
        }
    }
    pub(in crate::machine::engine) fn quarantined(&self) -> bool {
        self.rejected.load(Ordering::Acquire)
    }
    pub(in crate::machine::engine) fn record(&self, capture: FailureCapture) {
        // Process/dispatcher context only, never an ISR. No callbacks or other
        // locks are acquired while this bounded fixed-record copy is held.
        let mut first = self.first.lock().unwrap_or_else(|error| error.into_inner());
        if first.is_none() {
            *first = Some(capture);
        }
        // Release before any returned payload can be recovered/reused. A reader
        // observing rejection sees an initialized first record, never a gap.
        self.rejected.store(true, Ordering::Release);
    }
    pub(in crate::machine::engine) fn failure(&self) -> Option<FailureCapture> {
        if !self.quarantined() {
            return None;
        }
        *self.first.lock().unwrap_or_else(|error| error.into_inner())
    }
}
