//! Read-only view of the hosted system counter used by WFx deadlines.
//! Access and trap checks belong to `timer::resolve`.
use super::{Counter, Error};
use crate::system::{
    access::AccessKind,
    timer::{BackendRequest, CounterOffset, CounterOrdering},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CounterReadError {
    UnsupportedRequest,
    Counter(Error),
}

/// Borrowed counter view; callers cannot supply ticks, frequency or an epoch.
pub(crate) struct CounterView<'source> {
    counter: &'source mut Counter,
}
impl<'source> CounterView<'source> {
    pub(super) fn borrowed(counter: &'source mut Counter) -> Self {
        Self { counter }
    }

    /// Serve a resolved backend request. The caller must resolve architectural
    /// access before sampling, including for an XZR destination.
    pub(crate) fn read(&mut self, request: BackendRequest) -> Result<u64, CounterReadError> {
        match request {
            BackendRequest::Frequency(AccessKind::Read) => Ok(self.counter.frequency()),
            BackendRequest::Counter {
                offset: CounterOffset::None,
                ordering: CounterOrdering::CounterReads,
                ..
            } => self
                .counter
                .sample()
                .map(|sample| sample.ticks())
                .map_err(CounterReadError::Counter),
            // This profile has no EL2 offset, ECV self-synchronization, writable
            // frequency or CNTKCTL, timer registers or NV2 memory.
            _ => Err(CounterReadError::UnsupportedRequest),
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests;
