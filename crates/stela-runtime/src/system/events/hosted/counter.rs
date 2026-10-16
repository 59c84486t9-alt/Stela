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
mod tests {
    use super::*;
    use crate::system::timer::TimerKind;

    #[test]
    fn read_view_and_deadline_share_epoch_and_frequency() {
        let mut counter = Counter::new();
        let before = counter.sample().unwrap();
        let mut timer = counter.timer();
        let arm = timer.arm(before.ticks()).unwrap();
        let mut view = counter.view();
        assert_eq!(
            view.read(BackendRequest::Frequency(AccessKind::Read))
                .unwrap(),
            super::super::HOSTED_COUNTER_FREQUENCY
        );
        let ticks = view
            .read(BackendRequest::Counter {
                kind: TimerKind::Virtual,
                offset: CounterOffset::None,
                ordering: CounterOrdering::CounterReads,
            })
            .unwrap();
        assert!(ticks >= before.ticks());
        let after = counter.sample().unwrap();
        assert!(after.ticks() >= ticks);
        assert!(timer.poll(&after).unwrap().is_some());
        timer.cancel(&arm).unwrap();
    }

    #[test]
    fn unsupported_reads_never_sample_or_reconfigure_the_counter() {
        let mut counter = Counter::new();
        let previous = counter.previous;
        for request in [
            BackendRequest::Frequency(AccessKind::Write { value: 7 }),
            BackendRequest::Counter {
                kind: TimerKind::Physical,
                offset: CounterOffset::PhysicalEl2,
                ordering: CounterOrdering::CounterReads,
            },
            BackendRequest::Counter {
                kind: TimerKind::Virtual,
                offset: CounterOffset::None,
                ordering: CounterOrdering::SelfSynchronized,
            },
        ] {
            assert_eq!(
                counter.view().read(request),
                Err(CounterReadError::UnsupportedRequest)
            );
            assert_eq!(counter.previous, previous);
        }
    }
}
