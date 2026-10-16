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
