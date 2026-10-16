use super::*;

pub(super) fn fixture() -> (
    SoftwareAsyncDomain,
    Vec<WaitSourceKey>,
    hosted::Counter,
    WaitReceiver,
    Vec<LevelProducer>,
) {
    // Test domain for a new software PE.
    let mut domain = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
    let keys = [
        WaitSourceKind::Irq,
        WaitSourceKind::Fiq,
        WaitSourceKind::LocalTimeout,
    ]
    .into_iter()
    .map(|kind| domain.register_wait_source(kind).unwrap())
    .collect::<Vec<_>>();
    let counter = hosted::Counter::new();
    let (receiver, producers) = domain.bind_wait_transport(&keys, &counter).unwrap();
    (domain, keys, counter, receiver, producers)
}

#[test]
fn registration_is_sticky_complete_and_transport_lifetime_is_not_renewable() {
    let (mut domain, keys, counter, receiver, producers) = fixture();
    assert!(matches!(
        domain.lease_no_sources(),
        Err(AsyncError::RegisteredProducer)
    ));
    assert!(matches!(
        domain.bind_wait_transport(&keys, &counter),
        Err(AsyncError::SourceChanged)
    ));
    drop(receiver);
    assert_eq!(producers[0].publish(true), Err(PublishError::Retired));
    assert!(matches!(
        domain.lease_no_sources(),
        Err(AsyncError::RegisteredProducer)
    ));
    assert!(matches!(
        domain.bind_wait_transport(&keys, &counter),
        Err(AsyncError::SourceChanged)
    ));
}

#[test]
fn foreign_keys_receiver_counter_and_incomplete_inventory_refuse() {
    let (mut domain, keys, mut counter, mut receiver, _) = fixture();
    let (_, foreign_keys, mut foreign_counter, mut foreign_receiver, _) = fixture();
    assert!(matches!(
        domain.lease_wait_sources(&foreign_keys, &mut receiver, &mut counter),
        Err(AsyncError::WrongProducer)
    ));
    assert!(matches!(
        domain.lease_wait_sources(&keys[..2], &mut receiver, &mut counter),
        Err(AsyncError::RegisteredProducer)
    ));
    assert!(matches!(
        domain.lease_wait_sources(&keys, &mut foreign_receiver, &mut counter),
        Err(AsyncError::WrongProducer)
    ));
    assert!(matches!(
        domain.lease_wait_sources(&keys, &mut receiver, &mut foreign_counter),
        Err(AsyncError::WrongProducer)
    ));
    let _debug = domain.register_debug().unwrap();
    assert!(matches!(
        domain.lease_wait_sources(&keys, &mut receiver, &mut counter),
        Err(AsyncError::RegisteredProducer)
    ));
}

#[test]
fn assertion_then_deassertion_preserves_wake_without_fabricating_pending_level() {
    let (mut domain, keys, mut counter, mut receiver, producers) = fixture();
    assert_eq!(producers[0].publish(true), Ok(1));
    assert_eq!(producers[0].publish(false), Ok(2));
    let mut sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    let commits = sources.drain_inputs().unwrap();
    assert_eq!(commits[0].generation, 2);
    assert!(!commits[0].level);
    assert!(commits[0].wake);
    assert!(!sources.interrupt_pending().unwrap());
    let wake = sources.wake_observation().unwrap().unwrap();
    sources.settle_wake(wake).unwrap();
    assert!(sources.wake_observation().unwrap().is_none());
    let sequence = sources.domain.next_event;
    sources.drain_inputs().unwrap();
    assert_eq!(sources.domain.next_event, sequence);
}

#[test]
fn publication_between_commit_and_ack_does_not_erase_or_republish() {
    let (mut domain, keys, mut counter, mut receiver, producers) = fixture();
    producers[0].publish(true).unwrap();
    let input = &receiver.inputs[0];
    let sampled = input.wire.state.load(Ordering::Acquire);
    let accepted = commit_input(&mut domain, input, sampled).unwrap().unwrap();
    let original_sequence = domain.next_event;
    producers[0].publish(false).unwrap();
    let committed = acknowledge_input(input, accepted);
    assert_eq!(committed.acknowledgment, Acknowledgment::NewPublication);
    assert_eq!(domain.wait_committed[&input.source], (1, original_sequence));
    let mut sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    let next = sources.drain_inputs().unwrap();
    assert_eq!(next[0].generation, 2);
    assert_eq!(next[0].sequence, original_sequence + 1);
    assert!(next[0].wake);
    sources.drain_inputs().unwrap();
    assert_eq!(sources.domain.next_event, original_sequence + 1);
}

#[test]
fn wake_settlement_preserves_asserted_level_and_refuses_a_new_generation() {
    let (mut domain, keys, mut counter, mut receiver, producers) = fixture();
    producers[0].publish(true).unwrap();
    let mut sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    sources.drain_inputs().unwrap();
    let stale = sources.wake_observation().unwrap().unwrap();
    producers[0].publish(true).unwrap();
    sources.drain_inputs().unwrap();
    assert_eq!(sources.settle_wake(stale), Err(AsyncError::SourceChanged));
    let wake = sources.wake_observation().unwrap().unwrap();
    sources.settle_wake(wake).unwrap();
    assert!(sources.interrupt_pending().unwrap());
}

#[test]
fn deadline_commit_cannot_be_canceled_or_consumed_twice() {
    let (mut domain, keys, mut counter, mut receiver, _) = fixture();
    let mut sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    let arm = sources.arm_deadline(0).unwrap();
    let sample = sources.sample_counter().unwrap();
    let commit = sources.commit_deadline(&sample).unwrap().unwrap();
    assert!(matches!(
        sources.cancel_deadline(&arm),
        Err(WaitError::Domain(AsyncError::PendingEvent))
    ));
    assert!(matches!(
        sources.commit_deadline(&sample),
        Err(WaitError::Domain(AsyncError::PendingEvent))
    ));
    sources.settle_deadline(commit).unwrap();
    let sample = sources.sample_counter().unwrap();
    assert!(sources.commit_deadline(&sample).unwrap().is_none());
}

#[test]
fn wire_and_domain_sequence_exhaustion_do_not_acknowledge_input() {
    let (mut domain, keys, mut counter, mut receiver, producers) = fixture();
    receiver.inputs[0]
        .wire
        .state
        .store(MAX_GENERATION << GENERATION_SHIFT, Ordering::Release);
    assert_eq!(
        producers[0].publish(true),
        Err(PublishError::SequenceExhausted)
    );
    receiver.inputs[0]
        .wire
        .state
        .store((1 << GENERATION_SHIFT) | LEVEL | WAKE, Ordering::Release);
    domain.next_event = u64::MAX;
    let mut sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    assert!(matches!(
        sources.drain_inputs(),
        Err(AsyncError::SequenceExhausted)
    ));
    assert_eq!(
        sources.receiver.inputs[0]
            .wire
            .state
            .load(Ordering::Acquire)
            & WAKE,
        WAKE
    );
    assert!(sources.domain.pending.is_empty());
    assert_eq!(sources.domain.wait_committed[&keys[0].key.id], (0, 0));
}
