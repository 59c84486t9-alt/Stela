use super::*;

#[test]
fn counter_epoch_frequency_and_monotonic_samples_are_explicit() {
    let mut counter = Counter::new();
    let first = counter.sample().unwrap();
    let second = counter.sample().unwrap();
    assert!(second.ticks() >= first.ticks());
    assert_eq!(HOSTED_COUNTER_FREQUENCY, 1_000_000_000);
    assert!(counter.owns(&counter.timer()));
}

#[test]
fn sample_at_threshold_produces_once_consumed_expiration() {
    let mut counter = Counter::new();
    let mut timer = counter.timer();
    let sample = counter.sample().unwrap();
    let _arm = timer.arm(sample.ticks()).unwrap();
    let expiration = timer.poll(&sample).unwrap().unwrap();
    assert_eq!(expiration.observed_ticks(), sample.ticks());
    assert_eq!(timer.requested_sleep(&sample).unwrap(), Duration::ZERO);
    timer.consume(expiration).unwrap();
    assert!(timer.poll(&counter.sample().unwrap()).unwrap().is_none());
}

#[test]
fn cancellation_rearm_and_foreign_epoch_refuse_stale_receipts() {
    let mut counter = Counter::new();
    let mut timer = counter.timer();
    let sample = counter.sample().unwrap();
    let arm = timer.arm(0).unwrap();
    let expired = timer.poll(&sample).unwrap().unwrap();
    timer.cancel(&arm).unwrap();
    let _next = timer.arm(u64::MAX).unwrap();
    assert_eq!(timer.validate(&expired), Err(Error::StaleDeadline));
    assert_eq!(timer.cancel(&arm), Err(Error::StaleDeadline));
    assert!(timer.poll(&counter.sample().unwrap()).unwrap().is_none());
    let mut foreign = Counter::new();
    let foreign_sample = foreign.sample().unwrap();
    assert!(matches!(
        timer.poll(&foreign_sample),
        Err(Error::WrongCounter)
    ));
    assert_eq!(
        timer.requested_sleep(&foreign_sample),
        Err(Error::WrongCounter)
    );
}

#[test]
fn sleep_is_a_request_and_generation_exhaustion_is_transactional() {
    let mut counter = Counter::new();
    let mut timer = counter.timer();
    let _arm = timer.arm(u64::MAX).unwrap();
    assert_eq!(
        timer.requested_sleep(&counter.sample().unwrap()).unwrap(),
        HOSTED_MAX_REQUESTED_SLEEP
    );
    let threshold = timer.threshold;
    timer.generation = u64::MAX;
    assert!(matches!(timer.arm(0), Err(Error::SequenceExhausted)));
    assert_eq!(timer.threshold, threshold);
    counter.previous = u64::MAX;
    assert!(matches!(
        counter.sample(),
        Err(Error::CounterMovedBackwards)
    ));
}
