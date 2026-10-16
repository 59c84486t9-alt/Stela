//! The hosted system counter and the generation-bound WFx timeout. These
//! are separate from the Darwin clock and commpage and from ARM timers.
use alloc::sync::Arc;
use core::time::Duration;
#[cfg(feature = "std")]
use std::time::Instant;

mod counter;
pub(crate) use counter::CounterView;

pub(crate) const HOSTED_COUNTER_FREQUENCY: u64 = 1_000_000_000;
/// Requested sleep only; the host may return later.
pub(crate) const HOSTED_MAX_REQUESTED_SLEEP: Duration = Duration::from_millis(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    #[cfg(feature = "std")]
    CounterMovedBackwards,
    #[cfg(feature = "std")]
    CounterExhausted,
    WrongCounter,
    StaleDeadline,
    SequenceExhausted,
    #[cfg(not(feature = "std"))]
    PlatformUnavailable,
}

#[cfg(feature = "std")]
#[derive(Debug)]
struct Epoch {
    start: Instant,
}
// No epoch or clock exists without the host adapter.
#[cfg(not(feature = "std"))]
type Epoch = core::convert::Infallible;

/// Owns the counter epoch; snapshots and timer handles cannot create one.
#[derive(Debug)]
pub(crate) struct Counter {
    epoch: Arc<Epoch>,
    #[cfg(feature = "std")]
    previous: u64,
}

#[derive(Debug)]
pub(crate) struct Sample {
    epoch: Arc<Epoch>,
    ticks: u64,
}

impl Sample {
    pub(crate) fn ticks(&self) -> u64 {
        self.ticks
    }
}

impl Counter {
    #[cfg(feature = "std")]
    pub(crate) fn new() -> Self {
        Self {
            epoch: Arc::new(Epoch {
                start: Instant::now(),
            }),
            previous: 0,
        }
    }
    pub(crate) fn frequency(&self) -> u64 {
        HOSTED_COUNTER_FREQUENCY
    }
    pub(crate) fn sample(&mut self) -> Result<Sample, Error> {
        #[cfg(not(feature = "std"))]
        {
            Err(Error::PlatformUnavailable)
        }
        #[cfg(feature = "std")]
        {
            let duration = Instant::now()
                .checked_duration_since(self.epoch.start)
                .ok_or(Error::CounterMovedBackwards)?;
            let ticks = u64::try_from(duration.as_nanos()).map_err(|_| Error::CounterExhausted)?;
            if ticks < self.previous {
                return Err(Error::CounterMovedBackwards);
            }
            self.previous = ticks;
            Ok(Sample {
                epoch: Arc::clone(&self.epoch),
                ticks,
            })
        }
    }

    pub(crate) fn view(&mut self) -> CounterView<'_> {
        CounterView::borrowed(self)
    }
    #[cfg(feature = "std")]
    pub(crate) fn timer(&self) -> LocalTimer {
        LocalTimer {
            identity: Arc::new(()),
            epoch: Arc::clone(&self.epoch),
            generation: 0,
            threshold: None,
        }
    }
    pub(crate) fn owns(&self, timer: &LocalTimer) -> bool {
        Arc::ptr_eq(&self.epoch, &timer.epoch)
    }
}

#[derive(Debug)]
pub(crate) struct LocalTimer {
    identity: Arc<()>,
    epoch: Arc<Epoch>,
    generation: u64,
    threshold: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct Arm {
    timer: Arc<()>,
    epoch: Arc<Epoch>,
    generation: u64,
    threshold: u64,
}

#[derive(Debug)]
pub(crate) struct Expiration {
    timer: Arc<()>,
    epoch: Arc<Epoch>,
    generation: u64,
    threshold: u64,
    observed_ticks: u64,
}

impl Expiration {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn observed_ticks(&self) -> u64 {
        self.observed_ticks
    }
}

impl LocalTimer {
    pub(crate) fn arm(&mut self, threshold: u64) -> Result<Arm, Error> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        self.generation = generation;
        self.threshold = Some(threshold);
        Ok(Arm {
            timer: Arc::clone(&self.identity),
            epoch: Arc::clone(&self.epoch),
            generation,
            threshold,
        })
    }
    pub(crate) fn cancel(&mut self, arm: &Arm) -> Result<(), Error> {
        if !Arc::ptr_eq(&arm.timer, &self.identity)
            || !Arc::ptr_eq(&arm.epoch, &self.epoch)
            || arm.generation != self.generation
            || self.threshold != Some(arm.threshold)
        {
            return Err(Error::StaleDeadline);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        self.generation = generation;
        self.threshold = None;
        Ok(())
    }
    pub(crate) fn poll(&self, sample: &Sample) -> Result<Option<Expiration>, Error> {
        if !Arc::ptr_eq(&sample.epoch, &self.epoch) {
            return Err(Error::WrongCounter);
        }
        Ok(self
            .threshold
            .filter(|threshold| sample.ticks >= *threshold)
            .map(|threshold| Expiration {
                timer: Arc::clone(&self.identity),
                epoch: Arc::clone(&self.epoch),
                generation: self.generation,
                threshold,
                observed_ticks: sample.ticks,
            }))
    }
    pub(crate) fn validate(&self, expiration: &Expiration) -> Result<(), Error> {
        if !Arc::ptr_eq(&expiration.timer, &self.identity)
            || !Arc::ptr_eq(&expiration.epoch, &self.epoch)
            || expiration.generation != self.generation
            || self.threshold != Some(expiration.threshold)
            || expiration.observed_ticks < expiration.threshold
        {
            return Err(Error::StaleDeadline);
        }
        // Reserve the consume generation before the domain commit.
        self.generation
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        Ok(())
    }
    pub(crate) fn consume(&mut self, expiration: Expiration) -> Result<(), Error> {
        self.validate(&expiration)?;
        self.generation += 1;
        self.threshold = None;
        Ok(())
    }
    /// The consumer decides when to suspend. A poll timeout is not a wake and
    /// must always be followed by re-checks.
    pub(crate) fn requested_sleep(&self, sample: &Sample) -> Result<Duration, Error> {
        if !Arc::ptr_eq(&sample.epoch, &self.epoch) {
            return Err(Error::WrongCounter);
        }
        Ok(self
            .threshold
            .map_or(HOSTED_MAX_REQUESTED_SLEEP, |threshold| {
                Duration::from_nanos(threshold.saturating_sub(sample.ticks))
                    .min(HOSTED_MAX_REQUESTED_SLEEP)
            }))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
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
}
