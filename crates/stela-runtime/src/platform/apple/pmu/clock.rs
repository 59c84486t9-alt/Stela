//! One declared PMIC upcount owner shared by its SPMI and SMC interfaces.
use super::RTC_HZ;
use crate::platform::apple::counter::FREQUENCY_HZ;
use alloc::rc::Rc;
use core::cell::Cell;

const LIMIT: u64 = 1 << 47;

/// Declared emulated resource origin, not an observed Apple reset value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcEpoch {
    pub counter: u64,
    pub ticks: u64,
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    counter: u64,
    ticks: u64,
}
#[derive(Debug)]
struct Clock {
    epoch: RtcEpoch,
    sample: Cell<Option<Sample>>,
}

/// Retained ownership of one PMIC oscillator/epoch. Clones refer to the same
/// publication; no interface owns another wall clock or a default sample.
#[derive(Debug, Clone)]
pub struct RtcClock(Rc<Clock>);
impl RtcClock {
    pub fn new(epoch: RtcEpoch) -> Result<Self, &'static str> {
        if epoch.ticks >= LIMIT {
            return Err("PMU RTC epoch exceeds the qualified 47-bit upcount");
        }
        let remaining = counter_ticks(LIMIT - epoch.ticks);
        if epoch.counter.checked_add(remaining).is_none() {
            return Err("PMU RTC epoch cannot represent its qualified counter horizon");
        }
        Ok(Self(Rc::new(Clock {
            epoch,
            sample: Cell::new(None),
        })))
    }

    /// Check an actual Access.now without publishing or changing any owner.
    pub fn check(&self, now: u64) -> Result<u64, &'static str> {
        if self
            .0
            .sample
            .get()
            .is_some_and(|sample| now < sample.counter)
        {
            return Err("PMU RTC counter publication moved backwards");
        }
        let elapsed = now
            .checked_sub(self.0.epoch.counter)
            .ok_or("PMU RTC counter precedes its declared epoch")?;
        let elapsed = u128::from(elapsed) * u128::from(RTC_HZ) / u128::from(FREQUENCY_HZ);
        let ticks = u128::from(self.0.epoch.ticks) + elapsed;
        if ticks >= u128::from(LIMIT) {
            return Err("PMU RTC upcount/alarm wrap behavior is unqualified");
        }
        Ok(ticks as u64)
    }

    /// Board service boundary publication, before ASC receive/poll effects.
    /// Refusal preserves the previous sample. This is model time ownership,
    /// never authority to execute on a host worker.
    pub fn publish(&self, now: u64) -> Result<(), &'static str> {
        let ticks = self.check(now)?;
        self.0.sample.set(Some(Sample {
            counter: now,
            ticks,
        }));
        Ok(())
    }

    /// SMC reads the same published upcount. Missing publication must stop the
    /// service; it cannot be replaced with a successful zero-valued read.
    pub fn published_ticks(&self) -> Result<u64, &'static str> {
        self.0
            .sample
            .get()
            .map(|sample| sample.ticks)
            .ok_or("PMU RTC has no actual counter publication")
    }

    /// First counter at which the oscillator reaches a tick in this epoch.
    /// None denotes a tick already elapsed before the supplied epoch.
    pub(super) fn counter_for(&self, ticks: u64) -> Option<u64> {
        if ticks >= LIMIT {
            return None;
        }
        let elapsed = ticks.checked_sub(self.0.epoch.ticks)?;
        self.0.epoch.counter.checked_add(counter_ticks(elapsed))
    }
}

fn counter_ticks(ticks: u64) -> u64 {
    (u128::from(ticks) * u128::from(FREQUENCY_HZ)).div_ceil(u128::from(RTC_HZ)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_epoch_is_shared_and_has_no_implicit_sample() {
        let clock = RtcClock::new(RtcEpoch {
            counter: 240,
            ticks: 1234,
        })
        .unwrap();
        let smc = clock.clone();
        assert!(smc.published_ticks().is_err());
        clock.publish(240 + FREQUENCY_HZ).unwrap();
        assert_eq!(smc.published_ticks(), Ok(1234 + RTC_HZ));
        assert!(clock.publish(239).is_err());
        assert!(clock.publish(240).is_err());
        assert_eq!(smc.published_ticks(), Ok(1234 + RTC_HZ));
        smc.publish(240 + FREQUENCY_HZ).unwrap();
        assert_eq!(clock.published_ticks(), Ok(1234 + RTC_HZ));
    }
    #[test]
    fn deadlines_round_up_and_tick_epoch_overflow_refuses_atomically() {
        let clock = RtcClock::new(RtcEpoch {
            counter: 17,
            ticks: LIMIT - 2,
        })
        .unwrap();
        assert_eq!(clock.counter_for(LIMIT - 3), None);
        assert_eq!(clock.counter_for(LIMIT - 2), Some(17));
        let deadline = clock.counter_for(LIMIT - 1).unwrap();
        assert_eq!(clock.check(deadline - 1), Ok(LIMIT - 2));
        assert_eq!(clock.check(deadline), Ok(LIMIT - 1));
        clock.publish(deadline).unwrap();
        assert!(clock.publish(17 + counter_ticks(2)).is_err());
        assert_eq!(clock.published_ticks(), Ok(LIMIT - 1));
        assert_eq!(clock.counter_for(LIMIT), None);
        assert!(
            RtcClock::new(RtcEpoch {
                counter: 0,
                ticks: LIMIT
            })
            .is_err()
        );
        assert!(
            RtcClock::new(RtcEpoch {
                counter: u64::MAX,
                ticks: 0
            })
            .is_err()
        );
    }
}
