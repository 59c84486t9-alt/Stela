// SPDX-License-Identifier: GPL-2.0-only
//! Fail-sticky arithmetic for a single counter/control observation stream.
//! This is model data, not a CPU lease, calibrated clock or watchdog. The native
//! owner must supply ordered samples from its CPU, establish
//! rate/reference reliability and service any required reference watchdog. A
//! successful comparison never proves reference identity or time continuity.
use super::{Error, RateWindow, RationalRate};

#[derive(Debug, PartialEq, Eq)]
pub struct CounterSequence {
    rate: RationalRate,
    initial: u64,
    previous: u64,
    adjustment: Option<u64>,
    elapsed_ns: u64,
    failure: Option<Error>,
}
impl CounterSequence {
    /// Start at zero elapsed time. `adjustment` is the observed control
    /// when supported; absence is not a substitute for a reference watchdog.
    pub fn new(rate: RationalRate, initial: u64, adjustment: Option<u64>) -> Result<Self, Error> {
        rate.hz()?;
        Ok(Self {
            rate,
            initial,
            previous: initial,
            adjustment,
            elapsed_ns: 0,
            failure: None,
        })
    }
    /// Preserve the first failure permanently. Neither a later good sample nor
    /// restoring the old adjustment can repair an invalidated stream.
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        let first = *self.failure.get_or_insert(error);
        Err(first)
    }
    pub fn elapsed_ns(&self) -> Result<u64, Error> {
        self.failure.map_or(Ok(self.elapsed_ns), Err)
    }
    /// Accept equal timestamps (two ordered reads need not cross a tick), but
    /// refuse backwards time or any missing/changed adjustment observation.
    /// Convert total ticks once to avoid per-sample truncation drift. Failed
    /// samples publish neither a new raw counter nor an elapsed value.
    pub fn observe(&mut self, raw: u64, adjustment: Option<u64>) -> Result<u64, Error> {
        self.elapsed_ns()?;
        if adjustment != self.adjustment {
            return self.fail(if adjustment.is_none() && self.adjustment.is_some() {
                Error::MissingMsr(0x3b)
            } else {
                Error::AdjustmentChanged
            });
        }
        if raw < self.previous {
            return self.fail(Error::Backwards);
        }
        let ticks = raw - self.initial;
        let elapsed_ns = match self.rate.nanoseconds(ticks) {
            Ok(value) => value,
            Err(error) => return self.fail(error),
        };
        self.previous = raw;
        self.elapsed_ns = elapsed_ns;
        Ok(elapsed_ns)
    }
    /// Validate a separately obtained rate window against the kept
    /// rational rate. This comparison does not attest that the reference sample
    /// was timely, continuous, independent or from the same source.
    pub fn compare_reference(&mut self, observed: RateWindow) -> Result<(), Error> {
        self.elapsed_ns()?;
        if !observed.contains_rate(self.rate) {
            return self.fail(Error::InconsistentRate);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tsc::{ReferenceScale, Sample};
    fn sequence() -> CounterSequence {
        CounterSequence::new(RationalRate::new(3, 1).unwrap(), 7, Some(17)).unwrap()
    }
    fn window(minimum: u64, maximum: u64) -> RateWindow {
        RateWindow::from_samples(
            Sample {
                tsc_before: 0,
                reference: 0,
                tsc_after: maximum - minimum,
            },
            Sample {
                tsc_before: maximum,
                reference: 1,
                tsc_after: maximum,
            },
            u64::MAX,
            ReferenceScale::Hertz(1),
            maximum - minimum + 1,
        )
        .unwrap()
    }
    #[test]
    fn total_ticks_avoid_rounding_drift_and_equal_samples_are_valid() {
        let mut stream = sequence();
        assert_eq!(stream.observe(7, Some(17)), Ok(0));
        assert_eq!(stream.observe(8, Some(17)), Ok(333_333_333));
        assert_eq!(stream.observe(9, Some(17)), Ok(666_666_666));
        assert_eq!(stream.observe(10, Some(17)), Ok(1_000_000_000));
        assert_eq!(stream.elapsed_ns(), Ok(1_000_000_000));
    }
    #[test]
    fn adjustment_change_missing_observation_and_backwards_time_are_sticky() {
        let mut stream = sequence();
        stream.observe(10, Some(17)).unwrap();
        assert_eq!(stream.observe(11, Some(18)), Err(Error::AdjustmentChanged));
        assert_eq!(stream.observe(12, Some(17)), Err(Error::AdjustmentChanged));
        assert_eq!(stream.elapsed_ns(), Err(Error::AdjustmentChanged));
        assert_eq!(stream.previous, 10);
        assert_eq!(stream.elapsed_ns, 1_000_000_000);
        assert_eq!(
            stream.compare_reference(window(3, 3)),
            Err(Error::AdjustmentChanged)
        );
        let mut stream = sequence();
        assert_eq!(stream.observe(8, None), Err(Error::MissingMsr(0x3b)));
        assert_eq!(stream.observe(8, Some(17)), Err(Error::MissingMsr(0x3b)));
        let mut stream = sequence();
        assert_eq!(stream.observe(6, Some(17)), Err(Error::Backwards));
        assert_eq!(stream.observe(9, Some(17)), Err(Error::Backwards));
        let mut absent = CounterSequence::new(RationalRate::new(3, 1).unwrap(), 0, None).unwrap();
        assert_eq!(absent.observe(1, Some(0)), Err(Error::AdjustmentChanged));
    }
    #[test]
    fn exact_rate_comparison_rejects_rounded_boundary_and_keeps_first_failure() {
        let exact = window(3, 3);
        assert!(exact.contains_rate(RationalRate::new(3, 1).unwrap()));
        assert!(!exact.contains_rate(RationalRate::new(7, 2).unwrap()));
        assert!(!exact.contains_rate(RationalRate::new(5, 2).unwrap()));
        assert!(window(2, 4).contains_rate(RationalRate::new(7, 2).unwrap()));
        let mut stream = sequence();
        assert_eq!(stream.compare_reference(exact), Ok(()));
        assert_eq!(
            stream.compare_reference(window(4, 4)),
            Err(Error::InconsistentRate)
        );
        assert_eq!(stream.observe(6, Some(18)), Err(Error::InconsistentRate));
        assert_eq!(stream.previous, 7);
        assert_eq!(stream.elapsed_ns, 0);
    }
    #[test]
    fn elapsed_overflow_poisoning_publishes_no_partial_sample() {
        let mut stream = CounterSequence::new(RationalRate::new(1, 1).unwrap(), 0, None).unwrap();
        stream.observe(1, None).unwrap();
        assert_eq!(stream.observe(u64::MAX, None), Err(Error::Overflow));
        assert_eq!(stream.observe(2, None), Err(Error::Overflow));
        assert_eq!(stream.previous, 1);
        assert_eq!(stream.elapsed_ns, 1_000_000_000);
        assert_eq!(
            CounterSequence::new(RationalRate::new(1, 2).unwrap(), 0, None),
            Err(Error::InvalidRate)
        );
    }
}
