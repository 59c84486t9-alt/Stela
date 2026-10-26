// SPDX-License-Identifier: MIT
//! Attachment-local elapsed TSC time, preserving fractional ticks and wrap.
//! Minimum delays use the shared checked native PCI Timer implementation.
pub(super) struct Elapsed {
    previous: u64,
    remainder: u64,
    microseconds: u64,
}
impl Elapsed {
    pub(super) fn new(ticks: u64) -> Self {
        Self {
            previous: ticks,
            remainder: 0,
            microseconds: 0,
        }
    }
    pub(super) fn sample(&mut self, ticks: u64, rate: u64) -> u64 {
        // Native::validate checked this immutable producer-calibrated rate
        // before Controller can call now_us or issue any register operation.
        assert_ne!(rate, 0, "validated EHCI timer rate");
        let elapsed = u128::from(ticks.wrapping_sub(self.previous)) + u128::from(self.remainder);
        self.previous = ticks;
        self.remainder = (elapsed % u128::from(rate)) as u64;
        self.microseconds = self
            .microseconds
            .wrapping_add((elapsed / u128::from(rate)) as u64);
        self.microseconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Clock, bus::pci::power::Timer};

    #[test]
    fn native_clock_rejects_unusable_rates_before_waiting() {
        for rate in [0, u64::MAX] {
            let clock = Clock {
                ticks_per_microsecond: rate,
            };
            assert!(clock.check().is_err());
            assert!(clock.wait_us(40_000).is_err());
        }
        assert!(
            Clock {
                ticks_per_microsecond: 3_000
            }
            .check()
            .is_ok()
        );
    }
    #[test]
    fn elapsed_tsc_preserves_complete_microseconds_across_counter_wrap_and_fractional_reads() {
        for start in [50, u64::MAX - 4] {
            let mut elapsed = Elapsed::new(start);
            for ticks in 0..32u64 {
                assert_eq!(elapsed.sample(start.wrapping_add(ticks), 3), ticks / 3);
            }
        }
        let mut elapsed = Elapsed::new(0);
        // u128 accumulation preserves a fractional remainder even when the
        // next full raw delta would overflow a u64 sum.
        assert_eq!(elapsed.sample(u64::MAX - 1, u64::MAX), 0);
        assert_eq!(elapsed.sample(u64::MAX - 2, u64::MAX), 1);
        assert_eq!(elapsed.remainder, u64::MAX - 1);
        elapsed.microseconds = u64::MAX - 1;
        elapsed.remainder = 0;
        assert_eq!(elapsed.sample(0, 1).wrapping_sub(u64::MAX - 1), 3);
    }
}
