// SPDX-License-Identifier: MIT
//! Checked original calibrated timer for root-link transitions only.
use super::*;
use crate::bus::pci::power::Timer;

fn ticks(clock: Clock, microseconds: u64) -> Result<u64, BlockError> {
    clock
        .ticks_per_microsecond
        .checked_mul(microseconds)
        .filter(|value| clock.ticks_per_microsecond != 0 && *value <= u64::MAX / 2)
        .ok_or(BlockError::Unsupported(
            "USB root transition clock unavailable or out of range",
        ))
}
pub(super) fn check(clock: Clock) -> Result<(), BlockError> {
    clock.check().map_err(|_| {
        BlockError::Unsupported("USB root transition clock unavailable or out of range")
    })?;
    ticks(clock, LINK_TIMEOUT_US).map(|_| ())
}
pub(super) fn delay(clock: Clock, microseconds: u64) -> Result<(), BlockError> {
    ticks(clock, microseconds)?;
    clock.wait_us(microseconds).map_err(|_| {
        BlockError::Unsupported("USB root transition clock unavailable or out of range")
    })
}
pub(super) struct Deadline {
    start: u64,
    ticks: u64,
}
impl Deadline {
    pub(super) fn new(clock: Clock, microseconds: u64) -> Result<Self, BlockError> {
        let ticks = ticks(clock, microseconds)?;
        Ok(Self {
            start: Clock::ticks(),
            ticks,
        })
    }
    fn passed_at(&self, now: u64) -> bool {
        now.wrapping_sub(self.start) >= self.ticks
    }
    pub(super) fn passed(&self) -> bool {
        self.passed_at(Clock::ticks())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_root_deadlines_preserve_full_duration_across_raw_counter_wrap() {
        for rate in [1, 3, 3_000, 100_000] {
            for duration in [100, 10_000, 40_000, 100_000] {
                let clock = Clock {
                    ticks_per_microsecond: rate,
                };
                let wanted = ticks(clock, duration).unwrap();
                let deadline = Deadline {
                    start: u64::MAX - wanted / 2,
                    ticks: wanted,
                };
                assert!(!deadline.passed_at(deadline.start));
                assert!(!deadline.passed_at(deadline.start.wrapping_add(wanted - 1)));
                assert!(deadline.passed_at(deadline.start.wrapping_add(wanted)));
                assert!(deadline.passed_at(deadline.start.wrapping_add(wanted + 1)));
            }
        }
    }
    #[test]
    fn invalid_root_rates_refuse_before_counter_or_delay_use() {
        for rate in [0, u64::MAX, u64::MAX / 100_000 + 1] {
            let clock = Clock {
                ticks_per_microsecond: rate,
            };
            assert!(check(clock).is_err());
            assert!(Deadline::new(clock, 100_000).is_err());
        }
        assert_eq!(
            ticks(
                Clock {
                    ticks_per_microsecond: 3_000
                },
                40_000
            ),
            Ok(120_000_000)
        );
    }
}
