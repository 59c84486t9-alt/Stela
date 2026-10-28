// SPDX-License-Identifier: MIT
//! Checked original calibrated timer for root-link transitions only.
use super::*;
use crate::bus::pci::power::Timer;

fn in_range(clock: Clock, microseconds: u64) -> Result<(), BlockError> {
    clock.check_duration(microseconds).map_err(|_| {
        BlockError::Unsupported("USB root transition clock unavailable or out of range")
    })
}
pub(super) fn check(clock: Clock) -> Result<(), BlockError> {
    clock.check().map_err(|_| {
        BlockError::Unsupported("USB root transition clock unavailable or out of range")
    })?;
    in_range(clock, LINK_TIMEOUT_US)
}
pub(super) fn delay(clock: Clock, microseconds: u64) -> Result<(), BlockError> {
    in_range(clock, microseconds)?;
    clock.wait_us(microseconds).map_err(|_| {
        BlockError::Unsupported("USB root transition clock unavailable or out of range")
    })
}
/// A root-link transition's deadline, on the shared [`crate::Deadline`].
pub(super) fn deadline(clock: Clock, microseconds: u64) -> Result<crate::Deadline, BlockError> {
    clock.try_deadline(microseconds).map_err(|_| {
        BlockError::Unsupported("USB root transition clock unavailable or out of range")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_root_rates_refuse_before_counter_or_delay_use() {
        for rate in [0, u64::MAX, u64::MAX / 100_000 + 1] {
            let clock = Clock {
                ticks_per_microsecond: rate,
            };
            assert!(check(clock).is_err());
            assert!(deadline(clock, 100_000).is_err());
        }
        assert_eq!(
            in_range(
                Clock {
                    ticks_per_microsecond: 3_000
                },
                40_000
            ),
            Ok(())
        );
    }
}
