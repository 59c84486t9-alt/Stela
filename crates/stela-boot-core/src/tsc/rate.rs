//! Time on an invariant TSC at a nominal (CPUID crystal ratio, rounded base
//! frequency) or firmware-stall rate. Bounds and minimum waits widen by 1/64
//! either way, several times that rate's error, so a minimum never shortens.
use super::Error;
use crate::hpet::ElapsedBounds;

const MARGIN_SHIFT: u32 = 6;
const NS: u128 = 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NominalRate {
    hz: u64,
}

impl NominalRate {
    /// The slowest admitted rate, whose period still fits femtoseconds.
    pub const SLOWEST_HZ: u64 = 1_000_000;

    pub fn new(hz: u64) -> Result<Self, Error> {
        if hz < Self::SLOWEST_HZ {
            return Err(Error::InvalidRate);
        }
        Ok(Self { hz })
    }
    pub fn hz(self) -> u64 {
        self.hz
    }
    fn fast_hz(self) -> u128 {
        u128::from(self.hz) + u128::from(self.hz >> MARGIN_SHIFT)
    }
    fn slow_hz(self) -> u128 {
        u128::from(self.hz) - u128::from(self.hz >> MARGIN_SHIFT)
    }
    /// The nominal tick period, in femtoseconds.
    pub fn period_fs(self) -> u32 {
        (1_000_000_000_000_000 / self.hz) as u32
    }
    /// Nominal nanoseconds for a scheduler clock, flooring.
    pub fn ns(self, ticks: u64) -> Result<u64, Error> {
        u64::try_from(u128::from(ticks) * NS / u128::from(self.hz)).map_err(|_| Error::Overflow)
    }
    /// Ticks that cover at least `minimum_ns` at the fastest admitted rate.
    pub fn ticks_for_minimum_ns(self, minimum_ns: u64) -> Result<u64, Error> {
        let ticks = (u128::from(minimum_ns) * self.fast_hz()).div_ceil(NS);
        u64::try_from(ticks).map_err(|_| Error::Overflow)
    }
    /// Real time `ticks` spans, between the fastest and slowest rates.
    pub fn elapsed_bounds(self, ticks: u64) -> Result<ElapsedBounds, Error> {
        let scaled = u128::from(ticks) * NS;
        let bound = |ns: u128| u64::try_from(ns).map_err(|_| Error::Overflow);
        Ok(ElapsedBounds {
            lower_ns: bound(scaled / self.fast_hz())?,
            upper_ns: bound(scaled.div_ceil(self.slow_hz()))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_waits_outlast_the_fastest_rate_the_margin_admits() {
        let rate = NominalRate::new(3_000_000_000).unwrap();
        assert_eq!(rate.ticks_for_minimum_ns(0), Ok(0));
        assert_eq!(rate.ticks_for_minimum_ns(1_000_000), Ok(3_046_875));
        for ns in [1, 7, 999, 1_000_001, 60_000_000_000] {
            let ticks = rate.ticks_for_minimum_ns(ns).unwrap();
            assert!(rate.elapsed_bounds(ticks).unwrap().lower_ns >= ns);
            assert!(rate.elapsed_bounds(ticks - 1).unwrap().lower_ns < ns);
        }
    }

    #[test]
    fn bounds_enclose_the_nominal_time() {
        let rate = NominalRate::new(2_400_000_017).unwrap();
        for ticks in [0, 1, 2_399, 2_400_000_017, u64::MAX / 4] {
            let nominal = rate.ns(ticks).unwrap();
            let bounds = rate.elapsed_bounds(ticks).unwrap();
            assert!(bounds.lower_ns <= nominal && nominal <= bounds.upper_ns);
        }
        assert_eq!(rate.period_fs(), 416_666);
    }

    #[test]
    fn slow_or_unrepresentable_rates_are_refused() {
        assert_eq!(NominalRate::new(0), Err(Error::InvalidRate));
        assert_eq!(NominalRate::new(999_999), Err(Error::InvalidRate));
        let slow = NominalRate::new(NominalRate::SLOWEST_HZ).unwrap();
        assert_eq!(slow.period_fs(), 1_000_000_000);
        assert_eq!(slow.ns(u64::MAX), Err(Error::Overflow));
        assert_eq!(slow.elapsed_bounds(u64::MAX), Err(Error::Overflow));
    }
}
