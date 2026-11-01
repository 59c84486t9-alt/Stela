//! Directed arithmetic for an observed minimum-duration reference interval.
//! Safe data only: neither a completed reference action nor a CPU/time permit.
use super::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LowerScale {
    minimum_ns: u64,
    measured_ticks: u64,
}
impl LowerScale {
    /// The reference completed at least minimum_us while measured_ticks elapsed
    /// on an unchanged constant-rate counter. Native owners must establish the
    /// real action and continuity; authored observations alone grant nothing.
    pub fn from_minimum(minimum_us: u64, measured_ticks: u64) -> Result<Self, Error> {
        let minimum_ns = minimum_us.checked_mul(1000).ok_or(Error::Overflow)?;
        if minimum_ns == 0 || measured_ticks == 0 {
            return Err(Error::InvalidRate);
        }
        Ok(Self {
            minimum_ns,
            measured_ticks,
        })
    }
    /// Conservative LOWER real elapsed time, never a UTC/upper elapsed bound.
    /// Floor cannot overstate the observed reference's promised minimum.
    pub fn lower_ns(self, ticks: u64) -> Result<u64, Error> {
        let scaled = u128::from(ticks) * u128::from(self.minimum_ns);
        u64::try_from(scaled / u128::from(self.measured_ticks)).map_err(|_| Error::Overflow)
    }
    /// Source-counter ticks needed to ensure requested real microseconds. Ceil
    /// cannot shorten a required hardware minimum. Do not add this real duration
    /// directly to a different nominal clock or promise a maximum wake latency.
    pub fn ticks_for_minimum_us(self, microseconds: u64) -> Result<u64, Error> {
        let nanoseconds = microseconds.checked_mul(1000).ok_or(Error::Overflow)?;
        let scaled = u128::from(nanoseconds) * u128::from(self.measured_ticks);
        u64::try_from(scaled.div_ceil(u128::from(self.minimum_ns))).map_err(|_| Error::Overflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn added_reference_overhead_only_weakens_the_lower_bound() {
        let exact = LowerScale::from_minimum(10, 1000).unwrap();
        let delayed = LowerScale::from_minimum(10, 1100).unwrap();
        assert_eq!(exact.lower_ns(1000), Ok(10_000));
        assert_eq!(delayed.lower_ns(1000), Ok(9090));
        assert!(
            delayed.ticks_for_minimum_us(100).unwrap() > exact.ticks_for_minimum_us(100).unwrap()
        );
    }
    #[test]
    fn minimum_targets_round_up_and_lower_elapsed_rounds_down() {
        let bound = LowerScale::from_minimum(7, 13).unwrap();
        for requested in 1..1000 {
            let ticks = bound.ticks_for_minimum_us(requested).unwrap();
            assert!(bound.lower_ns(ticks).unwrap() >= requested * 1000);
            assert!(bound.lower_ns(ticks - 1).unwrap() < requested * 1000);
        }
        assert_eq!(bound.lower_ns(1), Ok(538));
        assert_eq!(bound.ticks_for_minimum_us(0), Ok(0));
    }
    #[test]
    fn zero_and_unrepresentable_inputs_never_supply_a_bound() {
        assert_eq!(LowerScale::from_minimum(0, 1), Err(Error::InvalidRate));
        assert_eq!(LowerScale::from_minimum(1, 0), Err(Error::InvalidRate));
        assert_eq!(LowerScale::from_minimum(u64::MAX, 1), Err(Error::Overflow));
        let fast = LowerScale::from_minimum(1, u64::MAX).unwrap();
        assert_eq!(fast.ticks_for_minimum_us(2), Err(Error::Overflow));
        assert_eq!(fast.ticks_for_minimum_us(u64::MAX), Err(Error::Overflow));
        let slow = LowerScale::from_minimum(u64::MAX / 1000, 1).unwrap();
        assert_eq!(slow.lower_ns(2), Err(Error::Overflow));
    }
    #[test]
    fn full_width_multiplication_preserves_representable_results() {
        let bound = LowerScale::from_minimum(u64::MAX / 1000, u64::MAX).unwrap();
        assert_eq!(bound.lower_ns(u64::MAX), Ok((u64::MAX / 1000) * 1000));
        assert_eq!(bound.ticks_for_minimum_us(u64::MAX / 1000), Ok(u64::MAX));
    }
}
