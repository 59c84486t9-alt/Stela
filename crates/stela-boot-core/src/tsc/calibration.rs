use super::Error;
/// Exact rational rate data. Not a measured native clock or permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RationalRate {
    numerator: u64,
    denominator: u64,
}
impl RationalRate {
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, Error> {
        if numerator == 0 || denominator == 0 {
            return Err(Error::InvalidRate);
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }
    pub fn numerator(self) -> u64 {
        self.numerator
    }
    pub fn denominator(self) -> u64 {
        self.denominator
    }
    pub fn hz(self) -> Result<u64, Error> {
        let hz = self.numerator / self.denominator;
        if hz == 0 {
            return Err(Error::InvalidRate);
        }
        Ok(hz)
    }
    pub fn nanoseconds(self, ticks: u64) -> Result<u64, Error> {
        let numerator = u128::from(ticks)
            .checked_mul(1_000_000_000)
            .and_then(|n| n.checked_mul(u128::from(self.denominator)))
            .ok_or(Error::Overflow)?;
        u64::try_from(numerator / u128::from(self.numerator)).map_err(|_| Error::Overflow)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub tsc_before: u64,
    pub reference: u64,
    pub tsc_after: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceScale {
    Hertz(u64),
    PeriodFemtoseconds(u32),
}
/// A modular difference cannot prove that multiple wraps did not occur. The
/// actual retained reference owner must independently establish that interval.
pub fn wrapped_delta(before: u64, after: u64, mask: u64) -> Result<u64, Error> {
    if !matches!(mask, 0x00ff_ffff | 0xffff_ffff | u64::MAX)
        || before & !mask != 0
        || after & !mask != 0
    {
        return Err(Error::InvalidMask);
    }
    let delta = after.wrapping_sub(before) & mask;
    if delta == 0 {
        return Err(Error::NoProgress);
    }
    Ok(delta)
}
/// Frequency uncertainty from actual before/reference/after read brackets.
/// Safe arithmetic/model output does not attest reference continuity/ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateWindow {
    minimum_hz: u64,
    maximum_hz: u64,
}
impl RateWindow {
    pub fn minimum_hz(self) -> u64 {
        self.minimum_hz
    }
    pub fn maximum_hz(self) -> u64 {
        self.maximum_hz
    }
    pub fn from_samples(
        start: Sample,
        end: Sample,
        reference_mask: u64,
        scale: ReferenceScale,
        max_read_cycles: u64,
    ) -> Result<Self, Error> {
        let reference_ticks = wrapped_delta(start.reference, end.reference, reference_mask)?;
        if max_read_cycles == 0 {
            return Err(Error::InvalidRate);
        }
        for sample in [start, end] {
            let width = sample
                .tsc_after
                .checked_sub(sample.tsc_before)
                .ok_or(Error::Backwards)?;
            if width >= max_read_cycles {
                return Err(Error::Disturbed);
            }
        }
        let minimum_cycles = end
            .tsc_before
            .checked_sub(start.tsc_after)
            .ok_or(Error::Backwards)?;
        let maximum_cycles = end
            .tsc_after
            .checked_sub(start.tsc_before)
            .ok_or(Error::Backwards)?;
        if minimum_cycles == 0 {
            return Err(Error::NoProgress);
        }
        let (multiplier, denominator) = match scale {
            ReferenceScale::Hertz(0) | ReferenceScale::PeriodFemtoseconds(0) => {
                return Err(Error::InvalidRate);
            }
            ReferenceScale::Hertz(hz) => (u128::from(hz), u128::from(reference_ticks)),
            ReferenceScale::PeriodFemtoseconds(period) => (
                1_000_000_000_000_000,
                u128::from(reference_ticks) * u128::from(period),
            ),
        };
        let lower = u128::from(minimum_cycles)
            .checked_mul(multiplier)
            .ok_or(Error::Overflow)?
            / denominator;
        let upper = u128::from(maximum_cycles)
            .checked_mul(multiplier)
            .ok_or(Error::Overflow)?
            .div_ceil(denominator);
        let minimum_hz = u64::try_from(lower).map_err(|_| Error::Overflow)?;
        let maximum_hz = u64::try_from(upper).map_err(|_| Error::Overflow)?;
        if minimum_hz == 0 || maximum_hz < minimum_hz {
            return Err(Error::InvalidRate);
        }
        Ok(Self {
            minimum_hz,
            maximum_hz,
        })
    }
    pub fn intersect(self, other: Self) -> Result<Self, Error> {
        let result = Self {
            minimum_hz: self.minimum_hz.max(other.minimum_hz),
            maximum_hz: self.maximum_hz.min(other.maximum_hz),
        };
        if result.minimum_hz == 0 || result.maximum_hz < result.minimum_hz {
            return Err(Error::InconsistentRate);
        }
        Ok(result)
    }
    pub fn contains(self, hz: u64) -> bool {
        self.minimum_hz <= hz && hz <= self.maximum_hz
    }
}
