use super::{CounterReference, Error};
use alloc::{vec, vec::Vec};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pair {
    pub value: u64,
    pub tick: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Delta {
    pub value: u64,
    pub ticks: u64,
    pub micros: u64,
}
pub(super) fn delta(index: u32, flags: u32, pairs: [Pair; 2], periods: (u32, u64)) -> Delta {
    if flags & 1 != 0 {
        Delta {
            value: pairs[(!index & 1) as usize].value,
            ticks: u64::from(periods.0),
            micros: periods.1,
        }
    } else if index <= 1 {
        Delta::default()
    } else {
        let old = pairs[(index & 1) as usize];
        let new = pairs[(!index & 1) as usize];
        let ticks = new.tick.wrapping_sub(old.tick);
        Delta {
            value: new.value.wrapping_sub(old.value),
            ticks,
            micros: (((u128::from(ticks) * 0xaaaaaaaaaaaaaaabu128) >> 64) >> 4) as u64,
        }
    }
}
pub(super) fn scaled(
    index: u32,
    r: CounterReference,
    pairs: [Pair; 2],
    periods: (u32, u64),
) -> Result<Delta, Error> {
    let mut d = delta(index, r.flags, pairs, periods);
    let factor = r.scale & 0x3ffffff;
    if factor != 0 {
        let mut v = d.value.wrapping_mul(u64::from(factor));
        let shift = (r.scale as i32) >> 27;
        if r.scale & (1 << 26) != 0 {
            let power = 10u64
                .checked_pow(shift.unsigned_abs())
                .ok_or(Error::Contract(
                    "source decimal scale exponent outside u64 table",
                ))?;
            if shift > 0 {
                v = v.wrapping_mul(power)
            } else if shift < 0 {
                v /= power
            }
        } else if shift >= 1 {
            v = v.wrapping_shl(shift as u32 & 63)
        } else if shift != 0 {
            v = 0
        }
        d.value = v;
    }
    Ok(d)
}
pub(super) fn percent(value: u64) -> u64 {
    let high = ((u128::from(value >> 2) * 0x28f5c28f5c28f5c3u128) >> 64) as u64;
    high >> 2
}
/// Software histogram1006f30. Initialization is explicit; it does not assert
/// that a counter event or native provider was observed.
#[derive(Clone, Debug)]
pub struct Statistics {
    bins: Vec<u64>,
    shift: u32,
    current: u32,
    run: u64,
}
impl Statistics {
    /// Declare source software histogram geometry, not observed counter state.
    pub fn from_source_layout(count: usize, shift: u32) -> Result<Self, Error> {
        if count == 0 || count > 511 || shift > 31 {
            return Err(Error::Contract(
                "source histogram geometry outside encoded bounds",
            ));
        }
        Ok(Self::initialized(count, shift))
    }

    pub(super) fn initialized(count: usize, shift: u32) -> Self {
        Self {
            bins: vec![0; count],
            shift,
            current: 0,
            run: 0,
        }
    }
    pub fn record(&mut self, value: u32) {
        let index = value
            .wrapping_shr(self.shift & 31)
            .min(self.bins.len() as u32 - 1);
        if index == self.current {
            self.run = self.run.wrapping_add(1)
        } else {
            self.bins[self.current as usize] =
                self.bins[self.current as usize].wrapping_add(self.run);
            self.current = index;
            self.run = 1;
        }
    }
    pub fn bins(&self) -> &[u64] {
        &self.bins
    }
    pub fn retained_run(&self) -> (u32, u64) {
        (self.current, self.run)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn declared_source_histogram_bounds_never_create_counter_observations() {
        assert!(Statistics::from_source_layout(0, 0).is_err());
        assert!(Statistics::from_source_layout(512, 0).is_err());
        assert!(Statistics::from_source_layout(32, 32).is_err());
        let mut s = Statistics::from_source_layout(128, 0).unwrap();
        assert_eq!(s.bins(), &[0; 128]);
        assert_eq!(s.retained_run(), (0, 0));
        s.record(200);
        assert_eq!(s.retained_run(), (127, 1));
    }
    #[test]
    fn source_delta_uses_wrapping_pairs_and_fixed_period_flag() {
        let p = [
            Pair {
                value: u64::MAX - 3,
                tick: u64::MAX - 47,
            },
            Pair { value: 5, tick: 48 },
        ];
        assert_eq!(
            delta(2, 0, p, (170, 7)),
            Delta {
                value: 9,
                ticks: 96,
                micros: 4
            }
        );
        assert_eq!(delta(1, 0, p, (170, 7)), Delta::default());
        assert_eq!(
            delta(2, 1, p, (170, 7)),
            Delta {
                value: 5,
                ticks: 170,
                micros: 7
            }
        );
    }
    #[test]
    fn source_scale_and_histogram_preserve_integer_width() {
        let r = CounterReference {
            kind: 1,
            provider: 0,
            start: 0,
            width: 0,
            flags: 1,
            scale: (1 << 26) | (((-3i32) as u32) << 27) | 4,
        };
        let p = [
            Pair::default(),
            Pair {
                value: 2500,
                tick: 0,
            },
        ];
        assert_eq!(scaled(2, r, p, (170, 7)).unwrap().value, 10);
        let mut s = Statistics::initialized(16, 0);
        s.record(30);
        s.record(20);
        s.record(0);
        assert_eq!(s.bins()[15], 2);
        assert_eq!(s.retained_run(), (0, 1));
        assert_eq!(percent(100), 1);
    }
}
