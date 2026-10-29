//! Outward UTC arithmetic over capture/counter bounds supplied by boot.
//! This pure calculation does not admit any clock, firmware service or epoch.
use super::Timestamp;
use core::{fmt, ops::RangeInclusive};
const SECOND: u128 = 1_000_000_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Resolution,
    Nanosecond,
    ElapsedOrder,
    BeforeEpoch,
    Overflow,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Resolution => "firmware RTC resolution is zero",
            Self::Nanosecond => "firmware nanoseconds are out of range",
            Self::ElapsedOrder => "elapsed UTC bounds are inverted",
            Self::BeforeEpoch => "UTC uncertainty extends before the Unix epoch",
            Self::Overflow => "UTC interval arithmetic overflowed",
        })
    }
}
impl core::error::Error for Error {}
/// Inclusive outward-rounded UTC seconds. `elapsed_ns` must come from the SAME
/// live counter epoch: lower(capture_after,now_before) through
/// upper(capture_before,now_after). Runtime service, RTC source and epoch
/// ownership are checked separately before this data-only function is called.
/// The firmware RTC's reporting quantum is bounded in BOTH directions; no
/// rounding convention or sub-quantum phase is assumed for the reported fields.
pub fn bounds(
    reading: Timestamp,
    resolution: u32,
    elapsed_ns: RangeInclusive<u64>,
) -> Result<RangeInclusive<u64>, Error> {
    if resolution == 0 {
        return Err(Error::Resolution);
    }
    if reading.nanosecond >= SECOND as u32 {
        return Err(Error::Nanosecond);
    }
    if elapsed_ns.is_empty() {
        return Err(Error::ElapsedOrder);
    }
    let quantum = SECOND.div_ceil(u128::from(resolution));
    let origin = u128::from(reading.seconds) * SECOND + u128::from(reading.nanosecond);
    let earliest = origin
        .checked_add(u128::from(*elapsed_ns.start()))
        .ok_or(Error::Overflow)?
        .checked_sub(quantum)
        .ok_or(Error::BeforeEpoch)?;
    let latest = origin
        .checked_add(quantum)
        .and_then(|n| n.checked_add(u128::from(*elapsed_ns.end())))
        .ok_or(Error::Overflow)?;
    let earliest = u64::try_from(earliest / SECOND).map_err(|_| Error::Overflow)?;
    let latest = u64::try_from(latest.div_ceil(SECOND)).map_err(|_| Error::Overflow)?;
    Ok(earliest..=latest)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn brackets_round_outward_and_stay_conservative() {
        for (seconds, nanosecond, resolution, counter, expected) in [
            // A coarse RTC phase and counter bracket round outward.
            (100, 250_000_000, 1, 200_000_000..=400_000_000, 99..=102),
            (
                10,
                500_000_000,
                1000,
                1_000_000_000..=2_000_000_000,
                11..=13,
            ),
            // Sub-nanosecond reporting and a second carry stay conservative.
            (5, 999_999_999, u32::MAX, 0..=0, 5..=6),
            (5, 0, u32::MAX, 0..=0, 4..=6),
        ] {
            let time = Timestamp {
                seconds,
                nanosecond,
            };
            assert_eq!(bounds(time, resolution, counter), Ok(expected));
        }
    }

    #[test]
    fn malformed_inputs_and_epoch_edges_refuse_instead_of_saturating() {
        let t = Timestamp {
            seconds: 10,
            nanosecond: 0,
        };
        assert_eq!(bounds(t, 0, 0..=0), Err(Error::Resolution));
        assert_eq!(
            bounds(
                Timestamp {
                    nanosecond: 1_000_000_000,
                    ..t
                },
                1,
                0..=0
            ),
            Err(Error::Nanosecond)
        );
        assert_eq!(
            bounds(t, 1, RangeInclusive::new(2, 1)),
            Err(Error::ElapsedOrder)
        );
        assert_eq!(
            bounds(
                Timestamp {
                    seconds: 0,
                    nanosecond: 0
                },
                1,
                0..=0
            ),
            Err(Error::BeforeEpoch)
        );
        assert_eq!(
            bounds(
                Timestamp {
                    seconds: u64::MAX,
                    nanosecond: 999_999_999
                },
                1,
                0..=0
            ),
            Err(Error::Overflow)
        );
    }
    #[test]
    fn wider_brackets_never_shrink_a_valid_utc_interval() {
        let t = Timestamp {
            seconds: 100,
            nanosecond: 600_000_000,
        };
        for resolution in [1, 10, 1000, u32::MAX] {
            let narrow = bounds(t, resolution, 2_000_000_000..=2_000_000_000).unwrap();
            let wide = bounds(t, resolution, 1_000_000_000..=3_000_000_000).unwrap();
            assert!(wide.contains(narrow.start()) && wide.contains(narrow.end()));
        }
    }
}
