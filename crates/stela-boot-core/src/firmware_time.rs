//! Gregorian and UEFI timezone normalization of firmware-reported calendar data.
use core::fmt;
pub mod interval;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Raw UEFI calendar fields. These copied values confer no source permission.
/// `timezone_minutes` is the EFI field; `0x07ff` means unspecified.
pub struct Time {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanosecond: u32,
    pub timezone_minutes: i16,
    pub daylight: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Caller policy for an unspecified firmware timezone; there is no default.
pub enum UnspecifiedZone {
    RequireKnown,
    /// An explicit platform policy that the RTC stores UTC.
    RtcIsUtc,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp {
    pub seconds: u64,
    pub nanosecond: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Year,
    Month,
    Day,
    TimeOfDay,
    Nanosecond,
    Timezone,
    UnspecifiedTimezone,
    Daylight,
    BeforeUnixEpoch,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Year => "firmware year is outside 1900..9999",
            Self::Month => "firmware month is outside 1..12",
            Self::Day => "firmware day is invalid for its Gregorian month",
            Self::TimeOfDay => "firmware hour/minute/second is out of range",
            Self::Nanosecond => "firmware nanoseconds are out of range",
            Self::Timezone => "firmware timezone is invalid",
            Self::UnspecifiedTimezone => "firmware timezone is unspecified",
            Self::Daylight => "firmware daylight contains reserved bits",
            Self::BeforeUnixEpoch => "firmware UTC is before the Unix epoch",
        })
    }
}
impl core::error::Error for Error {}

/// Normalize fields only. The caller separately admits the RTC source,
/// serialized runtime-service gate and continuous-counter epoch/correlation.
/// UEFI 2.11 §8.3.1 defines UTC = Local + TimeZone. Daylight adjustment is already
/// reflected in both local time and timezone; adding another hour is incorrect.
/// https://uefi.org/specs/UEFI/2.11/08_Services_Runtime_Services.html#gettime
pub fn utc(time: Time, unspecified: UnspecifiedZone) -> Result<Timestamp, Error> {
    if !(1900..=9999).contains(&time.year) {
        return Err(Error::Year);
    }
    if !(1..=12).contains(&time.month) {
        return Err(Error::Month);
    }
    let leap = time.year.is_multiple_of(4)
        && (!time.year.is_multiple_of(100) || time.year.is_multiple_of(400));
    let days = match time.month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if time.day == 0 || time.day > days {
        return Err(Error::Day);
    }
    if time.hour > 23 || time.minute > 59 || time.second > 59 {
        return Err(Error::TimeOfDay);
    }
    if time.nanosecond >= 1_000_000_000 {
        return Err(Error::Nanosecond);
    }
    let zone = match time.timezone_minutes {
        -1440..=1440 => time.timezone_minutes,
        0x07ff => match unspecified {
            UnspecifiedZone::RequireKnown => return Err(Error::UnspecifiedTimezone),
            UnspecifiedZone::RtcIsUtc => 0,
        },
        _ => return Err(Error::Timezone),
    };
    if time.daylight & !3 != 0 {
        return Err(Error::Daylight);
    }
    // Validated field bounds keep Gregorian arithmetic within i64. The civil
    // date reduction uses complete 400-year Gregorian eras.
    let year = i64::from(time.year) - i64::from(time.month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let month = (i64::from(time.month) + 9) % 12;
    let doy = (153 * month + 2) / 5 + i64::from(time.day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let local = days * 86_400
        + i64::from(time.hour) * 3600
        + i64::from(time.minute) * 60
        + i64::from(time.second);
    let seconds =
        u64::try_from(local + i64::from(zone) * 60).map_err(|_| Error::BeforeUnixEpoch)?;
    Ok(Timestamp {
        seconds,
        nanosecond: time.nanosecond,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn time(year: u16, month: u8, day: u8) -> Time {
        Time {
            year,
            month,
            day,
            hour: 0,
            minute: 0,
            second: 0,
            nanosecond: 0,
            timezone_minutes: 0,
            daylight: 0,
        }
    }
    #[test]
    fn known_zone_sign_crosses_epoch_and_calendar_boundaries() {
        for (value, expected) in [
            (time(1970, 1, 1), 0),
            (
                Time {
                    timezone_minutes: 480,
                    ..time(1970, 1, 1)
                },
                28_800,
            ),
            (
                Time {
                    hour: 5,
                    minute: 30,
                    timezone_minutes: -330,
                    ..time(1970, 1, 1)
                },
                0,
            ),
            (
                Time {
                    timezone_minutes: 1440,
                    ..time(1969, 12, 31)
                },
                0,
            ),
            (
                Time {
                    hour: 12,
                    ..time(2000, 2, 29)
                },
                951_825_600,
            ),
            (time(2100, 3, 1), 4_107_542_400),
            (time(2400, 2, 29), 13574563200),
            (
                Time {
                    hour: 23,
                    minute: 59,
                    second: 59,
                    ..time(9999, 12, 31)
                },
                253_402_300_799,
            ),
        ] {
            assert_eq!(
                utc(value, UnspecifiedZone::RequireKnown).unwrap().seconds,
                expected,
                "{value:?}"
            );
        }
        assert_eq!(
            utc(
                Time {
                    timezone_minutes: -1440,
                    ..time(1970, 1, 1)
                },
                UnspecifiedZone::RequireKnown
            ),
            Err(Error::BeforeUnixEpoch)
        );
    }
    #[test]
    fn daylight_is_already_accounted_for_and_nanoseconds_are_retained() {
        let standard = Time {
            hour: 12,
            timezone_minutes: 480,
            daylight: 1,
            ..time(2026, 6, 1)
        };
        let daylight = Time {
            hour: 13,
            timezone_minutes: 420,
            daylight: 3,
            ..standard
        };
        assert_eq!(
            utc(standard, UnspecifiedZone::RequireKnown),
            utc(daylight, UnspecifiedZone::RequireKnown)
        );
        let fine = Time {
            nanosecond: 999_999_999,
            ..time(2026, 6, 1)
        };
        assert_eq!(
            utc(fine, UnspecifiedZone::RequireKnown).unwrap().nanosecond,
            999_999_999
        );
    }
    #[test]
    fn malformed_fields_and_ambiguous_zone_are_explicit() {
        let base = time(2026, 1, 1);
        for (value, error) in [
            (Time { year: 1899, ..base }, Error::Year),
            (Time { month: 0, ..base }, Error::Month),
            (Time { month: 13, ..base }, Error::Month),
            (time(1900, 2, 29), Error::Day),
            (time(2100, 2, 29), Error::Day),
            (time(2026, 4, 31), Error::Day),
            (Time { day: 0, ..base }, Error::Day),
            (Time { hour: 24, ..base }, Error::TimeOfDay),
            (Time { minute: 60, ..base }, Error::TimeOfDay),
            (Time { second: 60, ..base }, Error::TimeOfDay),
            (
                Time {
                    nanosecond: 1_000_000_000,
                    ..base
                },
                Error::Nanosecond,
            ),
            (
                Time {
                    timezone_minutes: 1441,
                    ..base
                },
                Error::Timezone,
            ),
            (
                Time {
                    timezone_minutes: -1441,
                    ..base
                },
                Error::Timezone,
            ),
            (
                Time {
                    daylight: 4,
                    ..base
                },
                Error::Daylight,
            ),
        ] {
            assert_eq!(
                utc(value, UnspecifiedZone::RequireKnown),
                Err(error),
                "{value:?}"
            );
        }
        let ambiguous = Time {
            timezone_minutes: 0x07ff,
            ..base
        };
        assert_eq!(
            utc(ambiguous, UnspecifiedZone::RequireKnown),
            Err(Error::UnspecifiedTimezone)
        );
        assert_eq!(
            utc(ambiguous, UnspecifiedZone::RtcIsUtc),
            utc(base, UnspecifiedZone::RequireKnown)
        );
    }
}
