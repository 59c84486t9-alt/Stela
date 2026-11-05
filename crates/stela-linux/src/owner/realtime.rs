//! Fixed realtime correlation for a retained monotonic clock.
use core::{
    num::NonZeroU32,
    sync::atomic::{AtomicI64, Ordering},
};

const SECOND: i64 = 1_000_000_000;

#[derive(Clone, Copy)]
pub enum RealtimeRead {
    Fine,
    CoarseMultigrain(NonZeroU32),
    FineMultigrain,
}

/// A UTC sample correlated to one immutable monotonic clock epoch. Consumers
/// must supply samples from that same clock. This owns no timer authority.
pub struct RealtimeOrigin {
    monotonic_ns: i64,
    seconds: i64,
    nanoseconds: u32,
    floor: AtomicI64,
}

impl RealtimeOrigin {
    pub fn new(monotonic_ns: i64, seconds: i64, nanoseconds: u32) -> Option<Self> {
        (monotonic_ns >= 0 && nanoseconds < SECOND as u32).then(|| Self {
            monotonic_ns,
            seconds,
            nanoseconds,
            floor: AtomicI64::new(monotonic_ns),
        })
    }

    pub fn read(&self, now_ns: i64, read: RealtimeRead) -> Option<(i64, u32)> {
        if now_ns < self.monotonic_ns {
            return None;
        }
        let sample = match read {
            RealtimeRead::Fine => now_ns,
            RealtimeRead::CoarseMultigrain(tick) => {
                let coarse = now_ns - now_ns % i64::from(tick.get());
                coarse.max(self.floor.load(Ordering::Acquire))
            }
            RealtimeRead::FineMultigrain => {
                now_ns.max(self.floor.fetch_max(now_ns, Ordering::AcqRel))
            }
        };
        let elapsed = sample - self.monotonic_ns;
        let nanos = i64::from(self.nanoseconds) + elapsed % SECOND;
        let seconds = self
            .seconds
            .checked_add(elapsed / SECOND + nanos / SECOND)?;
        Some((seconds, (nanos % SECOND) as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coarse_samples_honor_the_fine_floor() {
        let clock = RealtimeOrigin::new(40, 17, 999_999_970).unwrap();
        let coarse = RealtimeRead::CoarseMultigrain(NonZeroU32::new(100).unwrap());
        assert_eq!(clock.read(39, coarse), None);
        assert_eq!(clock.read(60, coarse), Some((17, 999_999_970)));
        assert_eq!(clock.read(80, RealtimeRead::Fine), Some((18, 10)));
        assert_eq!(clock.read(90, coarse), Some((17, 999_999_970)));
        assert_eq!(clock.read(90, RealtimeRead::FineMultigrain), Some((18, 20)));
        assert_eq!(clock.read(95, coarse), Some((18, 20)));
        assert_eq!(clock.read(80, RealtimeRead::FineMultigrain), Some((18, 20)));
        assert_eq!(clock.read(101, coarse), Some((18, 30)));
    }

    #[test]
    fn invalid_origin_and_wall_overflow_are_rejected() {
        assert!(RealtimeOrigin::new(-1, 0, 0).is_none());
        assert!(RealtimeOrigin::new(0, 0, SECOND as u32).is_none());
        let clock = RealtimeOrigin::new(0, i64::MAX, 999_999_999).unwrap();
        assert_eq!(clock.read(1, RealtimeRead::Fine), None);
    }
}
