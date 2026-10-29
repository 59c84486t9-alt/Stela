//! A clock source's first failure, kept for the rest of its epoch.
use core::sync::atomic::{AtomicU32, Ordering};
use stela_drivers::platform::work::WorkError;
pub struct Health(AtomicU32);
impl Default for Health {
    fn default() -> Self {
        Self::new()
    }
}

impl Health {
    pub const fn new() -> Self {
        Self(AtomicU32::new(0))
    }
    pub fn check(&self) -> Result<(), WorkError> {
        let code = self.0.load(Ordering::Acquire);
        if code == 0 { Ok(()) } else { Err(decode(code)) }
    }
    pub fn fail(&self, error: WorkError) -> WorkError {
        match self
            .0
            .compare_exchange(0, encode(error), Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => error,
            Err(first) => decode(first),
        }
    }
}
fn encode(error: WorkError) -> u32 {
    match error {
        WorkError::Unavailable => 1,
        WorkError::WrongCpu => 2,
        WorkError::InterruptContext => 3,
        WorkError::Busy => 4,
        WorkError::Full => 5,
        WorkError::Closed => 6,
        WorkError::Exhausted => 7,
        WorkError::InvalidStack => 8,
        WorkError::InvalidTicket => 9,
        WorkError::WouldDeadlock => 10,
        WorkError::TimedOut => 11,
        WorkError::CorruptContext => 12,
        WorkError::Pending => 13,
    }
}
fn decode(code: u32) -> WorkError {
    match code {
        1 => WorkError::Unavailable,
        2 => WorkError::WrongCpu,
        3 => WorkError::InterruptContext,
        4 => WorkError::Busy,
        5 => WorkError::Full,
        6 => WorkError::Closed,
        7 => WorkError::Exhausted,
        8 => WorkError::InvalidStack,
        9 => WorkError::InvalidTicket,
        10 => WorkError::WouldDeadlock,
        11 => WorkError::TimedOut,
        13 => WorkError::Pending,
        _ => WorkError::CorruptContext,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_source_failure_stays_failed_after_later_observations() {
        let health = Health::new();
        assert_eq!(health.check(), Ok(()));
        assert_eq!(health.fail(WorkError::Unavailable), WorkError::Unavailable);
        assert_eq!(
            health.fail(WorkError::CorruptContext),
            WorkError::Unavailable
        );
        assert_eq!(health.check(), Err(WorkError::Unavailable));
    }

    #[test]
    fn retained_failures_keep_their_typed_cause() {
        for error in [
            WorkError::Unavailable,
            WorkError::WrongCpu,
            WorkError::InterruptContext,
            WorkError::Busy,
            WorkError::Full,
            WorkError::Closed,
            WorkError::Exhausted,
            WorkError::InvalidStack,
            WorkError::InvalidTicket,
            WorkError::WouldDeadlock,
            WorkError::TimedOut,
            WorkError::CorruptContext,
            WorkError::Pending,
        ] {
            let health = Health::new();
            assert_eq!(health.fail(error), error);
            assert_eq!(health.check(), Err(error));
        }
    }
}
