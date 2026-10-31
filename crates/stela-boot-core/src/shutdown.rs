//! Coalesced native shutdown requests, delivered only by the boot processor.
use core::sync::atomic::{AtomicU8, Ordering};

/// Whether the native requester permits waiting for the guest to exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Orderly = 1,
    Forced = 2,
}

/// A request remains pending across service installation and other processors'
/// service turns. A forced request always takes precedence over an orderly one.
#[derive(Default)]
pub struct Requests(AtomicU8);

impl Requests {
    pub const fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    pub fn request(&self, mode: Mode) {
        self.0.fetch_max(mode as u8, Ordering::Release);
    }

    pub fn pending(&self) -> bool {
        self.0.load(Ordering::Acquire) != 0
    }

    /// Leave requests untouched on another processor. The boot processor
    /// consumes the strongest pending request exactly once per delivery.
    pub fn take(&self, boot_processor: bool) -> Option<Mode> {
        if !boot_processor {
            return None;
        }
        match self.0.swap(0, Ordering::AcqRel) {
            1 => Some(Mode::Orderly),
            2 => Some(Mode::Forced),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn another_processor_leaves_a_pending_request_for_the_boot_processor() {
        let requests = Requests::new();
        requests.request(Mode::Orderly);
        assert_eq!(requests.take(false), None);
        assert!(requests.pending());
        assert_eq!(requests.take(true), Some(Mode::Orderly));
        assert!(!requests.pending());
        assert_eq!(requests.take(true), None);
    }

    #[test]
    fn a_forced_request_cannot_be_downgraded_or_delivered_twice() {
        let requests = Requests::new();
        requests.request(Mode::Orderly);
        requests.request(Mode::Forced);
        requests.request(Mode::Orderly);
        assert_eq!(requests.take(true), Some(Mode::Forced));
        assert_eq!(requests.take(true), None);
    }

    #[test]
    fn a_request_after_delivery_is_preserved_for_the_next_service_turn() {
        let requests = Requests::new();
        requests.request(Mode::Orderly);
        assert_eq!(requests.take(true), Some(Mode::Orderly));
        requests.request(Mode::Forced);
        assert_eq!(requests.take(false), None);
        assert_eq!(requests.take(true), Some(Mode::Forced));
    }
}
