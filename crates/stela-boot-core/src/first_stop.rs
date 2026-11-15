//! Which stop of the boot is the one shown and recorded.
//!
//! A fatal stop on one processor leaves the others running, and the boot
//! processor parked inside the step it stopped in: a watcher on another
//! processor, or a later failure there, would otherwise raise a second stop
//! whose reason replaces the first on the screen and in the kept record.
//! [`FirstStop`] keeps the first: once a stop began, a stop on another
//! processor, or any stop after the first finished, is [`Claim::Later`].
//! A stop raised on the stopping processor while it is still stopping, a
//! fault inside the stop's own work such as the firmware's variable service
//! it writes the record with, is [`Claim::Within`] and goes on as before.
use core::sync::atomic::{AtomicU64, Ordering};

/// No stop began.
const NONE: u64 = 0;
/// A stop runs on the processor in the bits above.
const STOPPING: u64 = 1;
/// The stop finished on the processor in the bits above: its reason is
/// shown and its record kept.
const FINISHED: u64 = 2;

/// What a stop raised on a processor is ([`FirstStop::claim`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Claim {
    /// The boot's first stop: it shows and records its reason.
    First,
    /// A stop raised by the first stop's own work, on its processor before
    /// it finished.
    Within,
    /// Any other stop after the first began: its reason gets one line and
    /// the first one's stands. `first_here`: this processor made the first
    /// stop, and goes back to the stop's wait for the power button.
    Later { first_here: bool },
}

/// The boot's first stop, for every processor.
pub struct FirstStop(AtomicU64);

impl Default for FirstStop {
    fn default() -> Self {
        Self::new()
    }
}

fn state(kind: u64, processor: u32) -> u64 {
    kind | u64::from(processor) << 2
}

impl FirstStop {
    pub const fn new() -> Self {
        Self(AtomicU64::new(NONE))
    }

    /// A stop is raised on `processor` (its APIC ID).
    pub fn claim(&self, processor: u32) -> Claim {
        let stopping = state(STOPPING, processor);
        match self
            .0
            .compare_exchange(NONE, stopping, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Claim::First,
            Err(now) if now == stopping => Claim::Within,
            Err(now) => Claim::Later {
                first_here: now >> 2 == u64::from(processor),
            },
        }
    }

    /// The stop on `processor` finished, or the boot stops there without a
    /// stop claimed: every later stop is [`Claim::Later`].
    pub fn finish(&self, processor: u32) {
        self.0.store(state(FINISHED, processor), Ordering::Release);
    }

    /// Whether a stop began: watchers of other processors then end.
    pub fn began(&self) -> bool {
        self.0.load(Ordering::Acquire) != NONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_stop_stands_against_other_processors_and_later_stops() {
        let stop = FirstStop::new();
        assert!(!stop.began());
        assert_eq!(stop.claim(0), Claim::First);
        assert!(stop.began());
        // Another processor's stop while the first one stops.
        assert_eq!(stop.claim(3), Claim::Later { first_here: false });
        // A fault inside the first stop's own work.
        assert_eq!(stop.claim(0), Claim::Within);
        stop.finish(0);
        // The step watchdog's NMI to the stopped processor, after it parked.
        assert_eq!(stop.claim(0), Claim::Later { first_here: true });
        assert_eq!(stop.claim(3), Claim::Later { first_here: false });
        assert!(stop.began());
    }

    #[test]
    fn a_stop_without_a_claim_still_ends_the_watchers() {
        let stop = FirstStop::new();
        stop.finish(5);
        assert!(stop.began());
        assert_eq!(stop.claim(5), Claim::Later { first_here: true });
        assert_eq!(stop.claim(0), Claim::Later { first_here: false });
    }

    #[test]
    fn processor_zero_and_a_wide_apic_id_are_told_apart() {
        let stop = FirstStop::new();
        assert_eq!(stop.claim(u32::MAX), Claim::First);
        assert_eq!(stop.claim(0), Claim::Later { first_here: false });
        assert_eq!(stop.claim(u32::MAX), Claim::Within);
    }
}
