//! Input observations shared by native producers and the original Linux bridge.
//! These values describe reports; no number, bitmap or snapshot grants device
//! ownership, kernel current, input injection, or radio authority.
extern crate alloc;
use alloc::vec::Vec;

/// Linux event width and signed value; source SYN values remain in the stream.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub kind: u16,
    pub code: u16,
    pub value: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Knowledge<T> {
    Unknown,
    /// A genuine source/protocol observation, never a zero-filled assumption.
    Observed(T),
    NotApplicable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub keys: Vec<u16>,
    pub switches: Vec<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyState {
    pub code: u16,
    pub pressed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwitchState {
    pub code: u16,
    pub on: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialState {
    pub keys: Knowledge<Vec<KeyState>>,
    pub switches: Knowledge<Vec<SwitchState>>,
}
impl InitialState {
    pub const fn unknown() -> Self {
        Self {
            keys: Knowledge::Unknown,
            switches: Knowledge::Unknown,
        }
    }
}

/// Only a call-prefix observation. It never acknowledges a handler, work item,
/// device transition or radio policy effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallProgress {
    pub accepted_calls: usize,
    pub uncertain_call: Option<usize>,
}

/// Failure history disposition only, never source/kernel/retirement authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureDisposition {
    RetainFirst,
    RetainTerminal,
    RetainBeforeClosure,
    RecoverableAfterClosure,
    RepeatedStoppedStatus,
}
impl FailureDisposition {
    pub const fn retains_cause(self) -> bool {
        matches!(
            self,
            Self::RetainFirst | Self::RetainTerminal | Self::RetainBeforeClosure
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureOrigin {
    Poll,
    GuestLed,
}
/// First cause plus the independently observed actual physical terminal pass.
/// Repeated post-close recoverable/status diagnostics do not grow a history.
/// The caller retains EVERY error in each selected pass with SAME custody.
/// physical_terminal MUST come from the actual physical owner's stopped()
/// observation, NEVER Source::Stopped(ObservationClosed) or an origin label.
#[derive(Clone, Copy, Debug, Default)]
pub struct FailureRetention {
    first: bool,
    terminal: bool,
    recoverable_after_close: u64,
    repeated_stopped: u64,
}
impl FailureRetention {
    pub const fn new() -> Self {
        Self {
            first: false,
            terminal: false,
            recoverable_after_close: 0,
            repeated_stopped: 0,
        }
    }
    pub fn observe(
        &mut self,
        physical_terminal: bool,
        observation_closed: bool,
    ) -> FailureDisposition {
        if !self.first {
            self.first = true;
            self.terminal = physical_terminal;
            return FailureDisposition::RetainFirst;
        }
        if physical_terminal && !self.terminal {
            self.terminal = true;
            return FailureDisposition::RetainTerminal;
        }
        if !observation_closed {
            return FailureDisposition::RetainBeforeClosure;
        }
        if physical_terminal {
            self.repeated_stopped = self.repeated_stopped.saturating_add(1);
            FailureDisposition::RepeatedStoppedStatus
        } else {
            self.recoverable_after_close = self.recoverable_after_close.saturating_add(1);
            FailureDisposition::RecoverableAfterClosure
        }
    }
    pub const fn disposed_recoverable_passes(&self) -> u64 {
        self.recoverable_after_close
    }
    pub const fn repeated_stopped_passes(&self) -> u64 {
        self.repeated_stopped
    }
}
#[cfg(test)]
mod failure_tests {
    use super::*;
    #[test]
    fn recoverable_first_does_not_consume_later_physical_terminal_cause() {
        let mut ledger = FailureRetention::new();
        assert_eq!(
            ledger.observe(false, false),
            FailureDisposition::RetainFirst
        );
        for _ in 0..10000 {
            assert_eq!(
                ledger.observe(false, true),
                FailureDisposition::RecoverableAfterClosure
            );
        }
        assert_eq!(
            ledger.observe(true, true),
            FailureDisposition::RetainTerminal
        );
        assert_eq!(
            ledger.observe(true, true),
            FailureDisposition::RepeatedStoppedStatus
        );
        assert_eq!(ledger.disposed_recoverable_passes(), 10000);
    }
    #[test]
    fn an_observation_close_is_not_a_physical_terminal_witness() {
        let mut ledger = FailureRetention::new();
        ledger.observe(false, false);
        assert_eq!(
            ledger.observe(false, true),
            FailureDisposition::RecoverableAfterClosure
        );
        assert_eq!(
            ledger.observe(true, true),
            FailureDisposition::RetainTerminal
        );
    }
}
