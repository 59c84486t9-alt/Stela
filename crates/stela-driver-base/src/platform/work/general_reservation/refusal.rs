//! Exact native admission branch observations, never inferred from errno.
use super::WorkError;

/// Which actual native prerequisite refused this admission attempt.
/// Geometry describes availability, never physical stack ownership/eligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneralBlocker {
    QueueCredit,
    CompatibleStack,
    /// No compatible never-entered worker is presently idle/unbound.
    /// Canceling an unpublished never-entered reservation can restore this;
    /// releasing a previously-entered worker does not reset entry history.
    UnstartedStack,
    UnsupportedPlacement,
    Other,
}
/// A private native branch record. It is NOT a no-exposure, canceled-request,
/// stack-pin, callback completion or resource-event receipt. In particular an
/// async broker must retain its request until its own actual publication join.
#[derive(Debug)]
pub struct GeneralRefusal {
    error: WorkError,
    blocker: GeneralBlocker,
}
impl GeneralRefusal {
    pub fn error(&self) -> WorkError {
        self.error
    }
    pub fn blocker(&self) -> GeneralBlocker {
        self.blocker
    }
    pub fn into_error(self) -> WorkError {
        self.error
    }
    pub(super) fn queue_credit() -> Self {
        Self {
            error: WorkError::Full,
            blocker: GeneralBlocker::QueueCredit,
        }
    }
    pub(super) fn compatible_stack() -> Self {
        Self {
            error: WorkError::Full,
            blocker: GeneralBlocker::CompatibleStack,
        }
    }
    pub(super) fn unstarted_stack() -> Self {
        Self {
            error: WorkError::Full,
            blocker: GeneralBlocker::UnstartedStack,
        }
    }
    pub(super) fn placement(error: WorkError) -> Self {
        Self {
            error,
            blocker: GeneralBlocker::UnsupportedPlacement,
        }
    }
}
impl From<WorkError> for GeneralRefusal {
    fn from(error: WorkError) -> Self {
        Self {
            error,
            blocker: GeneralBlocker::Other,
        }
    }
}
