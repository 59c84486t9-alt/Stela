//! Mandatory same-operation completion outside the physical inventory product.
use crate::{
    bus::pci::{
        ConfigEffect, ConfigError, ConfigFailure,
        assignment::{AdmissionClose, OpaqueUse, UseKind},
    },
    sync::FaultState,
};
use alloc::sync::Arc;
use core::mem::ManuallyDrop;

/// Actual preowned source/context/hardware postvalidation for this SAME count.
/// # Safety
/// Retain the actual original validator/epoch and all backing outside the
/// PhysicalAssignment graph; a readonly facade over a controller is not a
/// physical retention-only product. No fabricated/default/noop native validator
/// may stand in for required source or Command admission. The original custody
/// keeps a preowned Arc until all operations finish, so no per-access final
/// validator destructor is possible. Methods allocate nothing and hold no
/// mutable/entered borrow over return. postvalidate performs the actual required
/// checks before the count can retire. Its error is a cause-only ConfigError;
/// this transport attaches the actual config-write prefix. failure is ONLY a
/// bounded, any-CPU metadata observation: no context check, lock, cache/MMIO
/// access or callback/retry. Publishing must resolve only to the SAME original
/// actual Ready cause; neither Busy nor Publishing is that completed cause.
pub unsafe trait CompletionCheck: Send + Sync {
    fn postvalidate(&self) -> Result<(), ConfigError>;
    fn failure(&self) -> FaultState<ConfigError>;
}

/// Affine real count plus its separately retained actual completion validator.
/// No method extracts a bare count or substitutes an optional completion hook.
#[must_use = "complete the same actual configuration operation or retain it"]
pub struct ConfigOperation {
    count: ManuallyDrop<Option<OpaqueUse>>,
    completion: ManuallyDrop<Arc<dyn CompletionCheck>>,
    close: ManuallyDrop<AdmissionClose>,
    effect: ConfigEffect,
    finished: bool,
}
impl core::fmt::Debug for ConfigOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfigOperation")
            .field("effect", &self.effect)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}
impl ConfigOperation {
    /// # Safety
    /// count is the actual SAME original Configuration use admitted for this
    /// validator/epoch and operation. Custody retains the preowned validator
    /// outside physical P until all real operations have ended. No descriptor,
    /// type equality, unrelated count or metadata-only callback proves this.
    pub unsafe fn new(count: OpaqueUse, completion: Arc<dyn CompletionCheck>) -> Self {
        assert_eq!(count.kind(), UseKind::Configuration);
        let close = count.admission_close();
        Self {
            count: ManuallyDrop::new(Some(count)),
            completion: ManuallyDrop::new(completion),
            close: ManuallyDrop::new(close),
            effect: ConfigEffect::None,
            finished: false,
        }
    }
    /// Record only an actual issued volatile write, before ANY later check.
    /// # Safety
    /// These are the exact offset/width of this operation's already-issued
    /// bounded write. This records uncertainty, never permission to issue it.
    pub unsafe fn record_write(&mut self, offset: u16, width: u8) {
        assert!(matches!(width, 1 | 2 | 4));
        self.effect = ConfigEffect::WriteMayHaveApplied { offset, width };
    }
    fn with_effect(&self, mut error: ConfigError) -> ConfigError {
        if self.effect != ConfigEffect::None {
            error.effect = self.effect;
        }
        error
    }
    /// SAME producer metadata only, preserving this operation's real prefix.
    pub fn failure(&self) -> FaultState<ConfigError> {
        if self.finished {
            return FaultState::Empty;
        }
        match self.completion.failure() {
            FaultState::Ready(error) if error.reason == ConfigFailure::FaultPublishing => {
                FaultState::Publishing
            }
            FaultState::Ready(error) if error.is_observation() => FaultState::Empty,
            FaultState::Ready(error) => FaultState::Ready(self.with_effect(error)),
            other => other,
        }
    }
    pub fn close_metadata(&self) {
        if !self.finished {
            self.close.close();
        }
    }
    /// # Safety
    /// This operation's actual bounded volatile access and all raw/CPU return
    /// tails have ended. Actual required source postvalidation is mandatory
    /// here before releasing its count; no user or borrow may survive/restart.
    pub unsafe fn finish(&mut self) -> Result<(), ConfigError> {
        if self.finished {
            return Err(ConfigError::before_effect(
                ConfigFailure::UnqualifiedControl,
            ));
        }
        // Borrow the preowned guard IN PLACE: callback unwind cannot discard
        // its header, actual prefix, original count or validator association.
        let mut unwind = FinishGuard {
            close: &self.close,
            finished: false,
        };
        let checked = match self.failure() {
            FaultState::Ready(error) => Err(error),
            FaultState::Publishing => {
                Err(ConfigError::before_effect(ConfigFailure::FaultPublishing))
            }
            FaultState::Empty => self.completion.postvalidate(),
        };
        if let Err(error) = checked {
            let error = self.with_effect(error);
            self.close_metadata();
            unwind.finished = true;
            return Err(error);
        }
        let count = self.count.as_mut().expect("live configuration operation");
        // SAFETY: actual access/tails ended above and the same validator
        // succeeded. The count stays parked during the context callback.
        if let Err(error) = unsafe { count.release_in_place() } {
            let error =
                self.with_effect(ConfigError::before_effect(ConfigFailure::Ownership(error)));
            self.close_metadata();
            unwind.finished = true;
            return Err(error);
        }
        unwind.finished = true;
        drop(unwind);
        drop(self.count.take());
        self.finished = true;
        // SAFETY: explicit successful same-context completion. The original
        // custody still keeps its preowned validator; this drops only its clone.
        unsafe {
            ManuallyDrop::take(&mut self.close).dismiss();
            drop(ManuallyDrop::take(&mut self.completion));
        }
        Ok(())
    }
}
impl Drop for ConfigOperation {
    fn drop(&mut self) {
        if !self.finished {
            self.close_metadata();
        }
        // MD count, validator and close retain the ENTIRE actual graph.
        // No validator/native callback, allocator or final destructor runs.
    }
}

/// Only the SAME sealed atomic close runs if a completion callback unwinds.
struct FinishGuard<'a> {
    close: &'a AdmissionClose,
    finished: bool,
}
impl Drop for FinishGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.close.close();
        }
    }
}

#[cfg(test)]
mod tests;
