//! Stable opaque identity for one original attachment/configuration epoch.
use crate::bus::irq::IrqError;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
/// Metadata only; no config writer, native context or numeric source grant.
#[derive(Clone)]
pub struct RequesterId(Arc<Identity>);
struct Identity {
    outstanding: AtomicUsize,
    detached: AtomicBool,
}
impl RequesterId {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Identity {
            outstanding: AtomicUsize::new(0),
            detached: AtomicBool::new(false),
        }))
    }
    pub fn same_requester(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn issue(&self) -> Result<(), IrqError> {
        if self.0.detached.load(Ordering::Acquire) {
            return Err(IrqError::Unregistered);
        }
        self.0
            .outstanding
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| IrqError::Exhausted)?;
        Ok(())
    }
    /// Invoked once by that affine grant's cancellation or exact action join.
    /// Unreturned/abandoned grants deliberately keep the count outstanding.
    pub(crate) fn complete_action(&self) -> Result<(), IrqError> {
        self.0
            .outstanding
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .map_err(|_| IrqError::Unregistered)?;
        Ok(())
    }
    pub(crate) fn check_detach(&self) -> Result<(), IrqError> {
        if self.0.detached.load(Ordering::Acquire)
            || self.0.outstanding.load(Ordering::Acquire) != 0
        {
            return Err(IrqError::Drain);
        }
        Ok(())
    }
    pub(crate) fn detached(&self) -> Result<(), IrqError> {
        self.check_detach()?;
        self.0
            .detached
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| IrqError::Unregistered)?;
        Ok(())
    }
}
