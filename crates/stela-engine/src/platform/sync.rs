//! Locks: std mutexes in host-side tools.
#[cfg(feature = "std")]
pub(crate) use std::sync::{Mutex, MutexGuard, PoisonError, RwLock};

#[cfg(not(feature = "std"))]
mod freestanding;
#[cfg(not(feature = "std"))]
pub use freestanding::set_wait;
#[cfg(not(feature = "std"))]
pub(crate) use freestanding::{Mutex, MutexGuard, PoisonError, RwLock};

/// A device model's own lock, of the board lock's kind, for state a device
/// shares between the PEs outside the board's lock
/// ([`crate::machine::engine::OwnLockRegisters`]).
pub struct DeviceLock<T>(Mutex<T>);

/// [`DeviceLock`]'s guard.
pub struct DeviceGuard<'a, T>(MutexGuard<'a, T>);

impl<T> DeviceLock<T> {
    pub fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }
    /// Wait for the lock.
    pub fn lock(&self) -> DeviceGuard<'_, T> {
        DeviceGuard(self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
    /// The lock if no one holds it now.
    pub fn try_lock(&self) -> Option<DeviceGuard<'_, T>> {
        self.0.try_lock().ok().map(DeviceGuard)
    }
}

impl<T> core::ops::Deref for DeviceGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> core::ops::DerefMut for DeviceGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
