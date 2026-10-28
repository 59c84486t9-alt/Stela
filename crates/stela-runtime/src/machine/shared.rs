//! State that PEs of one cluster share. Each PE may run on its own host core,
//! so a share is a lock, not a `RefCell`.
use crate::platform::sync::{Mutex, MutexGuard};
use alloc::sync::Arc;

/// One value shared by every PE that holds a clone.
#[derive(Debug)]
pub struct Shared<T>(Arc<Mutex<T>>);

impl<T> Shared<T> {
    pub fn new(value: T) -> Self {
        Self(Arc::new(Mutex::new(value)))
    }

    /// Exclusive access until the guard drops. No guard may be held across
    /// another `Shared` borrow, so lock order never matters.
    pub(crate) fn borrow(&self) -> MutexGuard<'_, T> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn borrow_mut(&self) -> MutexGuard<'_, T> {
        self.borrow()
    }

    pub(crate) fn replace(&self, value: T) -> T {
        core::mem::replace(&mut *self.borrow(), value)
    }

    /// Whether both handles share one value.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<T: Default> Default for Shared<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
