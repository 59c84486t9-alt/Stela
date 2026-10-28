//! Locks: std mutexes in host-side tools.
#[cfg(feature = "std")]
pub(crate) use std::sync::{Mutex, MutexGuard, PoisonError, RwLock};

#[cfg(not(feature = "std"))]
mod freestanding;
#[cfg(not(feature = "std"))]
pub(crate) use freestanding::{Mutex, MutexGuard, PoisonError, RwLock};
