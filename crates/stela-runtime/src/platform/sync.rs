//! Locks: std mutexes when hosted.
#[cfg(feature = "std")]
pub(crate) use std::sync::{Mutex, MutexGuard, PoisonError, RwLock};

#[cfg(not(feature = "std"))]
mod freestanding;
#[cfg(not(feature = "std"))]
pub(crate) use freestanding::{Mutex, MutexGuard, PoisonError, RwLock};
