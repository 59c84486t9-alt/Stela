//! Unwinding in host-side tools; the freestanding build aborts on panic.
#[cfg(feature = "std")]
pub(crate) use std::panic::catch_unwind as invoke;
#[cfg(feature = "std")]
pub(crate) use std::thread::panicking;

/// The crate rejects unwind panic without std. A panic never returns here or
/// releases resources into a resumable CPU phase; the platform must terminate.
#[cfg(not(feature = "std"))]
pub(crate) fn invoke<R>(action: impl FnOnce() -> R) -> Result<R, core::convert::Infallible> {
    Ok(action())
}

#[cfg(not(feature = "std"))]
pub(crate) fn panicking() -> bool {
    // There is no unwinding state on the required aborting target. Destructors
    // run only on ordinary return, never during panic recovery.
    false
}
