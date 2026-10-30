//! Failures of Metal operations on this device.
//!
//! `Invalid` is a call Metal's API validation rejects; the frontend returns
//! nil or an `NSError` as the framework would. `Unsupported` is a valid call
//! this device cannot honor, reported with the capability it lacks.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The arguments violate Metal's documented contract.
    Invalid(&'static str),
    /// The call is valid Metal but this device lacks the capability.
    Unsupported(&'static str),
    /// The backend could not allocate memory or another object.
    OutOfMemory,
    /// The GPU was lost or removed; every pending command fails.
    DeviceLost,
}

pub type Result<T> = core::result::Result<T, Error>;

/// Fails with `Invalid(reason)` unless `condition` holds.
pub(crate) fn ensure(condition: bool, reason: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::Invalid(reason))
    }
}

/// Fails with `Unsupported(capability)` unless `condition` holds.
pub(crate) fn require(condition: bool, capability: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::Unsupported(capability))
    }
}
