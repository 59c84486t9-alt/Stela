//! Failures of Metal operations on this device.
//!
//! `Invalid` is a call Metal's API validation rejects; the frontend returns
//! nil or an `NSError` as the framework would. `Unsupported` is a valid call
//! this device cannot honor, reported with the capability it lacks.
//! `HeapFull` and `NotArchived` are Metal's own nil answers, which are no
//! refusal of this device's.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The arguments violate Metal's documented contract.
    Invalid(&'static str),
    /// The call is valid Metal but this device lacks the capability.
    Unsupported(&'static str),
    /// The backend could not allocate memory or another object.
    OutOfMemory,
    /// An automatic heap has no free range for the resource. Metal answers
    /// nil, as it does when an Apple GPU's heap is full; the device has
    /// memory to spare.
    HeapFull,
    /// The GPU was lost or removed; every pending command fails.
    DeviceLost,
    /// No binary archive the creation may read holds the pipeline.
    NotArchived,
    /// A driver result the Metal layer has no answer of its own for: the
    /// raw `VkResult`, which a refusal names.
    Driver(i32),
}

pub type Result<T> = core::result::Result<T, Error>;

/// A library holds no function of the name asked for: invalid where a
/// pipeline or graph names it, and Metal's nil answer to
/// `newFunctionWithName:`, which callers probe libraries with.
pub const NO_FUNCTION: Error = Error::Invalid("no function of that name");

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
