//! Native AMD storage and command interfaces. Actual initialized-device,
//! reservation, mapping and completion services remain the caller's owners.
#[cfg(feature = "amd-commands")]
mod commands;
#[cfg(feature = "amd-commands")]
pub use commands::*;

#[cfg(feature = "amd-port")]
pub mod vm;
