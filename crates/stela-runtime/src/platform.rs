//! Native device execution models and host I/O adapters.
pub(crate) mod apple;
pub mod net;
#[cfg(target_arch = "x86_64")]
pub mod pc;
pub(crate) mod usb;
