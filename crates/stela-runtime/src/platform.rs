//! Host network and PC adapters.
pub mod net;
#[cfg(target_arch = "x86_64")]
pub mod pc;
