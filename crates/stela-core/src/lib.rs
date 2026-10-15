//! Build-pinned inventories, evidence and shared artifact identity hashing.
#![cfg_attr(not(feature = "hosted"), no_std)]
extern crate alloc;
mod hash;
pub use hash::sha256;

#[cfg(feature = "hosted")]
mod hosted;
#[cfg(feature = "hosted")]
pub use hosted::*;
