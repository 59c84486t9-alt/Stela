//! Shared artifact hashing, build inventories and progress records.
#![cfg_attr(not(feature = "hosted"), no_std)]
extern crate alloc;
mod hash;
pub use hash::sha256;

#[cfg(feature = "hosted")]
mod hosted;
#[cfg(feature = "hosted")]
pub use hosted::*;
