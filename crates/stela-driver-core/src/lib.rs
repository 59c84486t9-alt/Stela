//! Shared host-device resource contracts, independent of native driver execution.
#![no_std]
#[cfg_attr(test, macro_use)]
extern crate alloc;

/// Byte-field readers and CRCs, shared with the crates below the drivers.
pub use stela_contracts::{bytes, crc};
pub mod firmware;
