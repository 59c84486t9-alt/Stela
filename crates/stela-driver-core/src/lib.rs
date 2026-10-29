//! Shared host-device resource contracts, independent of native driver execution.
#![no_std]
#[cfg_attr(test, macro_use)]
extern crate alloc;

pub mod bytes;
pub mod firmware;
