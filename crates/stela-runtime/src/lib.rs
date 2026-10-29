//! Native board composition, device models, restore and host I/O adapters.
//!
//! Generic ARM execution belongs to `stela_engine`; immutable shared formats
//! and contracts belong to their foundational crates.
#![cfg_attr(not(feature = "std"), no_std)]
#[macro_use]
extern crate alloc;

pub use stela_contracts::Refusal;

/// A refused request names the values that decided it.
pub type Result<T, E = Refusal> = core::result::Result<T, E>;

mod checksum;
pub mod machine;
mod platform;
pub mod restore;
pub mod translation_store;
/// Native network protocols over a raw Ethernet link.
pub use platform::net;
/// PC storage and firmware services used by the native UEFI mount.
#[cfg(target_arch = "x86_64")]
pub use platform::pc;

#[cfg(test)]
pub mod research;
