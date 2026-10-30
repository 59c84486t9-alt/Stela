//! Shared CPU descriptions and device boundaries used by loaders and engines.
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg_attr(all(test, not(feature = "std")), macro_use)]
extern crate alloc;

pub mod adt;
pub mod bus;
pub mod caches;
pub mod chip;
pub mod cpu_features;
pub mod ctrr;
pub mod dma;
pub mod gate;
pub mod identity;
pub mod interrupt;
pub mod pauth;
pub mod processor;
pub mod refusal;
pub mod tag_storage;

pub use chip::Chip;
pub use cpu_features::Feature;
pub use refusal::Refusal;
