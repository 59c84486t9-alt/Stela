//! Immutable ANS queue and namespace descriptions.
mod geometry;
mod namespace;
pub use geometry::{NVMMU_CONTROL, QueueGeometry};
pub use namespace::{BLOCK_BYTES, Description};

pub const REGISTER_BYTES: u64 = 0x28134;
pub const VDMA_CACHE_OFFSET: u64 = 0x2_0000;
