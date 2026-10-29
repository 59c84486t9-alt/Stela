//! Immutable memory-controller aperture topology.
pub mod t6020;
pub const PLANES: u8 = 4;
pub const PLANE_STRIDE: u64 = 0x40000;
pub const APERTURE_BYTES: u64 = 0x1000000;
