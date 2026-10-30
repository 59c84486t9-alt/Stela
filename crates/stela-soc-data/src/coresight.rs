//! Immutable register aperture geometry shared by parser and device model.
//! Offsets and extents imply no live mapping or device/lifecycle permission.
pub const UTT_OFFSET: u64 = 0x3_0000;
pub const PC_SAMPLE: u64 = 0x90;
pub const STATUS: u64 = 0xfb4;
pub const BYTES: u64 = 0x1000;
