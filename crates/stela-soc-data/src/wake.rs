//! Immutable register aperture geometry shared by parser and device model.
//! Offsets and extents imply no live mapping or device/lifecycle authority.
pub const WORDS: usize = 8;
pub const OFFSET: u64 = 8;
pub const BYTES: u64 = WORDS as u64 * 4;
