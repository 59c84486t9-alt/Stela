//! Immutable register aperture geometry shared by parser and device model.
//! Offsets and extents imply no live mapping or device/lifecycle permission.
const CONTROL: u64 = 0x80;
pub const CPM_OFFSET: u64 = 0x48000;
pub const CONTROL_OFFSET: u64 = CONTROL;
pub const COUNTER_BYTES: u64 = 16;
pub const CORE_BYTES: u64 = 0x10000;
pub const CORE_OFFSET: u64 = 0x9000;
