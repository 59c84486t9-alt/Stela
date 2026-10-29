//! Immutable UAT page granule; not a live GPU address-space owner.
pub const PAGE_SHIFT: u32 = 14;
pub const PAGE_BYTES: u64 = 1 << PAGE_SHIFT;
