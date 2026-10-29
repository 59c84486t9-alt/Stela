//! AMCC lock-register and cache-aperture descriptors.
//! These describe decoded hardware layouts; controller construction and live
//! lifecycle/resource admission remain execution-model responsibilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Register {
    pub offset: u64,
    pub mask: u32,
    pub value: u32,
}

/// The lock groups a map can describe: CTRR-A to CTRR-D, in that order.
pub const GROUPS: usize = 4;

/// Each group's region iBoot programs into its limits: a base and a length
/// in bytes.
pub type Programmed = [Option<(u64, u64)>; GROUPS];

/// Each group's region locked against writes: first and last byte.
pub type Locked = [Option<(u64, u64)>; GROUPS];

/// What iBoot leaves when it programs CTRR-A alone.
pub const fn ctrr_a(region: Option<(u64, u64)>) -> Programmed {
    [region, None, None, None]
}

/// A lock group's registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockGroup {
    pub page_size_shift: u32,
    pub lower_limit: Register,
    pub upper_limit: Register,
    pub enable: Option<Register>,
    pub write_disable: Option<Register>,
    pub lock: Option<Register>,
}

/// One aperture's planes and registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub aperture_bytes: u64,
    pub planes: u32,
    pub stride: u64,
    pub cache_status: Option<Register>,
    /// CTRR-A to CTRR-D, as described; CTRR-A always is.
    pub groups: [Option<LockGroup>; GROUPS],
    /// The address limit 0 names.
    pub dram_base: u64,
}

/// The memory cache of an `mcc,t8112`, its blocks as aperture offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cache {
    /// The registers the planes share (`/arm-io/mcc` `reg[0]`): offset and
    /// bytes.
    pub shared: (u64, u64),
    /// The window whose writes reach every plane (`reg[3]`), one plane
    /// stride long.
    pub broadcast: u64,
    pub bytes: u64,
    pub ways: u32,
}
