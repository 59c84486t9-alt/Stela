//! Execution context passed to native code using the extended ABI.

pub mod memory;
pub mod pointer;
use core::ffi::c_void;

pub const EXECUTION_CONTEXT_VERSION: u32 = 1;
pub const EXECUTION_CONTEXT_BYTES: u32 = 32;
pub const CONTEXT_LEAF_ABI: &str = "x86_64-sysv-guest-state-v1-context-direct-ram";
pub const CONTEXT_BLOCK_ABI: &str = "x86_64-sysv-guest-state-v1-context-block-exit-direct-ram";
pub const SCALABLE_STATE_VIEW_BYTES: usize = 72;
pub const EXECUTION_CONTEXT_MEMORY_OFFSET: u32 = 8;
pub const EXECUTION_CONTEXT_SCALABLE_OFFSET: u32 = 16;
pub const EXECUTION_CONTEXT_SYSTEM_OFFSET: u32 = 24;
pub const SCALABLE_SVL_OFFSET: u32 = 0;
pub const SCALABLE_SVCR_OFFSET: u32 = 8;
pub const SCALABLE_TPIDR2_OFFSET: u32 = 16;
pub const SCALABLE_FPMR_OFFSET: u32 = 24;
pub const SCALABLE_Z_UPPER_OFFSET: u32 = 32;
pub const SCALABLE_PREDICATES_OFFSET: u32 = 40;
pub const SCALABLE_FFR_OFFSET: u32 = 48;
pub const SCALABLE_ZA_OFFSET: u32 = 56;
pub const SCALABLE_ZT0_OFFSET: u32 = 64;

/// System V extended entry arguments are GuestState in RDI and this view in RSI.
/// The emitter preserves the context in R15. Null pointers denote unavailable
/// services; execution must validate the requested profile before native entry.
#[repr(C)]
#[derive(Debug)]
pub struct ExecutionContext {
    pub version: u32,
    pub bytes: u32,
    pub memory: *mut c_void,
    pub scalable: *mut ScalableStateView,
    pub system: *mut c_void,
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self {
            version: EXECUTION_CONTEXT_VERSION,
            bytes: EXECUTION_CONTEXT_BYTES,
            memory: core::ptr::null_mut(),
            scalable: core::ptr::null_mut(),
            system: core::ptr::null_mut(),
        }
    }
}

impl ExecutionContext {
    pub const fn has_supported_header(&self) -> bool {
        self.version == EXECUTION_CONTEXT_VERSION && self.bytes >= EXECUTION_CONTEXT_BYTES
    }
}

/// Borrowed scalable storage. GuestState.v is the sole owner of low128 Z bits.
/// Runtime owns backing allocations and keeps them fixed during native entry.
/// Mode changes go through the runtime so reset and allocation remain atomic.
#[repr(C)]
#[derive(Debug)]
pub struct ScalableStateView {
    pub svl_bytes: u16,
    pub reserved: [u8; 6],
    pub svcr: u64,
    pub tpidr2_el0: u64,
    pub fpmr: u64,
    pub z_upper: *mut u8,
    pub predicates: *mut u8,
    pub ffr: *mut u8,
    pub za: *mut u8,
    pub zt0: *mut u8,
}

#[cfg(test)]
mod tests;
