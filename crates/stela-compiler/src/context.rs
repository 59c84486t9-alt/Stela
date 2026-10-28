//! Execution context passed to native code using the context ABI.

pub mod memory;
pub mod pointer;
use core::ffi::c_void;

pub const EXECUTION_CONTEXT_VERSION: u32 = 1;
pub const EXECUTION_CONTEXT_BYTES: u32 = 32;
pub const CONTEXT_LEAF_ABI: &str = "x86_64-sysv-guest-state-v3-context-memory-v2-direct-ram";
pub const CONTEXT_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v3-context-memory-v2-block-exit-direct-ram";
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

/// Scalable register storage. `GuestState::v` holds the low 128 bits of each Z
/// register. The runtime owns the allocations and keeps them in place during
/// native entry; mode changes go through the runtime so that reset and
/// allocation stay atomic.
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
mod tests {
    use super::*;

    #[test]
    fn execution_context_layout_matches_native_offsets() {
        assert_eq!(
            core::mem::size_of::<ExecutionContext>(),
            EXECUTION_CONTEXT_BYTES as usize
        );
        assert_eq!(core::mem::align_of::<ExecutionContext>(), 8);
        assert_eq!(core::mem::offset_of!(ExecutionContext, version), 0);
        assert_eq!(core::mem::offset_of!(ExecutionContext, bytes), 4);
        assert_eq!(
            core::mem::offset_of!(ExecutionContext, memory),
            EXECUTION_CONTEXT_MEMORY_OFFSET as usize
        );
        assert_eq!(
            core::mem::offset_of!(ExecutionContext, scalable),
            EXECUTION_CONTEXT_SCALABLE_OFFSET as usize
        );
        assert_eq!(
            core::mem::offset_of!(ExecutionContext, system),
            EXECUTION_CONTEXT_SYSTEM_OFFSET as usize
        );
        assert!(ExecutionContext::default().has_supported_header());
        let mut context = ExecutionContext::default();
        context.bytes -= 1;
        assert!(!context.has_supported_header());
        context.bytes = EXECUTION_CONTEXT_BYTES + 8;
        assert!(context.has_supported_header());
        context.version += 1;
        assert!(!context.has_supported_header());
    }

    #[test]
    fn scalable_view_layout_matches_native_offsets() {
        assert_eq!(
            core::mem::size_of::<ScalableStateView>(),
            SCALABLE_STATE_VIEW_BYTES
        );
        assert_eq!(core::mem::align_of::<ScalableStateView>(), 8);
        assert_eq!(
            core::mem::offset_of!(ScalableStateView, svl_bytes),
            SCALABLE_SVL_OFFSET as usize
        );
        assert_eq!(
            core::mem::offset_of!(ScalableStateView, svcr),
            SCALABLE_SVCR_OFFSET as usize
        );
        assert_eq!(
            core::mem::offset_of!(ScalableStateView, tpidr2_el0),
            SCALABLE_TPIDR2_OFFSET as usize
        );
        assert_eq!(
            core::mem::offset_of!(ScalableStateView, fpmr),
            SCALABLE_FPMR_OFFSET as usize
        );
        assert_eq!(
            core::mem::offset_of!(ScalableStateView, z_upper),
            SCALABLE_Z_UPPER_OFFSET as usize
        );
        assert_eq!(
            core::mem::offset_of!(ScalableStateView, predicates),
            SCALABLE_PREDICATES_OFFSET as usize
        );
        assert_eq!(
            core::mem::offset_of!(ScalableStateView, ffr),
            SCALABLE_FFR_OFFSET as usize
        );
        assert_eq!(
            core::mem::offset_of!(ScalableStateView, za),
            SCALABLE_ZA_OFFSET as usize
        );
        assert_eq!(
            core::mem::offset_of!(ScalableStateView, zt0),
            SCALABLE_ZT0_OFFSET as usize
        );
    }
}
