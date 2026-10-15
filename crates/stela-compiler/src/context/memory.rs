//! Versioned native memory-service ABI shared by scalable and exclusive accesses.
//!
//! Requests describe one reached architectural element, never an instruction's
//! speculative footprint. The runtime splits its exact atomic quantities. Data points to private staging, not guest RAM.

use std::ffi::c_void;

pub const MEMORY_CONTEXT_VERSION: u32 = 1;
pub const MEMORY_CONTEXT_BYTES: u32 = 64;
pub const MEMORY_CALLBACK_OFFSET: u32 = 8;
pub const MEMORY_REQUEST_BYTES: usize = 32;
pub const MEMORY_REQUEST_ADDRESS_OFFSET: u32 = 0;
pub const MEMORY_REQUEST_DATA_OFFSET: u32 = 8;
pub const MEMORY_REQUEST_LENGTH_OFFSET: u32 = 16;
pub const MEMORY_REQUEST_FLAGS_OFFSET: u32 = 20;
pub const MEMORY_REQUEST_PC_OFFSET: u32 = 24;

/// Access descriptor bits retain architectural intent across the native ABI.
pub mod flags {
    pub const WRITE: u32 = 1 << 0;
    pub const TAG_CHECKED: u32 = 1 << 1;
    pub const NON_TEMPORAL: u32 = 1 << 2;
    pub const SME: u32 = 1 << 3;
    /// CreateAccDescSVE with predicated=true; SME accesses never acquire this
    /// descriptor's special two-doubleword splitting rule.
    pub const SVE_PREDICATED: u32 = 1 << 4;
    pub const ASIMD: u32 = 1 << 5;
    pub const KNOWN: u32 = WRITE | TAG_CHECKED | NON_TEMPORAL | SME | SVE_PREDICATED | ASIMD;
}

/// Requirements derived from and bound to one consumed native body. `None`
/// at a containing manifest means absent metadata, not these empty requirements.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRequirements {
    pub required_flags: u32,
    pub required_host_caps: u32,
    pub required_profile: u32,
}

pub mod host_caps {
    pub const ATOMIC_LOAD16: u32 = 1 << 0;
    pub const CX16: u32 = 1 << 1;
    pub const KNOWN: u32 = ATOMIC_LOAD16 | CX16;
}

pub mod profile_requirements {
    /// Native Normal-WB/SCA16 data access, with alignment enforcement and CPA2 off.
    pub const NATIVE_ACCESS: u32 = 1 << 0;
    /// Physical allocation-tag granules retain guest/physical alignment.
    pub const TAG_GRANULES: u32 = 1 << 1;
    pub const KNOWN: u32 = NATIVE_ACCESS | TAG_GRANULES;
}

/// Explicit runtime outcomes; only Success permits architectural load commits.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryStatus {
    Success = 0,
    Translation = 1,
    Permission = 2,
    Alignment = 3,
    TagCheck = 4,
    Unsupported = 5,
    InvalidRequest = 6,
    Domain = 7,
}

impl MemoryStatus {
    pub fn from_code(code: u32) -> Option<Self> {
        [
            Self::Success,
            Self::Translation,
            Self::Permission,
            Self::Alignment,
            Self::TagCheck,
            Self::Unsupported,
            Self::InvalidRequest,
            Self::Domain,
        ]
        .into_iter()
        .find(|status| *status as u32 == code)
    }
}

/// Buffer bytes are little endian. Reads may change staging before a later part
/// fails; callers must commit destinations only after every read succeeds.
#[repr(C)]
#[derive(Debug)]
pub struct MemoryRequest {
    pub address: u64,
    pub data: *mut u8,
    pub bytes: u32,
    pub flags: u32,
    pub pc: u64,
}

pub type MemoryCallback =
    unsafe extern "C" fn(context: *mut MemoryContextView, request: *const MemoryRequest) -> u32;

/// Borrowed dispatch view. Its owner retains resolver, tag and monitor state.
/// Callback failures preserve a diagnostic record after native stack unwind.
#[repr(C)]
#[derive(Debug)]
pub struct MemoryContextView {
    pub version: u32,
    pub bytes: u32,
    pub callback: MemoryCallback,
    pub opaque: *mut c_void,
    pub fault_kind: u32,
    pub reserved: u32,
    pub fault_address: u64,
    pub fault_pc: u64,
    pub completed_bytes: u64,
    pub reserved_tail: u64,
}

impl MemoryContextView {
    pub const fn has_supported_header(&self) -> bool {
        self.version == MEMORY_CONTEXT_VERSION
            && self.bytes >= MEMORY_CONTEXT_BYTES
            && self.reserved == 0
            && self.reserved_tail == 0
    }

    pub fn record(&mut self, status: MemoryStatus, address: u64, pc: u64, completed: u64) {
        self.fault_kind = status as u32;
        self.fault_address = address;
        self.fault_pc = pc;
        self.completed_bytes = completed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::offset_of;

    #[test]
    fn request_and_callback_offsets_match_native_contract() {
        assert_eq!(size_of::<MemoryRequest>(), MEMORY_REQUEST_BYTES);
        assert_eq!(
            offset_of!(MemoryRequest, address),
            MEMORY_REQUEST_ADDRESS_OFFSET as usize
        );
        assert_eq!(
            offset_of!(MemoryRequest, data),
            MEMORY_REQUEST_DATA_OFFSET as usize
        );
        assert_eq!(
            offset_of!(MemoryRequest, bytes),
            MEMORY_REQUEST_LENGTH_OFFSET as usize
        );
        assert_eq!(
            offset_of!(MemoryRequest, flags),
            MEMORY_REQUEST_FLAGS_OFFSET as usize
        );
        assert_eq!(
            offset_of!(MemoryRequest, pc),
            MEMORY_REQUEST_PC_OFFSET as usize
        );
        assert_eq!(
            size_of::<MemoryContextView>(),
            MEMORY_CONTEXT_BYTES as usize
        );
        assert_eq!(
            offset_of!(MemoryContextView, callback),
            MEMORY_CALLBACK_OFFSET as usize
        );
    }
}
