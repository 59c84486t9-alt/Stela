//! Native memory-service ABI used by scalable and exclusive accesses. Each
//! request describes one architectural element; data points to private staging.

use core::ffi::c_void;

mod operation;
pub use operation::{MemoryOperationClass, MemoryOrder};
pub mod address;
pub mod exclusive;

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
    /// Ordinary Mem accessor pair metadata. Atomic/exclusive pairs use their
    /// dedicated category and must never enter ordinary decomposition.
    pub const PAIR: u32 = 1 << 6;
    /// Reserved category allocations; ordinary dispatch rejects them. Their
    /// owners must add reviewed routing before extending global KNOWN.
    pub const ATOMIC: u32 = 1 << 7;
    pub const ORDERED: u32 = 1 << 8;
    pub const EXCLUSIVE: u32 = 1 << 9;
    pub const ORDINARY_KNOWN: u32 =
        WRITE | TAG_CHECKED | NON_TEMPORAL | SME | SVE_PREDICATED | ASIMD | PAIR;
    pub const KNOWN: u32 = ORDINARY_KNOWN | ATOMIC | ORDERED | EXCLUSIVE;
}

/// Requirements derived from and bound to one consumed native body. `None`
/// at a containing manifest means absent metadata, not these empty requirements.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemoryRequirements {
    pub required_flags: u32,
    pub required_host_caps: u32,
    pub required_profile: u32,
    pub required_sp_alignment: SpAlignmentRequirement,
    /// Original source AddressAdd and constrained AddressIncrement effects.
    #[serde(
        default,
        skip_serializing_if = "address::AddressCheckRequirements::is_empty"
    )]
    pub required_address_checks: address::AddressCheckRequirements,
    /// Feature-qualified CPA arithmetic at the original current EL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_pointer_arithmetic: Option<crate::context::pointer::PointerArithmeticRequirement>,
}

/// Original-SP checking specialized into one consumed native body. This is
/// a requirement on the effective CPU policy, never a copy of CPU control state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SpAlignmentRequirement {
    #[default]
    Any,
    Enabled,
    Disabled,
}

/// Named implementation identity for the current scalable memory artifacts.
/// The supported identity selects both independent SVE-streaming SIMD/FP and
/// SME-LDR/STR tag-suppression choices false, and selects
/// the permitted CHECKSPNONEACTIVE=true translation policy. Suppression is a
/// known CPU implementation choice, explicitly unsupported by these bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryImplementationProfile {
    ScalableTagChecks,
    StreamingSveTagSuppression,
    SmeTagSuppression,
}

pub const MEMORY_IMPLEMENTATION_PROFILE_ID: &str =
    "scalable-memory-tags-checked-checkspnoneactive-v2";

impl MemoryRequirements {
    /// Combine requirements for one consumed body. Opposite SP specializations
    /// cannot share a single effective-control policy and must fail compilation.
    pub fn merge(self, other: Self) -> Option<Self> {
        let required_sp_alignment = match (self.required_sp_alignment, other.required_sp_alignment)
        {
            (SpAlignmentRequirement::Any, requirement)
            | (requirement, SpAlignmentRequirement::Any) => requirement,
            (first, second) if first == second => first,
            _ => return None,
        };
        let required_pointer_arithmetic = match (
            self.required_pointer_arithmetic,
            other.required_pointer_arithmetic,
        ) {
            (None, required) | (required, None) => required,
            (Some(first), Some(second)) if first == second => Some(first),
            _ => return None,
        };
        let required_address_checks = self
            .required_address_checks
            .merge(other.required_address_checks)?;
        if let Some(required) = required_pointer_arithmetic
            && !required_address_checks.compatible_arithmetic(required)
        {
            return None;
        }
        Some(Self {
            required_flags: self.required_flags | other.required_flags,
            required_host_caps: self.required_host_caps | other.required_host_caps,
            required_profile: self.required_profile | other.required_profile,
            required_sp_alignment,
            required_address_checks,
            required_pointer_arithmetic,
        })
    }
}

pub mod host_caps {
    pub const ATOMIC_LOAD16: u32 = 1 << 0;
    pub const CX16: u32 = 1 << 1;
    pub const KNOWN: u32 = ATOMIC_LOAD16 | CX16;
}

pub mod profile_requirements {
    /// Native Normal-WB/SCA16 data access with AlignmentEnforced=false.
    /// CPA arithmetic/address specialization is separately typed and validated.
    /// Original-SP checking is separately specialized and validated.
    pub const NATIVE_ACCESS: u32 = 1 << 0;
    /// Physical allocation-tag granules retain guest/physical alignment.
    pub const TAG_GRANULES: u32 = 1 << 1;
    /// Require the fixed named implementation identity above. This is a body
    /// requirement, never a raw access descriptor or a copy of CPU controls.
    pub const SCALABLE_TAG_CHECKS: u32 = 1 << 2;
    /// Source-bound EL1 MMU-off staged Device RAM read64. No Normal-WB,
    /// allocation-tag or host-pointer permission is conferred by this bit.
    pub const M0_DEVICE_RAM_READ64: u32 = 1 << 3;
    /// Same-owner MMU-off Device RAM write8/pair. No Normal-WB or host-pointer
    /// authority: each reached aligned8B member needs the real source loan.
    pub const M0_DEVICE_RAM_WRITE8_OR_PAIR: u32 = 1 << 4;
    /// Same-owner MMU-off Device pair reads with actual no-LSE2 qualification.
    pub const M0_DEVICE_RAM_READ64_PAIR_NO_LSE2: u32 = 1 << 5;
    /// Source-bound EL1 MMU-off scalar loads of exactly 1/2/4/8 bytes. Actual
    /// controls, original-SP alignment and physical ordered access remain owned
    /// by the runtime; no Normal-WB, tag-plane or host-pointer loan is implied.
    pub const M0_DEVICE_RAM_SCALAR_LOAD: u32 = 1 << 6;
    pub const KNOWN: u32 = NATIVE_ACCESS
        | TAG_GRANULES
        | SCALABLE_TAG_CHECKS
        | M0_DEVICE_RAM_READ64
        | M0_DEVICE_RAM_WRITE8_OR_PAIR
        | M0_DEVICE_RAM_READ64_PAIR_NO_LSE2
        | M0_DEVICE_RAM_SCALAR_LOAD;
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
    /// Original SP alignment fault, distinct from data-access alignment.
    StackAlignment = 8,
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
            Self::StackAlignment,
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

impl MemoryRequest {
    /// The ordinary Mem category only. Reserved atomic/ordered categories have
    /// separate exact operations and must never acquire mechanical splitting.
    pub const fn has_supported_ordinary_shape(&self) -> bool {
        if self.flags & !flags::ORDINARY_KNOWN != 0 {
            return false;
        }
        let asimd = self.flags & flags::ASIMD != 0;
        let pair = self.flags & flags::PAIR != 0;
        if (asimd || pair) && self.flags & (flags::SME | flags::SVE_PREDICATED) != 0 {
            return false;
        }
        if pair {
            matches!(self.bytes, 8 | 16) || self.bytes == 32 && asimd
        } else {
            matches!(self.bytes, 1 | 2 | 4 | 8 | 16)
        }
    }
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
mod tests;
