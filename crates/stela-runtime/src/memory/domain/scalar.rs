//! Scalar reads through the existing native memory-service boundary.

use super::{
    AllocationTagPolicy, DataPolicy, MemoryRequest, MemoryStatus, MemoryThread, SCA_BYTES, flags,
};
use stela_compiler::context::memory::{MemoryRequirements, profile_requirements};

// Only ordinary read descriptors fit this service's private scalar staging.
// This whitelist remains safe when the global ABI gains typed payload classes.
const SCALAR_READ_FLAGS: u32 =
    flags::TAG_CHECKED | flags::NON_TEMPORAL | flags::SME | flags::SVE_PREDICATED | flags::ASIMD;

/// A scalar read fault with the original guest source location and read prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct MemoryFault {
    #[serde(serialize_with = "serialize_status")]
    pub status: MemoryStatus,
    pub address: u64,
    pub pc: u64,
    pub completed_bytes: u64,
}

fn serialize_status<S: serde::Serializer>(
    status: &MemoryStatus,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u32(*status as u32)
}

impl core::fmt::Display for MemoryFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "scalar read failed at {:#x} (PC {:#x}) after {} bytes: {:?}",
            self.address, self.pc, self.completed_bytes, self.status
        )
    }
}

impl core::error::Error for MemoryFault {}

/// Borrow the executing thread's memory policy without erasing its owner.
pub trait MemoryReader {
    fn address_space(&self) -> Option<u64>;

    fn validate_privilege(&self, privileged: bool) -> Result<(), MemoryStatus>;

    fn read_scalar(
        &mut self,
        address: u64,
        bytes: u8,
        required_flags: u32,
        guestpc: u64,
    ) -> Result<u128, MemoryFault>;
}

impl<P: AllocationTagPolicy> MemoryReader for MemoryThread<P> {
    fn address_space(&self) -> Option<u64> {
        MemoryThread::address_space(self)
    }

    fn validate_privilege(&self, privileged: bool) -> Result<(), MemoryStatus> {
        self.policy.validate_privilege(privileged)
    }

    fn read_scalar(
        &mut self,
        address: u64,
        bytes: u8,
        required_flags: u32,
        guestpc: u64,
    ) -> Result<u128, MemoryFault> {
        MemoryThread::read_scalar(self, address, bytes, required_flags, guestpc)
    }
}

impl<P: DataPolicy> MemoryThread<P> {
    /// Read an exact scalar into private staging, committing a value on success.
    ///
    /// `address` retains its raw logical tag for the thread's data policy. The
    /// checked service supplies translation, rights, tags, atomic parts and
    /// reservation cleanup. The backing's unsafe construction contract pins
    /// native storage and rights; this method creates no references to guest RAM.
    /// Unsupported host footprints remain explicit service failures. Partial
    /// reads remain private and only their diagnostic byte count is returned.
    pub fn read_scalar(
        &mut self,
        address: u64,
        bytes: u8,
        required_flags: u32,
        guestpc: u64,
    ) -> Result<u128, MemoryFault> {
        if required_flags & !SCALAR_READ_FLAGS != 0 || !matches!(bytes, 1 | 2 | 4 | 8 | 16) {
            return Err(MemoryFault {
                status: MemoryStatus::InvalidRequest,
                address,
                pc: guestpc,
                completed_bytes: 0,
            });
        }
        let entry = self
            .prepare(MemoryRequirements {
                required_flags,
                required_profile: profile_requirements::NATIVE_ACCESS
                    | if required_flags & flags::TAG_CHECKED != 0 {
                        profile_requirements::TAG_GRANULES
                    } else {
                        0
                    },
                ..MemoryRequirements::default()
            })
            .map_err(|status| MemoryFault {
                status,
                address,
                pc: guestpc,
                completed_bytes: 0,
            })?;
        let mut staging = [0; SCA_BYTES];
        let request = MemoryRequest {
            address,
            data: staging.as_mut_ptr(),
            bytes: u32::from(bytes),
            flags: required_flags,
            pc: guestpc,
        };
        // SAFETY: entry checks the native mapping profile and effective policy;
        // this invocation constructs valid ABI objects and private, disjoint
        // staging. Reached host recipes remain checked by the actual service.
        // Keep diagnostics outside R: checked finalization may discard the
        // callback result after real native reads have filled private staging.
        let mut observed = MemoryFault {
            status: MemoryStatus::Domain,
            address,
            pc: guestpc,
            completed_bytes: 0,
        };
        let finalized = unsafe {
            entry.with_checked_view(|view| {
                let code = (view.callback)(view, &request);
                let decoded = MemoryStatus::from_code(code);
                let callback_fault =
                    matches!(decoded, Some(status) if status != MemoryStatus::Success);
                observed = MemoryFault {
                    status: decoded.unwrap_or(MemoryStatus::Domain),
                    address: if callback_fault {
                        view.fault_address
                    } else {
                        address
                    },
                    pc: if callback_fault {
                        view.fault_pc
                    } else {
                        guestpc
                    },
                    completed_bytes: view.completed_bytes,
                };
            })
        };
        if let Err(status) = finalized {
            return Err(MemoryFault { status, ..observed });
        }
        if observed.status != MemoryStatus::Success {
            return Err(observed);
        }
        Ok(u128::from_le_bytes(staging))
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "scalar/tests.rs"]
mod tests;
