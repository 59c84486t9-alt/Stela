//! ARM commpage layouts. Page-size fields live here; the legacy clock and
//! tracing layout is in `legacy`. Only the declared fields are implemented
//! (XNU `osfmk/arm/cpu_capabilities.h`, `osfmk/arm/commpage/commpage.c`).
use crate::memory::{MemoryRegion, MemoryRegionSpec, OwnedMemory};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use anyhow::Result;
use serde::Serialize;

pub mod legacy;

pub const PROFILE_ID: &str = "darwin-arm64-page-sizes-v1";
pub const GUEST_BASE: u64 = 0xfffff4000;
pub const GUEST_BYTES: usize = 16 * 1024;
pub const USER_PAGE_SHIFT_64: usize = 0x25;
pub const KERNEL_PAGE_SHIFT: usize = 0x37;
pub const ARM64_USER_PAGE_SHIFT: u8 = 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelPageSize {
    FourKiB,
    SixteenKiB,
}
impl KernelPageSize {
    pub const fn shift(self) -> u8 {
        match self {
            Self::FourKiB => 12,
            Self::SixteenKiB => 14,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Field {
    pub address: u64,
    pub bytes: usize,
    pub value: u8,
}

/// A static mapping owned by the address space; no host pointer or writable
/// alias escapes.
#[derive(Debug)]
pub struct Context {
    address_space: u64,
    kernel: KernelPageSize,
    memory: OwnedMemory,
}
impl Context {
    pub fn new(address_space: u64, kernel: KernelPageSize) -> Result<Self> {
        let mut bytes = vec![0; GUEST_BYTES];
        bytes[USER_PAGE_SHIFT_64] = ARM64_USER_PAGE_SHIFT;
        bytes[KERNEL_PAGE_SHIFT] = kernel.shift();
        let memory = OwnedMemory::map(vec![MemoryRegionSpec {
            guest_address: GUEST_BASE,
            virtual_bytes: GUEST_BYTES as u64,
            initial_bytes: bytes,
            readable: true,
            writable: false,
            executable: false,
        }])?;
        Ok(Self {
            address_space,
            kernel,
            memory,
        })
    }

    /// Add the static backing to the process's memory domain.
    pub fn shared_memory_participant(&mut self) -> crate::memory::SharedMemoryParticipant<'_> {
        crate::memory::SharedMemoryParticipant::owned(&mut self.memory, self.address_space)
    }

    pub fn address_space(&self) -> u64 {
        self.address_space
    }
    pub fn profile_id(&self) -> &'static str {
        PROFILE_ID
    }
    pub fn region(&self) -> &MemoryRegion {
        &self.memory.regions()[0]
    }
    pub fn supported_fields(&self) -> [Field; 2] {
        [
            Field {
                address: GUEST_BASE + USER_PAGE_SHIFT_64 as u64,
                bytes: 1,
                value: ARM64_USER_PAGE_SHIFT,
            },
            Field {
                address: GUEST_BASE + KERNEL_PAGE_SHIFT as u64,
                bytes: 1,
                value: self.kernel.shift(),
            },
        ]
    }
    pub fn snapshot_bytes(&self) -> Result<Vec<u8>> {
        self.memory.read_snapshot(GUEST_BASE, GUEST_BYTES)
    }
}

#[cfg(test)]
mod tests;
