//! Explicit ARM commpage layouts for bounded Darwin execution.
//! Modern page-size fields live here; the legacy clock/tracing layout is in `legacy`.
//!
//! XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea:
//! osfmk/arm/cpu_capabilities.h and osfmk/arm/commpage/commpage.c.
//! Only the declared fields are implemented. Callers of unsafe native execution
//! must exclude reads of other fields; zero allocation padding has no ABI meaning.
use crate::memory::{MemoryRegion, MemoryRegionSpec, OwnedMemory};
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

/// An address-space-owned static mapping; no host pointer or writable alias escapes.
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

    /// Join the actual static backing to the process canonical domain.
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
mod tests {
    use super::*;

    #[test]
    fn arm64_page_sizes_are_explicit_owned_and_readonly() -> Result<()> {
        let _guard = crate::clock::TEST_CONTEXT_LOCK.lock().unwrap();
        for kernel in [KernelPageSize::FourKiB, KernelPageSize::SixteenKiB] {
            let mut context = Context::new(71, kernel)?;
            assert_eq!(context.address_space(), 71);
            assert_eq!(context.profile_id(), PROFILE_ID);
            let region = context.region();
            assert_eq!(region.guest_address, GUEST_BASE);
            assert_eq!(region.virtual_bytes, GUEST_BYTES as u64);
            assert!(region.readable && !region.writable && !region.executable);
            let fields = context.supported_fields();
            assert_eq!(fields[0].value, 14);
            assert_eq!(fields[1].value, kernel.shift());
            let bytes = context.snapshot_bytes()?;
            for field in fields {
                assert_eq!(field.bytes, 1);
                assert_eq!(bytes[(field.address - GUEST_BASE) as usize], field.value);
            }
            assert!(context.memory.write(GUEST_BASE + 0x25, &[12]).is_err());
            assert!(Context::new(72, kernel).is_err());
            assert_eq!(context.snapshot_bytes()?, bytes);
            // Dropping this owner releases the fixed address for the next profile.
        }
        Ok(())
    }
}
