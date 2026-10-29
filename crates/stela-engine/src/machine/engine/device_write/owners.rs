//! Sequential real memory/CPU borrows of one stopped synchronous write owner.
use super::*;
use crate::memory::{CanonicalRamService, RegisteredSystemRam};
use stela_contracts::refuse;

pub(in crate::machine::engine) mod sealed {
    pub trait Sealed {}
}
/// Only the recovered write owner can create either borrowing phase. The
/// mutable borrow prevents a RAM guard and CPU/native mutation lease coexisting.
pub trait CanonicalDeviceWrite: sealed::Sealed {
    fn memory(&mut self) -> Result<CanonicalWriteMemory<'_>, DeviceError>;
    fn processors(&mut self) -> Result<ProcessorWrite<'_>, DeviceError>;
}

/// Real canonical all-writer gates, kept until this phase ends. Every
/// assigned physical owner already completed its fence and remains held in the
/// same generation. Only the selected source owner/BSP helper can act here.
pub struct CanonicalWriteMemory<'a> {
    memory: CanonicalRamService<'a>,
    host: &'a mut dyn Host,
}
impl<'a> CanonicalWriteMemory<'a> {
    /// A serialized PE's borrow: every assigned worker is held, so only this
    /// BSP's own stores need the fence.
    pub(in crate::machine::engine) fn serial(
        memory: CanonicalRamService<'a>,
        host: &'a mut dyn Host,
    ) -> Self {
        Self { memory, host }
    }
}
impl super::super::device_read::sealed::Sealed for CanonicalWriteMemory<'_> {}
impl CanonicalDeviceMemory for CanonicalWriteMemory<'_> {
    fn memory(&self) -> &CanonicalRamService<'_> {
        &self.memory
    }
    fn fence_cpu_memory(&mut self) {
        // Other workers' fences remain completed under the unchanged
        // hold; no external/queued producer or device reentrancy is admitted.
        self.host.memory_barrier();
    }
}

pub(super) struct WriteOwners<'a> {
    ram: &'a RegisteredSystemRam,
    held: &'a publication::StoppedWorkers,
    processors: ProcessorWrite<'a>,
}
impl<'a> WriteOwners<'a> {
    pub(super) fn new(
        ram: &'a RegisteredSystemRam,
        held: &'a publication::StoppedWorkers,
        processors: ProcessorWrite<'a>,
    ) -> Self {
        Self {
            ram,
            held,
            processors,
        }
    }
    fn validate(&self) -> Result<(), DeviceError> {
        self.processors.require_native_hold(self.held).map_err(|_| {
            DeviceError::TransferRefused(refuse!(
                "canonical write lost its actual stopped generation"
            ))
        })
    }
}
impl sealed::Sealed for WriteOwners<'_> {}
impl CanonicalDeviceWrite for WriteOwners<'_> {
    fn memory(&mut self) -> Result<CanonicalWriteMemory<'_>, DeviceError> {
        self.validate()?;
        let memory = self
            .ram
            .try_service()
            .map_err(|_| DeviceError::TransferRefused(refuse!("canonical write RAM owner failed")))?
            .ok_or_else(|| {
                DeviceError::TransferRefused(refuse!("canonical write RAM gates unavailable"))
            })?;
        Ok(CanonicalWriteMemory {
            memory,
            host: self.processors.native_host(),
        })
    }
    fn processors(&mut self) -> Result<ProcessorWrite<'_>, DeviceError> {
        self.validate()?;
        Ok(self.processors.reborrow())
    }
}
