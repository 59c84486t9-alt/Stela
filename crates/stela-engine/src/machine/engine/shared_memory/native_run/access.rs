//! Linear recovered memory-access permission and original fault prefixes.
use super::*;

/// Non-Clone permission obtained only by consuming a real recovered settlement.
/// Public request diagnostics cannot construct or replace this owner.
#[derive(Debug)]
pub(in crate::machine::engine) struct RecoveredAccess<const WRITE: bool> {
    source: Settlement,
}
pub(in crate::machine::engine) type RecoveredRead = RecoveredAccess<false>;
pub(in crate::machine::engine) type RecoveredWrite = RecoveredAccess<true>;
pub(in crate::machine::engine) enum RecoveredDeviceAccess {
    Read(RecoveredRead),
    Write(RecoveredWrite),
}

impl Settlement {
    pub(in crate::machine::engine::shared_memory) fn into_read(self) -> RecoveredRead {
        RecoveredAccess { source: self }
    }
    pub(in crate::machine::engine::shared_memory) fn into_write(self) -> RecoveredWrite {
        RecoveredAccess { source: self }
    }
}
impl<const WRITE: bool> RecoveredAccess<WRITE> {
    pub(in crate::machine::engine) fn source(&self) -> (publication::WorkerBinding, u64, u64, u64) {
        (
            self.source.binding,
            self.source.generation,
            self.source.pc,
            self.source.retired,
        )
    }
    pub(in crate::machine::engine) fn machine_matches(
        &self,
        identity: &Arc<ExecutionDomain>,
    ) -> bool {
        Arc::ptr_eq(&self.source.machine, identity)
    }
    pub(in crate::machine::engine) fn controls(&self) -> Option<&str> {
        self.source.controls_sha256.as_deref()
    }
    pub(in crate::machine::engine) fn diagnostic(
        &self,
    ) -> (u32, Option<crate::memory::domain::MemoryFault>) {
        (
            self.source.fault_word.unwrap_or(self.source.terminal),
            self.source.memory_fault,
        )
    }
    pub(in crate::machine::engine) fn access(
        &self,
    ) -> Option<(u32, crate::memory::domain::DataRequest, u64, u64, usize)> {
        let fault = self.source.memory_fault?;
        let (request, address, physical, bytes) = match self.source.source_failure? {
            policy::Failure::DeviceRead {
                request,
                address,
                physical,
                bytes,
            } if !WRITE => (request, address, physical, bytes),
            policy::Failure::DeviceWrite {
                request,
                address,
                physical,
                bytes,
            } if WRITE => (request, address, physical, bytes),
            _ => return None,
        };
        if self.source.status.is_err()
            || fault.status != MemoryStatus::Unsupported
            || fault.completed_bytes != 0
            || fault.pc != self.source.pc
            || fault.address != address
            || WRITE && fault.access == FaultAccess::Read
            || !WRITE && fault.access == FaultAccess::Write
            || request.operation != crate::memory::domain::DataOperation::Ordinary
            || (request.flags & stela_compiler::context::memory::flags::WRITE != 0) != WRITE
            || request.pc != Some(self.source.pc)
            || request.address != address
        {
            return None;
        }
        Some((self.source.fault_word?, request, address, physical, bytes))
    }
}

#[cfg(test)]
mod tests;
