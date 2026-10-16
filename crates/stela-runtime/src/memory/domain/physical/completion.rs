//! Synchronous completion of the staged Device-RAM accesses (for DSB).

use super::{PhysicalAddressSpace, PhysicalReadPlatformError};
use crate::memory::domain::MemoryExecutionLoan;
use crate::platform::sync::MutexGuard;
use stela_compiler::context::memory::MemoryStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RamCompletionProgress {
    Unattempted,
    Attempted,
    Completed,
}

pub(crate) enum RamCompletionError {
    Physical(PhysicalReadPlatformError),
    Ordering(MemoryStatus),
    AlreadyAttempted(RamCompletionProgress),
}

/// The physical owner, outer object and Device-RAM serializer stay borrowed
/// through completion and settlement. No target RAM is accessed.
#[must_use]
pub(crate) struct PhysicalRamCompletion<'loan> {
    physical: &'loan PhysicalAddressSpace,
    execution: &'loan MemoryExecutionLoan,
    _order: MutexGuard<'loan, ()>,
    progress: RamCompletionProgress,
}

impl PhysicalRamCompletion<'_> {
    pub(crate) fn validate_current(&self) -> Result<(), RamCompletionError> {
        self.physical
            .check_execution_loan(self.execution)
            .map_err(RamCompletionError::Physical)
    }

    pub(crate) const fn progress(&self) -> RamCompletionProgress {
        self.progress
    }

    /// Called after the owner enters Retiring; the system-effect commit
    /// validates the source, outer object and PE separately. A failure before
    /// the MFENCE has no effect; completion is recorded infallibly before
    /// returning, so a later check keeps it.
    pub(crate) fn complete(&mut self) -> Result<(), RamCompletionError> {
        if self.progress != RamCompletionProgress::Unattempted {
            return Err(RamCompletionError::AlreadyAttempted(self.progress));
        }
        self.progress = RamCompletionProgress::Attempted;
        self.validate_current()?;
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: the physical domain, source binding and outer object are
            // checked above, and the order guard excludes other staged
            // Device-RAM sessions. The backing is coherent RAM. The asm must
            // not use `nomem`, `readonly` or `pure`, which would remove the
            // compiler barrier.
            unsafe {
                core::arch::asm!("mfence", options(nostack, preserves_flags));
            }
            self.progress = RamCompletionProgress::Completed;
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(RamCompletionError::Physical(
                PhysicalReadPlatformError::UnsupportedHost,
            ))
        }
    }
}

impl PhysicalAddressSpace {
    /// Prepare without any data, maintenance or architectural effect. A busy or
    /// failed order or source owner is refused.
    pub(crate) fn prepare_ram_completion<'loan>(
        &'loan self,
        execution: &'loan MemoryExecutionLoan,
    ) -> Result<PhysicalRamCompletion<'loan>, RamCompletionError> {
        if !cfg!(target_arch = "x86_64") {
            return Err(RamCompletionError::Physical(
                PhysicalReadPlatformError::UnsupportedHost,
            ));
        }
        self.check_execution_loan(execution)
            .map_err(RamCompletionError::Physical)?;
        let order = execution
            .device_ram_order()
            .map_err(RamCompletionError::Ordering)?;
        let prepared = PhysicalRamCompletion {
            physical: self,
            execution,
            _order: order,
            progress: RamCompletionProgress::Unattempted,
        };
        prepared.validate_current()?;
        Ok(prepared)
    }
}

impl core::fmt::Debug for RamCompletionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Physical(value) => f.debug_tuple("Physical").field(value).finish(),
            Self::Ordering(value) => f.debug_tuple("Ordering").field(value).finish(),
            Self::AlreadyAttempted(value) => {
                f.debug_tuple("AlreadyAttempted").field(value).finish()
            }
        }
    }
}
