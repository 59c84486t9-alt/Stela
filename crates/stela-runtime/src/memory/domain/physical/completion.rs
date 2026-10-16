//! Actual synchronous side-effect-free coherent RAM participant completion.
//!
//! This covers the original staged Device-RAM service, not MMIO, bus masters or
//! all DSB obligations. The canonical factory must close its real data and
//! maintenance participants. No source/PE/retirement authority is created here.

use super::{PhysicalAddressSpace, PhysicalReadPlatformError};
use crate::memory::domain::MemoryExecutionLoan;
use std::sync::MutexGuard;
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

/// The same original physical/source owner, outer and Device-RAM serializer
/// stay borrowed through actual completion and canonical architectural settling.
/// This type reads/writes no target RAM and supplies no new execution loan.
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

    /// Called only after the original canonical owner enters Retiring. The
    /// actual SystemEffectCommit validates the exact source/outer/PE separately.
    /// Failure before MFENCE is NoEffect. Completed is stored infallibly before
    /// returning, so a later owner check preserves this reached prefix.
    pub(crate) fn complete(&mut self) -> Result<(), RamCompletionError> {
        if self.progress != RamCompletionProgress::Unattempted {
            return Err(RamCompletionError::AlreadyAttempted(self.progress));
        }
        self.progress = RamCompletionProgress::Attempted;
        self.validate_current()?;
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: the SAME physical domain/current source binding and outer
            // are checked above; this original MemorySystem order guard excludes
            // simultaneous staged Device-RAM sessions. Its bounded host backing
            // is coherent RAM; this fence grants no device-bus/MMIO semantics.
            // No nomem/readonly/pure may erase the compiler memory boundary.
            unsafe {
                std::arch::asm!("mfence", options(nostack, preserves_flags));
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
    /// Prepare without data/maintenance/architectural effects. Busy or poisoned
    /// real order/source owners decline finitely before acquiring a completion.
    /// This real RAM participant is not complete factory-wide DSB authority.
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
