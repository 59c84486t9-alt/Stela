//! M0 scalar and STP stores to physical RAM, in exact source widths.

use super::{PhysicalAddressSpace, PhysicalReadPlatformError};
use crate::platform::sync::MutexGuard;
use crate::{
    memory::domain::{
        MemoryExecutionLoan, PhysicalAccess, PublicationFault,
        m0_write::{M0WriteIntent, M0WriteMember},
    },
    system::translation_controls::m0_data::{M0ControlError, M0DataWriteLoan},
};
use alloc::vec::Vec;
use stela_compiler::{TargetCpu, context::memory::MemoryStatus};

/// A copied observation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct M0RamWriteProgress {
    pub(crate) attempted: bool,
    pub(crate) completed_bytes: u64,
    pub(crate) publication_attempted: Option<M0WriteMember>,
    pub(crate) uncertain_member: Option<M0WriteMember>,
    pub(crate) modified_instruction_ram: bool,
}
impl M0RamWriteProgress {
    const fn unattempted() -> Self {
        Self {
            attempted: false,
            completed_bytes: 0,
            publication_attempted: None,
            uncertain_member: None,
            modified_instruction_ram: false,
        }
    }
}

pub(crate) enum M0RamWritePlatformError {
    SourceControl {
        error: M0ControlError,
        progress: M0RamWriteProgress,
    },
    Physical {
        error: PhysicalReadPlatformError,
        progress: M0RamWriteProgress,
    },
    DeviceOrdering(MemoryStatus),
    MissingMember {
        member: M0WriteMember,
        progress: M0RamWriteProgress,
    },
    Publication {
        fault: PublicationFault,
        progress: M0RamWriteProgress,
    },
    UnexpectedPublicationPrefix {
        fault: PublicationFault,
        progress: M0RamWriteProgress,
    },
    AlreadyAttempted(M0RamWriteProgress),
}

impl M0RamWritePlatformError {
    /// The write progress, for settlement diagnostics.
    pub(crate) fn progress(&self) -> M0RamWriteProgress {
        match self {
            Self::SourceControl { progress, .. }
            | Self::Physical { progress, .. }
            | Self::MissingMember { progress, .. }
            | Self::Publication { progress, .. }
            | Self::UnexpectedPublicationPrefix { progress, .. }
            | Self::AlreadyAttempted(progress) => *progress,
            // Ordering refusal occurs only in NO-WRITE preparation.
            Self::DeviceOrdering(_) => M0RamWriteProgress::unattempted(),
        }
    }
}

// Show the error and the reached prefix, including errors found during
// preparation.
impl core::fmt::Debug for M0RamWritePlatformError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SourceControl { error, .. } => f
                .debug_struct("SourceControl")
                .field("error", error)
                .field("progress", &self.progress())
                .finish(),
            Self::Physical { error, .. } => f
                .debug_struct("Physical")
                .field("error", error)
                .field("progress", &self.progress())
                .finish(),
            Self::DeviceOrdering(status) => f.debug_tuple("DeviceOrdering").field(status).finish(),
            Self::MissingMember { member, .. } => f
                .debug_struct("MissingMember")
                .field("member", member)
                .field("progress", &self.progress())
                .finish(),
            Self::Publication { fault, .. } => f
                .debug_struct("Publication")
                .field("fault", fault)
                .field("progress", &self.progress())
                .finish(),
            Self::UnexpectedPublicationPrefix { fault, .. } => f
                .debug_struct("UnexpectedPublicationPrefix")
                .field("fault", fault)
                .field("progress", &self.progress())
                .finish(),
            Self::AlreadyAttempted(_) => f
                .debug_tuple("AlreadyAttempted")
                .field(&self.progress())
                .finish(),
        }
    }
}

// Private physical pin; no standalone write capability escapes this module.
struct PhysicalRamWritePin<'loan> {
    physical: &'loan PhysicalAddressSpace,
    execution: &'loan MemoryExecutionLoan,
    reached: PhysicalAccess,
    bytes: usize,
}
impl PhysicalRamWritePin<'_> {
    fn check_current(&self) -> Result<(), PhysicalReadPlatformError> {
        self.physical.check_execution_loan(self.execution)?;
        self.physical.check_reached(&self.reached)
    }

    fn publish(
        &self,
        value: u64,
        receipts: &mut Vec<crate::memory::domain::SourceWriteReceipt>,
    ) -> Result<(), PublicationFault> {
        let first = self.reached.first();
        // SAFETY: the source borrow admitted this write, and the outer object
        // and order guard pin the physical rights and storage. Resolution
        // checked the naturally aligned source-width footprint and host
        // read-modify-write readability, and the staging is private stack
        // memory. Publication performs an exact-width XCHG and invalidates
        // reservations on every alias, even for same-value writes.
        unsafe {
            self.physical.domain.system.publish_tracked(
                first.view().backing(),
                first.backing_offset(),
                &value.to_le_bytes()[..self.bytes],
                Some(receipts),
            )
        }
    }
}

fn resolve_write_pin<'loan>(
    physical: &'loan PhysicalAddressSpace,
    execution: &'loan MemoryExecutionLoan,
    physical_address: u64,
    bytes: u8,
) -> Result<PhysicalRamWritePin<'loan>, PhysicalReadPlatformError> {
    use crate::memory::{access, backing::AccessKind};
    physical.check_execution_loan(execution)?;
    if !cfg!(target_arch = "x86_64") {
        return Err(PhysicalReadPlatformError::UnsupportedHost);
    }
    let bytes = usize::from(bytes);
    if !matches!(bytes, 1 | 2 | 4 | 8)
        || physical_address & (bytes as u64 - 1) != 0
        || physical_address.checked_add(bytes as u64).is_none()
    {
        return Err(PhysicalReadPlatformError::Alignment);
    }
    let reached = physical
        .domain
        .resolve_source_physical(execution, physical_address, bytes, AccessKind::Write)
        .map_err(PhysicalReadPlatformError::Domain)?;
    physical.check_reached(&reached)?;
    if core::iter::once(reached.first())
        .chain(reached._remaining.iter())
        .any(|span| {
            span.view().permissions().executable
                && span.view().backing().instruction_generation().is_none()
        })
    {
        return Err(PhysicalReadPlatformError::Unavailable);
    }
    let first = reached.first();
    let pointer = first.host_ptr().as_ptr();
    if pointer as usize & (bytes - 1) != 0 {
        return Err(PhysicalReadPlatformError::HostAlignment);
    }
    first
        .view()
        .backing()
        .host_pointer(first.backing_offset(), bytes, AccessKind::Read)
        .map_err(|_| PhysicalReadPlatformError::Unavailable)?;
    let (address, footprint) = access::read_footprint(pointer as usize, bytes, TargetCpu::Baseline)
        .map_err(|_| PhysicalReadPlatformError::UnsupportedHost)?;
    if address != pointer as usize || footprint != bytes {
        return Err(PhysicalReadPlatformError::UnsupportedHost);
    }
    Ok(PhysicalRamWritePin {
        physical,
        execution,
        reached,
        bytes,
    })
}

/// Created before any write and held by the failure guard through finalization
/// and the single base and PC settlement. Neither outcome releases its pins.
#[must_use]
pub(crate) struct M0RamWritePrepared<'loan, 'owner> {
    execution: &'loan MemoryExecutionLoan,
    source: &'loan M0DataWriteLoan<'owner>,
    first: PhysicalRamWritePin<'loan>,
    second: Option<PhysicalRamWritePin<'loan>>,
    _order: MutexGuard<'loan, ()>,
    progress: M0RamWriteProgress,
    receipts: Vec<crate::memory::domain::SourceWriteReceipt>,
}

impl M0RamWritePrepared<'_, '_> {
    pub(crate) fn validate_current(&self) -> Result<(), M0RamWritePlatformError> {
        self.source
            .validate_current_with_writes(self.execution, &self.receipts)
            .map_err(|error| M0RamWritePlatformError::SourceControl {
                error,
                progress: self.progress,
            })?;
        self.first
            .check_current()
            .map_err(|error| M0RamWritePlatformError::Physical {
                error,
                progress: self.progress,
            })?;
        if let Some(second) = &self.second {
            second
                .check_current()
                .map_err(|error| M0RamWritePlatformError::Physical {
                    error,
                    progress: self.progress,
                })?;
        }
        Ok(())
    }

    pub(crate) fn progress(&self) -> M0RamWriteProgress {
        self.progress
    }

    pub(crate) fn intent(&self) -> M0WriteIntent {
        self.source.intent()
    }

    fn record_publication(
        &mut self,
        result: Result<(), PublicationFault>,
    ) -> Result<(), M0RamWritePlatformError> {
        self.progress.modified_instruction_ram = !self.receipts.is_empty();
        match result {
            Ok(()) => {
                // Infallible primitive observations immediately follow the
                // The member published at its source width.
                self.progress.completed_bytes += u64::from(self.intent().member_bytes);
                self.progress.uncertain_member = None;
                Ok(())
            }
            Err(fault) => {
                // An aligned scalar is published in one part, so any reported
                // prefix is a terminal diagnostic: never clamped, completed
                // or retried.
                if fault.completed != 0 {
                    return Err(M0RamWritePlatformError::UnexpectedPublicationPrefix {
                        fault,
                        progress: self.progress,
                    });
                }
                Err(M0RamWritePlatformError::Publication {
                    fault,
                    progress: self.progress,
                })
            }
        }
    }

    /// At most one attempt, including pre-write refusal. A pair store is two
    /// ascending 8-byte writes without 16-byte atomicity; the second member is
    /// checked only after the first completes.
    pub(crate) fn attempt(&mut self) -> Result<(), M0RamWritePlatformError> {
        if self.progress.attempted {
            return Err(M0RamWritePlatformError::AlreadyAttempted(self.progress));
        }
        self.progress.attempted = true;
        self.validate_current()?;
        let (_, first) = self.source.intent().member(M0WriteMember::First).ok_or(
            M0RamWritePlatformError::MissingMember {
                member: M0WriteMember::First,
                progress: self.progress,
            },
        )?;
        self.progress.publication_attempted = Some(M0WriteMember::First);
        self.progress.uncertain_member = Some(M0WriteMember::First);
        let result = self.first.publish(first, &mut self.receipts);
        self.record_publication(result)?;
        self.validate_current()?;
        if let Some((_, value)) = self.source.intent().member(M0WriteMember::Second) {
            let translated = self
                .source
                .qualify_member_after_writes(self.execution, M0WriteMember::Second, &self.receipts)
                .map_err(|error| M0RamWritePlatformError::SourceControl {
                    error,
                    progress: self.progress,
                })?;
            let second = resolve_write_pin(
                self.source.physical_space(),
                self.execution,
                translated.physical_address(),
                self.intent().member_bytes,
            )
            .map_err(|error| M0RamWritePlatformError::Physical {
                error,
                progress: self.progress,
            })?;
            self.second = Some(second);
            self.validate_current()?;
            self.progress.publication_attempted = Some(M0WriteMember::Second);
            self.progress.uncertain_member = Some(M0WriteMember::Second);
            let result = self
                .second
                .as_ref()
                .expect("resolved reached second member")
                .publish(value, &mut self.receipts);
            self.record_publication(result)?;
        }
        // A failure after the effect reports the known prefix of 0, 8 or 16
        // bytes.
        self.validate_current()
    }
}

pub(crate) fn prepare_aligned_device_ram_scalar_or_pair<'loan, 'owner>(
    execution: &'loan MemoryExecutionLoan,
    source: &'loan M0DataWriteLoan<'owner>,
) -> Result<M0RamWritePrepared<'loan, 'owner>, M0RamWritePlatformError> {
    let progress = M0RamWriteProgress::unattempted();
    source
        .validate_current(execution)
        .map_err(|error| M0RamWritePlatformError::SourceControl { error, progress })?;
    let translated = source
        .qualify_member(execution, M0WriteMember::First)
        .map_err(|error| M0RamWritePlatformError::SourceControl { error, progress })?;
    let first = resolve_write_pin(
        source.physical_space(),
        execution,
        translated.physical_address(),
        source.intent().member_bytes,
    )
    .map_err(|error| M0RamWritePlatformError::Physical { error, progress })?;
    let order = execution
        .device_ram_order()
        .map_err(M0RamWritePlatformError::DeviceOrdering)?;
    let prepared = M0RamWritePrepared {
        execution,
        source,
        first,
        second: None,
        _order: order,
        progress,
        receipts: Vec::with_capacity(2),
    };
    prepared.validate_current()?;
    Ok(prepared)
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
pub(crate) mod tests;
