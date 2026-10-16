//! Retained two-member aligned Device RAM read, for the actual no-LSE2 M0 PE.
//!
//! Unregistered source until the genuine pair source/control producer joins.
//! The producer must positively prove LSE2 absence from its SAME identification
//! owner. Missing IDs are not absence. LSE2-contained pairs require a different
//! whole-quantity translation contract; this module cannot qualify that path.
//! Guest Device attributes do not turn ordinary host RAM into MMIO.

use crate::platform::sync::MutexGuard;

use super::pair::{M0ReadMember, M0ReadPairIntent};
use crate::{
    memory::domain::{
        MemoryExecutionLoan,
        physical::{PhysicalRamReadPin, PhysicalReadPlatformError},
    },
    system::translation_controls::m0_data::{M0ControlError, M0DataPairReadLoan},
};
use stela_compiler::context::memory::MemoryStatus;

const MEMBER_BYTES: u64 = size_of::<u64>() as u64;
const PAIR_BYTES: u64 = MEMBER_BYTES * 2;
const HOST_ALIGNMENT_MASK: usize = size_of::<u64>() - 1;

/// Actual read observations only; no source, retry or settlement authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct M0RamPairReadProgress {
    pub(crate) attempted: bool,
    pub(crate) completed_bytes: u64,
    pub(crate) read_attempted: Option<M0ReadMember>,
    pub(crate) uncertain_member: Option<M0ReadMember>,
}

impl M0RamPairReadProgress {
    const fn unattempted() -> Self {
        Self {
            attempted: false,
            completed_bytes: 0,
            read_attempted: None,
            uncertain_member: None,
        }
    }
}

/// Keeps original errors and the actual reached prefix. Physical ownership
/// refusals are not invented Arm external aborts. Translation errors can only
/// originate from the genuine reached-member control producer.
pub(crate) enum M0RamPairReadPlatformError {
    SourceControl {
        error: M0ControlError,
        progress: M0RamPairReadProgress,
    },
    Physical {
        error: PhysicalReadPlatformError,
        progress: M0RamPairReadProgress,
    },
    DeviceOrdering(MemoryStatus),
    HostAlignment {
        member: M0ReadMember,
        progress: M0RamPairReadProgress,
    },
    UnsupportedHost,
    AlreadyAttempted(M0RamPairReadProgress),
}

// Retain every original diagnostic field explicitly; no field is discarded or
// hidden behind derived formatting or a dead-code lint exemption.
impl core::fmt::Debug for M0RamPairReadPlatformError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SourceControl { error, progress } => f
                .debug_struct("SourceControl")
                .field("error", error)
                .field("progress", progress)
                .finish(),
            Self::Physical { error, progress } => f
                .debug_struct("Physical")
                .field("error", error)
                .field("progress", progress)
                .finish(),
            Self::DeviceOrdering(status) => f.debug_tuple("DeviceOrdering").field(status).finish(),
            Self::HostAlignment { member, progress } => f
                .debug_struct("HostAlignment")
                .field("member", member)
                .field("progress", progress)
                .finish(),
            Self::UnsupportedHost => f.write_str("UnsupportedHost"),
            Self::AlreadyAttempted(progress) => {
                f.debug_tuple("AlreadyAttempted").field(progress).finish()
            }
        }
    }
}

impl M0RamPairReadPlatformError {
    pub(crate) fn progress(&self) -> M0RamPairReadProgress {
        match self {
            Self::SourceControl { progress, .. }
            | Self::Physical { progress, .. }
            | Self::HostAlignment { progress, .. }
            | Self::AlreadyAttempted(progress) => *progress,
            Self::DeviceOrdering(_) | Self::UnsupportedHost => M0RamPairReadProgress::unattempted(),
        }
    }
}

/// NO-READ session. The original canonical authority guard must own this object
/// before `read`, and retain it through finalization/once-only state+PC settle.
/// On failure/unwind that guard poisons the actual PE BEFORE these loans drop.
/// No destination, base, SP, architectural bank or PC is retained or written.
#[must_use]
pub(crate) struct M0RamPairReadPrepared<'loan, 'owner> {
    execution: &'loan MemoryExecutionLoan,
    source: &'loan M0DataPairReadLoan<'owner>,
    first: PhysicalRamReadPin<'loan>,
    second: Option<PhysicalRamReadPin<'loan>>,
    _order: MutexGuard<'loan, ()>,
    progress: M0RamPairReadProgress,
}

impl M0RamPairReadPrepared<'_, '_> {
    pub(crate) fn progress(&self) -> M0RamPairReadProgress {
        self.progress
    }

    pub(crate) fn intent(&self) -> M0ReadPairIntent {
        self.source.intent()
    }

    pub(crate) fn validate_current(&self) -> Result<(), M0RamPairReadPlatformError> {
        self.source
            .validate_current(self.execution)
            .map_err(|error| M0RamPairReadPlatformError::SourceControl {
                error,
                progress: self.progress,
            })?;
        self.first
            .check_current()
            .map_err(|error| M0RamPairReadPlatformError::Physical {
                error,
                progress: self.progress,
            })?;
        if let Some(second) = &self.second {
            second
                .check_current()
                .map_err(|error| M0RamPairReadPlatformError::Physical {
                    error,
                    progress: self.progress,
                })?;
        }
        Ok(())
    }

    /// At most one attempt, including pre-read refusal. The first value remains
    /// private on every second-member failure. Even both completed reads do not
    /// expose values until current source/control/physical checks succeed.
    pub(crate) fn read(&mut self) -> Result<[u64; 2], M0RamPairReadPlatformError> {
        if self.progress.attempted {
            return Err(M0RamPairReadPlatformError::AlreadyAttempted(self.progress));
        }
        self.progress.attempted = true;
        self.validate_current()?;
        let first_pointer = self.first.pointer();
        self.check_alignment(first_pointer, M0ReadMember::First)?;
        #[cfg(target_arch = "x86_64")]
        {
            self.progress.read_attempted = Some(M0ReadMember::First);
            self.progress.uncertain_member = Some(M0ReadMember::First);
            // SAFETY: authentic no-LSE2 source/control qualification and exact
            // same-outer readable RAM pin/order retain this aligned8 quantity.
            // Reuse the scalar backend, with its full coherent-WB-RAM contract.
            let first_value = unsafe { super::ram::read_host_ram8(first_pointer) };
            // Infallible scalar observations immediately follow the real read.
            self.progress.completed_bytes = MEMBER_BYTES;
            self.progress.uncertain_member = None;
            self.validate_current()?;

            // No second target translation or physical resolution precedes the
            // completed first8. Canonical source priority remains in the producer.
            let translation = self
                .source
                .qualify_member(self.execution, M0ReadMember::Second)
                .map_err(|error| M0RamPairReadPlatformError::SourceControl {
                    error,
                    progress: self.progress,
                })?;
            let second = self
                .source
                .physical_space()
                .resolve_ram8(self.execution, translation.physical_address())
                .map_err(|error| M0RamPairReadPlatformError::Physical {
                    error,
                    progress: self.progress,
                })?;
            let second_pointer = second.pointer();
            self.second = Some(second);
            self.validate_current()?;
            // The just-installed pin remains retained through canonical settle.
            self.check_alignment(second_pointer, M0ReadMember::Second)?;
            self.progress.read_attempted = Some(M0ReadMember::Second);
            self.progress.uncertain_member = Some(M0ReadMember::Second);
            // SAFETY: the same genuine reached-member producer/pin/order now
            // qualifies only this second aligned8B coherent host RAM quantity.
            let second_value = unsafe { super::ram::read_host_ram8(second_pointer) };
            self.progress.completed_bytes = PAIR_BYTES;
            self.progress.uncertain_member = None;
            self.validate_current()?;
            Ok([first_value, second_value])
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = first_pointer;
            Err(M0RamPairReadPlatformError::UnsupportedHost)
        }
    }

    fn check_alignment(
        &self,
        pointer: *const u8,
        member: M0ReadMember,
    ) -> Result<(), M0RamPairReadPlatformError> {
        if pointer as usize & HOST_ALIGNMENT_MASK != 0 {
            return Err(M0RamPairReadPlatformError::HostAlignment {
                member,
                progress: self.progress,
            });
        }
        Ok(())
    }
}

/// Qualify only First and acquire one SAME-System order gate without reading.
/// Actual loan mint must authenticate original instruction, operands/overlap,
/// source currency, EL1 little endian/M0, positive no-LSE2 profile and actual
/// same-outer physical owner. Base-register forms/offset/pre/post and ZR data
/// are descriptive source policy; SP forms require their own original-SP fault
/// owner and must decline unless that owner is joined. This leaf checks neither
/// a copied Config nor application address. It grants no ATOMIC_LOAD16 capability.
/// Device order is the existing bounded side-effect-free coherent RAM profile,
/// with no MMIO, debug/watchpoint, speculation or host fault emulation claim.
pub(crate) fn prepare_aligned_device_ram8_pair<'loan, 'owner>(
    execution: &'loan MemoryExecutionLoan,
    source: &'loan M0DataPairReadLoan<'owner>,
) -> Result<M0RamPairReadPrepared<'loan, 'owner>, M0RamPairReadPlatformError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(M0RamPairReadPlatformError::UnsupportedHost);
    }
    let progress = M0RamPairReadProgress::unattempted();
    source
        .validate_current(execution)
        .map_err(|error| M0RamPairReadPlatformError::SourceControl { error, progress })?;
    let translation = source
        .qualify_member(execution, M0ReadMember::First)
        .map_err(|error| M0RamPairReadPlatformError::SourceControl { error, progress })?;
    let first = source
        .physical_space()
        .resolve_ram8(execution, translation.physical_address())
        .map_err(|error| M0RamPairReadPlatformError::Physical { error, progress })?;
    let order = execution
        .device_ram_order()
        .map_err(M0RamPairReadPlatformError::DeviceOrdering)?;
    let prepared = M0RamPairReadPrepared {
        execution,
        source,
        first,
        second: None,
        _order: order,
        progress,
    };
    prepared.validate_current()?;
    prepared.check_alignment(prepared.first.pointer(), M0ReadMember::First)?;
    Ok(prepared)
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "pair_ram/tests.rs"]
pub(crate) mod fixtures;
