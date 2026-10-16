//! Naturally aligned Device-nGnRnE scalar reads from physical RAM.

use crate::platform::sync::MutexGuard;

use super::{M0ScalarReadIntent, MetadataFailure};
use crate::{
    memory::domain::{
        MemoryExecutionLoan,
        physical::{PhysicalRamReadPin, PhysicalReadPlatformError},
    },
    system::translation_controls::m0_data::{M0ControlError, M0DataReadLoan},
};
use stela_compiler::context::memory::MemoryStatus;

/// Platform failures, never an Arm translation error or invented external
/// abort. Failures after the read keep the completed access.
pub(crate) enum M0RamReadPlatformError {
    SourceControl {
        error: M0ControlError,
        completed_bytes: u64,
    },
    Physical {
        error: PhysicalReadPlatformError,
        completed_bytes: u64,
    },
    SourceMetadata(MetadataFailure),
    DeviceOrdering(MemoryStatus),
    HostAlignment,
    UnsupportedHost,
    ReadAlreadyAttempted {
        completed_bytes: u64,
    },
}

/// Internal state. A read is attempted at most once, even after a refusal.
enum ReadState {
    Unattempted,
    Attempted,
    Completed,
}

/// A session created before the read, holding the invocation's resources.
///
/// Preparation takes the physical pins and the order guard without reading the
/// target. The consumer must place this inside its failure guard before calling
/// `read`, so an error or unwind marks the PE failed before these fields drop.
/// On success it is kept through finalization and settlement.
#[must_use]
pub(crate) struct M0RamReadPrepared<'loan, 'owner> {
    execution: &'loan MemoryExecutionLoan,
    source: &'loan M0DataReadLoan<'owner>,
    physical: PhysicalRamReadPin<'loan>,
    _order: MutexGuard<'loan, ()>,
    state: ReadState,
}

impl M0RamReadPrepared<'_, '_> {
    pub(crate) fn validate_current(&self) -> Result<(), M0RamReadPlatformError> {
        let completed_bytes = self.completed_bytes();
        self.source
            .validate_current(self.execution)
            .map_err(|error| M0RamReadPlatformError::SourceControl {
                error,
                completed_bytes,
            })?;
        self.physical
            .check_current()
            .map_err(|error| M0RamReadPlatformError::Physical {
                error,
                completed_bytes,
            })
    }

    /// Perform the single target read once the failure guard owns this session.
    /// Failure never releases the fields or allows a retry; success records the
    /// value and completion before returning.
    pub(crate) fn read(&mut self) -> Result<u64, M0RamReadPlatformError> {
        if !matches!(self.state, ReadState::Unattempted) {
            return Err(M0RamReadPlatformError::ReadAlreadyAttempted {
                completed_bytes: self.completed_bytes(),
            });
        }
        self.state = ReadState::Attempted;
        self.validate_current()?;
        let pointer = self.physical.pointer();
        if pointer as usize & (usize::from(self.intent().bytes) - 1) != 0 {
            return Err(M0RamReadPlatformError::HostAlignment);
        }
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: the CPU and physical checks covered this exact coherent
            // RAM access of the source width, and the failure guard owns the
            // session, keeping the source, outer, pin and order resources
            // through the read, finalization and settlement.
            let value = unsafe { read_host_ram_scalar(pointer, self.intent().bytes) };
            // Scalar/enum assignments are infallible; no callback, allocation or
            // fallible validation occurs between the read and this observation.
            self.state = ReadState::Completed;
            Ok(value)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = pointer;
            Err(M0RamReadPlatformError::UnsupportedHost)
        }
    }

    pub(crate) fn intent(&self) -> M0ScalarReadIntent {
        self.source.intent()
    }

    /// Zero until the read returns, then the access width.
    pub(crate) fn completed_bytes(&self) -> u64 {
        match self.state {
            ReadState::Completed => self.intent().bytes as u64,
            ReadState::Unattempted | ReadState::Attempted => 0,
        }
    }
}

/// Prepare a session under the CPU, source and physical owners, without
/// reading.
///
/// Producer contracts:
/// - `source` holds the PE's thread and system state, its translation controls, the source and the same `execution` object. Creating it already performed translation, so `validate_current` reports only platform failures, never a new architectural fault.
/// - `physical_space().resolve_ram_scalar` checks the physical registry for the same domain and system and returns readable host RAM spans without side effects. Equal VA and PA values prove nothing.
/// - MFENCE orders the architectural loads and stores; speculative host cache traffic is not observable. MMIO, watchpoints and bus transactions are outside this profile.
///
/// No target byte is read and nothing is committed here. The checks read
/// neither the target nor any descriptor, and no second execution, service or
/// snapshot borrow is taken.
pub(crate) fn prepare_aligned_device_ram_scalar<'loan, 'owner>(
    execution: &'loan MemoryExecutionLoan,
    source: &'loan M0DataReadLoan<'owner>,
) -> Result<M0RamReadPrepared<'loan, 'owner>, M0RamReadPlatformError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(M0RamReadPlatformError::UnsupportedHost);
    }
    source
        .validate_current(execution)
        .map_err(|error| M0RamReadPlatformError::SourceControl {
            error,
            completed_bytes: 0,
        })?;
    // Descriptive consistency checks are additional rejection guards; they
    // cannot turn copied translation metadata into source/physical permission.
    source
        .intent()
        .check_translation(source.derived_translation())
        .map_err(M0RamReadPlatformError::SourceMetadata)?;
    let physical = source
        .physical_space()
        .resolve_ram_scalar(
            execution,
            source.derived_translation().physical_address(),
            source.intent().bytes,
        )
        .map_err(|error| M0RamReadPlatformError::Physical {
            error,
            completed_bytes: 0,
        })?;
    // Borrow from the outer object, not from the local pin. Busy or re-entrant
    // transactions are refused before any read.
    let order = execution
        .device_ram_order()
        .map_err(M0RamReadPlatformError::DeviceOrdering)?;
    source
        .validate_current(execution)
        .map_err(|error| M0RamReadPlatformError::SourceControl {
            error,
            completed_bytes: 0,
        })?;
    physical
        .check_current()
        .map_err(|error| M0RamReadPlatformError::Physical {
            error,
            completed_bytes: 0,
        })?;
    if physical.bytes() != usize::from(source.intent().bytes) {
        return Err(M0RamReadPlatformError::SourceMetadata(
            MetadataFailure::IncompletePhysicalExtent,
        ));
    }
    let pointer = physical.pointer();
    if pointer as usize & (usize::from(source.intent().bytes) - 1) != 0 {
        return Err(M0RamReadPlatformError::HostAlignment);
    }
    Ok(M0RamReadPrepared {
        execution,
        source,
        physical,
        _order: order,
        state: ReadState::Unattempted,
    })
}

/// Read one naturally aligned atomic 8-byte value from host RAM.
///
/// # Safety
/// The caller holds the CPU and source permission, the physical registry and
/// execution borrow, the Device order guard and every readable view covering
/// these eight bytes. The host supports the x86-64 baseline. `pointer` is the
/// resolved backing address, 8-byte aligned, with no incompatible Rust aliases,
/// and points to coherent host write-back RAM without side effects, never MMIO;
/// this does not change the guest's Device-nGnRnE attributes. MFENCE provides
/// the host load and store ordering. The asm must not use `nomem`, `readonly`
/// or `pure`, which would remove the compiler barriers. Unexpected host faults
/// are not converted into Arm faults.
#[cfg(target_arch = "x86_64")]
pub(super) unsafe fn read_host_ram8(pointer: *const u8) -> u64 {
    let value: u64;
    // SAFETY: the caller's pins and order guard cover this aligned access. The
    // MOV reads exactly this qword and writes no RAM; neither it nor the fences
    // change flags, MXCSR or other registers.
    unsafe {
        core::arch::asm!(
            "mfence",
            "mov {value}, qword ptr [{pointer}]",
            "mfence",
            value = out(reg) value,
            pointer = in(reg) pointer,
            options(nostack, preserves_flags),
        );
    }
    value
}

impl core::fmt::Debug for M0RamReadPlatformError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SourceControl {
                error,
                completed_bytes,
            } => f
                .debug_struct("SourceControl")
                .field("error", error)
                .field("completed_bytes", completed_bytes)
                .finish(),
            Self::Physical {
                error,
                completed_bytes,
            } => f
                .debug_struct("Physical")
                .field("error", error)
                .field("completed_bytes", completed_bytes)
                .finish(),
            Self::SourceMetadata(value) => f.debug_tuple("SourceMetadata").field(value).finish(),
            Self::DeviceOrdering(value) => f.debug_tuple("DeviceOrdering").field(value).finish(),
            Self::HostAlignment => f.write_str("HostAlignment"),
            Self::UnsupportedHost => f.write_str("UnsupportedHost"),
            Self::ReadAlreadyAttempted { completed_bytes } => f
                .debug_struct("ReadAlreadyAttempted")
                .field("completed_bytes", completed_bytes)
                .finish(),
        }
    }
}

/// Read exactly the source's naturally aligned width; narrow accesses never use
/// a wider snapshot.
///
/// # Safety
/// The scalar source, control, outer, physical pin and order guard must cover
/// exactly `bytes` (1, 2, 4 or 8). Every width has the same barriers and
/// touches nothing beyond its footprint. MMIO is not supported.
#[cfg(target_arch = "x86_64")]
unsafe fn read_host_ram_scalar(pointer: *const u8, bytes: u8) -> u64 {
    let value: u64;
    match bytes {
        1 => unsafe {
            core::arch::asm!(
                "mfence", "movzx {value:e}, byte ptr [{pointer}]", "mfence",
                value = out(reg) value, pointer = in(reg) pointer,
                options(nostack, preserves_flags),
            )
        },
        2 => unsafe {
            core::arch::asm!(
                "mfence", "movzx {value:e}, word ptr [{pointer}]", "mfence",
                value = out(reg) value, pointer = in(reg) pointer,
                options(nostack, preserves_flags),
            )
        },
        4 => unsafe {
            core::arch::asm!(
                "mfence", "mov {value:e}, dword ptr [{pointer}]", "mfence",
                value = out(reg) value, pointer = in(reg) pointer,
                options(nostack, preserves_flags),
            )
        },
        8 => return unsafe { read_host_ram8(pointer) },
        _ => unreachable!("original source and physical pin qualified scalar width"),
    }
    value
}
