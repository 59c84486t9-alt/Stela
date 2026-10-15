//! Exact aligned8B Device-nGnRnE reads from the canonical physical RAM owner.
//!
//! Private, unregistered source. The required scalar M0DataReadLoan and physical
//! registry port are not replaced by stubs here. No Config, copied translation,
//! logical-domain address, retirement token or host pointer can mint this loan.

use std::sync::MutexGuard;

use super::{M0Read64Intent, MetadataFailure};
use crate::{
    memory::domain::{
        MemoryExecutionLoan,
        physical::{PhysicalRamReadPin, PhysicalReadPlatformError},
    },
    system::translation_controls::m0_data::{M0ControlError, M0DataReadLoan},
};
use stela_compiler::context::memory::MemoryStatus;

const READ_BYTES: u64 = size_of::<u64>() as u64;
const HOST_ALIGNMENT_MASK: usize = size_of::<u64>() - 1;

/// Platform/authority diagnostics, never an Arm TranslationError or an invented
/// physical external abort. Post-read failures preserve the actual8B completion.
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

/// Internal observation state, never source, access or retirement authority.
/// An attempted read cannot be retried, including after a pre-read refusal.
enum ReadState {
    Unattempted,
    Attempted,
    Completed,
}

/// NO-READ session plus the SAME invocation's retained resources.
///
/// Preparation acquires current physical pins and the same-System ordering
/// guard without reading target bytes. The canonical consumer must put this
/// object inside its ORIGINAL authority guard BEFORE calling `read`. On error
/// or unwind that outer guard poisons the real PE before these fields drop.
/// Success retains this object through finalization and once-only architectural
/// state/PC settlement. Extracting a value is not settlement or loan release.
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

    /// Perform at most one target read, after the real authority guard owns this
    /// session. Failure never releases the retained fields or permits a retry.
    /// A successful read stores the candidate and completion before returning.
    pub(crate) fn read(&mut self) -> Result<u64, M0RamReadPlatformError> {
        if !matches!(self.state, ReadState::Unattempted) {
            return Err(M0RamReadPlatformError::ReadAlreadyAttempted {
                completed_bytes: self.completed_bytes(),
            });
        }
        self.state = ReadState::Attempted;
        self.validate_current()?;
        let pointer = self.physical.pointer();
        if pointer as usize & HOST_ALIGNMENT_MASK != 0 {
            return Err(M0RamReadPlatformError::HostAlignment);
        }
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: actual opaque CPU/physical producers qualified this exact
            // current eight-byte coherent RAM quantity and supported baseline.
            // The original authority guard owns this session before invocation;
            // all source/outer/pin/order resources stay retained through read,
            // finalization and success or poison settlement.
            let value = unsafe { read_host_ram8(pointer) };
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

    pub(crate) fn intent(&self) -> M0Read64Intent {
        self.source.intent()
    }

    /// Zero until the sole read returns; eight afterward. Unexpected host faults
    /// remain outside this recipe, not fabricated completed/fault observations.
    pub(crate) const fn completed_bytes(&self) -> u64 {
        match self.state {
            ReadState::Completed => READ_BYTES,
            ReadState::Unattempted | ReadState::Attempted => 0,
        }
    }
}

/// Prepare a retained NO-READ session under actual CPU/source/physical owners.
///
/// Required producer contracts:
/// - `source` retains the actual same PE/thread/System, sole translation-control
///   bank, source and the identical `execution` object. Its successful mint has
///   already performed canonical translation; `validate_current` reports only
///   authority/platform failure, never a new architectural fault.
/// - `physical_space().resolve_ram8` is a genuine PA-registry operation. It checks
///   the same actual execution domain/System and returns exact current readable,
///   side-effect-free host-RAM spans. Numeric VA/PA equality grants nothing.
/// - The physical/host producer qualifies the bounded side-effect-free coherent
///   RAM profile. MFENCE orders architectural loads/stores here; speculative host
///   cache traffic is unobservable. MMIO, watchpoints, bus transactions and
///   non-speculative instruction dispatch are explicitly outside this profile.
///
/// No target byte is read and no candidate or GuestState destination is committed
/// by this function. Producer/current checks must issue no TARGET or descriptor
/// read. Immutable instruction-source revalidation remains with the actual source/
/// fetch owner; that is distinct from this pending target read. This function does not
/// acquire a second execution/service/snapshot loan or change a reservation.
pub(crate) fn prepare_aligned_device_ram8<'loan, 'owner>(
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
        .resolve_ram8(execution, source.derived_translation().physical_address())
        .map_err(|error| M0RamReadPlatformError::Physical {
            error,
            completed_bytes: 0,
        })?;
    // Borrow from the original outer loan, not from the movable local pin.
    // This is same-System serialization only; it grants no CPU/PA/PE authority.
    // Busy/reentrant transactions decline finitely before any physical read.
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
    let pointer = physical.pointer();
    if pointer as usize & HOST_ALIGNMENT_MASK != 0 {
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

/// Read one naturally aligned atomic eight-byte quantity from ordinary host RAM.
///
/// # Safety
/// The memory-owned caller must retain the actual CPU/source permission, same
/// canonical physical registry/execution loan, Device order gate and every
/// current readable view/backing covering this exact eight-byte footprint.
/// The actual host must support the x86-64/SSE2 baseline. `pointer` is the
/// resolved backing pointer, aligned to eight, without incompatible Rust aliases.
/// It denotes side-effect-free coherent host-WB RAM, never MMIO. These storage
/// properties do not change logical guest Device-nGnRnE attributes.
///
/// MFENCE supplies architectural host load/store ordering. This RAM-only mapping
/// permits unobservable speculative host cache traffic and makes no device-bus,
/// watchpoint or non-speculative-dispatch promise. No `nomem`, `readonly` or
/// `pure` option may remove the compiler memory barriers. Unexpected host faults
/// are outside this recipe and cannot become fabricated Arm translation faults
/// or physical external aborts. Actual emitted-code inspection remains required.
#[cfg(target_arch = "x86_64")]
unsafe fn read_host_ram8(pointer: *const u8) -> u64 {
    let value: u64;
    // SAFETY: caller-owned current pins and the order guard protect this exact
    // aligned RAM quantity. The qword MOV uses no wider host snapshot and writes
    // no RAM. Neither fences nor MOV modify flags, MXCSR or undeclared registers.
    unsafe {
        std::arch::asm!(
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
