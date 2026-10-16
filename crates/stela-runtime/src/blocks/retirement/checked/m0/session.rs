//! One actual hosted checked native call, with original context and RAM pin.
//! Private proposal; registration, type/lifetime review and native gates pending.
#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux", target_os = "none")
))]
use crate::execution::context::ContextLoan;

use super::super::source::BoundSource;
use super::callback::{CallbackFailure, ReadCallback};
use crate::{
    memory::domain::{
        MemoryExecutionLoan,
        m0_read::{M0RamReadPlatformError, M0RamReadPrepared, prepare_aligned_device_ram_scalar},
    },
    system::translation_controls::m0_data::M0DataReadLoan,
};
use stela_compiler::{
    GuestState,
    block::BlockExit,
    context::{ExecutionContext, ScalableStateView, memory::MemoryStatus},
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct RawM0Memory {
    pub(super) status: u32,
    pub(super) address: u64,
    pub(super) pc: u64,
    pub(super) completed_bytes: u64,
}

pub(crate) enum M0SessionFailure {
    AlreadyInvoked,
    StorageBefore(crate::execution::NativeStorageError),
    StorageAfter(crate::execution::NativeStorageError),
    Platform(M0RamReadPlatformError),
    ContextChanged,
    InvalidCompletion,
}

/// Output only; no constructor/call accepts this as read or commit authority.
/// Typed post-read errors and raw carrier survive regardless of qualification.
#[derive(Debug)]
pub(crate) struct M0NativeReport {
    pub(super) invoked: bool,
    /// Descriptive post-native bank only; never a commit or PE authority.
    #[cfg(not(feature = "std"))]
    pub(super) observed_registers: Option<GuestState>,
    pub(super) raw_carrier: Option<(u64, u64)>,
    pub(super) memory: Option<RawM0Memory>,
    pub(super) completed_bytes: u64,
    pub(super) callback_failure: Option<CallbackFailure>,
    pub(super) failure: Option<M0SessionFailure>,
}

#[derive(Clone, Copy)]
struct ContextIdentity {
    version: u32,
    bytes: u32,
    memory: *mut core::ffi::c_void,
    scalable: *mut ScalableStateView,
    system: *mut core::ffi::c_void,
}
impl ContextIdentity {
    fn capture(context: &ExecutionContext) -> Self {
        Self {
            version: context.version,
            bytes: context.bytes,
            memory: context.memory,
            scalable: context.scalable,
            system: context.system,
        }
    }
    fn matches(&self, context: &ExecutionContext) -> bool {
        context.has_supported_header()
            && context.version == self.version
            && context.bytes == self.bytes
            && context.memory == self.memory
            && context.scalable == self.scalable
            && context.system == self.system
    }
}

/// Constructed with NO target read. Canonical Active MUST put this whole object
/// in RetainedM0Session before invoke, so ORIGINAL authority poisons before any
/// prepared pin/order/control/source resources release on error or unwind.
pub(super) struct NativeM0Session<'call, 'owner, 'code> {
    prepared: M0RamReadPrepared<'call, 'owner>,
    bound: &'call BoundSource<'code>,
    context: &'call mut ExecutionContext,
    context_before: ContextIdentity,
    invoked: bool,
    valid_return: bool,
}
impl<'call, 'owner, 'code> NativeM0Session<'call, 'owner, 'code> {
    pub(super) fn prepare(
        bound: &'call BoundSource<'code>,
        outer: &'call MemoryExecutionLoan,
        control: &'call M0DataReadLoan<'owner>,
        context: &'call mut ExecutionContext,
    ) -> Result<Self, M0RamReadPlatformError> {
        let prepared = prepare_aligned_device_ram_scalar(outer, control)?;
        let context_before = ContextIdentity::capture(context);
        Ok(Self {
            prepared,
            bound,
            context,
            context_before,
            invoked: false,
            valid_return: false,
        })
    }

    pub(super) fn invoke(&mut self, candidate: &mut GuestState) -> M0NativeReport {
        let mut report = M0NativeReport {
            invoked: false,
            raw_carrier: None,
            #[cfg(not(feature = "std"))]
            observed_registers: None,
            memory: None,
            completed_bytes: self.prepared.completed_bytes(),
            callback_failure: None,
            failure: None,
        };
        if self.invoked {
            self.valid_return = false;
            report.failure = Some(M0SessionFailure::AlreadyInvoked);
            return report;
        }
        // Never retry even when a last-moment pre-FFI check refuses this attempt.
        self.invoked = true;
        if !self.context_before.matches(self.context) {
            report.failure = Some(M0SessionFailure::ContextChanged);
            return report;
        }
        if let Err(error) = self.prepared.validate_current() {
            report.failure = Some(M0SessionFailure::Platform(error));
            return report;
        }
        #[cfg(not(all(
            target_arch = "x86_64",
            any(target_os = "macos", target_os = "linux", target_os = "none")
        )))]
        let _ = candidate;
        let mut callback = ReadCallback::new(&mut self.prepared);
        callback.with_view(|view| {
            #[cfg(not(all(
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux", target_os = "none")
            )))]
            {
                let _ = view;
                report.failure = Some(M0SessionFailure::Platform(
                    M0RamReadPlatformError::UnsupportedHost,
                ));
            }
            #[cfg(all(
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux", target_os = "none")
            ))]
            {
                let mut context_loan = ContextLoan::memory(self.context, view);
                // SAFETY: exact BoundSource/source/map/requirements/RX and current
                // context are retained. ORIGINAL RetainedM0Session authority guard
                // already owns this NO-READ physical session before FFI is reached.
                let reached = unsafe {
                    self.bound
                        .block
                        .mapping
                        .call_context_block_observed(candidate, context_loan.context())
                };
                let reached = match reached {
                    Ok(reached) => reached,
                    Err(error) => {
                        report.failure = Some(M0SessionFailure::StorageBefore(error));
                        return;
                    }
                };
                report.invoked = true;
                let (returned, storage_after) = reached.into_observations();
                #[cfg(not(feature = "std"))]
                {
                    report.observed_registers = Some(candidate.clone());
                }
                // Capture raw carrier and actual service footprint before any
                // fallible validation/finalizer can erase these observations.
                report.raw_carrier = Some((returned.next_pc, returned.kind));
                report.memory = Some(RawM0Memory {
                    status: view.fault_kind,
                    address: view.fault_address,
                    pc: view.fault_pc,
                    completed_bytes: view.completed_bytes,
                });
                report.completed_bytes = view.completed_bytes;
                // Preserve a real protected-storage failure alongside the already
                // captured raw carrier and reached prefix. Cleanup still runs.
                match storage_after {
                    Ok(()) => {}
                    Err(error) => report.failure = Some(M0SessionFailure::StorageAfter(error)),
                }
                if (!context_loan.context().has_supported_header()
                    || context_loan.context().memory != core::ptr::from_mut(view).cast()
                    || context_loan.context().scalable != self.context_before.scalable
                    || context_loan.context().system != self.context_before.system
                    || context_loan.context().version != self.context_before.version
                    || context_loan.context().bytes != self.context_before.bytes)
                    && report.failure.is_none()
                {
                    report.failure = Some(M0SessionFailure::ContextChanged);
                }
            }
        }); // Original context pointers restored; RAM/pin/order remain owned.
        if let Some(failure) = callback.take_failure() {
            report.callback_failure = Some(failure);
        }
        let attempts = callback.attempts();
        drop(callback);
        // Actual physical completion, including any source-width read preceding a
        // failed callback/finalizer, takes precedence over raw ABI metadata.
        report.completed_bytes = self.prepared.completed_bytes();
        if !self.context_before.matches(self.context) && report.failure.is_none() {
            report.failure = Some(M0SessionFailure::ContextChanged);
        }
        let intent = self.prepared.intent();
        let valid_memory = report.memory.is_some_and(|memory| {
            memory.status == MemoryStatus::Success as u32
                && memory.completed_bytes == u64::from(intent.bytes)
                && memory.address == intent.raw_address
                && memory.pc == intent.source_pc.0
        });
        self.valid_return = report.failure.is_none()
            && report.callback_failure.is_none()
            && report.raw_carrier.is_some()
            && report.completed_bytes == u64::from(intent.bytes)
            && valid_memory
            && attempts == 1;
        if !self.valid_return && report.failure.is_none() {
            report.failure = Some(M0SessionFailure::InvalidCompletion);
        }
        report
    }

    /// Every fallible native/context/Device finalizer completes before the
    /// paired infallible actual-register/PC commit, with original pins held.
    pub(super) fn precommit(&self) -> Result<(), M0SessionFailure> {
        if !self.invoked || !self.valid_return {
            return Err(M0SessionFailure::InvalidCompletion);
        }
        if !self.context_before.matches(self.context) {
            return Err(M0SessionFailure::ContextChanged);
        }
        self.prepared
            .validate_current()
            .map_err(M0SessionFailure::Platform)
    }
}

/// Reconstruct descriptive carrier only after the caller has retained the full
/// report. Canonical source/exit/state/PC checks remain in Active.
impl M0NativeReport {
    pub(super) fn returned_exit(&self) -> Option<BlockExit> {
        self.raw_carrier
            .map(|(next_pc, kind)| BlockExit { next_pc, kind })
    }
}

impl core::fmt::Debug for M0SessionFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyInvoked => f.write_str("AlreadyInvoked"),
            Self::StorageBefore(error) => f.debug_tuple("StorageBefore").field(error).finish(),
            Self::StorageAfter(error) => f.debug_tuple("StorageAfter").field(error).finish(),
            Self::ContextChanged => f.write_str("ContextChanged"),
            Self::InvalidCompletion => f.write_str("InvalidCompletion"),
            Self::Platform(value) => f.debug_tuple("Platform").field(value).finish(),
        }
    }
}
