//! One actual hosted checked native call, with original context and RAM pin.
//! Private proposal; registration, type/lifetime review and native gates pending.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
use crate::execution::context::ContextLoan;
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString};

use super::super::super::source::BoundSource;
use super::callback::{CallbackFailure, PairReadCallback};
use crate::{
    memory::domain::{
        MemoryExecutionLoan,
        m0_read::{
            M0RamPairReadPlatformError, M0RamPairReadPrepared, M0RamPairReadProgress,
            prepare_aligned_device_ram8_pair,
        },
    },
    system::translation_controls::m0_data::M0DataPairReadLoan,
};
use stela_compiler::{
    GuestState,
    block::BlockExit,
    context::{ExecutionContext, ScalableStateView, memory::MemoryStatus},
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct RawM0PairReadMemory {
    pub(super) status: u32,
    pub(super) address: u64,
    pub(super) pc: u64,
    pub(super) completed_bytes: u64,
}

pub(crate) enum M0PairReadSessionFailure {
    AlreadyInvoked,
    #[cfg(not(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux"))))]
    UnsupportedHost,
    Platform(M0RamPairReadPlatformError),
    ContextChanged,
    SourceChanged(String),
    InvalidCompletion,
}

/// Output only; no constructor/call accepts this as write or commit authority.
/// Typed post-read errors and raw carrier survive regardless of qualification.
#[derive(Debug)]
pub(crate) struct M0PairReadNativeReport {
    pub(super) invoked: bool,
    pub(super) raw_carrier: Option<(u64, u64)>,
    pub(super) memory: Option<RawM0PairReadMemory>,
    pub(super) completed_bytes: u64,
    pub(super) progress: M0RamPairReadProgress,
    #[cfg(test)]
    pub(super) producer_observation: Option<serde_json::Value>,
    pub(super) callback_failure: Option<CallbackFailure>,
    pub(super) failure: Option<M0PairReadSessionFailure>,
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
pub(super) struct NativeM0PairReadSession<'call, 'owner, 'code> {
    prepared: M0RamPairReadPrepared<'call, 'owner>,
    bound: &'call BoundSource<'code>,
    context: &'call mut ExecutionContext,
    context_before: ContextIdentity,
    invoked: bool,
    valid_return: bool,
    values: Option<[u64; 2]>,
    #[cfg(test)]
    producer_observation: Option<serde_json::Value>,
}
impl<'call, 'owner, 'code> NativeM0PairReadSession<'call, 'owner, 'code> {
    pub(super) fn prepare(
        bound: &'call BoundSource<'code>,
        outer: &'call MemoryExecutionLoan,
        control: &'call M0DataPairReadLoan<'owner>,
        context: &'call mut ExecutionContext,
    ) -> Result<Self, M0RamPairReadPlatformError> {
        let prepared = prepare_aligned_device_ram8_pair(outer, control)?;
        #[cfg(test)]
        let producer_observation = control.producer_observation(outer).map_err(|error| {
            M0RamPairReadPlatformError::SourceControl {
                error,
                progress: prepared.progress(),
            }
        })?;
        let context_before = ContextIdentity::capture(context);
        Ok(Self {
            prepared,
            bound,
            context,
            context_before,
            invoked: false,
            valid_return: false,
            values: None,
            #[cfg(test)]
            producer_observation: Some(producer_observation),
        })
    }

    pub(super) fn invoke(&mut self, candidate: &mut GuestState) -> M0PairReadNativeReport {
        let mut report = M0PairReadNativeReport {
            invoked: false,
            raw_carrier: None,
            memory: None,
            completed_bytes: self.prepared.progress().completed_bytes,
            progress: self.prepared.progress(),
            #[cfg(test)]
            producer_observation: self.producer_observation.take(),
            callback_failure: None,
            failure: None,
        };
        if self.invoked {
            self.valid_return = false;
            report.failure = Some(M0PairReadSessionFailure::AlreadyInvoked);
            return report;
        }
        // Never retry even when a last-moment pre-FFI check refuses this attempt.
        self.invoked = true;
        if !self.context_before.matches(self.context) {
            report.failure = Some(M0PairReadSessionFailure::ContextChanged);
            return report;
        }
        if let Err(error) = self.bound.recheck() {
            report.failure = Some(M0PairReadSessionFailure::SourceChanged(error.to_string()));
            return report;
        }
        if let Err(error) = self.prepared.validate_current() {
            report.failure = Some(M0PairReadSessionFailure::Platform(error));
            return report;
        }
        #[cfg(not(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux"))))]
        let _ = candidate;
        let mut callback = PairReadCallback::new(&mut self.prepared);
        callback.with_view(|view| {
            #[cfg(not(all(
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            )))]
            {
                let _ = view;
                report.failure = Some(M0PairReadSessionFailure::UnsupportedHost);
            }
            #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
            {
                let mut context_loan = ContextLoan::memory(self.context, view);
                report.invoked = true;
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
                    Err(never) => match never {},
                };
                let (returned, storage_after) = reached.into_observations();
                // Capture raw carrier and actual service footprint before any
                // fallible validation/finalizer can erase these observations.
                report.raw_carrier = Some((returned.next_pc, returned.kind));
                report.memory = Some(RawM0PairReadMemory {
                    status: view.fault_kind,
                    address: view.fault_address,
                    pc: view.fault_pc,
                    completed_bytes: view.completed_bytes,
                });
                report.completed_bytes = view.completed_bytes;
                // The actual hosted storage owner has Infallible postchecks. This
                // match retains the same receipt shape as the real storage layer;
                // a future fallible protected owner requires its typed error here.
                match storage_after {
                    Ok(()) => {}
                    Err(never) => match never {},
                }
                if !context_loan.context().has_supported_header()
                    || context_loan.context().memory != core::ptr::from_mut(view).cast()
                    || context_loan.context().scalable != self.context_before.scalable
                    || context_loan.context().system != self.context_before.system
                    || context_loan.context().version != self.context_before.version
                    || context_loan.context().bytes != self.context_before.bytes
                {
                    report.failure = Some(M0PairReadSessionFailure::ContextChanged);
                }
            }
        }); // Original context pointers restored; RAM/pin/order remain owned.
        if let Some(failure) = callback.take_failure() {
            report.callback_failure = Some(failure);
        }
        let attempts = callback.attempts();
        self.values = callback.values();
        drop(callback);
        // Actual physical completion, including any eight-byte read preceding a
        // failed callback/finalizer, takes precedence over raw ABI metadata.
        report.completed_bytes = self.prepared.progress().completed_bytes;
        report.progress = self.prepared.progress();
        if !self.context_before.matches(self.context) && report.failure.is_none() {
            report.failure = Some(M0PairReadSessionFailure::ContextChanged);
        }
        let intent = self.prepared.intent();
        let valid_memory = report.memory.is_some_and(|memory| {
            memory.status == MemoryStatus::Success as u32
                && memory.completed_bytes == self.prepared.intent().bytes()
                && memory.address == intent.raw_address
                && memory.pc == intent.source_pc.0
        });
        self.valid_return = report.failure.is_none()
            && report.callback_failure.is_none()
            && report.raw_carrier.is_some()
            && report.completed_bytes == self.prepared.intent().bytes()
            && valid_memory
            && attempts == 1
            && self.values.is_some();
        if !self.valid_return && report.failure.is_none() {
            report.failure = Some(M0PairReadSessionFailure::InvalidCompletion);
        }
        report
    }

    /// Every fallible native/context/Device finalizer completes before the
    /// paired infallible actual-register/PC commit, with original pins held.
    pub(super) fn completed_values(&self) -> Option<[u64; 2]> {
        self.values
    }

    pub(super) fn precommit(&self) -> Result<(), M0PairReadSessionFailure> {
        if !self.invoked || !self.valid_return {
            return Err(M0PairReadSessionFailure::InvalidCompletion);
        }
        if !self.context_before.matches(self.context) {
            return Err(M0PairReadSessionFailure::ContextChanged);
        }
        self.prepared
            .validate_current()
            .map_err(M0PairReadSessionFailure::Platform)?;
        self.bound
            .recheck()
            .map_err(|error| M0PairReadSessionFailure::SourceChanged(error.to_string()))
    }
}

/// Reconstruct descriptive carrier only after the caller has retained the full
/// report. Canonical source/exit/state/PC checks remain in Active.
impl M0PairReadNativeReport {
    pub(super) fn returned_exit(&self) -> Option<BlockExit> {
        self.raw_carrier
            .map(|(next_pc, kind)| BlockExit { next_pc, kind })
    }
}

impl core::fmt::Debug for M0PairReadSessionFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyInvoked => f.write_str("AlreadyInvoked"),
            #[cfg(not(all(
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            )))]
            Self::UnsupportedHost => f.write_str("UnsupportedHost"),
            Self::ContextChanged => f.write_str("ContextChanged"),
            Self::InvalidCompletion => f.write_str("InvalidCompletion"),
            Self::Platform(value) => f.debug_tuple("Platform").field(value).finish(),
            Self::SourceChanged(value) => f.debug_tuple("SourceChanged").field(value).finish(),
        }
    }
}
