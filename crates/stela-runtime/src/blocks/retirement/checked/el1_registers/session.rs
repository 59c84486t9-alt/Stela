//! One synchronous typed EL1 register call over original canonical storage/source.
//! The actual source profile selects the one-argument B or context ABI.
//! Current concrete Mapping is hosted; protected/none mounting is not inferred.
use super::super::source::BoundSource;
use crate::{
    blocks::InstalledEl1SourceScope,
    memory::domain::{MemoryExecutionLoan, physical::BoundPhysicalInstruction},
    system::{
        state::SystemState,
        translation_controls::{PhysicalFetch, TranslationControls},
    },
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString};
use core::convert::Infallible;
use stela_compiler::{GuestState, context::ExecutionContext};

pub(crate) enum RegisterFailure {
    AlreadyInvoked,
    ContextChanged,
    #[cfg(not(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux"))))]
    PlatformUnavailable,
    Source(String),
}
#[derive(Debug)]
pub(crate) struct RegisterNativeReport {
    pub(in crate::blocks::retirement::checked) invoked: bool,
    pub(in crate::blocks::retirement::checked) raw_carrier: Option<(u64, u64)>,
    pub(in crate::blocks::retirement::checked) storage_after: Option<Result<(), Infallible>>,
    pub(in crate::blocks::retirement::checked) failure: Option<RegisterFailure>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct ContextIdentity {
    version: u32,
    bytes: u32,
    memory: *mut core::ffi::c_void,
    scalable: *mut stela_compiler::context::ScalableStateView,
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
}
/// Actual original source/bank/outer/System/context and reached physical pin
/// remain borrowed inside the retained authority guard before native invocation.
/// This session cannot create authority, use a callback or expose an entry ptr.
pub(in crate::blocks::retirement::checked) struct RegisterSession<'call, 'code> {
    bound: &'call BoundSource<'code>,
    outer: &'call MemoryExecutionLoan,
    scope: &'call InstalledEl1SourceScope<'call>,
    controls: &'call TranslationControls,
    context: &'call mut ExecutionContext,
    before: ContextIdentity,
    reached: BoundPhysicalInstruction,
    invoked: bool,
}
impl<'call, 'code> RegisterSession<'call, 'code> {
    pub(in crate::blocks::retirement::checked) fn prepare(
        bound: &'call BoundSource<'code>,
        outer: &'call MemoryExecutionLoan,
        scope: &'call InstalledEl1SourceScope<'call>,
        controls: &'call TranslationControls,
        system: &SystemState,
        context: &'call mut ExecutionContext,
    ) -> anyhow::Result<Self> {
        bound.el1_carrier_intent()?;
        anyhow::ensure!(
            context.has_supported_header()
                && context.bytes == stela_compiler::context::EXECUTION_CONTEXT_BYTES
                && context.memory.is_null()
                && context.scalable.is_null()
                && context.system.is_null(),
            "one-argument EL1 register requires original context without installed service views"
        );
        let reached = scope
            .physical_space()
            .fetch_el1_instruction(outer, controls, scope, system, bound.entry.entry().0)
            .map_err(|error| anyhow::anyhow!("EL1 register actual source fetch: {error:?}"))?;
        Self::check_binding(bound, scope, &reached)?;
        Ok(Self {
            bound,
            outer,
            scope,
            controls,
            before: ContextIdentity::capture(context),
            context,
            reached,
            invoked: false,
        })
    }
    fn check_binding(
        bound: &BoundSource<'_>,
        scope: &InstalledEl1SourceScope<'_>,
        reached: &BoundPhysicalInstruction,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            bound.source == reached.word().to_le_bytes()
                && reached.raw_pc() == bound.entry.entry().0,
            "EL1 register original reached source differs"
        );
        bound
            .runtime
            .check_physical_source(
                scope.installed_snapshot(),
                PhysicalFetch {
                    pc: reached.raw_pc(),
                    word: reached.word(),
                    physical_address: reached.physical_address(),
                    source_generation: bound.entry.generation(),
                },
                reached,
            )
            .map_err(anyhow::Error::msg)
    }
    fn context_unchanged(&self) -> bool {
        self.context.has_supported_header() && ContextIdentity::capture(self.context) == self.before
    }
    pub(in crate::blocks::retirement::checked) fn validate_current(
        &self,
        system: &SystemState,
    ) -> anyhow::Result<()> {
        self.bound.el1_carrier_intent()?;
        anyhow::ensure!(
            self.context_unchanged(),
            "EL1 register actual context changed"
        );
        let reached = self
            .scope
            .physical_space()
            .fetch_el1_instruction(
                self.outer,
                self.controls,
                self.scope,
                system,
                self.bound.entry.entry().0,
            )
            .map_err(|error| anyhow::anyhow!("EL1 register current source fetch: {error:?}"))?;
        anyhow::ensure!(
            self.reached.same_source(&reached),
            "EL1 register original physical source changed"
        );
        Self::check_binding(self.bound, self.scope, &reached)
    }
    pub(in crate::blocks::retirement::checked) fn invoke(
        &mut self,
        system: &SystemState,
        candidate: &mut GuestState,
    ) -> RegisterNativeReport {
        let mut report = RegisterNativeReport {
            invoked: false,
            raw_carrier: None,
            storage_after: None,
            failure: None,
        };
        if self.invoked {
            report.failure = Some(RegisterFailure::AlreadyInvoked);
            return report;
        }
        if let Err(error) = self.validate_current(system) {
            report.failure = Some(RegisterFailure::Source(error.to_string()));
            return report;
        }
        #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
        {
            self.invoked = true;
            report.invoked = true;
            // SAFETY: caller already owns original retained NativeActive and
            // SAME full ThreadState/System/backend/closed-producer/outer. Whole
            // typed source is register-only, with no memory/helper/FP operation;
            // actual compiled mapping/ABI/source/map and physical fetch match.
            let reached = match unsafe {
                if self.bound.runtime.profile()
                    == stela_compiler::block::BlockProfile::El1DirectBranchV1
                {
                    self.bound.block.mapping.call_block_observed(candidate)
                } else {
                    self.bound
                        .block
                        .mapping
                        .call_context_block_observed(candidate, self.context)
                }
            } {
                Ok(reached) => reached,
                Err(never) => match never {},
            };
            let (returned, after) = reached.into_observations();
            // Preserve actual raw bits and actual storage postcheck FIRST.
            report.raw_carrier = Some((returned.next_pc, returned.kind));
            report.storage_after = Some(after);
            // Neither typed register ABI installs service views. No context helper or
            // borrowed-view finalizer was installed; preserve its actual state.
            if !self.context_unchanged() {
                report.failure = Some(RegisterFailure::ContextChanged);
            }
        }
        #[cfg(not(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux"))))]
        {
            let _ = candidate;
            report.failure = Some(RegisterFailure::PlatformUnavailable);
        }
        report
    }
}

impl core::fmt::Debug for RegisterFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(not(all(
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            )))]
            Self::PlatformUnavailable => f.write_str("PlatformUnavailable"),
            Self::AlreadyInvoked => f.write_str("AlreadyInvoked"),
            Self::ContextChanged => f.write_str("ContextChanged"),
            Self::Source(value) => f.debug_tuple("Source").field(value).finish(),
        }
    }
}
