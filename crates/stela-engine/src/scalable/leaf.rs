//! Preparing and running a context-backed leaf with checked memory.
use alloc::rc::Rc;
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String};
use core::marker::PhantomData;
use stela_contracts::{refuse, require};

use crate::Result;
use stela_compiler::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::scalable::execution::{
        SCALABLE_EXECUTION_REQUIREMENTS_VERSION, ScalableExecutionRequirements,
    },
    block::{BlockProfile, CompilationPlan, Features},
    context::{
        ExecutionContext,
        memory::{
            MEMORY_IMPLEMENTATION_PROFILE_ID, MemoryRequirements, MemoryStatus,
            profile_requirements,
        },
    },
    scalable_context::ScalableProfile,
};
use stela_formats::sha256;

use super::{ScalableState, context::ContextLoan};
use crate::{
    execution::{MAX_NATIVE_BYTES, platform},
    memory::domain::{DataPolicy, MemoryThread},
};

/// Complete identity of the source and generated context leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalableLeafIdentity {
    pub source_sha256: String,
    pub native_sha256: String,
    pub compiler_source_sha256: String,
    pub guest_base: GuestAddress,
    pub abi: String,
    pub target_cpu: String,
    pub profile: ScalableProfile,
    pub memory_requirements: MemoryRequirements,
    pub execution_requirements_version: u32,
    pub execution_requirements: ScalableExecutionRequirements,
    /// Translation target identity, including the fixed CHECKSPNONEACTIVE choice.
    /// Runtime policy matching is required only by SCALABLE_TAG_CHECKS.
    pub memory_implementation_profile: Option<&'static str>,
}

/// Memory-service outcome after the still-faulting guest instruction returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryFault {
    pub status: MemoryStatus,
    pub address: GuestAddress,
    pub pc: GuestAddress,
    pub completed_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalableLeafExit {
    Returned,
    /// Effective controls or platform storage declined before native entry.
    EntryDeclined(MemoryStatus),
    /// Architectural faults and callback service failures.
    MemoryFault(MemoryFault),
    /// The body returned, but common fault settlement or domain health failed.
    /// Original architectural fault provenance remains distinct from this failure.
    FinalizationFailed {
        status: MemoryStatus,
        native_executed: bool,
        completed_bytes: u64,
        original_fault: Option<MemoryFault>,
    },
}

/// Immutable native code, its requirements and source bytes. Calls are
/// serialized.
#[derive(Debug)]
pub struct PreparedScalableLeaf {
    identity: ScalableLeafIdentity,
    source: Box<[u8]>,
    source_map: Box<[(GuestAddress, usize)]>,
    native_bytes: usize,
    target: TargetCpu,
    mapping: platform::Mapping,
    _serialized: PhantomData<Rc<()>>,
}

impl PreparedScalableLeaf {
    /// Compile a fixed context profile and bind its requirements to that exact
    /// source. Native bytes and caller-supplied requirements are never accepted.
    pub fn prepare(
        source: &[u8],
        base: GuestAddress,
        profile: ScalableProfile,
        target: TargetCpu,
    ) -> Result<Self> {
        require!(
            source.len() <= MAX_NATIVE_BYTES,
            "context leaf source exceeds the native preparation bound"
        );
        platform::ensure_supported()?;
        require!(
            crate::platform::cpu::admitted(target),
            "host lacks context-leaf CPU requirements"
        );
        let source: Box<[u8]> = source.into();
        let options = Options::new(
            BlockProfile::new(Features::LEAF | Features::CONTEXT),
            target,
        )
        .with_scalable(profile);
        let plan = CompilationPlan::new(&source, base, &options)?;
        let requirements = plan
            .memory_requirements()
            .ok_or(refuse!("context leaf memory requirements absent"))?;
        let execution_requirements = plan
            .execution_requirements()
            .ok_or(refuse!("context leaf execution requirements absent"))?;
        let native = plan.compile()?.native;
        require!(
            !native.x86_64_code.is_empty() && native.x86_64_code.len() <= MAX_NATIVE_BYTES,
            "generated context leaf exceeds the native preparation bound"
        );
        let identity = ScalableLeafIdentity {
            source_sha256: sha256(&source),
            native_sha256: sha256(&native.x86_64_code),
            compiler_source_sha256: stela_compiler::SOURCE_SHA256.into(),
            guest_base: base,
            abi: options.profile().abi(),
            target_cpu: target.id(),
            profile,
            memory_requirements: requirements,
            execution_requirements_version: SCALABLE_EXECUTION_REQUIREMENTS_VERSION,
            execution_requirements,
            memory_implementation_profile: (requirements.required_profile
                & profile_requirements::NATIVE_ACCESS
                != 0)
                .then_some(MEMORY_IMPLEMENTATION_PROFILE_ID),
        };
        let mapping = platform::Mapping::new(&native.x86_64_code)?;
        Ok(Self {
            identity,
            source,
            source_map: native.source_map.into_boxed_slice(),
            native_bytes: native.x86_64_code.len(),
            target,
            mapping,
            _serialized: PhantomData,
        })
    }

    pub fn identity(&self) -> &ScalableLeafIdentity {
        &self.identity
    }

    pub fn source(&self) -> &[u8] {
        &self.source
    }

    pub fn source_map(&self) -> &[(GuestAddress, usize)] {
        &self.source_map
    }

    pub fn native_bytes(&self) -> usize {
        self.native_bytes
    }

    /// Run after the memory preflight and view validation. Platform refusals
    /// leave guest state unchanged; faults keep the completed instructions and
    /// the memory service's reached prefix.
    ///
    /// # Safety
    /// The CPU owner must ensure the prepared feature and SMCR profile and
    /// `profile.required_dit()` match the effective controls, and that FP, SVE
    /// and SME access is enabled at the current EL (including CPACR and CPTR
    /// traps). Native memory access requires little-endian data, unenforced
    /// alignment and FEAT_CPA2 disabled; view validation does not check these,
    /// while the memory preflight checks SA/SA0 and the memory implementation
    /// profile. The source must be trusted to terminate. Guest memory must be
    /// disjoint from register storage, the native code, the context, the native
    /// stack and live Rust references, and its owners must keep host rights
    /// pinned. There is no signal recovery or unwinding through native code.
    pub unsafe fn execute<P: DataPolicy>(
        &self,
        registers: &mut GuestState,
        scalable: &mut ScalableState,
        memory: &mut MemoryThread<P>,
        context: &mut ExecutionContext,
    ) -> Result<ScalableLeafExit> {
        require!(
            context.has_supported_header(),
            "unsupported execution context"
        );
        require!(
            crate::platform::cpu::admitted(self.target),
            "context-leaf host requirements changed"
        );
        require!(
            scalable.vector_length() == self.identity.profile.vector_length()
                && scalable.mode() == self.identity.profile.mode(),
            "owned scalable state differs from prepared profile"
        );
        // SAFETY: the state owner keeps every register allocation; the guards
        // restore the service pointers before their borrows expire; the caller
        // supplies disjoint memory and terminating code.
        unsafe {
            scalable.with_view(|view| {
                let mut scalable_loan = ContextLoan::scalable(context, view);
                self.identity
                    .profile
                    .validate_view(scalable_loan.context(), view)?;
                let entry = match memory.prepare(self.identity.memory_requirements) {
                    Ok(entry) => entry,
                    Err(status) => return Ok(ScalableLeafExit::EntryDeclined(status)),
                };
                let mut native_executed = false;
                let mut completed_bytes = 0;
                let mut original_fault = None;
                let result = entry.with_checked_view(|memory_view| {
                    let mut memory_loan = ContextLoan::memory(scalable_loan.context(), memory_view);
                    self.mapping
                        .call_context(registers, memory_loan.context())?;
                    native_executed = true;
                    completed_bytes = memory_view.completed_bytes;
                    let status = memory_status(memory_view.fault_kind)?;
                    if status == MemoryStatus::Success {
                        return Ok(ScalableLeafExit::Returned);
                    }
                    let fault = MemoryFault {
                        status,
                        address: GuestAddress(memory_view.fault_address),
                        pc: GuestAddress(memory_view.fault_pc),
                        completed_bytes: memory_view.completed_bytes,
                    };
                    // Finalization can discard the callback result, so keep the
                    // fault before validating its PC.
                    original_fault = Some(fault);
                    require!(
                        self.source_map
                            .iter()
                            .any(|(address, _)| *address == fault.pc),
                        "memory service reported a PC outside the consumed source"
                    );
                    Ok(ScalableLeafExit::MemoryFault(fault))
                });
                match result {
                    Ok(exit) => exit,
                    Err(status) => Ok(ScalableLeafExit::FinalizationFailed {
                        status,
                        native_executed,
                        completed_bytes,
                        original_fault,
                    }),
                }
            })
        }
    }
}

fn memory_status(raw: u32) -> Result<MemoryStatus> {
    MemoryStatus::from_code(raw)
        .ok_or_else(|| refuse!("memory service returned an unknown status", raw).into())
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests;
