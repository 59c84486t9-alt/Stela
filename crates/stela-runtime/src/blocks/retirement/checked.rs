//! Checked execution of a software processing element (PE): source, controls,
//! memory and retirement, held for the whole run.

#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};
mod darwin_services;
mod diagnostics;
mod el1_context;
mod el1_registers;
pub(crate) mod el1_system;
mod entry_controls;
mod halted;
#[cfg(feature = "std")]
mod low128_call;
mod m0;
#[cfg(feature = "std")]
mod pauth_lr;
#[cfg(feature = "std")]
mod pauth_policy;
mod privileged;
mod privileged_debug;
mod provider;
pub(crate) mod system_effects;
pub(crate) use halted::{OwnedDebugOutcome, run_halted_owned};
pub(crate) use privileged::PrivilegedOwner;
pub(crate) mod software_el1;
pub(crate) mod software_privileged;
mod source;

use super::{ConsumerKey, RetainedResources, SystemExecutionLoan, accept_retained_loan};
use crate::{
    blocks::{BlockRuntime, RunOutcome, StopReason},
    memory::domain::MemoryExecutionLoan,
};
pub(crate) use entry_controls::ProcessEntryControls;
pub(crate) use m0::{M0PairReadSourceInput, M0SourceInput, M0WriteSourceInput};
#[cfg(feature = "std")]
pub(crate) use provider::CheckedProcessOwner;
pub(crate) use source::CheckedFacts;
use source::{BoundSource, ReturnedTerminal};
use stela_compiler::{
    GuestAddress,
    block::{BlockProfile, CheckedMemoryProfile},
};

pub(crate) struct OwnedRunRequest {
    pub stop_pc: Option<GuestAddress>,
    pub block_budget: usize,
}

pub(crate) enum OwnedStop {
    StopAddress,
    BudgetExhausted,
    EntryDeclined(String),
    HelperRefused(String),
    Halted {
        instruction_pc: GuestAddress,
    },
    #[cfg(feature = "std")]
    PointerAuthenticationFault {
        instruction: stela_compiler::block::PointerAuthentication,
        code: u8,
    },
    #[cfg(feature = "std")]
    PointerAuthenticationPoisonedTransfer {
        instruction: stela_compiler::block::PointerAuthentication,
        target: GuestAddress,
    },
    /// No Ready/retry grant: delivery requires a separately reviewed consumer.
    FaultPending(OwnedMemoryFault),
    /// Original synchronous trap is settled, but no Darwin callback is exposed.
    TrapPending(stela_compiler::block::SynchronousTrap),
    /// All retained observations survive; actual authority is poisoned.
    Indeterminate(String),
}

#[derive(Debug)]
// Hosted process reports read every retained observation.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(crate) struct OwnedRunOutcome {
    pub stop: OwnedStop,
    pub accounting: RunOutcome,
    pub actual_pc: GuestAddress,
    pub last_native_observation: Option<NativeObservation>,
    pub last_m0_observation: Option<m0::M0Observation>,
    pub last_m0_write_observation: Option<m0::M0WriteObservation>,
    pub last_m0_pair_read_observation: Option<m0::M0PairReadObservation>,
    pub last_el1_register_observation: Option<el1_registers::RegisterObservation>,
    pub last_el1_system_observation: Option<el1_system::SystemObservation>,
    pub last_system_effect_observation: Option<system_effects::SystemEffectObservation>,
    pub last_el1_context_observation: Option<el1_context::ContextObservation>,
    pub settled_prefixes: Vec<SettledPrefix>,
    pub service_events: darwin_services::TrapServiceEvents,
}

/// Diagnostic metadata only; cannot mint entry/retirement/source authority.
#[derive(Debug)]
// Hosted process reports read every retained observation.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(crate) struct SettledPrefix {
    pub entry: GuestAddress,
    pub generation: u64,
    pub source_sha256: String,
    pub consumed_source_bytes: usize,
    pub source_prefix_bytes: usize,
    pub source_map: Vec<(GuestAddress, usize)>,
    pub stopped_before: Option<GuestAddress>,
    pub completed_memory_bytes: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct OwnedMemoryFault {
    pub status: stela_compiler::context::memory::MemoryStatus,
    pub address: GuestAddress,
    pub pc: GuestAddress,
    pub completed_bytes: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct RawMemoryObservation {
    pub status_code: u32,
    pub address: u64,
    pub pc: u64,
    pub completed_bytes: u64,
}

impl From<super::super::checked_memory::MemoryFault> for OwnedMemoryFault {
    fn from(fault: super::super::checked_memory::MemoryFault) -> Self {
        Self {
            status: fault.status,
            address: fault.address,
            pc: fault.pc,
            completed_bytes: fault.completed_bytes,
        }
    }
}

#[derive(Clone)]
// Only the hosted EL0 process owner produces entry declines and faults today.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(crate) enum NativeObservation {
    Returned {
        next_pc: u64,
        kind: u64,
    },
    Fault(OwnedMemoryFault),
    CpuDeclined(String),
    EntryDeclined(stela_compiler::context::memory::MemoryStatus),
    FinalizationFailed {
        status: stela_compiler::context::memory::MemoryStatus,
        native_executed: bool,
        original_fault: Option<OwnedMemoryFault>,
        completed_bytes: u64,
        observed_exit: Option<(u64, u64)>,
        native_invoked: Option<bool>,
        callback_failure: Option<String>,
        raw_memory: Option<RawMemoryObservation>,
        /// Unqualified native bits; fault service state takes precedence.
        raw_returned_carrier: Option<(u64, u64)>,
    },
    InvocationFailed {
        detail: String,
        native_invoked: bool,
        native_executed: bool,
        original_fault: Option<OwnedMemoryFault>,
        raw_memory: Option<RawMemoryObservation>,
        completed_bytes: u64,
        observed_exit: Option<(u64, u64)>,
        raw_returned_carrier: Option<(u64, u64)>,
    },
    /// checked call's outer Err has no qualified completion/prefix result.
    UnqualifiedCallFailure(String),
}

impl BlockRuntime {
    /// Sole proposed adopted-PE entry. B is sealed to the concrete owner below.
    /// A request has no mapping, ThreadState, dispatcher, callbacks or permit.
    pub(crate) fn run_owned<B: provider::Owner>(
        &mut self,
        loan: SystemExecutionLoan<'_, B>,
        request: OwnedRunRequest,
    ) -> OwnedRunOutcome {
        let mut pe = accept_retained_loan(loan);
        let mut accounting = empty_accounting();
        let mut last_native_observation = None;
        let mut last_m0_observation = None;
        let mut last_m0_write_observation = None;
        let mut last_m0_pair_read_observation = None;
        let mut last_el1_register_observation = None;
        let mut last_el1_system_observation = None;
        let mut last_system_effect_observation = None;
        let mut last_el1_context_observation = None;
        let mut settled_prefixes = Vec::new();
        let mut service_events = darwin_services::TrapServiceEvents::default();
        let stop = loop {
            if !pe.authority.ready() {
                break OwnedStop::EntryDeclined("actual PE is not Ready".into());
            }
            if request.stop_pc == Some(pe.thread.pc) {
                break OwnedStop::StopAddress;
            }
            if accounting.blocks_executed >= request.block_budget {
                break OwnedStop::BudgetExhausted;
            }
            // Acquisition precedes source selection, loading, parser preparation,
            // CPU preparation, exact FFI, every finalizer and all PC settlement.
            let outer = match pe.backend.execution_loan() {
                Ok(loan) => loan,
                Err(error) => break OwnedStop::EntryDeclined(error.to_string()),
            };
            let prepared = (|| -> anyhow::Result<()> {
                crate::execution::platform::ensure_supported()?;
                anyhow::ensure!(
                    crate::platform::cpu::admitted(self.target_cpu()),
                    "host target unsupported"
                );
                anyhow::ensure!(
                    pe.backend.supports_profile(self.profile),
                    "checked profile required"
                );
                anyhow::ensure!(pe.thread.pc.0.is_multiple_of(4), "unaligned actual PC");
                pe.backend
                    .prepare_source(self, pe.system, pe.thread.pc, &outer)?;
                self.load(pe.thread.pc, &mut accounting)?;
                Ok(())
            })();
            if let Err(error) = prepared {
                break OwnedStop::EntryDeclined(error.to_string());
            }
            let bound = match BoundSource::new(self, pe.thread.pc) {
                Ok(bound) => bound,
                Err(error) => break OwnedStop::EntryDeclined(error.to_string()),
            };
            if let Err(error) = pe
                .backend
                .qualify_debug_lifecycle(pe.debug.as_ref(), pe.system)
                .and_then(|()| {
                    pe.backend
                        .qualify(&bound, pe.system, &mut pe.thread.registers, &outer)
                })
            {
                break OwnedStop::EntryDeclined(error.to_string());
            }
            let attempt = match pe.authority.begin_native(&ConsumerKey(())) {
                Ok(attempt) => attempt,
                Err(()) => break OwnedStop::Indeterminate("begin-native authority failed".into()),
            };
            let active = Active {
                pe: &mut pe,
                outer: Some(outer),
                attempt,
                closed: false,
            };
            if self.profile == BlockProfile::El1PlatformV1
                && matches!(bound.el1_platform_intent(),
                    Ok(stela_compiler::block::el1_platform::Intent::System(instruction))
                        if instruction.is_el1_ram_completion())
            {
                match active.execute_system_effects(
                    &bound,
                    &mut accounting,
                    &mut last_system_effect_observation,
                    &mut settled_prefixes,
                ) {
                    Ok(None) => continue,
                    Ok(Some(stop)) => break stop,
                    Err(error) => break OwnedStop::Indeterminate(error.to_string()),
                }
            }
            if self.profile == BlockProfile::El1PlatformV1
                && matches!(bound.el1_platform_intent(),
                    Ok(stela_compiler::block::el1_platform::Intent::System(instruction))
                        if instruction.is_el1_context_operation())
            {
                match active.execute_el1_context(
                    self,
                    &mut accounting,
                    &mut last_el1_context_observation,
                    &mut settled_prefixes,
                ) {
                    Ok(()) => continue,
                    Err(error) => break OwnedStop::Indeterminate(error.to_string()),
                }
            }
            if self.profile == BlockProfile::El1PlatformV1
                && matches!(
                    bound.el1_platform_intent(),
                    Ok(stela_compiler::block::el1_platform::Intent::System(_))
                )
            {
                match active.execute_el1_system(
                    &bound,
                    &mut accounting,
                    &mut last_el1_system_observation,
                    &mut settled_prefixes,
                ) {
                    Ok(None) => continue,
                    Ok(Some(stop)) => break stop,
                    Err(error) => break OwnedStop::Indeterminate(error.to_string()),
                }
            }
            if self.profile == BlockProfile::El1PlatformV1
                && matches!(
                    bound.el1_platform_intent(),
                    Ok(stela_compiler::block::el1_platform::Intent::Write64Pair(_))
                )
            {
                match active.execute_m0_write64_pair(
                    &bound,
                    &mut accounting,
                    &mut last_m0_write_observation,
                    &mut settled_prefixes,
                ) {
                    Ok(m0::M0Step::Committed) => {
                        // The one-word write carrier has returned, settled and
                        // dropped its original source/native/outer loans. Retire
                        // only derived snapshots made stale by real source writes.
                        if last_m0_write_observation
                            .as_ref()
                            .is_some_and(m0::M0WriteObservation::modified_instruction_ram)
                        {
                            self.retire_mutated_translation_sources();
                        }
                        continue;
                    }
                    Ok(m0::M0Step::SourceResourcesBlocked) => {
                        break OwnedStop::Indeterminate(
                            "M0 write original resources unavailable".into(),
                        );
                    }
                    Ok(m0::M0Step::SourceControlBlocked) => {
                        break OwnedStop::Indeterminate(
                            "M0 write source/control qualification blocked".into(),
                        );
                    }
                    Ok(m0::M0Step::PreparationBlocked) => {
                        break OwnedStop::Indeterminate(
                            "M0 write no-effect preparation blocked".into(),
                        );
                    }
                    Ok(m0::M0Step::Indeterminate(detail)) => {
                        break OwnedStop::Indeterminate(detail);
                    }
                    Err(error) => break OwnedStop::Indeterminate(error.to_string()),
                }
            }
            if self.profile == BlockProfile::El1PlatformV1
                && matches!(
                    bound.el1_platform_intent(),
                    Ok(stela_compiler::block::el1_platform::Intent::Read64Pair(_))
                )
            {
                match active.execute_m0_read64_pair(
                    &bound,
                    &mut accounting,
                    &mut last_m0_pair_read_observation,
                    &mut settled_prefixes,
                ) {
                    Ok(m0::M0Step::Committed) => continue,
                    Ok(m0::M0Step::SourceResourcesBlocked) => {
                        break OwnedStop::Indeterminate(
                            "M0 pair read original resources unavailable".into(),
                        );
                    }
                    Ok(m0::M0Step::SourceControlBlocked) => {
                        break OwnedStop::Indeterminate(
                            "M0 pair read source/control qualification blocked".into(),
                        );
                    }
                    Ok(m0::M0Step::PreparationBlocked) => {
                        break OwnedStop::Indeterminate(
                            "M0 pair read no-effect preparation blocked".into(),
                        );
                    }
                    Ok(m0::M0Step::Indeterminate(detail)) => {
                        break OwnedStop::Indeterminate(detail);
                    }
                    Err(error) => break OwnedStop::Indeterminate(error.to_string()),
                }
            }
            if matches!(
                self.profile,
                BlockProfile::El1DirectBranchV1
                    | BlockProfile::El1M0IntegerV1
                    | BlockProfile::El1PlatformV1
            ) && bound.el1_register_intent().is_ok()
            {
                match active.execute_el1_registers(
                    &bound,
                    &mut accounting,
                    &mut last_el1_register_observation,
                    &mut settled_prefixes,
                ) {
                    Ok(()) => continue,
                    Err(error) => break OwnedStop::Indeterminate(error.to_string()),
                }
            }
            // The immutable typed source profile selects the concrete consumer;
            // it grants no CPU/domain access. The sealed M0 backend still must
            // lend its original resources and genuine control/source witnesses.
            if matches!(
                self.profile,
                BlockProfile::El1M0IntegerV1 | BlockProfile::El1PlatformV1
            ) || self.profile
                == BlockProfile::CheckedMemory(CheckedMemoryProfile::M0DeviceRamRead64Staged)
            {
                match active.execute_m0_scalar_load(
                    &bound,
                    &mut accounting,
                    &mut last_m0_observation,
                    &mut settled_prefixes,
                ) {
                    Ok(m0::M0Step::Committed) => continue,
                    Ok(m0::M0Step::SourceResourcesBlocked) => {
                        break OwnedStop::Indeterminate(
                            "M0 original resource loan unavailable".into(),
                        );
                    }
                    Ok(m0::M0Step::SourceControlBlocked) => {
                        break OwnedStop::Indeterminate(
                            "M0 source/control fault remains blocked".into(),
                        );
                    }
                    Ok(m0::M0Step::PreparationBlocked) => {
                        break OwnedStop::Indeterminate("M0 no-read preparation failed".into());
                    }
                    Ok(m0::M0Step::Indeterminate(detail)) => {
                        break OwnedStop::Indeterminate(detail);
                    }
                    Err(error) => break OwnedStop::Indeterminate(error.to_string()),
                }
            }
            match active.execute(
                &bound,
                &mut accounting,
                &mut last_native_observation,
                &mut settled_prefixes,
                &mut service_events,
            ) {
                Ok(None) => {}
                Ok(Some(stop)) => break stop,
                Err(error) => break OwnedStop::Indeterminate(error.to_string()),
            }
        };
        accounting.reason = match &stop {
            OwnedStop::Halted { instruction_pc } => StopReason::Halted {
                instruction_pc: *instruction_pc,
            },
            OwnedStop::StopAddress => StopReason::StopAddress,
            OwnedStop::BudgetExhausted => StopReason::BudgetExhausted,
            #[cfg(feature = "std")]
            OwnedStop::PointerAuthenticationPoisonedTransfer {
                instruction,
                target,
            } => {
                if instruction.operation.is_return() {
                    StopReason::PointerAuthenticationPoisonedReturn {
                        instruction: *instruction,
                        poisoned_target: *target,
                    }
                } else {
                    StopReason::PointerAuthenticationPoisonedBranch {
                        instruction: *instruction,
                        poisoned_target: *target,
                    }
                }
            }
            _ => StopReason::Unsupported {
                detail: format!("owned retirement stop: {stop:?}"),
            },
        };
        OwnedRunOutcome {
            stop,
            accounting,
            actual_pc: pe.thread.pc,
            last_native_observation,
            last_m0_observation,
            last_m0_write_observation,
            last_m0_pair_read_observation,
            last_el1_register_observation,
            last_el1_system_observation,
            last_system_effect_observation,
            last_el1_context_observation,
            settled_prefixes,
            service_events,
        }
    }
}

/// Drop never repairs authority or discards the native/finalizer failure.
struct Active<'active, 'run, B> {
    pe: &'active mut RetainedResources<'run, B>,
    outer: Option<MemoryExecutionLoan>,
    attempt: u64,
    closed: bool,
}

impl<B: provider::Owner> Active<'_, '_, B> {
    fn execute(
        mut self,
        bound: &BoundSource<'_>,
        accounting: &mut RunOutcome,
        observation: &mut Option<NativeObservation>,
        prefixes: &mut Vec<SettledPrefix>,
        service_events: &mut darwin_services::TrapServiceEvents,
    ) -> anyhow::Result<Option<OwnedStop>> {
        let result =
            match self
                .pe
                .backend
                .invoke(bound, self.pe.system, &mut self.pe.thread.registers)
            {
                Ok(result) => result,
                Err(error) => {
                    *observation =
                        Some(NativeObservation::UnqualifiedCallFailure(error.to_string()));
                    return Err(error);
                }
            };
        // Preserve the actual return/fault/finalizer record before any fallible
        // carrier/source qualification. A validation error cannot erase it.
        *observation = Some(result.clone());
        // `invoke` wraps ALL of checked_memory::call, including outer Result,
        // ContextLoan restoration and provider finalization. outer remains live.
        match result {
            NativeObservation::UnqualifiedCallFailure(error) => anyhow::bail!("{error}"),
            NativeObservation::InvocationFailed { detail, .. } => anyhow::bail!("{detail}"),
            NativeObservation::CpuDeclined(failure) => {
                self.pre_ffi_refusal(bound)?;
                Ok(Some(OwnedStop::EntryDeclined(format!("{failure:?}"))))
            }
            NativeObservation::EntryDeclined(status) => {
                // Legacy checked call's native_executed flag is set only
                // after mapping returns successfully. A future frame error
                // plus failed finalizer must not be promoted to no-effect by
                // this status-only carrier. Decline without reopening Ready.
                anyhow::bail!("unqualified checked-entry/finalizer decline: {status:?}")
            }
            NativeObservation::FinalizationFailed {
                status,
                native_executed,
                original_fault,
                completed_bytes,
                observed_exit,
                native_invoked,
                callback_failure,
                raw_memory,
                raw_returned_carrier,
            } => {
                // No carrier authorizes success after a failed finalizer. The
                // actual old PC is preserved unless an exact original fault PC
                // can still be established; either way Drop poisons this PE.
                if let Some(fault) = original_fault {
                    bound.validate_fault(&fault)?;
                    prefixes.push(bound.prefix(Some(fault.pc), fault.completed_bytes)?);
                    self.pe.thread.pc = fault.pc;
                }
                anyhow::bail!(
                    "checked finalization failed: {status:?}; native={native_executed}; original={original_fault:?}; completed={completed_bytes}; exit={observed_exit:?}; invoked={native_invoked:?}; callback={callback_failure:?}; raw={raw_memory:?}; raw_carrier={raw_returned_carrier:?}"
                )
            }
            NativeObservation::Fault(fault) => {
                bound.validate_fault(&fault)?;
                self.require_native()?;
                prefixes.push(bound.prefix(Some(fault.pc), fault.completed_bytes)?);
                self.pe.thread.pc = fault.pc;
                accounting.blocks_executed += 1;
                // This stops in RequalificationRequired/FaultPending. No Ready
                // transition or retry of the partially completed instruction.
                self.pe
                    .authority
                    .finish_native_fault(&ConsumerKey(()), self.attempt)
                    .map_err(|()| anyhow::anyhow!("fault settlement authority failed"))?;
                self.closed = true;
                Ok(Some(OwnedStop::FaultPending(fault)))
            }
            NativeObservation::Returned { next_pc, kind } => {
                let exit = stela_compiler::block::BlockExit { next_pc, kind };
                let terminal = bound.validate_return(&exit, &self.pe.thread.registers)?;
                self.require_native()?;
                let stopped_before = match &terminal {
                    ReturnedTerminal::Ordinary(_) => None,
                    ReturnedTerminal::Helper(helper) => Some(helper.pc()),
                    ReturnedTerminal::Trap(trap) => Some(trap.instruction_pc),
                    ReturnedTerminal::System(boundary) => {
                        Some(boundary.instruction().instruction_pc)
                    }
                };
                prefixes.push(bound.prefix(stopped_before, 0)?);
                accounting.blocks_executed += 1;
                accounting.last_exit = Some((exit.next_pc, exit.kind));
                match terminal {
                    ReturnedTerminal::Ordinary(continuation) => {
                        self.pe
                            .authority
                            .start_native_retirement(&ConsumerKey(()), self.attempt)
                            .map_err(|()| anyhow::anyhow!("native retirement authority failed"))?;
                        self.pe.thread.pc = continuation;
                        // Actual producer registry/control/domain checks run
                        // after the store. No no-op callback or saved bool.
                        self.pe.backend.post_retirement(
                            bound,
                            self.pe.system,
                            &mut self.pe.thread.registers,
                            self.outer.as_ref().ok_or_else(|| {
                                anyhow::anyhow!("actual outer exclusion unavailable")
                            })?,
                        )?;
                        self.finish_retirement(false)?;
                        Ok(None)
                    }
                    ReturnedTerminal::Helper(helper) => {
                        self.pe.thread.pc = helper.pc();
                        self.pe
                            .authority
                            .enter_system(&ConsumerKey(()), self.attempt)
                            .map_err(|()| anyhow::anyhow!("helper entry authority failed"))?;
                        // Publication helpers use the real canonical service
                        // loan, which rejects native_loans>0. Only now, with
                        // actual prefix/terminal PC settled and SystemActive,
                        // may the old mapping exclusion be released.
                        if helper.needs_publication() {
                            self.outer.take();
                        }
                        let outcome = self.pe.backend.complete_helper(
                            &helper,
                            self.pe.system,
                            &mut self.pe.thread.registers,
                            self.outer.as_ref(),
                        );
                        use provider::HelperOutcome;
                        match outcome {
                            HelperOutcome::NoEffect(error) => {
                                self.ensure_outer()?;
                                self.pe.backend.qualify(
                                    bound,
                                    self.pe.system,
                                    &mut self.pe.thread.registers,
                                    self.outer.as_ref().ok_or_else(|| {
                                        anyhow::anyhow!("actual outer exclusion unavailable")
                                    })?,
                                )?;
                                anyhow::ensure!(
                                    self.pe.thread.pc == helper.pc()
                                        && self.pe.authority.system_attempt(self.attempt),
                                    "helper refusal lost actual terminal"
                                );
                                self.pe
                                    .authority
                                    .finish_refusal(&ConsumerKey(()), self.attempt)
                                    .map_err(|()| {
                                        anyhow::anyhow!("helper refusal authority failed")
                                    })?;
                                self.closed = true;
                                Ok(Some(OwnedStop::HelperRefused(error.to_string())))
                            }
                            HelperOutcome::Indeterminate(error) => Err(error),
                            #[cfg(feature = "std")]
                            HelperOutcome::PreparedPauth {
                                instruction,
                                effect,
                            } => {
                                effect.validate(self.pe.system)?;
                                let continuation = effect.continuation();
                                let authenticated = effect.authenticated();
                                self.pe
                                    .authority
                                    .start_retirement(&ConsumerKey(()), self.attempt)
                                    .map_err(|()| {
                                        anyhow::anyhow!("LR retirement authority failed")
                                    })?;
                                effect.commit(&mut self.pe.thread.registers, self.pe.system)?;
                                // A staged candidate becomes an actual service observation only after commit.
                                accounting.pointer_authentication_events.push(
                                    crate::blocks::PointerAuthenticationEvent {
                                        instruction,
                                        next_pc: continuation,
                                        authenticated,
                                    },
                                );
                                self.pe.thread.pc = continuation;
                                self.ensure_outer()?;
                                self.pe.backend.post_retirement(
                                    bound,
                                    self.pe.system,
                                    &mut self.pe.thread.registers,
                                    self.outer.as_ref().ok_or_else(|| {
                                        anyhow::anyhow!("actual LR outer unavailable")
                                    })?,
                                )?;
                                self.finish_retirement(false)?;
                                Ok(None)
                            }
                            #[cfg(feature = "std")]
                            HelperOutcome::AuthenticationFault { instruction, code } => {
                                // Precise no-commit fault. No exception owner or destination/link write is fabricated.
                                anyhow::ensure!(
                                    self.pe.thread.pc == instruction.instruction_pc,
                                    "LR fault lost actual PC"
                                );
                                self.pe
                                    .authority
                                    .start_retirement(&ConsumerKey(()), self.attempt)
                                    .map_err(|()| {
                                        anyhow::anyhow!("LR fault settlement authority failed")
                                    })?;
                                self.ensure_outer()?;
                                self.pe.backend.post_retirement(
                                    bound,
                                    self.pe.system,
                                    &mut self.pe.thread.registers,
                                    self.outer.as_ref().ok_or_else(|| {
                                        anyhow::anyhow!("actual LR outer unavailable")
                                    })?,
                                )?;
                                self.finish_retirement(true)?;
                                Ok(Some(OwnedStop::PointerAuthenticationFault {
                                    instruction,
                                    code,
                                }))
                            }

                            #[cfg(feature = "std")]
                            HelperOutcome::Complete {
                                continuation,
                                event,
                            } => {
                                // This actual same-call helper completed even
                                // if later requalification fails. Retain its
                                // observation before any fallible transition.
                                let poisoned_transfer = event.poisoned_transfer();
                                event.record(accounting);
                                self.pe
                                    .authority
                                    .start_retirement(&ConsumerKey(()), self.attempt)
                                    .map_err(|()| {
                                        anyhow::anyhow!("helper retirement authority failed")
                                    })?;
                                self.pe.thread.pc = continuation;
                                self.ensure_outer()?;
                                self.pe.backend.post_retirement(
                                    bound,
                                    self.pe.system,
                                    &mut self.pe.thread.registers,
                                    self.outer.as_ref().ok_or_else(|| {
                                        anyhow::anyhow!("actual outer exclusion unavailable")
                                    })?,
                                )?;
                                self.finish_retirement(poisoned_transfer.is_some())?;
                                Ok(poisoned_transfer.map(|(instruction, target)| {
                                    OwnedStop::PointerAuthenticationPoisonedTransfer {
                                        instruction,
                                        target,
                                    }
                                }))
                            }
                        }
                    }
                    ReturnedTerminal::System(boundary) => {
                        self.pe.thread.pc = boundary.instruction().instruction_pc;
                        self.pe
                            .authority
                            .enter_system(&ConsumerKey(()), self.attempt)
                            .map_err(|()| anyhow::anyhow!("System entry authority failed"))?;
                        let outcome = self.pe.backend.complete_system(
                            bound,
                            &boundary,
                            self.pe.system,
                            &mut self.pe.thread.registers,
                            self.pe.debug.as_mut(),
                            self.outer
                                .as_ref()
                                .ok_or_else(|| anyhow::anyhow!("System outer unavailable"))?,
                        );
                        match outcome {
                            privileged::SystemOutcome::NoEffect(error) => {
                                self.pe.backend.qualify_debug_lifecycle(
                                    self.pe.debug.as_ref(),
                                    self.pe.system,
                                )?;
                                self.pe.backend.qualify(
                                    bound,
                                    self.pe.system,
                                    &mut self.pe.thread.registers,
                                    self.outer.as_ref().ok_or_else(|| {
                                        anyhow::anyhow!("System outer unavailable")
                                    })?,
                                )?;
                                self.pe
                                    .authority
                                    .finish_refusal(&ConsumerKey(()), self.attempt)
                                    .map_err(|()| {
                                        anyhow::anyhow!("System refusal authority failed")
                                    })?;
                                self.closed = true;
                                Ok(Some(OwnedStop::HelperRefused(error.to_string())))
                            }
                            privileged::SystemOutcome::Indeterminate { committed, error } => Err(
                                anyhow::anyhow!("System effects through {committed:?}: {error}"),
                            ),
                            privileged::SystemOutcome::Entry { target } => {
                                self.pe
                                    .authority
                                    .start_retirement(&ConsumerKey(()), self.attempt)
                                    .map_err(|()| {
                                        anyhow::anyhow!("System retirement authority failed")
                                    })?;
                                self.pe.thread.pc = target;
                                let target_source = BoundSource::new(bound.runtime, target)?;
                                self.pe.backend.qualify(
                                    &target_source,
                                    self.pe.system,
                                    &mut self.pe.thread.registers,
                                    self.outer.as_ref().ok_or_else(|| {
                                        anyhow::anyhow!("actual target outer unavailable")
                                    })?,
                                )?;
                                self.pe.backend.post_retirement(
                                    bound,
                                    self.pe.system,
                                    &mut self.pe.thread.registers,
                                    self.outer.as_ref().ok_or_else(|| {
                                        anyhow::anyhow!("System outer unavailable")
                                    })?,
                                )?;
                                self.pe.backend.qualify_debug_lifecycle(
                                    self.pe.debug.as_ref(),
                                    self.pe.system,
                                )?;
                                self.finish_retirement(false)?;
                                Ok(None)
                            }
                            privileged::SystemOutcome::Halted { source_pc } => {
                                anyhow::ensure!(
                                    self.pe.thread.pc == source_pc,
                                    "Halt source PC changed"
                                );
                                let debug =
                                    self.pe.debug.as_ref().ok_or_else(|| {
                                        anyhow::anyhow!("Halt lifecycle unavailable")
                                    })?;
                                debug
                                    .qualify_halted_boundary()
                                    .map_err(|e| anyhow::anyhow!("Halt gate: {e:?}"))?;
                                // EndOfInstruction(Exception): the actual instruction PC remains
                                // the restart source, and the sole phase becomes Halted. No Ready.
                                self.pe
                                    .authority
                                    .finish_halt(&ConsumerKey(()), self.attempt)
                                    .map_err(|()| anyhow::anyhow!("Halt authority failed"))?;
                                self.closed = true;
                                Ok(Some(OwnedStop::Halted {
                                    instruction_pc: source_pc,
                                }))
                            }
                        }
                    }
                    ReturnedTerminal::Trap(trap) => {
                        self.pe.thread.pc = trap.instruction_pc;
                        self.pe
                            .authority
                            .enter_system(&ConsumerKey(()), self.attempt)
                            .map_err(|()| anyhow::anyhow!("trap entry authority failed"))?;
                        // Non-memory Darwin services retain native mapping
                        // exclusion as well as this same actual SystemActive PE.
                        let continuation = match self.pe.backend.complete_trap(
                            &trap,
                            self.pe.system,
                            &mut self.pe.thread.registers,
                            service_events,
                        ) {
                            #[cfg(feature = "std")]
                            darwin_services::Outcome::Complete(pc) => Some(pc),
                            darwin_services::Outcome::NoEffect => None,
                            darwin_services::Outcome::Indeterminate(error) => return Err(error),
                        };
                        self.pe
                            .authority
                            .start_retirement(&ConsumerKey(()), self.attempt)
                            .map_err(|()| anyhow::anyhow!("trap retirement authority failed"))?;
                        if let Some(continuation) = continuation {
                            anyhow::ensure!(
                                continuation == trap.exception_return_pc,
                                "Darwin service continuation differs"
                            );
                            self.pe.thread.pc = continuation;
                            self.pe.backend.post_retirement(
                                bound,
                                self.pe.system,
                                &mut self.pe.thread.registers,
                                self.outer.as_ref().ok_or_else(|| {
                                    anyhow::anyhow!("actual outer exclusion unavailable")
                                })?,
                            )?;
                            self.finish_retirement(false)?;
                            Ok(None)
                        } else {
                            self.finish_retirement(true)?;
                            Ok(Some(OwnedStop::TrapPending(trap)))
                        }
                    }
                }
            }
        }
    }

    fn pre_ffi_refusal(&mut self, bound: &BoundSource<'_>) -> anyhow::Result<()> {
        self.require_native()?;
        anyhow::ensure!(
            self.pe.thread.pc == bound.entry.entry(),
            "entry refusal changed actual PC"
        );
        self.pe.backend.qualify(
            bound,
            self.pe.system,
            &mut self.pe.thread.registers,
            self.outer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("actual outer exclusion unavailable"))?,
        )?;
        self.pe
            .authority
            .finish_native_refusal(&ConsumerKey(()), self.attempt)
            .map_err(|()| anyhow::anyhow!("native refusal authority failed"))?;
        self.closed = true;
        Ok(())
    }

    fn require_native(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.pe.authority.native_attempt(self.attempt),
            "actual NativeActive attempt lost"
        );
        Ok(())
    }

    fn ensure_outer(&mut self) -> anyhow::Result<()> {
        if self.outer.is_none() {
            self.outer = Some(self.pe.backend.execution_loan()?);
        }
        Ok(())
    }

    fn finish_retirement(&mut self, requalify: bool) -> anyhow::Result<()> {
        self.pe
            .authority
            .finish_retirement(&ConsumerKey(()), self.attempt, requalify)
            .map_err(|()| anyhow::anyhow!("retirement authority failed"))?;
        self.closed = true;
        Ok(())
    }
}

impl<B> Drop for Active<'_, '_, B> {
    fn drop(&mut self) {
        if !self.closed {
            self.pe.authority.poison();
        }
        // outer drops only after qualified closure or actual failstop poison.
    }
}

fn empty_accounting() -> RunOutcome {
    RunOutcome {
        reason: StopReason::BudgetExhausted,
        blocks_executed: 0,
        compiled_blocks: 0,
        disk_cache_hits: 0,
        memory_cache_hits: 0,
        last_exit: None,
        floating_point_helpers: 0,
        pointer_authentication_events: Vec::new(),
        clock_events: Vec::new(),
        thread_register_events: Vec::new(),
    }
}

#[cfg(feature = "std")]
mod observation;
#[cfg(feature = "std")]
pub(crate) use observation::OwnedProcessObservation;

// ConsumerKey is constructed only by the canonical retirement consumer.
// This check is immutable and grants no execution or service completion.
#[cfg(feature = "std")]
pub(crate) fn qualify_observation(
    authority: &crate::system::execution::authority::PeExecutionAuthority,
) -> anyhow::Result<()> {
    authority
        .check_observation(&super::ConsumerKey(()))
        .map_err(|()| anyhow::anyhow!("actual retained PE observation is active"))
}
