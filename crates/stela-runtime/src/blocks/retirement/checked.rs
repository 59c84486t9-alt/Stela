//! Checked execution of a software processing element (PE): source, controls,
//! memory and retirement, held for the whole run.

#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};
mod call;
mod darwin_services;
mod entry_controls;
#[cfg(feature = "std")]
mod low128_call;
#[cfg(feature = "std")]
mod pauth_lr;
#[cfg(feature = "std")]
mod pauth_policy;
mod provider;
pub(crate) use call::CallRecord;
mod source;

use super::{ConsumerKey, RetainedResources, SystemExecutionLoan, accept_retained_loan};
use crate::{
    blocks::{BlockRuntime, RunOutcome, StopReason},
    memory::domain::MemoryExecutionLoan,
};
pub(crate) use entry_controls::ProcessEntryControls;
#[cfg(feature = "std")]
pub(crate) use provider::CheckedProcessOwner;
pub(crate) use source::CheckedFacts;
use source::{BoundSource, ReturnedTerminal};
use stela_compiler::GuestAddress;

pub(crate) struct OwnedRunRequest {
    pub stop_pc: Option<GuestAddress>,
    pub block_budget: usize,
}

#[allow(dead_code, reason = "run reports read the stop details through Debug")]
#[derive(Debug)]
pub(crate) enum OwnedStop {
    StopAddress,
    BudgetExhausted,
    EntryDeclined(String),
    HelperRefused(String),
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
    /// A fault is pending; delivering it is not implemented.
    FaultPending(OwnedMemoryFault),
    /// Original synchronous trap is settled, but no Darwin callback is exposed.
    TrapPending(stela_compiler::block::SynchronousTrap),
    /// Every observation is kept and the PE is marked failed.
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
    pub settled_prefixes: Vec<SettledPrefix>,
    pub service_events: darwin_services::TrapServiceEvents,
}

/// Diagnostic metadata only.
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

#[derive(Clone, Copy, Debug)]
#[allow(dead_code, reason = "run reports read the fault through Debug")]
pub(crate) struct OwnedMemoryFault {
    pub access: stela_compiler::context::memory::FaultAccess,
    pub status: stela_compiler::context::memory::MemoryStatus,
    pub address: GuestAddress,
    pub pc: GuestAddress,
    pub completed_bytes: u64,
}

#[derive(Clone, Debug)]
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
    /// The finalizer failed after the call started. `fault` is the memory
    /// fault the call reported, if any; `detail` holds every other observation.
    FinalizationFailed {
        status: stela_compiler::context::memory::MemoryStatus,
        fault: Option<OwnedMemoryFault>,
        detail: String,
    },
    /// The call, or a check around it, failed without a qualified result.
    InvocationFailed(String),
}

impl BlockRuntime {
    /// Run a request on the owned PE. `B` is sealed to the concrete backends.
    pub(crate) fn run_owned<B: provider::Owner>(
        &mut self,
        loan: SystemExecutionLoan<'_, B>,
        request: OwnedRunRequest,
    ) -> OwnedRunOutcome {
        let mut pe = accept_retained_loan(loan);
        let mut accounting = empty_accounting();
        let mut last_native_observation = None;
        let mut settled_prefixes = Vec::new();
        let mut service_events = darwin_services::TrapServiceEvents::default();
        let stop = loop {
            if !pe.authority.ready() {
                break OwnedStop::EntryDeclined("PE is not Ready".into());
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
                anyhow::ensure!(pe.thread.pc.0.is_multiple_of(4), "unaligned PC");
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
            if let Err(error) =
                pe.backend
                    .qualify(&bound, pe.system, &mut pe.thread.registers, &outer)
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
            settled_prefixes,
            service_events,
        }
    }
}

/// Dropping it never repairs state or discards a native or finalizer failure.
struct Active<'active, 'run, B: provider::Owner> {
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
                    *observation = Some(NativeObservation::InvocationFailed(error.to_string()));
                    return Err(error);
                }
            };
        // Record the return, fault or finalizer result before any fallible
        // validation, so an error cannot erase it.
        *observation = Some(result.clone());
        // `invoke` wraps ALL of checked_memory::call, including outer Result,
        // ContextLoan restoration and provider finalization. outer remains live.
        match result {
            NativeObservation::InvocationFailed(error) => anyhow::bail!("{error}"),
            NativeObservation::CpuDeclined(failure) => {
                self.pre_ffi_refusal(bound)?;
                Ok(Some(OwnedStop::EntryDeclined(format!("{failure:?}"))))
            }
            NativeObservation::EntryDeclined(status) => {
                // The checked call sets its executed flag only after the
                // mapping returns. A frame error plus a failed finalizer must
                // not be promoted to no-effect by this status-only carrier, so
                // decline without reopening Ready.
                anyhow::bail!("unqualified checked-entry/finalizer decline: {status:?}")
            }
            NativeObservation::FinalizationFailed {
                status,
                fault,
                detail,
            } => {
                // A failed finalizer never yields success. The old PC is kept
                // unless the fault PC can still be determined; either way Drop
                // marks the PE failed.
                if let Some(fault) = fault {
                    bound.validate_fault(&fault)?;
                    prefixes.push(bound.prefix(Some(fault.pc), fault.completed_bytes)?);
                    self.pe.thread.pc = fault.pc;
                }
                anyhow::bail!("checked finalization failed: {status:?}; {detail}")
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
                        // Control and domain checks run after the store.
                        self.pe.backend.post_retirement(
                            bound,
                            self.pe.system,
                            &mut self.pe.thread.registers,
                            self.outer
                                .as_ref()
                                .ok_or_else(|| anyhow::anyhow!("outer exclusion unavailable"))?,
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
                        // Publication helpers need the memory service, which
                        // refuses while native calls are active. Release the
                        // mapping exclusion only now, with PC settled.
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
                                        anyhow::anyhow!("outer exclusion unavailable")
                                    })?,
                                )?;
                                anyhow::ensure!(
                                    self.pe.thread.pc == helper.pc()
                                        && self.pe.authority.system_attempt(self.attempt),
                                    "helper refusal lost terminal"
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
                                // A staged effect is recorded as an event only
                                // after it commits.
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
                                    self.outer
                                        .as_ref()
                                        .ok_or_else(|| anyhow::anyhow!("LR outer unavailable"))?,
                                )?;
                                self.finish_retirement(false)?;
                                Ok(None)
                            }
                            #[cfg(feature = "std")]
                            HelperOutcome::AuthenticationFault { instruction, code } => {
                                // Precise no-commit fault. No exception owner or destination/link write is fabricated.
                                anyhow::ensure!(
                                    self.pe.thread.pc == instruction.instruction_pc,
                                    "LR fault lost PC"
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
                                    self.outer
                                        .as_ref()
                                        .ok_or_else(|| anyhow::anyhow!("LR outer unavailable"))?,
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
                                // The helper completed even if later validation
                                // fails; record it before any fallible step.
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
                                        anyhow::anyhow!("outer exclusion unavailable")
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
                        // No checked backend owns System effects: the
                        // instruction refuses and leaves PC at its source.
                        self.pe.thread.pc = boundary.instruction().instruction_pc;
                        self.pe
                            .authority
                            .enter_system(&ConsumerKey(()), self.attempt)
                            .map_err(|()| anyhow::anyhow!("System entry authority failed"))?;
                        self.pe.backend.qualify(
                            bound,
                            self.pe.system,
                            &mut self.pe.thread.registers,
                            self.outer
                                .as_ref()
                                .ok_or_else(|| anyhow::anyhow!("System outer unavailable"))?,
                        )?;
                        self.pe
                            .authority
                            .finish_refusal(&ConsumerKey(()), self.attempt)
                            .map_err(|()| anyhow::anyhow!("System refusal authority failed"))?;
                        self.closed = true;
                        Ok(Some(OwnedStop::HelperRefused(
                            "System instruction has no checked owner".into(),
                        )))
                    }
                    ReturnedTerminal::Trap(trap) => {
                        self.pe.thread.pc = trap.instruction_pc;
                        self.pe
                            .authority
                            .enter_system(&ConsumerKey(()), self.attempt)
                            .map_err(|()| anyhow::anyhow!("trap entry authority failed"))?;
                        // Darwin services that do not touch memory still keep
                        // native mappings excluded.
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
                                    anyhow::anyhow!("outer exclusion unavailable")
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
            "entry refusal changed PC"
        );
        self.pe.backend.qualify(
            bound,
            self.pe.system,
            &mut self.pe.thread.registers,
            self.outer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("outer exclusion unavailable"))?,
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
            "NativeActive attempt lost"
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

impl<B: provider::Owner> Drop for Active<'_, '_, B> {
    fn drop(&mut self) {
        if !self.closed {
            self.pe.authority.poison();
        }
        // `outer` is dropped only after successful completion or after the PE
        // is marked failed.
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
        amx_operations: 0,
        amx_native_operations: 0,
        pointer_authentication_events: Vec::new(),
        clock_events: Vec::new(),
        thread_register_events: Vec::new(),
    }
}

#[cfg(feature = "std")]
mod observation;
#[cfg(feature = "std")]
pub(crate) use observation::OwnedProcessObservation;

/// Check that the PE is not executing, so it may be observed. Only the
/// retirement module can construct the key this needs.
#[cfg(feature = "std")]
pub(crate) fn qualify_observation(
    authority: &crate::system::execution::authority::PeExecutionAuthority,
) -> anyhow::Result<()> {
    authority
        .check_observation(&super::ConsumerKey(()))
        .map_err(|()| anyhow::anyhow!("the PE is executing and cannot be observed"))
}
