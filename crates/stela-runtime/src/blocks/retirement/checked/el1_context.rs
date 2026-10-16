//! Translation publication after native return and EL1 exception completion.
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};
pub(super) mod interrupt;
mod services;
use super::{
    Active, ConsumerKey, SettledPrefix,
    el1_registers::{RegisterNativeReport, RegisterSession},
    el1_system::{RetainedSystemSession, RetiredSystemBoundary, SystemStep},
    provider,
    source::BoundSource,
};
use crate::{
    blocks::{BlockRuntime, RunOutcome},
    system::{
        exception::{
            self, EntryEvent, EntryPlan, ExceptionServices, ExecuteError, ReturnPlan,
            ServiceRequest,
        },
        translation_controls::{Completion, ContextSynchronizationCause, ControlError},
    },
};
use services::{BorrowedExceptionServices, ExceptionEffect};
use stela_compiler::{
    GuestAddress,
    aarch64::system::{exception::Operation, registers::Direction},
    block::{ExitKind, SystemInstruction, system::SystemOperation},
};

const ZERO_REGISTER: u8 = 31;

pub(crate) struct ContextObservation {
    pub instruction: SystemInstruction,
    pub native: RegisterNativeReport,
    pub control_result: Option<Result<Completion, ControlError>>,
    pub exception_result: Option<Result<u64, ExecuteError<String>>>,
    effects: Vec<ExceptionEffect>,
    pub actual_continuation: Option<GuestAddress>,
    pub failure: Option<String>,
}

enum ExceptionPlan {
    Entry(EntryPlan),
    Return(ReturnPlan),
}
impl ExceptionPlan {
    fn request(&self) -> ServiceRequest {
        match self {
            Self::Entry(plan) => plan.service_request(),
            Self::Return(plan) => plan.service_request(),
        }
    }
    fn target(&self) -> u64 {
        match self {
            Self::Entry(plan) => plan.target_address(),
            Self::Return(plan) => plan.target_address(),
        }
    }
    fn destination(&self) -> crate::system::access::ExceptionLevel {
        match self {
            Self::Entry(plan) => plan.target_exception_level(),
            Self::Return(plan) => plan.target_exception_level(),
        }
    }
    fn cause(&self) -> ContextSynchronizationCause {
        match self {
            Self::Entry(_) => ContextSynchronizationCause::ExceptionEntry,
            Self::Return(_) => ContextSynchronizationCause::ExceptionReturn,
        }
    }
}

impl<B: provider::Owner> Active<'_, '_, B> {
    /// The caller has ended its BoundSource borrow and passes the same runtime
    /// mutably. Native validation is repeated here.
    pub(super) fn execute_el1_context(
        &mut self,
        runtime: &mut BlockRuntime,
        accounting: &mut RunOutcome,
        observation: &mut Option<ContextObservation>,
        prefixes: &mut Vec<SettledPrefix>,
    ) -> anyhow::Result<SystemStep> {
        self.require_native()?;
        let result =
            (|| -> anyhow::Result<(SystemInstruction, crate::system::execution::EntryBoundary)> {
                let outer = self
                    .outer
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("context execution exclusion absent"))?;
                let (instruction, prefix, blocks, source_entry) = {
                    let bound = BoundSource::new(&*runtime, self.pe.thread.pc)?;
                    let instruction = bound
                        .el1_carrier_intent()?
                        .ok_or_else(|| anyhow::anyhow!("context source has no System carrier"))?;
                    anyhow::ensure!(
                        instruction.is_el1_context_operation(),
                        "context operation has no mounted owner"
                    );
                    anyhow::ensure!(
                        bound.source.len() == size_of::<u32>()
                            && instruction.matches_source(self.pe.thread.pc, instruction.word),
                        "context requires the exact one-word typed source"
                    );
                    let provider::El1ExecutionResources {
                        sources,
                        controls,
                        memory: _,
                        platform,
                        context,
                        checks,
                    } = self.pe.backend.split_el1_resources()?;
                    let platform =
                        platform.ok_or_else(|| anyhow::anyhow!("context platform absent"))?;
                    platform.context(self.pe.system)?;
                    checks.check(outer)?;
                    let scope = sources.el1_scope().map_err(anyhow::Error::msg)?;
                    let session = RegisterSession::prepare(
                        &bound,
                        outer,
                        &scope,
                        controls,
                        self.pe.system,
                        context,
                    )?;
                    let mut retained = RetainedSystemSession {
                        authority: &mut *self.pe.authority,
                        session,
                        closed: false,
                    };
                    let mut candidate = self.pe.thread.registers.clone();
                    let native = retained.session.invoke(self.pe.system, &mut candidate);
                    let valid = native.invoked
                        && native.failure.is_none()
                        && matches!(native.storage_after, Some(Ok(())));
                    let carrier = native.raw_carrier;
                    *observation = Some(ContextObservation {
                        instruction,
                        native,
                        control_result: None,
                        exception_result: None,
                        effects: Vec::new(),
                        actual_continuation: None,
                        failure: None,
                    });
                    anyhow::ensure!(
                        valid,
                        "context carrier native/storage finalization is unqualified"
                    );
                    anyhow::ensure!(
                        carrier == Some((instruction.instruction_pc.0, ExitKind::System as u64))
                            && candidate == self.pe.thread.registers
                            && self.pe.thread.pc == instruction.instruction_pc,
                        "effect-free context carrier changed state or source exit"
                    );
                    self.source_pin = Some(
                        retained
                            .session
                            .take_source_pin(&ConsumerKey(()), self.pe.system)?,
                    );
                    checks.check(outer)?;
                    let prefix = bound.prefix(Some(instruction.instruction_pc), 0)?;
                    prefixes.try_reserve(1)?;
                    let blocks = accounting
                        .blocks_executed
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("context accounting overflow"))?;
                    retained
                        .authority
                        .enter_system(&ConsumerKey(()), self.attempt)
                        .map_err(|()| anyhow::anyhow!("context SystemActive transition failed"))?;
                    retained.closed = true;
                    drop(retained);
                    (instruction, prefix, blocks, bound.entry)
                }; // Native/context/session/BoundSource loans END; original cache pin remains.
                prefixes.push(prefix);
                accounting.blocks_executed = blocks;
                accounting.last_exit =
                    Some((instruction.instruction_pc.0, ExitKind::System as u64));
                let resources = self.pe.backend.split_el1_context_resources()?;
                resources.check(outer)?;
                resources
                    .execution
                    .check_snapshot(Some(resources.platform.identification()), self.pe.system)?;
                let profile = resources.platform.context(self.pe.system)?.profile;
                let features = resources.platform.entry_profile();
                let entry_controls = resources.execution.exception_controls(resources.controls)?;
                let mut scope = resources
                    .sources
                    .publication_scope(runtime, resources.controls, self.pe.system, outer)
                    .map_err(anyhow::Error::msg)?;
                let fetched = resources
                    .controls
                    .fetch(instruction.instruction_pc.0, self.pe.system, &mut scope)
                    .map_err(|error| anyhow::anyhow!("context source fetch: {error:?}"))?;
                anyhow::ensure!(
                    fetched.pc() == instruction.instruction_pc.0
                        && fetched.word() == instruction.word
                        && instruction.matches_source(GuestAddress(fetched.pc()), fetched.word()),
                    "publication source differs from the native terminal"
                );
                let next_pc = match instruction.operation {
                    SystemOperation::Register(access) => {
                        let prepared = match access.direction() {
                            Direction::Read => PreparedControl::Read(
                                resources
                                    .controls
                                    .prepare_read(&fetched, self.pe.system, &mut scope)
                                    .map_err(|error| {
                                        anyhow::anyhow!("context MRS preparation: {error:?}")
                                    })?,
                            ),
                            Direction::Write => PreparedControl::Write(
                                resources
                                    .controls
                                    .prepare_write(
                                        &fetched,
                                        self.pe.system,
                                        &self.pe.thread.registers,
                                        &mut scope,
                                    )
                                    .map_err(|error| {
                                        anyhow::anyhow!("context MSR preparation: {error:?}")
                                    })?,
                            ),
                        };
                        self.pe
                            .authority
                            .start_retirement(&ConsumerKey(()), self.attempt)
                            .map_err(|()| {
                                anyhow::anyhow!("context control Retiring transition failed")
                            })?;
                        let result = prepared.commit();
                        let next = control_continuation(&result, &mut self.pe.thread.registers);
                        if let Some(report) = observation {
                            report.control_result = Some(result);
                        }
                        next?
                    }
                    SystemOperation::InstructionSynchronization { .. } => {
                        let prepared = resources
                            .controls
                            .prepare_isb(
                                &fetched,
                                self.pe.system,
                                &self.pe.thread.registers,
                                &mut scope,
                            )
                            .map_err(|error| {
                                anyhow::anyhow!("context ISB preparation: {error:?}")
                            })?;
                        self.pe
                            .authority
                            .start_retirement(&ConsumerKey(()), self.attempt)
                            .map_err(|()| {
                                anyhow::anyhow!("context ISB Retiring transition failed")
                            })?;
                        let result = prepared.commit();
                        let next = control_continuation(&result, &mut self.pe.thread.registers);
                        if let Some(report) = observation {
                            report.control_result = Some(result);
                        }
                        next?
                    }
                    SystemOperation::Exception(operation) => {
                        let plan = match operation {
                            Operation::ExceptionReturn { key: None } => ExceptionPlan::Return(
                                exception::prepare_return(
                                    instruction.instruction_pc.0,
                                    &features,
                                    profile,
                                    entry_controls,
                                    self.pe.system,
                                    &self.pe.thread.registers,
                                )
                                .map_err(|error| anyhow::anyhow!("ERET plan: {error:?}"))?,
                            ),
                            Operation::Undefined { .. }
                            | Operation::SupervisorCall { .. }
                            | Operation::SoftwareBreakpoint { .. } => {
                                let event = match operation {
                                    Operation::Undefined { .. } => EntryEvent::Undefined {
                                        instruction_pc: instruction.instruction_pc.0,
                                    },
                                    Operation::SupervisorCall { immediate } => {
                                        EntryEvent::SupervisorCall {
                                            instruction_pc: instruction.instruction_pc.0,
                                            immediate,
                                        }
                                    }
                                    Operation::SoftwareBreakpoint { immediate } => {
                                        EntryEvent::SoftwareBreakpoint {
                                            instruction_pc: instruction.instruction_pc.0,
                                            immediate,
                                        }
                                    }
                                    _ => unreachable!(),
                                };
                                ExceptionPlan::Entry(
                                    exception::prepare_entry(
                                        &features,
                                        profile,
                                        entry_controls,
                                        self.pe.system,
                                        &self.pe.thread.registers,
                                        event,
                                    )
                                    .map_err(|error| {
                                        anyhow::anyhow!("exception plan: {error:?}")
                                    })?,
                                )
                            }
                            _ => anyhow::bail!(
                                "authenticated or higher-EL exception resources unavailable"
                            ),
                        };
                        let request = plan.request();
                        let target = plan.target();
                        let destination = plan.destination();
                        let publication = resources
                            .controls
                            .prepare_exception_context(
                                &fetched,
                                self.pe.system,
                                plan.cause(),
                                &mut scope,
                            )
                            .map_err(|error| {
                                anyhow::anyhow!("exception context preparation: {error:?}")
                            })?;
                        let mut services = BorrowedExceptionServices::new(
                            publication,
                            &mut *resources.memory,
                            resources.endpoint,
                            request,
                            target,
                            destination,
                        );
                        let permit = services.preflight(request).map_err(anyhow::Error::msg)?;
                        self.pe
                            .authority
                            .start_retirement(&ConsumerKey(()), self.attempt)
                            .map_err(|()| {
                                anyhow::anyhow!("context exception Retiring transition failed")
                            })?;
                        let result = match plan {
                            ExceptionPlan::Entry(plan) => plan.execute_preflighted(
                                self.pe.system,
                                &mut self.pe.thread.registers,
                                &mut services,
                                permit,
                            ),
                            ExceptionPlan::Return(plan) => plan.execute_preflighted(
                                self.pe.system,
                                &mut self.pe.thread.registers,
                                &mut services,
                                permit,
                            ),
                        };
                        let next = result
                            .as_ref()
                            .copied()
                            .map(GuestAddress)
                            .map_err(|error| anyhow::anyhow!("exception effect: {error:?}"));
                        if let Some(report) = observation {
                            report.effects = core::mem::take(&mut services.effects);
                            report.exception_result = Some(result);
                        }
                        next?
                    }
                    _ => anyhow::bail!("source has no context effect owner"),
                };
                // Effects and observations come before the single PC store.
                self.pe.thread.pc = next_pc;
                if let Some(report) = observation {
                    report.actual_continuation = Some(next_pc);
                }
                // The prepared loans are consumed above, so the scope is unused
                // while resources are re-checked.
                resources.check(outer)?;
                resources
                    .execution
                    .check_snapshot(Some(resources.platform.identification()), self.pe.system)?;
                resources
                    .sources
                    .el1_scope()
                    .map_err(anyhow::Error::msg)?
                    .physical_space()
                    .validate_retired_instruction(
                        outer,
                        self.source_pin
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("context source pin missing"))?,
                    )
                    .map_err(anyhow::Error::msg)?;
                self.pe
                    .authority
                    .finish_retirement(&ConsumerKey(()), self.attempt, false)
                    .map_err(|()| anyhow::anyhow!("context retirement completion failed"))?;
                Ok((instruction, source_entry))
            })();
        if let Err(error) = &result
            && let Some(report) = observation
        {
            report.failure = Some(error.to_string());
        }
        let (instruction, source) = result?;
        match self.pe.backend.system_retirement(self.pe.system)? {
            provider::SystemRetirement::Complete => {
                self.closed = true;
                Ok(SystemStep::Retired)
            }
            provider::SystemRetirement::ArbitrateHostedIrq => {
                self.closed = false;
                Ok(SystemStep::InterruptBoundary(
                    RetiredSystemBoundary::after_context_retirement(
                        instruction,
                        self.pe.authority.identity(),
                        self.attempt,
                        self.pe.thread.pc,
                        source,
                    ),
                ))
            }
        }
    }
}

// Both nonescaping prepared variants stay inline on this one effect boundary.
// Boxing the write plan would add a fallible allocation after service preparation.
#[allow(clippy::large_enum_variant)]
enum PreparedControl<'a, P: crate::system::translation_controls::PreparedPublication> {
    Read(crate::system::translation_controls::PreparedRead<'a, P>),
    Write(crate::system::translation_controls::PreparedWrite<'a, P>),
}
impl<P: crate::system::translation_controls::PreparedPublication> PreparedControl<'_, P> {
    fn commit(self) -> Result<Completion, ControlError> {
        match self {
            Self::Read(plan) => plan.commit(),
            Self::Write(plan) => plan.commit(),
        }
    }
}

fn control_continuation(
    result: &Result<Completion, ControlError>,
    registers: &mut stela_compiler::GuestState,
) -> anyhow::Result<GuestAddress> {
    match result {
        Ok(Completion::Read { rt, value, next_pc }) => {
            if *rt != ZERO_REGISTER {
                registers.x[usize::from(*rt)] = *value;
            }
            Ok(GuestAddress(*next_pc))
        }
        Ok(Completion::FetchRequired { pc, .. }) => Ok(GuestAddress(*pc)),
        Err(error) => anyhow::bail!("control publication: {error:?}"),
    }
}

impl core::fmt::Debug for ContextObservation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ContextObservation")
            .field("instruction", &self.instruction)
            .field("native", &self.native)
            .field("control_result", &self.control_result)
            .field("exception_result", &self.exception_result)
            .field("effects", &self.effects)
            .field("actual_continuation", &self.actual_continuation)
            .field("failure", &self.failure)
            .finish()
    }
}
