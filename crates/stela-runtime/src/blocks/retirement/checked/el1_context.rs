//! Canonical post-native translation publication and base exception completion.
//! The runtime's original physical pin survives ending BoundSource; the actual
//! publisher revalidates that pin and retains its replacement before retirement.
mod services;
use super::{
    Active, ConsumerKey, SettledPrefix,
    el1_registers::{RegisterNativeReport, RegisterSession},
    el1_system::RetainedSystemSession,
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
    /// Caller has ended its immutable BoundSource borrow before supplying the
    /// SAME mutable runtime. Actual native validation is repeated below; no
    /// request-carried descriptor or stale cache metadata authorizes effects.
    pub(super) fn execute_el1_context(
        mut self,
        runtime: &mut BlockRuntime,
        accounting: &mut RunOutcome,
        observation: &mut Option<ContextObservation>,
        prefixes: &mut Vec<SettledPrefix>,
    ) -> anyhow::Result<()> {
        self.require_native()?;
        let result = (|| -> anyhow::Result<()> {
            let outer = self
                .outer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("context original execution exclusion absent"))?;
            let (instruction, prefix, blocks) = {
                let bound = BoundSource::new(&*runtime, self.pe.thread.pc)?;
                let instruction = bound.el1_carrier_intent()?.ok_or_else(|| {
                    anyhow::anyhow!("actual context source has no System carrier")
                })?;
                anyhow::ensure!(
                    instruction.is_el1_context_operation(),
                    "context operation has no mounted owner"
                );
                anyhow::ensure!(
                    bound.source.len() == size_of::<u32>()
                        && instruction.matches_source(self.pe.thread.pc, instruction.word),
                    "context requires the exact original one-word typed source"
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
                    platform.ok_or_else(|| anyhow::anyhow!("original context platform absent"))?;
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
                    "effect-free context carrier changed original state or source exit"
                );
                retained.session.validate_current(self.pe.system)?;
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
                    .map_err(|()| {
                        anyhow::anyhow!("context original SystemActive transition failed")
                    })?;
                retained.closed = true;
                (instruction, prefix, blocks)
            }; // Native/context/session/BoundSource loans END; original cache pin remains.
            prefixes.push(prefix);
            accounting.blocks_executed = blocks;
            accounting.last_exit = Some((instruction.instruction_pc.0, ExitKind::System as u64));
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
                .map_err(|error| anyhow::anyhow!("actual context source fetch: {error:?}"))?;
            anyhow::ensure!(
                fetched.pc() == instruction.instruction_pc.0
                    && fetched.word() == instruction.word
                    && instruction.matches_source(GuestAddress(fetched.pc()), fetched.word()),
                "publication source differs from the original native terminal"
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
                        .map_err(|error| anyhow::anyhow!("context ISB preparation: {error:?}"))?;
                    self.pe
                        .authority
                        .start_retirement(&ConsumerKey(()), self.attempt)
                        .map_err(|()| anyhow::anyhow!("context ISB Retiring transition failed"))?;
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
                            .map_err(|error| anyhow::anyhow!("actual ERET plan: {error:?}"))?,
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
                                    anyhow::anyhow!("actual exception plan: {error:?}")
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
                            anyhow::anyhow!("actual exception context preparation: {error:?}")
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
                        .map_err(|error| anyhow::anyhow!("actual exception effect: {error:?}"));
                    if let Some(report) = observation {
                        report.effects = std::mem::take(&mut services.effects);
                        report.exception_result = Some(result);
                    }
                    next?
                }
                _ => anyhow::bail!("source has no actual context effect owner"),
            };
            // Original effects and exact observations precede the sole PC store.
            self.pe.thread.pc = next_pc;
            if let Some(report) = observation {
                report.actual_continuation = Some(next_pc);
            }
            // All prepared source/publication loans are consumed above; the
            // scope is no longer used before original-resource requalification.
            resources.check(outer)?;
            resources
                .execution
                .check_snapshot(Some(resources.platform.identification()), self.pe.system)?;
            self.pe
                .authority
                .finish_retirement(&ConsumerKey(()), self.attempt, false)
                .map_err(|()| anyhow::anyhow!("context original retirement completion failed"))?;
            Ok(())
        })();
        if let Err(error) = &result {
            if let Some(report) = observation {
                report.failure = Some(error.to_string());
            }
        } else {
            self.closed = true;
        }
        result
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
        Err(error) => anyhow::bail!("actual control publication: {error:?}"),
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
