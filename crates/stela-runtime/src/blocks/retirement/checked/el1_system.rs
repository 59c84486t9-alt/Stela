//! EL1 system-register effects. The native block finishes first; the staged
//! effect then commits and the retiring owner sets PC.
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};
mod controls;
use super::{
    Active, ConsumerKey, OwnedStop, SettledPrefix,
    el1_registers::{RegisterNativeReport, RegisterSession},
    provider,
    source::{BoundSource, RetiredInstructionSource},
};
use crate::{
    blocks::RunOutcome,
    memory::domain::MemoryExecutionLoan,
    system::{
        execution::authority::PeExecutionAuthority,
        registers::{el1::vbar, pstate::immediate::el1_daif},
        state::SystemState,
        translation_controls::TranslationControls,
    },
};
pub(super) use controls::El1PlatformControls;
use stela_compiler::{
    GuestAddress, GuestState,
    block::{ExitKind, SystemInstruction, el1_platform::Intent},
};

/// A retired System instruction that may be followed by IRQ entry. It does
/// not itself permit entry; the run loop keeps the runtime's physical pin,
/// the PE and the outer loan while the BoundSource borrow ends.
pub(super) struct RetiredSystemBoundary {
    instruction: SystemInstruction,
    pe: crate::system::execution::authority::PeIdentity,
    retirement_attempt: u64,
    // Taken from the BoundSource by the run loop. It records where the
    // instruction came from; it is not a second physical source pin.
    source_entry: Option<crate::system::execution::EntryBoundary>,
    retired_pc: GuestAddress,
}
impl RetiredSystemBoundary {
    pub(super) fn after_retirement(
        instruction: SystemInstruction,
        pe: crate::system::execution::authority::PeIdentity,
        retirement_attempt: u64,
    ) -> Self {
        Self {
            instruction,
            pe,
            retirement_attempt,
            source_entry: None,
            retired_pc: instruction.next_pc,
        }
    }

    pub(super) fn bind_retired_source(mut self, bound: BoundSource<'_>) -> anyhow::Result<Self> {
        anyhow::ensure!(self.source_entry.is_none(), "retired source already bound");
        anyhow::ensure!(
            bound.el1_platform_intent()? == Intent::System(self.instruction)
                && bound.entry.entry() == self.instruction.instruction_pc
                && bound.entry.word() == self.instruction.word,
            "retired boundary differs from source"
        );
        self.source_entry = Some(bound.entry);
        Ok(self)
    }
    pub(super) fn after_context_retirement(
        instruction: SystemInstruction,
        pe: crate::system::execution::authority::PeIdentity,
        retirement_attempt: u64,
        retired_pc: GuestAddress,
        source_entry: crate::system::execution::EntryBoundary,
    ) -> Self {
        Self {
            instruction,
            pe,
            retirement_attempt,
            retired_pc,
            source_entry: Some(source_entry),
        }
    }
    pub(super) fn source<'pin>(
        &'pin self,
        pin: &'pin crate::memory::domain::physical::BoundPhysicalInstruction,
    ) -> anyhow::Result<RetiredInstructionSource<'pin>> {
        RetiredInstructionSource::borrow(
            &ConsumerKey(()),
            self.source_entry
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("retired source entry missing"))?,
            self.instruction,
            pin,
        )
    }

    pub(super) fn instruction(&self) -> SystemInstruction {
        self.instruction
    }
    pub(super) fn retired_pc(&self) -> stela_compiler::GuestAddress {
        self.retired_pc
    }
    pub(super) fn same_pe(&self, actual: &crate::system::execution::authority::PeIdentity) -> bool {
        self.pe.same_pe(actual)
    }
    pub(super) fn retirement_attempt(&self) -> u64 {
        self.retirement_attempt
    }
}

pub(super) enum SystemStep {
    Retired,
    Refused(OwnedStop),
    InterruptBoundary(RetiredSystemBoundary),
}

const ZERO_REGISTER: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectBinding {
    LocalEvent,
    Daif(u64),
    Vbar(u64),
    Register { destination: u8, value: u64 },
}
enum DeferredSystem {
    Wait(SystemInstruction),
    CounterRead(SystemInstruction),
}

enum Staged {
    LocalEvent(SystemInstruction),
    Daif(el1_daif::StagedEl1Daif),
    Vbar(vbar::StagedEl1Vbar),
}
impl Staged {
    fn binding(&self) -> EffectBinding {
        match self {
            Self::LocalEvent(_) => EffectBinding::LocalEvent,
            Self::Daif(stage) => EffectBinding::Daif(stage.value()),
            Self::Vbar(stage) => match stage.kind() {
                vbar::Kind::Write => EffectBinding::Vbar(stage.value()),
                vbar::Kind::Read { destination } => {
                    assert_eq!(stage.destination(), Some(destination));
                    EffectBinding::Register {
                        destination,
                        value: stage.value(),
                    }
                }
            },
        }
    }
    fn instruction(&self) -> SystemInstruction {
        match self {
            Self::LocalEvent(instruction) => *instruction,
            Self::Daif(stage) => stage.instruction(),
            Self::Vbar(stage) => stage.instruction(),
        }
    }
    fn apply(self, mut loan: El1SystemEffectLoan<'_>) -> GuestAddress {
        match self {
            Self::LocalEvent(instruction) => {
                let checks = loan._checks;
                checks.send_local_event(&mut loan);
                instruction.next_pc
            }
            Self::Daif(stage) => stage.apply(loan),
            Self::Vbar(stage) => stage.apply(loan),
        }
    }
}

/// Created only by the consumer after source, control and asynchronous
/// validation and the transition to retiring. Every field borrows the PE's own
/// objects.
pub(crate) struct El1SystemEffectLoan<'loan> {
    system: &'loan mut SystemState,
    registers: &'loan mut GuestState,
    binding: EffectBinding,
    _authority: &'loan PeExecutionAuthority,
    _source: &'loan BoundSource<'loan>,
    _outer: &'loan MemoryExecutionLoan,
    _controls: &'loan TranslationControls,
    _platform: &'loan El1PlatformControls,
    _checks: &'loan provider::M0ExecutionChecks<'loan>,
}
impl El1SystemEffectLoan<'_> {
    /// Only the backend's checks can supply the PE event endpoint.
    pub(in crate::blocks::retirement::checked) fn send_local_event_authorized(
        &mut self,
        checks: &provider::M0ExecutionChecks<'_>,
        endpoint: &crate::system::events::EventEndpoint,
    ) {
        assert_eq!(self.binding, EffectBinding::LocalEvent);
        assert!(core::ptr::eq(self._checks, checks));
        endpoint.signal_local();
    }
    pub(crate) fn write_daif_authorized(&mut self, value: u64) {
        assert_eq!(self.binding, EffectBinding::Daif(value));
        self.system.write_daif(value);
    }
    pub(crate) fn write_vbar_authorized(&mut self, value: u64) {
        assert_eq!(self.binding, EffectBinding::Vbar(value));
        self.system.el1_registers_mut().set_vbar(value);
    }
    pub(crate) fn write_register_authorized(&mut self, destination: u8, value: u64) {
        assert_eq!(self.binding, EffectBinding::Register { destination, value });
        if destination != ZERO_REGISTER {
            self.registers.x[usize::from(destination)] = value;
        }
    }
}

pub(crate) struct SystemObservation {
    pub instruction: SystemInstruction,
    pub native: RegisterNativeReport,
    staged: Option<EffectBinding>,
    pub wait_outcome: Option<crate::system::events::Outcome>,
    pub applied: bool,
    pub actual_continuation: Option<GuestAddress>,
    pub failure: Option<String>,
}
pub(super) struct RetainedSystemSession<'active, S> {
    pub(super) authority: &'active mut PeExecutionAuthority,
    pub(super) session: S,
    pub(super) closed: bool,
}
impl<S> Drop for RetainedSystemSession<'_, S> {
    fn drop(&mut self) {
        if !self.closed {
            self.authority.poison();
        }
        // The real PE fails closed before source/context/order fields release.
    }
}

impl<B: provider::Owner> Active<'_, '_, B> {
    pub(super) fn execute_el1_system(
        &mut self,
        bound: &BoundSource<'_>,
        accounting: &mut RunOutcome,
        observation: &mut Option<SystemObservation>,
        prefixes: &mut Vec<SettledPrefix>,
    ) -> anyhow::Result<SystemStep> {
        self.require_native()?;
        let Intent::System(instruction) = bound.el1_platform_intent()? else {
            anyhow::bail!("source is not a mixed System carrier")
        };
        let outer = self
            .outer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("System effect original outer absent"))?;
        let mut deferred_system = None;
        let result = (|| -> anyhow::Result<Option<OwnedStop>> {
            let provider::El1ExecutionResources {
                sources,
                platform,
                controls,
                memory: _,
                context,
                checks,
            } = self.pe.backend.split_el1_resources()?;
            let platform = platform
                .ok_or_else(|| anyhow::anyhow!("System effect implementation owner absent"))?;
            checks.check(outer)?;
            let context_snapshot = platform.context(self.pe.system)?;
            let scope = sources.el1_scope().map_err(anyhow::Error::msg)?;
            let session =
                RegisterSession::prepare(bound, outer, &scope, controls, self.pe.system, context)?;
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
            *observation = Some(SystemObservation {
                instruction,
                native,
                staged: None,
                wait_outcome: None,
                applied: false,
                actual_continuation: None,
                failure: None,
            });
            anyhow::ensure!(
                valid,
                "System native carrier/storage finalization is not qualified"
            );
            anyhow::ensure!(
                carrier == Some((instruction.instruction_pc.0, ExitKind::System as u64)),
                "System native carrier differs from exact source descriptor"
            );
            anyhow::ensure!(
                candidate == self.pe.thread.registers
                    && self.pe.thread.pc == instruction.instruction_pc,
                "effect-free System carrier changed original architectural state"
            );
            let deferred = if matches!(
                instruction.operation,
                stela_compiler::block::system::SystemOperation::Wait { .. }
            ) {
                Some(DeferredSystem::Wait(instruction))
            } else if provider::hosted_wait::counter::is_ordinary_counter_read(instruction) {
                Some(DeferredSystem::CounterRead(instruction))
            } else {
                None
            };
            if deferred.is_some() {
                // The transfer re-checks the session and keeps its pin, without
                // another fetch or source analysis at the deferred completion.
                self.source_pin = Some(
                    retained
                        .session
                        .take_source_pin(&ConsumerKey(()), self.pe.system)?,
                );
            } else {
                retained.session.validate_current(self.pe.system)?;
            }
            checks.check(outer)?;
            anyhow::ensure!(
                retained.authority.native_attempt(self.attempt),
                "original System NativeActive attempt lost"
            );
            retained
                .authority
                .enter_system(&ConsumerKey(()), self.attempt)
                .map_err(|()| anyhow::anyhow!("System carrier phase transition failed"))?;
            if let Some(deferred) = deferred {
                // The native carrier, context restoration, finalizer, source prefix
                // and phase are settled. End the backend resource borrows before
                // wait or counter completion borrows the backend again.
                let prefix = bound.prefix(Some(instruction.instruction_pc), 0)?;
                prefixes.try_reserve(1)?;
                let blocks = accounting
                    .blocks_executed
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("deferred System accounting overflow"))?;
                prefixes.push(prefix);
                accounting.blocks_executed = blocks;
                accounting.last_exit = carrier;
                deferred_system = Some(deferred);
                retained.closed = true;
                return Ok(None);
            }
            let staged: Result<Staged, String> = match instruction.operation {
                stela_compiler::block::system::SystemOperation::SendEvent { local: true } => {
                    Ok(Staged::LocalEvent(instruction))
                }
                stela_compiler::block::system::SystemOperation::PstateImmediate(_) => {
                    el1_daif::PreparedEl1Daif::prepare(
                        instruction,
                        instruction.instruction_pc,
                        instruction.word,
                        self.pe.system,
                    )
                    .map_err(|error| format!("DAIF source/state preparation: {error:?}"))
                    .and_then(|plan| {
                        plan.stage(self.pe.system, &self.pe.thread.registers)
                            .map_err(|error| format!("DAIF stage: {error:?}"))
                    })
                    .map(Staged::Daif)
                }
                stela_compiler::block::system::SystemOperation::Register(_) => {
                    match vbar::prepare(
                        instruction,
                        instruction.instruction_pc,
                        instruction.word,
                        &context_snapshot,
                        self.pe.system,
                        &self.pe.thread.registers,
                    ) {
                        Ok(vbar::Preparation::Staged(stage)) => Ok(Staged::Vbar(stage)),
                        Ok(vbar::Preparation::Uncompleted { request, decision }) => {
                            Err(format!("EL1 register request {request:?}: {decision:?}"))
                        }
                        Err(error) => Err(format!("EL1 register source preparation: {error:?}")),
                    }
                }
                operation => Err(format!("System effect owner unavailable: {operation:?}")),
            };
            let staged = match staged {
                Ok(staged) => staged,
                Err(detail) => {
                    checks.check(outer)?;
                    retained.session.validate_current(self.pe.system)?;
                    if let Some(report) = observation {
                        report.failure = Some(detail.clone());
                    }
                    retained
                        .authority
                        .finish_refusal(&ConsumerKey(()), self.attempt)
                        .map_err(|()| {
                            anyhow::anyhow!("System no-effect refusal settlement failed")
                        })?;
                    retained.closed = true;
                    return Ok(Some(OwnedStop::HelperRefused(detail)));
                }
            };
            anyhow::ensure!(
                staged.instruction() == instruction,
                "staged System descriptor differs"
            );
            let binding = staged.binding();
            let prefix = bound.prefix(None, 0)?;
            prefixes.try_reserve(1)?;
            let blocks = accounting
                .blocks_executed
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("System accounting overflow"))?;
            // Every pre-effect check precedes the fallible phase transition,
            // and the staged value stays private.
            retained.session.validate_current(self.pe.system)?;
            checks.check(outer)?;
            platform.context(self.pe.system)?;
            if let Some(report) = observation {
                report.staged = Some(binding);
            }
            retained
                .authority
                .start_retirement(&ConsumerKey(()), self.attempt)
                .map_err(|()| anyhow::anyhow!("System retirement transition failed"))?;
            let loan = El1SystemEffectLoan {
                system: &mut *self.pe.system,
                registers: &mut self.pe.thread.registers,
                binding,
                _authority: &*retained.authority,
                _source: bound,
                _outer: outer,
                _controls: controls,
                _platform: platform,
                _checks: &checks,
            };
            let continuation = staged.apply(loan);
            // Recording the observation and storing PC follow the effect
            // directly, with nothing fallible in between.
            if let Some(report) = observation {
                report.applied = true;
            }
            self.pe.thread.pc = continuation;
            if let Some(report) = observation {
                report.actual_continuation = Some(continuation);
            }
            prefixes.push(prefix);
            accounting.blocks_executed = blocks;
            accounting.last_exit = carrier;
            // Re-check the resources after retirement while the pins are still
            // held.
            self.source_pin = Some(
                retained
                    .session
                    .take_source_pin(&ConsumerKey(()), self.pe.system)?,
            );
            checks.post_retirement_el1(outer, &scope, controls, platform, self.pe.system)?;
            retained
                .authority
                .finish_retirement(&ConsumerKey(()), self.attempt, false)
                .map_err(|()| anyhow::anyhow!("System retirement completion failed"))?;
            retained.closed = true;
            Ok(None)
        })();
        if result.is_ok()
            && let Some(deferred) = deferred_system
        {
            // The same SystemActive attempt, after the native session ends.
            let mut wait_outcome = None;
            let (instruction, result) = match deferred {
                DeferredSystem::Wait(instruction) => (
                    instruction,
                    self.complete_wait(bound, instruction, &mut wait_outcome),
                ),
                DeferredSystem::CounterRead(instruction) => (
                    instruction,
                    self.complete_hosted_counter(bound, instruction),
                ),
            };
            return match result {
                Ok(super::wait::WaitStep::Retired) => {
                    if let Some(report) = observation {
                        report.wait_outcome = wait_outcome;
                        report.applied = true;
                        report.actual_continuation = Some(instruction.next_pc);
                    }
                    Ok(SystemStep::Retired)
                }
                Ok(super::wait::WaitStep::InterruptBoundary(boundary)) => {
                    if let Some(report) = observation {
                        report.wait_outcome = wait_outcome;
                        report.applied = true;
                        report.actual_continuation = Some(instruction.next_pc);
                    }
                    Ok(SystemStep::InterruptBoundary(boundary))
                }
                Ok(super::wait::WaitStep::IrqPending) => Ok(SystemStep::Refused(
                    OwnedStop::Indeterminate("WFE IRQ needs its declared wake policy".into()),
                )),
                Ok(super::wait::WaitStep::ExceptionPending(outcome)) => Ok(SystemStep::Refused(
                    OwnedStop::Indeterminate(format!("WFx exception needs CSE entry: {outcome:?}")),
                )),
                Err(error) => {
                    if let Some(report) = observation {
                        report.failure = Some(error.to_string());
                    }
                    Err(error)
                }
            };
        }
        if let Err(error) = &result
            && let Some(report) = observation
        {
            report.failure = Some(error.to_string());
        }
        match result? {
            None => match self.pe.backend.system_retirement(self.pe.system)? {
                provider::SystemRetirement::Complete => {
                    self.closed = true;
                    Ok(SystemStep::Retired)
                }
                provider::SystemRetirement::ArbitrateHostedIrq => {
                    // The DAIF/VBAR effect and the PC store have retired. Keep the PE
                    // armed before any target fetch; the IRQ resources decide entry.
                    self.closed = false;
                    Ok(SystemStep::InterruptBoundary(
                        RetiredSystemBoundary::after_retirement(
                            instruction,
                            self.pe.authority.identity(),
                            self.attempt,
                        ),
                    ))
                }
            },
            Some(stop) => {
                self.closed = true;
                Ok(SystemStep::Refused(stop))
            }
        }
    }
}

impl core::fmt::Debug for SystemObservation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SystemObservation")
            .field("instruction", &self.instruction)
            .field("native", &self.native)
            .field("staged", &self.staged)
            .field("wait_outcome", &self.wait_outcome)
            .field("applied", &self.applied)
            .field("actual_continuation", &self.actual_continuation)
            .field("failure", &self.failure)
            .finish()
    }
}
