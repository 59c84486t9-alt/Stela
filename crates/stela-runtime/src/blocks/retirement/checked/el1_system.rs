//! System register effects under the original canonical Active and retained PE.
//! The native carrier finalizes first; staged effects never write PC themselves.
mod controls;
use super::{
    Active, ConsumerKey, OwnedStop, SettledPrefix,
    el1_registers::{RegisterNativeReport, RegisterSession},
    provider,
    source::BoundSource,
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

const ZERO_REGISTER: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectBinding {
    Daif(u64),
    Vbar(u64),
    Register { destination: u8, value: u64 },
}
enum Staged {
    Daif(el1_daif::StagedEl1Daif),
    Vbar(vbar::StagedEl1Vbar),
}
impl Staged {
    fn binding(&self) -> EffectBinding {
        match self {
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
            Self::Daif(stage) => stage.instruction(),
            Self::Vbar(stage) => stage.instruction(),
        }
    }
    fn apply(self, loan: El1SystemEffectLoan<'_>) -> GuestAddress {
        match self {
            Self::Daif(stage) => stage.apply(loan),
            Self::Vbar(stage) => stage.apply(loan),
        }
    }
}

/// No public constructor or mutable state accessor. Only this canonical Active
/// creates the token after real source/control/async validation and the actual
/// Retiring transition. All fields borrow the same original retained objects.
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
        mut self,
        bound: &BoundSource<'_>,
        accounting: &mut RunOutcome,
        observation: &mut Option<SystemObservation>,
        prefixes: &mut Vec<SettledPrefix>,
    ) -> anyhow::Result<Option<OwnedStop>> {
        self.require_native()?;
        let Intent::System(instruction) = bound.el1_platform_intent()? else {
            anyhow::bail!("actual source is not a mixed System carrier")
        };
        let outer = self
            .outer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("System effect original outer absent"))?;
        let result = (|| -> anyhow::Result<Option<OwnedStop>> {
            let provider::El1ExecutionResources {
                sources,
                platform,
                controls,
                memory: _,
                context,
                checks,
            } = self.pe.backend.split_el1_resources()?;
            let platform = platform.ok_or_else(|| {
                anyhow::anyhow!("System effect actual implementation owner absent")
            })?;
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
            retained.session.validate_current(self.pe.system)?;
            checks.check(outer)?;
            anyhow::ensure!(
                retained.authority.native_attempt(self.attempt),
                "original System NativeActive attempt lost"
            );
            retained
                .authority
                .enter_system(&ConsumerKey(()), self.attempt)
                .map_err(|()| anyhow::anyhow!("System carrier phase transition failed"))?;
            let staged: Result<Staged, String> = match instruction.operation {
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
            // All actual pre-effect source/control/async and state resolution
            // precedes the fallible phase transition. The exact staged value
            // remains private and cannot be replaced by a saved caller value.
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
            // Infallible observation and the sole actual PC store follow the
            // bank effect; no fallible work or callback lies between them.
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
            // Actual original resources perform post-retirement qualification
            // while the same source/context/native-finalizer pins stay held.
            retained.session.validate_current(self.pe.system)?;
            checks.post_retirement_el1(outer, &scope, controls, platform, self.pe.system)?;
            retained
                .authority
                .finish_retirement(&ConsumerKey(()), self.attempt, false)
                .map_err(|()| anyhow::anyhow!("System retirement completion failed"))?;
            retained.closed = true;
            Ok(None)
        })();
        if let Err(error) = &result
            && let Some(report) = observation
        {
            report.failure = Some(error.to_string());
        }
        if result.is_ok() {
            self.closed = true;
        }
        result
    }
}

impl core::fmt::Debug for SystemObservation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SystemObservation")
            .field("instruction", &self.instruction)
            .field("native", &self.native)
            .field("staged", &self.staged)
            .field("applied", &self.applied)
            .field("actual_continuation", &self.actual_continuation)
            .field("failure", &self.failure)
            .finish()
    }
}
