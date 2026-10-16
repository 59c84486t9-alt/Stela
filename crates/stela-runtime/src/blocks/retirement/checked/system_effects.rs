//! Resource-specific System effects under the original canonical retiring owner.
//! Native carrier finalization precedes preparation; actual source/control/RAM
//! loans survive the effect, sole PC settlement and post-retirement checks.
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};
mod commit;
mod dsb;

use super::{
    Active, ConsumerKey, OwnedStop, SettledPrefix,
    el1_registers::{RegisterNativeReport, RegisterSession},
    el1_system::RetainedSystemSession,
    provider,
    source::BoundSource,
};
use crate::{
    blocks::RunOutcome,
    system::execution::{Boundary, EntryBoundary, authority::PeExecutionAuthority},
};
pub(crate) use commit::{SystemEffectCommit, SystemEffectCommitError, SystemEffectCommitView};
use dsb::{PreparedRamDsb, RamDsbApplied, RamDsbFailure};
use stela_compiler::{
    GuestAddress,
    block::{ExitKind, SystemInstruction},
};

pub(crate) struct SystemEffectObservation {
    pub(crate) instruction: SystemInstruction,
    pub(crate) native: RegisterNativeReport,
    pub(crate) completion: Option<Result<RamDsbApplied, RamDsbFailure>>,
    pub(crate) actual_continuation: Option<GuestAddress>,
    pub(crate) failure: Option<String>,
}

/// Poison the original owner BEFORE the real RAM/source loans release on a
/// reached effect or settlement failure. This stores no alternate phase/state.
struct RetainedRamCompletion<'active, 'resources> {
    authority: &'active mut PeExecutionAuthority,
    prepared: PreparedRamDsb<'resources>,
    closed: bool,
}
impl Drop for RetainedRamCompletion<'_, '_> {
    fn drop(&mut self) {
        if !self.closed {
            self.authority.poison();
        }
    }
}

impl<B: provider::Owner> Active<'_, '_, B> {
    pub(super) fn execute_system_effects(
        mut self,
        bound: &BoundSource<'_>,
        accounting: &mut RunOutcome,
        observation: &mut Option<SystemEffectObservation>,
        prefixes: &mut Vec<SettledPrefix>,
    ) -> anyhow::Result<Option<OwnedStop>> {
        self.require_native()?;
        let instruction = bound
            .el1_carrier_intent()?
            .ok_or_else(|| anyhow::anyhow!("System effect carrier absent"))?;
        anyhow::ensure!(
            instruction.is_el1_ram_completion(),
            "System effect owner is not mounted"
        );
        let outer = self
            .outer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("System effect original outer absent"))?;
        let result = (|| -> anyhow::Result<Option<OwnedStop>> {
            anyhow::ensure!(
                bound.source.len() == size_of::<u32>(),
                "System effect must be one original instruction"
            );
            let boundary = Boundary::new(
                EntryBoundary::new(
                    bound.entry.address_space(),
                    bound.entry.generation(),
                    bound.entry.entry(),
                    bound.entry.region_base(),
                    bound.entry.source_bytes(),
                    instruction.word,
                ),
                bound.source.len(),
                instruction,
            );
            // End the ORIGINAL native session and mutable context loan before
            // splitting completion resources from the same retained backend.
            {
                let provider::El1ExecutionResources {
                    sources,
                    platform,
                    controls,
                    memory: _,
                    context,
                    checks,
                } = self.pe.backend.split_el1_resources()?;
                let platform = platform
                    .ok_or_else(|| anyhow::anyhow!("System effect original platform absent"))?;
                platform.context(self.pe.system)?;
                checks.check(outer)?;
                let scope = sources.el1_scope().map_err(anyhow::Error::msg)?;
                let session = RegisterSession::prepare(
                    bound,
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
                *observation = Some(SystemEffectObservation {
                    instruction,
                    native,
                    completion: None,
                    actual_continuation: None,
                    failure: None,
                });
                anyhow::ensure!(
                    valid,
                    "System effect native/storage finalization is unqualified"
                );
                anyhow::ensure!(
                    carrier == Some((instruction.instruction_pc.0, ExitKind::System as u64))
                        && candidate == self.pe.thread.registers
                        && self.pe.thread.pc == instruction.instruction_pc,
                    "effect-free carrier changed actual state or source exit"
                );
                retained.session.validate_current(self.pe.system)?;
                checks.check(outer)?;
                retained
                    .authority
                    .enter_system(&ConsumerKey(()), self.attempt)
                    .map_err(|()| {
                        anyhow::anyhow!("System effect original SystemActive transition failed")
                    })?;
                retained.closed = true;
            }
            let provider::El1SystemEffectResources {
                sources,
                controls,
                platform,
                checks,
            } = self.pe.backend.split_el1_system_effect_resources()?;
            checks.check(outer)?;
            let scope = sources
                .ram_completion_scope(bound.runtime, controls, self.pe.system, outer)
                .map_err(anyhow::Error::msg)?;
            let prepared = PreparedRamDsb::prepare(
                &boundary,
                outer,
                self.pe.authority.identity(),
                &scope,
                controls,
                platform,
                &checks,
                self.pe.system,
                &self.pe.thread.registers,
            );
            let prepared = match prepared {
                Ok(prepared) => prepared,
                Err(error) => {
                    checks.check(outer)?;
                    scope
                        .check_installed(controls, self.pe.system)
                        .map_err(anyhow::Error::msg)?;
                    let detail = format!("RAM completion preparation declined: {error:?}");
                    if let Some(report) = observation {
                        report.failure = Some(detail.clone());
                    }
                    self.pe
                        .authority
                        .finish_refusal(&ConsumerKey(()), self.attempt)
                        .map_err(|()| {
                            anyhow::anyhow!("System effect no-effect refusal settlement failed")
                        })?;
                    return Ok(Some(OwnedStop::HelperRefused(detail)));
                }
            };
            let prefix = bound.prefix(None, 0)?;
            prefixes.try_reserve(1)?;
            let blocks = accounting
                .blocks_executed
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("System effect accounting overflow"))?;
            checks.check(outer)?;
            let mut retained = RetainedRamCompletion {
                authority: &mut *self.pe.authority,
                prepared,
                closed: false,
            };
            retained
                .authority
                .start_retirement(&ConsumerKey(()), self.attempt)
                .map_err(|()| {
                    anyhow::anyhow!("System effect original Retiring transition failed")
                })?;
            let result = SystemEffectCommit {
                authority: &*retained.authority,
                boundary: &boundary,
                outer,
                attempt: self.attempt,
                system: &mut *self.pe.system,
                registers: &mut self.pe.thread.registers,
            }
            .apply_dsb(&mut retained.prepared);
            let next = result
                .as_ref()
                .map(|applied| applied.next_pc)
                .map_err(|failure| anyhow::anyhow!("System effect terminal failure: {failure:?}"));
            if let Some(report) = observation {
                report.completion = Some(result);
            }
            let next = next?;
            // A successful apply has fully qualified the reached completion;
            // no additional fallible step precedes the sole PC store. An apply
            // failure after MFENCE retains Completed and blocks replay instead.
            // Later owner failures preserve the actual committed PC/prefix.
            self.pe.thread.pc = next;
            if let Some(report) = observation {
                report.actual_continuation = Some(next);
            }
            prefixes.push(prefix);
            accounting.blocks_executed = blocks;
            accounting.last_exit = Some((instruction.instruction_pc.0, ExitKind::System as u64));
            checks.post_retirement_el1(outer, &scope, controls, platform, self.pe.system)?;
            retained
                .authority
                .finish_retirement(&ConsumerKey(()), self.attempt, false)
                .map_err(|()| {
                    anyhow::anyhow!("System effect original retirement completion failed")
                })?;
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

impl core::fmt::Debug for SystemEffectObservation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SystemEffectObservation")
            .field("instruction", &self.instruction)
            .field("native", &self.native)
            .field("completion", &self.completion)
            .field("actual_continuation", &self.actual_continuation)
            .field("failure", &self.failure)
            .finish()
    }
}
