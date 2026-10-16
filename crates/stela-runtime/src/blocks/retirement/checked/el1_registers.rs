//! Typed EL1 register-only instructions and terminals under the SAME canonical Active/PE authority.
//! Original source/controls/full ThreadState/System/backend/outer are retained;
//! no saved carrier or mode flag can create completion or retry authority.
use super::{
    Active, ConsumerKey, SettledPrefix, provider,
    source::{BoundSource, ReturnedTerminal},
};
use crate::{
    blocks::{RunOutcome, ThreadState},
    memory::domain::MemoryExecutionLoan,
    system::{
        execution::authority::{NativeRetirementCommit, PeExecutionAuthority},
        state::SystemState,
    },
};
use stela_compiler::{
    GuestAddress, GuestState,
    block::{BlockExit, ExitKind},
};
mod session;
pub(super) use session::{RegisterNativeReport, RegisterSession};

pub(crate) struct RegisterObservation {
    pub source_pc: GuestAddress,
    pub report: RegisterNativeReport,
    pub settlement_failure: Option<String>,
}
struct RetainedRegisterSession<'active, S> {
    authority: &'active mut PeExecutionAuthority,
    session: S,
    closed: bool,
}
impl<S> Drop for RetainedRegisterSession<'_, S> {
    fn drop(&mut self) {
        if !self.closed {
            self.authority.poison();
        }
        // Failstop precedes physical/source/bank/session field teardown.
    }
}
struct PreparedRegisterCommit<'commit, 'code, C, S> {
    authority: NativeRetirementCommit<'commit>,
    actual_thread: &'commit mut ThreadState,
    _system: &'commit SystemState,
    _checks: &'commit C,
    _session: &'commit S,
    _source: &'commit BoundSource<'code>,
    _outer: &'commit MemoryExecutionLoan,
    candidate: GuestState,
    next_pc: GuestAddress,
}
impl<C, S> PreparedRegisterCommit<'_, '_, C, S> {
    fn commit(self) {
        self.actual_thread.registers = self.candidate;
        self.actual_thread.pc = self.next_pc;
        self.authority.finish(&ConsumerKey(()));
    }
}
impl<B: provider::Owner> Active<'_, '_, B> {
    pub(super) fn execute_el1_registers(
        mut self,
        bound: &BoundSource<'_>,
        accounting: &mut RunOutcome,
        observation: &mut Option<RegisterObservation>,
        prefixes: &mut Vec<SettledPrefix>,
    ) -> anyhow::Result<()> {
        *observation = None;
        self.require_native()?;
        let outer = self
            .outer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("EL1 register original outer absent"))?;
        bound.el1_register_intent()?;
        anyhow::ensure!(
            self.pe.thread.pc == bound.entry.entry(),
            "EL1 register actual PC differs before call"
        );
        {
            // One whole-backend split. Never reborrow B until every original
            // field/session/source loan ends; original outer Active stays armed.
            let provider::El1ExecutionResources {
                sources,
                platform: _,
                controls,
                memory: _,
                context,
                checks,
            } = self.pe.backend.split_el1_resources()?;
            checks.check(outer)?;
            let scope = sources.el1_scope().map_err(anyhow::Error::msg)?;
            let session = RegisterSession::prepare(
                bound,
                outer,
                &scope,
                controls,
                &*self.pe.system,
                context,
            )?;
            let mut retained = RetainedRegisterSession {
                authority: &mut *self.pe.authority,
                session,
                closed: false,
            };
            let mut candidate = self.pe.thread.registers.clone();
            let report = retained.session.invoke(&*self.pe.system, &mut candidate);
            let carrier = report.raw_carrier;
            let valid = report.invoked
                && report.failure.is_none()
                && matches!(report.storage_after, Some(Ok(())));
            *observation = Some(RegisterObservation {
                source_pc: bound.entry.entry(),
                report,
                settlement_failure: None,
            });
            // All actual reached observations already belong to output before
            // any fallible source/postcheck/finalization/settlement validation.
            let settled = (|| -> anyhow::Result<_> {
                anyhow::ensure!(valid, "EL1 register reached call is not qualified");
                let (next_pc, kind) =
                    carrier.ok_or_else(|| anyhow::anyhow!("EL1 register actual carrier absent"))?;
                let exit = BlockExit { next_pc, kind };
                let ReturnedTerminal::Ordinary(next) = bound.validate_return(&exit, &candidate)?
                else {
                    anyhow::bail!("EL1 register helper/trap is not admitted");
                };
                if bound.runtime.profile() == stela_compiler::block::BlockProfile::El1DirectBranchV1
                {
                    anyhow::ensure!(
                        next == bound.direct_branch_target()?
                            && candidate == self.pe.thread.registers,
                        "exact EL1 register changed architectural state or destination"
                    );
                }
                anyhow::ensure!(
                    self.pe.thread.pc == bound.entry.entry(),
                    "EL1 register changed full state or terminal intent"
                );
                retained.session.validate_current(&*self.pe.system)?;
                checks.check(outer)?;
                anyhow::ensure!(
                    retained.authority.native_attempt(self.attempt),
                    "EL1 register original NativeActive attempt lost"
                );
                // validate_return already binds conditional taken/fallthrough
                // to the actual post-prefix predicate. Only a taken branch uses
                // BranchAddr; a sequential continuation keeps its original PC.
                let next = match ExitKind::try_from(exit.kind) {
                    Ok(ExitKind::Fallthrough) => next,
                    Ok(
                        ExitKind::Direct | ExitKind::Call | ExitKind::Indirect | ExitKind::Return,
                    ) => GuestAddress(
                        controls
                            .branch_address(next.0, self.pe.system.current_el())
                            .map_err(|error| anyhow::anyhow!("EL1 branch address: {error:?}"))?,
                    ),
                    _ => anyhow::bail!("EL1 ordinary source/carrier kind differs"),
                };
                let prefix = bound.prefix(None, 0)?;
                prefixes.try_reserve(1)?;
                let blocks = accounting
                    .blocks_executed
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("EL1 register accounting overflow"))?;
                Ok((next, exit, prefix, blocks))
            })();
            let (next_pc, exit, prefix, blocks) = match settled {
                Ok(value) => value,
                Err(error) => {
                    if let Some(observation) = observation {
                        observation.settlement_failure = Some(error.to_string());
                    }
                    return Err(error);
                }
            };
            let authority = match retained
                .authority
                .prepare_native_commit(&ConsumerKey(()), self.attempt)
            {
                Ok(authority) => authority,
                Err(()) => {
                    let detail = "EL1 register original neutral commit refused";
                    if let Some(observation) = observation {
                        observation.settlement_failure = Some(detail.into());
                    }
                    anyhow::bail!(detail);
                }
            };
            PreparedRegisterCommit {
                authority,
                actual_thread: &mut *self.pe.thread,
                _system: &*self.pe.system,
                _checks: &checks,
                _session: &retained.session,
                _source: bound,
                _outer: outer,
                candidate,
                next_pc,
            }
            .commit();
            prefixes.push(prefix);
            accounting.blocks_executed = blocks;
            accounting.last_exit = Some((exit.next_pc, exit.kind));
            retained.closed = true;
        } // Actual session/source/split resource loans teardown under armed Active.
        self.closed = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "el1_registers/branch_fixture.rs"]
mod branch_fixture;
#[cfg(test)]
#[path = "el1_registers/firmware_fixture.rs"]
mod firmware_fixture;

impl core::fmt::Debug for RegisterObservation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegisterObservation")
            .field("source_pc", &self.source_pc)
            .field("report", &self.report)
            .field("settlement_failure", &self.settlement_failure)
            .finish()
    }
}
