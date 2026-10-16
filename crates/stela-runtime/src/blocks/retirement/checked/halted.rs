//! Executing one instruction queued through EDITR while the PE is halted.
use super::{
    Active, ConsumerKey, SystemExecutionLoan, accept_retained_loan,
    privileged::PrivilegedOwner,
    privileged_debug::{DebugRecord, PreparedDebug},
    provider::Owner,
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString};
use stela_compiler::GuestAddress;

#[derive(Debug)]
pub(crate) enum DebugStop {
    Empty,
    EntryDeclined(String),
    Complete,
    Indeterminate(String),
}
#[derive(Debug)]
pub(crate) struct OwnedDebugOutcome {
    pub stop: DebugStop,
    pub actual_pc: GuestAddress,
    pub record: Option<DebugRecord>,
}

/// Software debugger input was queued in the domain before this call.
/// Cross-halt and unknown events are kept and refused, never discarded.
pub(crate) fn run_halted_owned(
    loan: SystemExecutionLoan<'_, PrivilegedOwner<'_>>,
) -> OwnedDebugOutcome {
    let mut pe = accept_retained_loan(loan);
    let mut record = None;
    let outcome = (|| -> anyhow::Result<DebugStop> {
        anyhow::ensure!(pe.authority.halted(), "actual PE is not Halted");
        crate::execution::platform::ensure_supported()?;
        let outer = pe.backend.execution_loan()?;
        let debug = pe
            .debug
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("actual halted lifecycle unavailable"))?;
        let prepared =
            match pe
                .backend
                .prepare_debug(pe.system, &mut pe.thread.registers, debug, &outer)
            {
                Ok(Some(prepared)) => prepared,
                Ok(None) => return Ok(DebugStop::Empty),
                Err(error) => return Ok(DebugStop::EntryDeclined(error.to_string())),
            };
        let attempt = match pe.authority.begin_debug(&ConsumerKey(())) {
            Ok(attempt) => attempt,
            Err(()) => {
                return Ok(DebugStop::Indeterminate(
                    "actual DebugActive admission poisoned authority".into(),
                ));
            }
        };
        let active = Active {
            pe: &mut pe,
            outer: Some(outer),
            attempt,
            closed: false,
        };
        let result = active.execute_debug(prepared, &mut record);
        Ok(match result {
            Ok(()) => DebugStop::Complete,
            Err(error) => DebugStop::Indeterminate(error.to_string()),
        })
    })();
    OwnedDebugOutcome {
        stop: outcome.unwrap_or_else(|error| DebugStop::EntryDeclined(error.to_string())),
        actual_pc: pe.thread.pc,
        record,
    }
}

impl Active<'_, '_, PrivilegedOwner<'_>> {
    /// Complete the debug instruction after its body and finalizer.
    pub(super) fn settle_debug(&mut self, source_pc: GuestAddress) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.pe.authority.debug_attempt(self.attempt),
            "actual debug phase lost"
        );
        anyhow::ensure!(
            self.pe.thread.pc == source_pc,
            "halted instruction changed actual PC"
        );
        let debug = self
            .pe
            .debug
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("actual debug resource lost"))?;
        self.pe.backend.qualify_debug_resources(
            self.pe.system,
            debug,
            self.outer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("actual debug outer lost"))?,
        )?;
        debug
            .qualify_halted_boundary()
            .map_err(|e| anyhow::anyhow!("actual final halted resource: {e:?}"))?;
        self.pe
            .authority
            .finish_debug(&ConsumerKey(()), self.attempt)
            .map_err(|()| anyhow::anyhow!("actual debug settlement failed"))?;
        self.closed = true;
        Ok(())
    }
    fn execute_debug(
        mut self,
        mut prepared: PreparedDebug,
        record: &mut Option<DebugRecord>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.pe.authority.debug_attempt(self.attempt),
            "actual DebugActive attempt changed"
        );
        let source_pc = self.pe.thread.pc;
        let result = (|| -> anyhow::Result<()> {
            let debug = self
                .pe
                .debug
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("actual debug resource lost"))?;
            self.pe.backend.execute_debug(
                &mut prepared,
                self.pe.system,
                &mut self.pe.thread.registers,
                debug,
                self.outer
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("actual debug outer lost"))?,
            )?;
            self.settle_debug(source_pc)?;
            Ok(())
        })();
        // Every observation survives an error; Drop marks unfinished work
        // failed and never reports ready.
        *record = Some(prepared.record);
        result
    }
}
