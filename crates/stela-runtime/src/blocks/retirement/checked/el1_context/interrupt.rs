//! IRQ entry after an instruction retires, using the same PE and source pin.
//! No further instruction is fetched or run before the entry.
use super::services::{BorrowedExceptionServices, ExceptionEffect};
use crate::{
    blocks::{
        BlockRuntime, RunOutcome,
        retirement::checked::{Active, ConsumerKey, el1_system::RetiredSystemBoundary, provider},
    },
    system::exception::{self, EntryEvent, ExceptionServices, ExecuteError},
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};
use stela_compiler::{GuestAddress, block::SystemInstruction};

pub(crate) struct InterruptObservation {
    instruction: SystemInstruction,
    pending: bool,
    exception_result: Option<Result<u64, ExecuteError<String>>>,
    effects: Vec<ExceptionEffect>,
    actual_continuation: Option<GuestAddress>,
    failure: Option<String>,
}
impl core::fmt::Debug for InterruptObservation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("InterruptObservation")
            .field("retired_instruction", &self.instruction)
            .field("actual_pending_irq", &self.pending)
            .field("exception_result", &self.exception_result)
            .field("effects", &self.effects)
            .field("actual_continuation", &self.actual_continuation)
            .field("failure", &self.failure)
            .finish()
    }
}

impl<B: provider::Owner> Active<'_, '_, B> {
    pub(in crate::blocks::retirement::checked) fn execute_interrupt_boundary(
        mut self,
        runtime: &mut BlockRuntime,
        boundary: RetiredSystemBoundary,
        accounting: &mut RunOutcome,
        observation: &mut Option<InterruptObservation>,
    ) -> anyhow::Result<()> {
        let result = (|| -> anyhow::Result<()> {
            anyhow::ensure!(
                !self.closed
                    && self
                        .pe
                        .authority
                        .ready_after_retirement(boundary.retirement_attempt())
                    && boundary.same_pe(&self.pe.authority.identity())
                    && self.attempt == boundary.retirement_attempt()
                    && self.pe.thread.pc == boundary.retired_pc()
                    && accounting.blocks_executed != 0,
                "IRQ handoff differs from the retired PE boundary"
            );
            let instruction = boundary.instruction();
            let retained_source = boundary.source(
                self.source_pin
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Active physical source pin missing"))?,
            )?;
            let original = &retained_source;
            anyhow::ensure!(
                original.instruction() == instruction,
                "IRQ lost its retired instruction source"
            );
            let outer = self
                .outer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("IRQ outer exclusion absent"))?;
            let resources = self.pe.backend.split_el1_irq_resources()?;
            resources.check(outer, self.pe.system)?;
            // Check the installed runtime and physical pin even when the receiver
            // sample has no pending IRQ.
            let mut scope = resources
                .sources
                .publication_scope(runtime, resources.controls, self.pe.system, outer)
                .map_err(anyhow::Error::msg)?;
            scope
                .bind_retired_system_source(&ConsumerKey(()), original)
                .map_err(anyhow::Error::msg)?;
            let pending = resources.irq.receipt().is_some();
            *observation = Some(InterruptObservation {
                instruction,
                pending,
                exception_result: None,
                effects: Vec::new(),
                actual_continuation: None,
                failure: None,
            });
            if !pending {
                // A fresh sample from the receiver, not an inference from its queue.
                self.closed = true;
                return Ok(());
            }
            resources
                .irq
                .validate_presented()
                .map_err(|error| anyhow::anyhow!("pending IRQ changed: {error:?}"))?;
            let profile = resources.platform.context(self.pe.system)?.profile;
            let features = resources.platform.entry_profile();
            let controls = resources.execution.exception_controls(resources.controls)?;
            let plan = exception::prepare_entry(
                &features,
                profile,
                controls,
                self.pe.system,
                &self.pe.thread.registers,
                EntryEvent::Irq {
                    next_pc: boundary.retired_pc().0,
                },
            )
            .map_err(|error| anyhow::anyhow!("post-retirement IRQ plan: {error:?}"))?;
            let request = plan.service_request();
            let target = plan.target_address();
            let destination = plan.target_exception_level();
            let next = {
                let publication = resources
                    .controls
                    .prepare_interrupt_context(
                        &ConsumerKey(()),
                        self.pe.system,
                        original,
                        &mut scope,
                    )
                    .map_err(|error| anyhow::anyhow!("IRQ CSE preparation: {error:?}"))?;
                let mut services = BorrowedExceptionServices::new_irq(
                    publication,
                    &mut *resources.memory,
                    &resources.irq,
                    request,
                    target,
                    destination,
                );
                let permit = services.preflight(request).map_err(anyhow::Error::msg)?;
                self.attempt = self
                    .pe
                    .authority
                    .begin_interrupt(&ConsumerKey(()), boundary.retirement_attempt())
                    .map_err(|()| anyhow::anyhow!("IRQ SystemActive transition failed"))?;
                self.pe
                    .authority
                    .start_retirement(&ConsumerKey(()), self.attempt)
                    .map_err(|()| anyhow::anyhow!("IRQ Retiring transition failed"))?;
                let actual = plan.execute_preflighted(
                    self.pe.system,
                    &mut self.pe.thread.registers,
                    &mut services,
                    permit,
                );
                let next = actual
                    .as_ref()
                    .copied()
                    .map(GuestAddress)
                    .map_err(|error| anyhow::anyhow!("IRQ committed effect: {error:?}"));
                if let Some(report) = observation {
                    report.effects = core::mem::take(&mut services.effects);
                    report.exception_result = Some(actual);
                }
                next?
            };
            // Architectural effects come before the IRQ PC store. The retired
            // WFx/System instruction was already counted.
            self.pe.thread.pc = next;
            if let Some(report) = observation {
                report.actual_continuation = Some(next);
            }
            resources.check(outer, self.pe.system)?;
            self.pe
                .authority
                .finish_retirement(&ConsumerKey(()), self.attempt, false)
                .map_err(|()| anyhow::anyhow!("IRQ retirement completion failed"))?;
            self.closed = true;
            Ok(())
        })();
        if let Err(error) = &result
            && let Some(report) = observation
        {
            report.failure = Some(error.to_string());
        }
        // On error, Active's Drop poisons the PE before the outer loan is
        // released, and the backend abandons waits without clearing pending state.
        result
    }
}
