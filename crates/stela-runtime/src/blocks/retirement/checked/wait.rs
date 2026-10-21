//! WFE, WFI, WFET and WFIT completion on the checked Active.
use super::el1_system::RetiredSystemBoundary;
use super::{
    Active, ConsumerKey,
    provider::{self, hosted_wait::WaitReply},
    source::BoundSource,
};
use crate::system::events::{Outcome, RetireReason};
mod counter;
use stela_compiler::{
    aarch64::system::synchronization::WaitKind,
    block::system::{SystemInstruction, SystemOperation},
};

pub(super) enum WaitStep {
    Retired,
    InterruptBoundary(RetiredSystemBoundary),
    /// The receipt stays in the backend; the PC does not advance.
    IrqPending,
    /// An undefined or trapped wait needs exception services; it is not
    /// retired as a no-op or retried.
    ExceptionPending(Outcome),
}

impl<B: provider::Owner> Active<'_, '_, B> {
    /// Called by the native System-return consumer after finalizer, source and
    /// carrier validation, prefix recording and SystemActive. The PC still
    /// names the wait instruction.
    pub(super) fn complete_wait(
        &mut self,
        bound: &BoundSource<'_>,
        instruction: SystemInstruction,
        observation: &mut Option<Outcome>,
    ) -> anyhow::Result<WaitStep> {
        anyhow::ensure!(
            self.pe.authority.system_attempt(self.attempt),
            "wait requires SystemActive"
        );
        anyhow::ensure!(
            matches!(instruction.operation, SystemOperation::Wait { .. }),
            "non-wait System carrier"
        );
        anyhow::ensure!(
            instruction.matches_source(instruction.instruction_pc, instruction.word),
            "wait source descriptor changed"
        );
        anyhow::ensure!(
            self.pe.thread.pc == instruction.instruction_pc,
            "wait terminal PC differs"
        );
        anyhow::ensure!(
            bound.wait_instruction()? == instruction,
            "wait descriptor differs from bound source"
        );
        let reply = self.pe.backend.prepare_wait(
            bound,
            instruction,
            self.pe.system,
            &self.pe.thread.registers,
            self.outer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("outer loan missing"))?,
        )?;
        #[cfg(feature = "std")]
        let reply = self.poll_hosted_wait(bound, reply)?;
        match reply {
            WaitReply::Park { requested } => {
                let _ = requested;
                anyhow::bail!("hosted parking adapter is unavailable")
            }
            WaitReply::WakeIrqPending => {
                if matches!(
                    instruction.operation,
                    SystemOperation::Wait {
                        kind: WaitKind::Interrupt,
                        ..
                    }
                ) {
                    // A WFI wake retires the instruction even when I is clear.
                    // The IRQ is a separate boundary afterward; the next
                    // instruction is not fetched before arbitration.
                    let outcome = self.pe.backend.wait_outcome()?;
                    self.retire_wait(instruction, outcome, bound)?;
                    // Record the outcome only after the PC store, post-checks
                    // and retirement have completed.
                    *observation = Some(outcome);
                    return Ok(self.retired_wait_step(instruction));
                }
                // How an IRQ wakes WFE is decided separately; no event bit
                // is invented and the wait is not resumed by polling.
                Ok(WaitStep::IrqPending)
            }
            WaitReply::CompletionReady => {
                let outcome = self.pe.backend.wait_outcome()?;
                let Outcome::Retired { .. } = outcome else {
                    return Ok(WaitStep::ExceptionPending(outcome));
                };
                self.retire_wait(instruction, outcome, bound)?;
                // Record the outcome only after the PC store, post-checks
                // and retirement have completed.
                *observation = Some(outcome);
                Ok(self.retired_wait_step(instruction))
            }
        }
    }

    /// Hosted suspension releases the execution loan, then requalifies the
    /// source and architectural wake conditions before retirement can proceed.
    #[cfg(feature = "std")]
    fn poll_hosted_wait(
        &mut self,
        bound: &BoundSource<'_>,
        mut reply: WaitReply,
    ) -> anyhow::Result<WaitReply> {
        while let WaitReply::Park { requested } = reply {
            self.pe
                .authority
                .suspend_system(&ConsumerKey(()), self.attempt)
                .map_err(|()| anyhow::anyhow!("wait suspension authority failed"))?;
            // The caller settled the native context, finalizer and source
            // prefix. Keep the PE and source but release the domain
            // exclusion before the host thread parks.
            self.outer.take();
            std::thread::park_timeout(requested);
            self.pe
                .authority
                .resume_suspended(&ConsumerKey(()), self.attempt)
                .map_err(|()| anyhow::anyhow!("wait wake authority failed"))?;
            // A host service may still be active after a spurious or poll
            // return. Only that busy result is retried; any other domain
            // failure is terminal.
            loop {
                match self.pe.backend.reacquire_wait_loan()? {
                    crate::memory::domain::ExecutionLoanAttempt::Acquired(loan) => {
                        self.outer = Some(loan);
                        break;
                    }
                    crate::memory::domain::ExecutionLoanAttempt::ServiceBusy => {
                        std::thread::park_timeout(
                            crate::system::events::hosted::HOSTED_MAX_REQUESTED_SLEEP,
                        );
                    }
                }
            }
            self.pe.backend.qualify_wake(
                bound,
                self.pe.system,
                &mut self.pe.thread.registers,
                self.outer
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("wake outer missing"))?,
            )?;
            self.pe
                .authority
                .qualify_wake(&ConsumerKey(()), self.attempt)
                .map_err(|()| anyhow::anyhow!("wait requalification authority failed"))?;
            // A host return is not an architectural wake. Re-check the
            // event, IRQ and counter conditions.
            reply = self.pe.backend.poll_wait()?;
        }
        Ok(reply)
    }

    fn retired_wait_step(&mut self, instruction: SystemInstruction) -> WaitStep {
        if crate::system::exception::irq_masked(self.pe.system) {
            WaitStep::Retired
        } else {
            // The PE stays retained. An ignored boundary must fail before
            // another native run or before this Active is released.
            self.closed = false;
            WaitStep::InterruptBoundary(RetiredSystemBoundary::after_retirement(
                instruction,
                self.pe.authority.identity(),
                self.attempt,
            ))
        }
    }

    fn retire_wait(
        &mut self,
        instruction: SystemInstruction,
        outcome: Outcome,
        bound: &BoundSource<'_>,
    ) -> anyhow::Result<()> {
        let Outcome::Retired { next_pc, reason } = outcome else {
            anyhow::bail!("nonretired wait cannot settle as success");
        };
        anyhow::ensure!(
            next_pc == instruction.next_pc.0,
            "wait continuation differs"
        );
        match reason {
            RetireReason::EventConsumed
            | RetireReason::EventObserved
            | RetireReason::DeadlineExpired => {}
            RetireReason::PresentedIrqResume => {
                anyhow::ensure!(
                    matches!(
                        instruction.operation,
                        SystemOperation::Wait {
                            kind: WaitKind::Event,
                            ..
                        }
                    ),
                    "presented IRQ WFE policy cannot retire another instruction"
                );
            }
            RetireReason::InterruptPending => {
                anyhow::ensure!(
                    matches!(
                        instruction.operation,
                        SystemOperation::Wait {
                            kind: WaitKind::Interrupt,
                            ..
                        }
                    ),
                    "WFE IRQ retirement needs its declared wake policy"
                );
            }
            _ => anyhow::bail!("unqualified wait retirement reason"),
        }
        self.pe
            .authority
            .start_retirement(&ConsumerKey(()), self.attempt)
            .map_err(|()| anyhow::anyhow!("wait retirement authority failed"))?;
        self.pe.thread.pc = instruction.next_pc;
        self.pe.backend.settle_wait()?;
        self.pe.backend.post_retirement(
            bound,
            self.pe.system,
            &mut self.pe.thread.registers,
            self.outer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("retirement outer missing"))?,
        )?;
        self.finish_retirement(false)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        blocks::retirement::ConsumerKey, system::execution::authority::PeExecutionAuthority,
    };

    #[test]
    fn host_return_cannot_grant_ready_or_retirement_before_requalification() {
        let mut authority = unsafe { PeExecutionAuthority::new_pe() };
        let key = ConsumerKey(());
        let attempt = authority.begin_native(&key).unwrap();
        authority.enter_system(&key, attempt).unwrap();
        authority.suspend_system(&key, attempt).unwrap();
        assert!(!authority.ready());
        assert!(!authority.system_attempt(attempt));
        assert!(authority.check_observation(&key).is_err());
        authority.resume_suspended(&key, attempt).unwrap();
        assert!(!authority.ready());
        assert!(!authority.system_attempt(attempt));
        assert!(authority.check_observation(&key).is_err());
        authority.qualify_wake(&key, attempt).unwrap();
        assert!(authority.system_attempt(attempt));
        authority.start_retirement(&key, attempt).unwrap();
        authority.finish_retirement(&key, attempt, false).unwrap();
        assert!(authority.ready());
    }

    #[test]
    fn stale_wake_attempt_poison_cannot_reopen_entry() {
        let mut authority = unsafe { PeExecutionAuthority::new_pe() };
        let key = ConsumerKey(());
        let attempt = authority.begin_native(&key).unwrap();
        authority.enter_system(&key, attempt).unwrap();
        authority.suspend_system(&key, attempt).unwrap();
        assert!(authority.resume_suspended(&key, attempt + 1).is_err());
        assert!(authority.resume_suspended(&key, attempt).is_err());
        assert!(authority.qualify_wake(&key, attempt).is_err());
        assert!(authority.begin_native(&key).is_err());
    }

    #[test]
    fn retirement_during_wake_requalification_poison_is_sticky() {
        let mut authority = unsafe { PeExecutionAuthority::new_pe() };
        let key = ConsumerKey(());
        let attempt = authority.begin_native(&key).unwrap();
        authority.enter_system(&key, attempt).unwrap();
        authority.suspend_system(&key, attempt).unwrap();
        authority.resume_suspended(&key, attempt).unwrap();
        assert!(authority.start_retirement(&key, attempt).is_err());
        assert!(authority.qualify_wake(&key, attempt).is_err());
        assert!(authority.begin_native(&key).is_err());
    }
}
