//! Hosted wait resources. The checked Active owns suspension, source and
//! control re-checks, exception effects and PC writes.
use crate::{
    blocks::retirement::software_async::{
        HostedIrqResources, HostedWaitCompletion, HostedWaitError, HostedWaitPlatform, WaitPoll,
        WaitPreparation, WaitSources,
    },
    system::events::{
        Context, EventDomain, EventEndpoint, EventInstruction, Outcome, RetireReason,
        hosted::CounterView,
    },
};
use core::time::Duration;
pub(in crate::blocks::retirement::checked) mod counter;
pub(crate) use counter::HostedCounterRead;

/// The next step of a wait. The pending wait state stays in the backend;
/// this reply cannot advance the PC or deliver an IRQ.
pub(crate) enum WaitReply {
    CompletionReady,
    Park { requested: Duration },
    WakeIrqPending,
}

enum State {
    Idle,
    Waiting,
    Completed,
    Poisoned,
}

pub(in crate::blocks::retirement) struct HostedWaitResources<'pe> {
    platform: HostedWaitPlatform<'pe>,
    state: State,
    // The completion is stored inline, so completing a wait does not allocate.
    completion: Option<HostedWaitCompletion>,
}

impl<'pe> HostedWaitResources<'pe> {
    /// The hosted factory passes its complete producer lease and the event
    /// endpoint once; the backend keeps them for its lifetime.
    pub(in crate::blocks::retirement) fn new(
        sources: WaitSources<'pe>,
        events: &'pe EventDomain,
        endpoint: &'pe mut EventEndpoint,
    ) -> Result<Self, HostedWaitError> {
        sources
            .check_hosted_irq_profile()
            .map_err(HostedWaitError::Domain)?;
        Ok(Self {
            platform: sources.attach_hosted_events(events, endpoint)?,
            state: State::Idle,
            completion: None,
        })
    }

    pub(in crate::blocks::retirement) fn check_resources(&self) -> Result<(), HostedWaitError> {
        if matches!(self.state, State::Poisoned) {
            return Err(HostedWaitError::AwaitingSettlement);
        }
        self.platform.check_resources()
    }
    /// Checked at native entry and after retirement. This only checks
    /// membership and lifetime; it says nothing about pending effects.
    pub(in crate::blocks::retirement) fn check_native_boundary(
        &mut self,
        system: &crate::system::state::SystemState,
    ) -> Result<(), HostedWaitError> {
        if !matches!(self.state, State::Idle) {
            return Err(HostedWaitError::AwaitingSettlement);
        }
        self.platform.check_native_boundary(system)
    }
    #[cfg(feature = "std")]
    pub(in crate::blocks::retirement) fn check_wake_resources(
        &self,
    ) -> Result<(), HostedWaitError> {
        if !matches!(self.state, State::Waiting) {
            return Err(HostedWaitError::NoWait);
        }
        self.platform.check_wait_resources()
    }
    /// Poison on failure or unwind, before resources or the outer loan are
    /// released. Pending effects, the armed deadline and the receipt are kept.
    pub(in crate::blocks::retirement) fn abandon(&mut self) {
        if !matches!(self.state, State::Idle) {
            self.state = State::Poisoned;
            self.platform.abandon();
        }
    }
    pub(in crate::blocks::retirement) fn endpoint(&self) -> &EventEndpoint {
        self.platform.endpoint()
    }
    pub(in crate::blocks::retirement) fn irq_resources(
        &mut self,
    ) -> Result<HostedIrqResources<'_>, HostedWaitError> {
        if !matches!(self.state, State::Idle) {
            return Err(HostedWaitError::AwaitingSettlement);
        }
        self.platform.irq_resources()
    }
    pub(in crate::blocks::retirement) fn counter_view(
        &mut self,
    ) -> Result<CounterView<'_>, HostedWaitError> {
        self.check_resources()?;
        self.platform.counter_view()
    }

    /// Called by the hosted backend with its own source, control,
    /// identification, debug and state borrows. Active has already matched the
    /// instruction to the BoundSource after native finalization.
    pub(in crate::blocks::retirement) fn prepare_typed(
        &mut self,
        instruction: stela_compiler::block::system::SystemInstruction,
        controls: &crate::system::translation_controls::TranslationControls,
        identification: &crate::system::identification_snapshot::Snapshot,
        execution: &super::super::entry_controls::ProcessEntryControls,
        system: &crate::system::state::SystemState,
        registers: &stela_compiler::GuestState,
    ) -> anyhow::Result<WaitReply> {
        anyhow::ensure!(
            matches!(
                instruction.operation,
                stela_compiler::block::system::SystemOperation::Wait { .. }
            ),
            "non-wait source"
        );
        anyhow::ensure!(
            instruction.matches_source(instruction.instruction_pc, instruction.word),
            "wait descriptor does not match its word"
        );
        execution.check()?;
        execution.check_snapshot(Some(identification), system)?;
        let context = controls
            .event_context(identification, system, execution.debug_controls())
            .map_err(|error| anyhow::anyhow!("event context: {error}"))?;
        let event =
            EventInstruction::decode(instruction.word, instruction.instruction_pc.0, registers)
                .ok_or_else(|| anyhow::anyhow!("wait decoder declined"))?;
        self.prepare(event, context)
            .map_err(|error| anyhow::anyhow!("wait preparation: {error}"))
    }

    pub(in crate::blocks::retirement) fn prepare(
        &mut self,
        instruction: EventInstruction,
        context: Context,
    ) -> Result<WaitReply, HostedWaitError> {
        if !matches!(self.state, State::Idle) {
            return Err(HostedWaitError::AlreadyWaiting);
        }
        // After event or counter effects, an error cannot reset this backend.
        self.state = State::Poisoned;
        let prepared: WaitPreparation = self.platform.prepare(instruction, context)?;
        match prepared.into_completion() {
            Some(completion) => {
                self.retain_completion(completion)?;
                self.completed_reply()
            }
            None => {
                self.state = State::Waiting;
                self.poll()
            }
        }
    }

    pub(in crate::blocks::retirement) fn poll(&mut self) -> Result<WaitReply, HostedWaitError> {
        if matches!(self.state, State::Completed) {
            return self.completed_reply();
        }
        if !matches!(self.state, State::Waiting) {
            return Err(HostedWaitError::NoWait);
        }
        self.state = State::Poisoned;
        match self.platform.poll()? {
            WaitPoll::Sleep { requested } => {
                self.state = State::Waiting;
                Ok(WaitReply::Park { requested })
            }
            WaitPoll::InterruptArbitrationRequired => {
                self.state = State::Waiting;
                Ok(WaitReply::WakeIrqPending)
            }
            WaitPoll::Complete(completion) => {
                self.retain_completion(completion)?;
                self.completed_reply()
            }
        }
    }

    fn completed_reply(&self) -> Result<WaitReply, HostedWaitError> {
        let outcome = self.outcome()?;
        Ok(
            if matches!(
                outcome,
                Outcome::Retired {
                    reason: RetireReason::InterruptPending,
                    ..
                }
            ) {
                // An immediate WFI still uses the generation receipt. Whether it
                // wakes masked or takes the IRQ is decided by arbitration.
                WaitReply::WakeIrqPending
            } else {
                WaitReply::CompletionReady
            },
        )
    }

    // Only these methods access the completion. Idle and Waiting have none;
    // Completed has exactly one receipt. Poisoned may keep a receipt after
    // abandonment but cannot expose or consume it.
    fn retain_completion(
        &mut self,
        completion: HostedWaitCompletion,
    ) -> Result<(), HostedWaitError> {
        if !matches!(self.state, State::Poisoned) || self.completion.is_some() {
            return Err(HostedWaitError::AwaitingSettlement);
        }
        self.completion = Some(completion);
        self.state = State::Completed;
        Ok(())
    }
    fn completion(&self) -> Result<&HostedWaitCompletion, HostedWaitError> {
        if !matches!(self.state, State::Completed) {
            return Err(HostedWaitError::AwaitingSettlement);
        }
        self.completion
            .as_ref()
            .ok_or(HostedWaitError::AwaitingSettlement)
    }
    fn take_completion(&mut self) -> Result<HostedWaitCompletion, HostedWaitError> {
        if !matches!(
            core::mem::replace(&mut self.state, State::Poisoned),
            State::Completed
        ) {
            return Err(HostedWaitError::AwaitingSettlement);
        }
        self.completion
            .take()
            .ok_or(HostedWaitError::AwaitingSettlement)
    }
    pub(in crate::blocks::retirement) fn outcome(&self) -> Result<Outcome, HostedWaitError> {
        let completion = self.completion()?;
        self.platform.check_resources()?;
        Ok(completion.outcome())
    }

    /// Called only inside retirement or exception handling. A failure keeps
    /// the effects and poisons; it never returns to Ready.
    pub(in crate::blocks::retirement) fn settle(&mut self) -> Result<(), HostedWaitError> {
        let completion = self.take_completion()?;
        self.platform.settle(completion)?;
        self.state = State::Idle;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blocks::retirement::checked::software_el1::hosted::HostedWaitInstallation,
        system::{
            access::{ExceptionLevel, Profile, SecurityState},
            events::hosted,
        },
    };
    use stela_compiler::GuestState;

    const PC: u64 = 0x1000;
    const WFE: u32 = 0xd503_205f;
    const WFI: u32 = 0xd503_207f;
    const WFIT_X0: u32 = 0xd503_1020;

    fn context() -> Context {
        Context::new(
            Profile {
                current_el: ExceptionLevel::El1,
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            true,
            false,
            false,
            true,
            true,
        )
        .unwrap()
    }
    fn instruction(word: u32, ticks: u64) -> EventInstruction {
        let mut registers = GuestState::default();
        registers.x[0] = ticks;
        EventInstruction::decode(word, PC, &registers).unwrap()
    }

    #[test]
    fn same_backend_retains_pending_descriptor_across_host_returns() {
        let (mut installation, _) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
        let events = EventDomain::new();
        let mut endpoint = events.register(false, None).unwrap();
        let producer = endpoint.producer();
        let mut resources = installation.resources(&events, &mut endpoint).unwrap();
        assert!(matches!(
            resources.prepare(instruction(WFE, 0), context()).unwrap(),
            WaitReply::Park { .. }
        ));
        assert!(resources.outcome().is_err());
        assert!(resources.prepare(instruction(WFE, 0), context()).is_err());
        let WaitReply::Park { requested } = resources.poll().unwrap() else {
            panic!("missing event cannot retire");
        };
        std::thread::park_timeout(requested);
        assert!(matches!(resources.poll().unwrap(), WaitReply::Park { .. }));
        assert!(producer.signal_local());
        assert!(matches!(
            resources.poll().unwrap(),
            WaitReply::CompletionReady
        ));
        assert!(matches!(
            resources.outcome().unwrap(),
            Outcome::Retired {
                reason: RetireReason::EventObserved,
                ..
            }
        ));
        assert!(matches!(
            resources.poll().unwrap(),
            WaitReply::CompletionReady
        ));
        resources.settle().unwrap();
        assert!(resources.outcome().is_err());
    }

    #[test]
    fn immediate_irq_reply_retains_receipt_until_settlement() {
        let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
        let events = EventDomain::new();
        let mut endpoint = events.register(false, None).unwrap();
        let mut resources = installation.resources(&events, &mut endpoint).unwrap();
        irq.publish(true).unwrap();
        assert!(matches!(
            resources.prepare(instruction(WFI, 0), context()).unwrap(),
            WaitReply::WakeIrqPending
        ));
        assert!(matches!(
            resources.outcome().unwrap(),
            Outcome::Retired {
                reason: RetireReason::InterruptPending,
                ..
            }
        ));
        assert!(matches!(
            resources.poll().unwrap(),
            WaitReply::WakeIrqPending
        ));
        // Masked-WFI arbitration may consume this wake; the adapter itself never
        // permits a masked wake or IRQ entry.
        resources.settle().unwrap();
        irq.publish(false).unwrap();
        assert!(matches!(
            resources.prepare(instruction(WFI, 0), context()).unwrap(),
            WaitReply::Park { .. }
        ));
    }

    #[test]
    fn guest_read_and_timed_wait_use_the_same_counter() {
        use crate::system::{
            access::AccessKind,
            timer::{BackendRequest, CounterOffset, CounterOrdering, TimerKind},
        };
        let (mut installation, _) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
        let events = EventDomain::new();
        let mut endpoint = events.register(false, None).unwrap();
        let mut resources = installation.resources(&events, &mut endpoint).unwrap();
        let request = BackendRequest::Counter {
            kind: TimerKind::Virtual,
            offset: CounterOffset::None,
            ordering: CounterOrdering::CounterReads,
        };
        assert_eq!(
            resources
                .counter_view()
                .unwrap()
                .read(BackendRequest::Frequency(AccessKind::Read))
                .unwrap(),
            hosted::HOSTED_COUNTER_FREQUENCY
        );
        let before = resources.counter_view().unwrap().read(request).unwrap();
        assert!(matches!(
            resources
                .prepare(instruction(WFIT_X0, before), context())
                .unwrap(),
            WaitReply::CompletionReady
        ));
        assert!(matches!(
            resources.outcome().unwrap(),
            Outcome::Retired {
                reason: RetireReason::DeadlineExpired,
                ..
            }
        ));
        resources.settle().unwrap();
        let after = resources.counter_view().unwrap().read(request).unwrap();
        assert!(after >= before);
    }

    #[test]
    fn registry_membership_check_is_not_native_pending_delivery_permission() {
        let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
        let events = EventDomain::new();
        let mut endpoint = events.register(false, None).unwrap();
        let mut resources = installation.resources(&events, &mut endpoint).unwrap();
        let system = crate::system::state::SystemState::new(
            crate::system::state::PSTATE_EL1H,
            0,
            crate::system::state::El1Registers::new(0, 0, 0, 0, 0),
        )
        .unwrap();
        resources.check_native_boundary(&system).unwrap();
        irq.publish(true).unwrap();
        irq.publish(false).unwrap();
        resources.check_resources().unwrap();
        assert!(matches!(
            resources.check_native_boundary(&system),
            Err(HostedWaitError::InterruptArbitrationRequired)
        ));
        // Re-checking cannot acknowledge or discard the pending wake.
        assert!(matches!(
            resources.check_native_boundary(&system),
            Err(HostedWaitError::InterruptArbitrationRequired)
        ));
    }

    #[test]
    fn masked_wfi_settlement_preserves_presented_irq_for_the_entry_owner() {
        let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
        let events = EventDomain::new();
        let mut endpoint = events.register(false, None).unwrap();
        let mut resources = installation.resources(&events, &mut endpoint).unwrap();
        let masked = crate::system::state::SystemState::new(
            crate::system::state::PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
            0,
            crate::system::state::El1Registers::new(0, 0, 0, 0, 0),
        )
        .unwrap();
        irq.publish(true).unwrap();
        assert!(matches!(
            resources.prepare(instruction(WFI, 0), context()).unwrap(),
            WaitReply::WakeIrqPending
        ));
        resources.settle().unwrap();
        resources.check_native_boundary(&masked).unwrap();
        {
            let original = resources.irq_resources().unwrap();
            let receipt = original.receipt().unwrap();
            receipt.validate().unwrap();
            // A later deassertion cannot rewrite the leased pending state; the
            // level is sampled again afterward.
            irq.publish(false).unwrap();
            receipt.validate().unwrap();
        }
        assert!(resources.irq_resources().unwrap().receipt().is_none());
    }

    #[test]
    fn transient_wake_is_not_a_pending_irq_exception() {
        let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
        let events = EventDomain::new();
        let mut endpoint = events.register(false, None).unwrap();
        let mut resources = installation.resources(&events, &mut endpoint).unwrap();
        irq.publish(true).unwrap();
        irq.publish(false).unwrap();
        // The receipt is only constructed beside its own endpoint; nothing
        // accepts a receipt and endpoint from different sources.
        let endpoint = resources.endpoint() as *const _;
        let original = resources.irq_resources().unwrap();
        assert!(original.receipt().is_none());
        assert!(core::ptr::eq(original.endpoint(), endpoint));
    }

    #[test]
    fn active_wait_qualification_is_distinct_from_native_entry_permission() {
        let (mut installation, _) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
        let events = EventDomain::new();
        let mut endpoint = events.register(false, None).unwrap();
        let mut resources = installation.resources(&events, &mut endpoint).unwrap();
        let system = crate::system::state::SystemState::new(
            crate::system::state::PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
            0,
            crate::system::state::El1Registers::new(0, 0, 0, 0, 0),
        )
        .unwrap();
        assert!(resources.check_wake_resources().is_err());
        assert!(matches!(
            resources.prepare(instruction(WFE, 0), context()).unwrap(),
            WaitReply::Park { .. }
        ));
        resources.check_wake_resources().unwrap();
        assert!(resources.check_native_boundary(&system).is_err());
        resources.abandon();
        assert!(resources.check_resources().is_err());
        assert!(resources.check_wake_resources().is_err());
    }

    #[test]
    fn hosted_wfe_presented_irq_resume_preserves_event_and_pending_level() {
        let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
        let events = EventDomain::new();
        let mut endpoint = events.register(false, None).unwrap();
        let mut resources = installation.resources(&events, &mut endpoint).unwrap();
        assert!(matches!(
            resources.prepare(instruction(WFE, 0), context()).unwrap(),
            WaitReply::Park { .. }
        ));
        irq.publish(true).unwrap();
        assert!(matches!(
            resources.poll().unwrap(),
            WaitReply::CompletionReady
        ));
        assert!(
            matches!(resources.outcome().unwrap(), Outcome::Retired { next_pc, reason: RetireReason::PresentedIrqResume } if next_pc == PC + 4)
        );
        assert!(!resources.endpoint().is_set());
        resources.settle().unwrap();
        assert!(!resources.endpoint().is_set());
        resources
            .irq_resources()
            .unwrap()
            .receipt()
            .unwrap()
            .validate()
            .unwrap();
    }

    #[test]
    fn hosted_wfe_transient_wake_does_not_replace_event_or_presented_irq() {
        let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
        let events = EventDomain::new();
        let mut endpoint = events.register(false, None).unwrap();
        let producer = endpoint.producer();
        let mut resources = installation.resources(&events, &mut endpoint).unwrap();
        assert!(matches!(
            resources.prepare(instruction(WFE, 0), context()).unwrap(),
            WaitReply::Park { .. }
        ));
        irq.publish(true).unwrap();
        irq.publish(false).unwrap();
        assert!(matches!(resources.poll().unwrap(), WaitReply::Park { .. }));
        assert!(resources.outcome().is_err());
        assert!(!resources.endpoint().is_set());
        assert!(producer.signal_local());
        assert!(matches!(
            resources.poll().unwrap(),
            WaitReply::CompletionReady
        ));
        assert!(matches!(
            resources.outcome().unwrap(),
            Outcome::Retired {
                reason: RetireReason::EventObserved,
                ..
            }
        ));
        resources.settle().unwrap();
    }

    #[test]
    fn simultaneous_sev_and_irq_preserve_event_and_do_not_ack_irq() {
        let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
        let events = EventDomain::new();
        let mut endpoint = events.register(false, None).unwrap();
        let producer = endpoint.producer();
        let mut resources = installation.resources(&events, &mut endpoint).unwrap();
        assert!(matches!(
            resources.prepare(instruction(WFE, 0), context()).unwrap(),
            WaitReply::Park { .. }
        ));
        irq.publish(true).unwrap();
        assert!(producer.signal_local());
        assert!(matches!(
            resources.poll().unwrap(),
            WaitReply::CompletionReady
        ));
        assert!(matches!(
            resources.outcome().unwrap(),
            Outcome::Retired {
                reason: RetireReason::EventObserved,
                ..
            }
        ));
        resources.settle().unwrap();
        assert!(resources.endpoint().is_set());
        resources
            .irq_resources()
            .unwrap()
            .receipt()
            .unwrap()
            .validate()
            .unwrap();
        assert!(matches!(
            resources.prepare(instruction(WFE, 0), context()).unwrap(),
            WaitReply::CompletionReady
        ));
        assert!(matches!(
            resources.outcome().unwrap(),
            Outcome::Retired {
                reason: RetireReason::EventConsumed,
                ..
            }
        ));
        resources.settle().unwrap();
        assert!(!resources.endpoint().is_set());
    }
}
