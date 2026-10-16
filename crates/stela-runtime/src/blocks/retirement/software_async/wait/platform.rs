//! Combines the hosted wait resources. Only Active parks and retires.
use super::*;
use crate::system::events::{
    self, Context, EventDomain, EventEndpoint, EventInstruction, Outcome, RetireReason,
    SendAttachment, WaitPreparation, WaitRequest,
};
use core::time::Duration;

pub(in crate::blocks::retirement) struct HostedWaitPlatform<'pe> {
    sources: WaitSources<'pe>,
    domain: &'pe EventDomain,
    endpoint: &'pe mut EventEndpoint,
    identity: Arc<()>,
    generation: u64,
    waiting: Option<WaitRequest>,
    arm: Option<hosted::Arm>,
    awaiting_settlement: bool,
    policy: IrqWakePolicy,
}
enum IrqWakePolicy {
    Arbitrate,
    PresentedIrqPreserveEvent,
}

/// Receipt and endpoint split after the wait settles. Only the platform
/// constructs it, so they cannot come from different sources.
pub(in crate::blocks::retirement) struct HostedIrqResources<'call> {
    receipt: Option<PendingIrqReceipt<'call>>,
    endpoint: &'call EventEndpoint,
}
impl HostedIrqResources<'_> {
    pub(in crate::blocks::retirement) fn receipt(&self) -> Option<&PendingIrqReceipt<'_>> {
        self.receipt.as_ref()
    }
    pub(in crate::blocks::retirement) fn endpoint(&self) -> &EventEndpoint {
        self.endpoint
    }
    pub(in crate::blocks::retirement) fn validate_presented(&self) -> Result<(), AsyncError> {
        self.receipt
            .as_ref()
            .ok_or(AsyncError::PendingEvent)?
            .validate()
    }
}

/// Consumes either the inline completion or the pending indication; nothing
/// is copied or allocated.
pub(in crate::blocks::retirement) struct Preparation(Option<Completion>);
impl Preparation {
    pub(in crate::blocks::retirement) fn into_completion(self) -> Option<Completion> {
        self.0
    }
}
pub(in crate::blocks::retirement) enum Poll {
    /// Requested sleep; returning from it is not a wake.
    Sleep {
        requested: Duration,
    },
    /// WFE still needs the interrupt owner; it is not completed here with an
    /// invented event bit or exception entry.
    InterruptArbitrationRequired,
    Complete(Completion),
}
pub(in crate::blocks::retirement) struct Completion {
    platform: Arc<()>,
    generation: u64,
    outcome: Outcome,
    interrupt: Option<InterruptWake>,
    deadline: Option<DeadlineCommit>,
    presented_irq: Option<PresentedIrqWake>,
}
impl Completion {
    pub(in crate::blocks::retirement) fn outcome(&self) -> Outcome {
        self.outcome
    }
}

#[derive(Debug)]
pub(in crate::blocks::retirement) enum Error {
    Domain(AsyncError),
    Counter(hosted::Error),
    Event(events::Error<hosted::Error>),
    Endpoint(events::DomainError),
    AlreadyWaiting,
    NoWait,
    AwaitingSettlement,
    StaleCompletion,
    InterruptArbitrationRequired,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Domain(error) => write!(f, "async domain: {error:?}"),
            Self::Counter(error) => write!(f, "hosted counter: {error:?}"),
            Self::Event(error) => write!(f, "architectural event preparation: {error:?}"),
            Self::Endpoint(error) => write!(f, "event endpoint: {error:?}"),
            Self::AlreadyWaiting => f.write_str("wait already active"),
            Self::NoWait => f.write_str("no wait active"),
            Self::AwaitingSettlement => f.write_str("completion awaits settlement"),
            Self::StaleCompletion => {
                f.write_str("completion is stale or belongs to another platform")
            }
            Self::InterruptArbitrationRequired => f.write_str("IRQ requires arbitration"),
        }
    }
}

impl<'pe> WaitSources<'pe> {
    /// The hosted wake policy, chosen once by the IRQ and deadline factory.
    pub(in crate::blocks::retirement) fn attach_hosted_events(
        self,
        domain: &'pe EventDomain,
        endpoint: &'pe mut EventEndpoint,
    ) -> Result<HostedWaitPlatform<'pe>, Error> {
        self.check_hosted_irq_profile().map_err(Error::Domain)?;
        let mut platform = self.attach_events(domain, endpoint)?;
        platform.policy = IrqWakePolicy::PresentedIrqPreserveEvent;
        Ok(platform)
    }

    /// Joins the PE's receiver, endpoint and counter. This permits no native
    /// entry, PC change or exception.
    pub(in crate::blocks::retirement) fn attach_events(
        self,
        domain: &'pe EventDomain,
        endpoint: &'pe mut EventEndpoint,
    ) -> Result<HostedWaitPlatform<'pe>, Error> {
        self.check_idle_wait().map_err(Error::Domain)?;
        {
            let _attachment = SendAttachment::new(domain, endpoint).map_err(Error::Endpoint)?;
        }
        Ok(HostedWaitPlatform {
            sources: self,
            domain,
            endpoint,
            identity: Arc::new(()),
            generation: 0,
            waiting: None,
            arm: None,
            awaiting_settlement: false,
            policy: IrqWakePolicy::Arbitrate,
        })
    }
}

impl HostedWaitPlatform<'_> {
    /// Re-borrow the same resources to re-check an active wait.
    #[cfg(feature = "std")]
    pub(in crate::blocks::retirement) fn check_wait_resources(&self) -> Result<(), Error> {
        self.sources
            .validate_wait(&self.identity, self.generation)
            .map_err(Error::Domain)
    }
    pub(in crate::blocks::retirement) fn abandon(&mut self) {
        self.sources.abandon_wait(&self.identity);
    }
    pub(in crate::blocks::retirement) fn endpoint(&self) -> &EventEndpoint {
        self.endpoint
    }
    pub(in crate::blocks::retirement) fn check_resources(&self) -> Result<(), Error> {
        self.sources.check_registry().map_err(Error::Domain)
    }
    /// The first hosted entry check. Until IRQ arbitration handles pending
    /// effects using PSTATE, any registered publication blocks another native
    /// run.
    pub(in crate::blocks::retirement) fn check_native_boundary(
        &mut self,
        system: &crate::system::state::SystemState,
    ) -> Result<(), Error> {
        self.sources
            .check_hosted_irq_profile()
            .map_err(Error::Domain)?;
        self.sources.check_idle_wait().map_err(Error::Domain)?;
        self.sources.drain_inputs().map_err(Error::Domain)?;
        if self
            .sources
            .wake_observation()
            .map_err(Error::Domain)?
            .is_some()
            && !crate::system::exception::irq_masked(system)
        {
            return Err(Error::InterruptArbitrationRequired);
        }
        Ok(())
    }

    pub(in crate::blocks::retirement) fn irq_resources(
        &mut self,
    ) -> Result<HostedIrqResources<'_>, Error> {
        // Disjoint fields. The receipt borrows the sources, and the endpoint
        // is the one already bound to the PE monitor.
        let Self {
            sources, endpoint, ..
        } = self;
        let receipt = sources.pending_irq_receipt().map_err(Error::Domain)?;
        Ok(HostedIrqResources { receipt, endpoint })
    }
    pub(in crate::blocks::retirement) fn counter_view(
        &mut self,
    ) -> Result<hosted::CounterView<'_>, Error> {
        self.sources.counter_view().map_err(Error::Domain)
    }

    pub(in crate::blocks::retirement) fn prepare(
        &mut self,
        instruction: EventInstruction,
        context: Context,
    ) -> Result<Preparation, Error> {
        if self.awaiting_settlement {
            return Err(Error::AwaitingSettlement);
        }
        if self.waiting.is_some() {
            return Err(Error::AlreadyWaiting);
        }
        // Reserve the generation before any event or counter effect.
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::Domain(AsyncError::SequenceExhausted))?;
        self.sources
            .begin_wait(&self.identity, generation)
            .map_err(Error::Domain)?;
        // Keep the generation even if a later step fails. Drop poisons the
        // receiver instead of rebuilding an idle one.
        self.generation = generation;
        self.sources.drain_inputs().map_err(Error::Domain)?;
        let interrupt = self.sources.interrupt_pending().map_err(Error::Domain)?;
        let prepared = self
            .endpoint
            .prepare_wait(self.domain, instruction, context, interrupt, || {
                self.sources.sample_counter().map(|sample| sample.ticks())
            })
            .map_err(Error::Event)?;
        match prepared {
            WaitPreparation::Ready(outcome) => {
                let interrupt = if matches!(
                    outcome,
                    Outcome::Retired {
                        reason: RetireReason::InterruptPending,
                        ..
                    }
                ) {
                    self.sources.wake_observation().map_err(Error::Domain)?
                } else {
                    None
                };
                self.generation = generation;
                self.awaiting_settlement = true;
                Ok(Preparation(Some(Completion {
                    platform: Arc::clone(&self.identity),
                    generation,
                    outcome,
                    interrupt,
                    deadline: None,
                    presented_irq: None,
                })))
            }
            WaitPreparation::Pending(wait) => {
                let arm = wait
                    .deadline()
                    .map(|ticks| self.sources.arm_deadline(ticks))
                    .transpose()
                    .map_err(convert_wait_error)?;
                self.generation = generation;
                self.arm = arm;
                self.waiting = Some(wait);
                Ok(Preparation(None))
            }
        }
    }

    /// The deadline was armed by prepare; every call drains the lines and
    /// re-checks the conditions before requesting sleep. A publication after
    /// the re-check stays in the line or event bit for the next poll, and the
    /// requested sleep is bounded.
    pub(in crate::blocks::retirement) fn poll(&mut self) -> Result<Poll, Error> {
        if self.awaiting_settlement {
            return Err(Error::AwaitingSettlement);
        }
        self.sources
            .validate_wait(&self.identity, self.generation)
            .map_err(Error::Domain)?;
        let wait = self.waiting.as_ref().ok_or(Error::NoWait)?;
        self.sources.drain_inputs().map_err(Error::Domain)?;
        let interrupt = self.sources.wake_observation().map_err(Error::Domain)?;
        let mut counter_sample = None;
        let outcome = self
            .endpoint
            .recheck_wait(wait, interrupt.is_some(), || {
                let sample = self.sources.sample_counter()?;
                let ticks = sample.ticks();
                counter_sample = Some(sample);
                Ok(ticks)
            })
            .map_err(Error::Event)?;
        if let Some(outcome) = outcome {
            let (interrupt, deadline) = match outcome {
                Outcome::Retired {
                    reason: RetireReason::InterruptPending,
                    ..
                } => (interrupt, None),
                Outcome::Retired {
                    reason: RetireReason::DeadlineExpired,
                    ..
                } => {
                    let sample = counter_sample
                        .as_ref()
                        .expect("timed predicate sampled the counter");
                    let deadline = self
                        .sources
                        .commit_deadline(sample)
                        .map_err(convert_wait_error)?
                        .ok_or(Error::StaleCompletion)?;
                    (None, Some(deadline))
                }
                _ => (None, None),
            };
            self.awaiting_settlement = true;
            return Ok(Poll::Complete(Completion {
                platform: Arc::clone(&self.identity),
                generation: self.generation,
                outcome,
                interrupt,
                deadline,
                presented_irq: None,
            }));
        }
        if interrupt.is_some() {
            match self.policy {
                IrqWakePolicy::Arbitrate => return Ok(Poll::InterruptArbitrationRequired),
                IrqWakePolicy::PresentedIrqPreserveEvent => {
                    if let Some(presented) =
                        self.sources.presented_irq_wake().map_err(Error::Domain)?
                    {
                        return self.complete_presented_wfe(presented).map(Poll::Complete);
                    }
                    // An earlier assert/deassert episode does not wake WFE under
                    // this policy. Keep it and keep waiting.
                }
            }
        }
        let sample = self.sources.sample_counter().map_err(Error::Counter)?;
        let requested = self
            .sources
            .requested_sleep(&sample)
            .map_err(Error::Counter)?;
        Ok(Poll::Sleep { requested })
    }

    fn complete_presented_wfe(&mut self, presented: PresentedIrqWake) -> Result<Completion, Error> {
        let wait = self.waiting.as_ref().ok_or(Error::NoWait)?;
        if wait.kind() != stela_compiler::aarch64::system::synchronization::WaitKind::Event {
            return Err(Error::NoWait);
        }
        self.sources
            .validate_wait(&self.identity, self.generation)
            .map_err(Error::Domain)?;
        // The WFE event and deadline conditions were checked first. Honor a
        // racing SEV and keep its bit, including a later publication.
        let event_seen = self.endpoint.is_set();
        self.awaiting_settlement = true;
        Ok(Completion {
            platform: Arc::clone(&self.identity),
            generation: self.generation,
            outcome: Outcome::Retired {
                next_pc: wait.next_pc(),
                reason: if event_seen {
                    RetireReason::EventObserved
                } else {
                    RetireReason::PresentedIrqResume
                },
            },
            interrupt: None,
            deadline: None,
            presented_irq: (!event_seen).then_some(presented),
        })
    }

    /// Called by Active after the wait instruction settles; wake receipts are
    /// consumed only when a WFI retires. Effects survive an error, and this
    /// never changes the PC.
    pub(in crate::blocks::retirement) fn settle(
        &mut self,
        completion: Completion,
    ) -> Result<(), Error> {
        if !self.awaiting_settlement
            || !Arc::ptr_eq(&completion.platform, &self.identity)
            || completion.generation != self.generation
        {
            return Err(Error::StaleCompletion);
        }
        self.sources
            .validate_wait(&self.identity, self.generation)
            .map_err(Error::Domain)?;
        if let Some(deadline) = completion.deadline {
            self.sources
                .settle_deadline(deadline)
                .map_err(convert_wait_error)?;
        } else if let Some(arm) = &self.arm {
            self.sources
                .cancel_deadline(arm)
                .map_err(convert_wait_error)?;
        }
        if let Some(presented) = completion.presented_irq {
            self.sources
                .settle_presented_irq_wake(presented)
                .map_err(Error::Domain)?;
        }
        if let Some(interrupt) = completion.interrupt {
            self.sources.settle_wake(interrupt).map_err(Error::Domain)?;
        }
        self.sources
            .finish_wait(&self.identity, self.generation)
            .map_err(Error::Domain)?;
        self.arm = None;
        self.waiting = None;
        self.awaiting_settlement = false;
        Ok(())
    }
}

impl Drop for HostedWaitPlatform<'_> {
    fn drop(&mut self) {
        // Active's Drop also poisons the PE. Poisoning the receiver keeps a
        // later attachment from resetting pending waits.
        self.sources.abandon_wait(&self.identity);
    }
}

fn convert_wait_error(error: WaitError) -> Error {
    match error {
        WaitError::Domain(error) => Error::Domain(error),
        WaitError::Counter(error) => Error::Counter(error),
    }
}

#[cfg(test)]
mod tests;
