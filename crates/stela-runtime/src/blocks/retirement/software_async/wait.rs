//! Hosted IRQ lines and WFx wake state. Lines are external inputs; only the
//! domain's borrow drains them into pending state.
use super::*;
use crate::system::events::hosted;
use alloc::sync::Weak;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const LEVEL: u64 = 1;
const WAKE: u64 = 2;
const GENERATION_SHIFT: u32 = 2;
const MAX_GENERATION: u64 = u64::MAX >> GENERATION_SHIFT;
const MAX_WAIT_SOURCES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::blocks::retirement) enum WaitSourceKind {
    Irq,
    Fiq,
    LocalTimeout,
}
impl WaitSourceKind {
    fn class(self) -> SourceClass {
        match self {
            Self::Irq => SourceClass::Irq,
            Self::Fiq => SourceClass::Fiq,
            Self::LocalTimeout => SourceClass::WaitDeadline,
        }
    }
}
pub(in crate::blocks::retirement) struct WaitSourceKey {
    key: SourceKey,
    kind: WaitSourceKind,
}

struct Wire {
    state: AtomicU64,
    live: AtomicBool,
}
struct Input {
    source: u64,
    wire: Arc<Wire>,
}

/// The external end of an IRQ line. Signalling is a single atomic update
/// (no allocation, lock or syscall). The source stays registered.
pub(in crate::blocks::retirement) struct LevelProducer {
    wire: Weak<Wire>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::blocks::retirement) enum PublishError {
    Retired,
    SequenceExhausted,
}
impl LevelProducer {
    pub(in crate::blocks::retirement) fn publish(
        &self,
        asserted: bool,
    ) -> Result<u64, PublishError> {
        let wire = self.wire.upgrade().ok_or(PublishError::Retired)?;
        if !wire.live.load(Ordering::Acquire) {
            return Err(PublishError::Retired);
        }
        let mut before = wire.state.load(Ordering::Acquire);
        loop {
            let generation = before >> GENERATION_SHIFT;
            if generation == MAX_GENERATION {
                return Err(PublishError::SequenceExhausted);
            }
            let after = ((generation + 1) << GENERATION_SHIFT)
                | (before & WAKE)
                | if asserted { LEVEL | WAKE } else { 0 };
            match wire.state.compare_exchange_weak(
                before,
                after,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(generation + 1),
                Err(current) => before = current,
            }
        }
    }
}

pub(in crate::blocks::retirement) struct WaitReceiver {
    identity: Arc<()>,
    domain: Arc<()>,
    inputs: Vec<Input>,
    timeout_source: u64,
    timer: hosted::LocalTimer,
    transaction: WaitTransaction,
}
enum WaitTransaction {
    Idle,
    Active { platform: Arc<()>, generation: u64 },
    Poisoned,
}

impl Drop for WaitReceiver {
    fn drop(&mut self) {
        for input in &self.inputs {
            input.wire.live.store(false, Ordering::Release);
        }
    }
}

pub(in crate::blocks::retirement) struct WaitSources<'pe> {
    domain: &'pe mut SoftwareAsyncDomain,
    keys: &'pe [WaitSourceKey],
    receiver: &'pe mut WaitReceiver,
    counter: &'pe mut hosted::Counter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::blocks::retirement) enum Acknowledgment {
    ExactGeneration,
    NewPublication,
}
/// Diagnostic record of a commit; it permits nothing.
#[derive(Debug)]
pub(in crate::blocks::retirement) struct InputCommit {
    pub source: u64,
    pub generation: u64,
    pub sequence: u64,
    pub level: bool,
    pub wake: bool,
    pub acknowledgment: Acknowledgment,
}
impl core::fmt::Display for InputCommit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "source={} generation={} sequence={} level={} wake={} acknowledgment={:?}",
            self.source, self.generation, self.sequence, self.level, self.wake, self.acknowledgment
        )
    }
}
/// A pending-state observation. Retirement may consume only its wake
/// episode; current IRQ and FIQ levels stay pending and unacknowledged.
#[derive(Debug)]
pub(in crate::blocks::retirement) struct InterruptWake {
    domain: Arc<()>,
    receiver: Arc<()>,
    inputs: Vec<(u64, u64)>,
}
/// A wake receipt for which a committed IRQ level was presented. It is
/// not a copy of the pending state and does not permit IRQ entry.
struct PresentedIrqWake {
    wake: InterruptWake,
}
/// The pending-controller state, distinct from a latched WFI wake. Holding
/// the borrow prevents pending changes during exception preflight and
/// effects. Lines remain external inputs.
pub(in crate::blocks::retirement) struct PendingIrqReceipt<'call> {
    domain: &'call SoftwareAsyncDomain,
    receiver: &'call WaitReceiver,
    keys: &'call [WaitSourceKey],
    inputs: Vec<(u64, u64, u64)>,
}
impl PendingIrqReceipt<'_> {
    pub(in crate::blocks::retirement) fn validate(&self) -> Result<(), AsyncError> {
        validate_keys(self.domain, self.keys)?;
        if self.inputs.is_empty()
            || !matches!(self.receiver.transaction, WaitTransaction::Idle)
            || !Arc::ptr_eq(&self.domain.identity, &self.receiver.domain)
            || !self
                .domain
                .wait_receiver
                .as_ref()
                .is_some_and(|identity| Arc::ptr_eq(identity, &self.receiver.identity))
        {
            return Err(AsyncError::SourceChanged);
        }
        for &(source, generation, sequence) in &self.inputs {
            if self.domain.registered.get(&source) != Some(&SourceClass::Irq)
                || !self.keys.iter().any(|key| key.key.id == source && key.kind == WaitSourceKind::Irq)
                || !self.receiver.inputs.iter().any(|input| input.source == source)
                || self.domain.wait_committed.get(&source) != Some(&(generation, sequence))
                || !self.domain.pending.iter().any(|event| event.source == source && matches!(event.kind,
                    PendingKind::InterruptLevel { level: true, generation: current, sequence: current_sequence, .. }
                    if current == generation && current_sequence == sequence))
            {
                return Err(AsyncError::SourceChanged);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(in crate::blocks::retirement) struct DeadlineCommit {
    domain: Arc<()>,
    receiver: Arc<()>,
    source: u64,
    expiration: hosted::Expiration,
}

impl SoftwareAsyncDomain {
    #[cfg(feature = "std")]
    pub(in crate::blocks::retirement) fn register_wait_source(
        &mut self,
        kind: WaitSourceKind,
    ) -> Result<WaitSourceKey, AsyncError> {
        Ok(WaitSourceKey {
            key: self.register(kind.class())?,
            kind,
        })
    }
    /// Bind once before execution. Dropping the receiver does not renew the
    /// line or make the PE source-free again.
    #[cfg(feature = "std")]
    pub(in crate::blocks::retirement) fn bind_wait_transport(
        &mut self,
        keys: &[WaitSourceKey],
        counter: &hosted::Counter,
    ) -> Result<(WaitReceiver, Vec<LevelProducer>), AsyncError> {
        validate_keys(self, keys)?;
        if self.wait_receiver.is_some() {
            return Err(AsyncError::SourceChanged);
        }
        if !self.pending.is_empty() {
            return Err(AsyncError::PendingEvent);
        }
        let timeouts: Vec<_> = keys
            .iter()
            .filter(|key| key.kind == WaitSourceKind::LocalTimeout)
            .collect();
        if timeouts.len() != 1 {
            return Err(AsyncError::WrongProducer);
        }
        let mut inputs = Vec::new();
        let mut producers = Vec::new();
        inputs
            .try_reserve(keys.len())
            .map_err(|_| AsyncError::Capacity)?;
        producers
            .try_reserve(keys.len())
            .map_err(|_| AsyncError::Capacity)?;
        for key in keys
            .iter()
            .filter(|key| key.kind != WaitSourceKind::LocalTimeout)
        {
            let wire = Arc::new(Wire {
                state: AtomicU64::new(0),
                live: AtomicBool::new(true),
            });
            producers.push(LevelProducer {
                wire: Arc::downgrade(&wire),
            });
            inputs.push(Input {
                source: key.key.id,
                wire,
            });
        }
        let identity = Arc::new(());
        let receiver = WaitReceiver {
            identity: Arc::clone(&identity),
            domain: Arc::clone(&self.identity),
            inputs,
            timeout_source: timeouts[0].key.id,
            timer: counter.timer(),
            transaction: WaitTransaction::Idle,
        };
        for key in keys {
            self.wait_committed.insert(key.key.id, (0, 0));
        }
        self.wait_receiver = Some(identity);
        Ok((receiver, producers))
    }
    pub(in crate::blocks::retirement) fn lease_wait_sources<'pe>(
        &'pe mut self,
        keys: &'pe [WaitSourceKey],
        receiver: &'pe mut WaitReceiver,
        counter: &'pe mut hosted::Counter,
    ) -> Result<WaitSources<'pe>, AsyncError> {
        let lease = WaitSources {
            domain: self,
            keys,
            receiver,
            counter,
        };
        lease.check_registry()?;
        Ok(lease)
    }
}

fn validate_keys(domain: &SoftwareAsyncDomain, keys: &[WaitSourceKey]) -> Result<(), AsyncError> {
    if keys.len() > MAX_WAIT_SOURCES {
        return Err(AsyncError::Capacity);
    }
    for (index, key) in keys.iter().enumerate() {
        if !Arc::ptr_eq(&domain.identity, &key.key.domain)
            || domain.registered.get(&key.key.id) != Some(&key.kind.class())
            || keys[..index].iter().any(|other| other.key.id == key.key.id)
        {
            return Err(AsyncError::WrongProducer);
        }
    }
    if keys.len() != domain.registered.len() {
        return Err(AsyncError::RegisteredProducer);
    }
    Ok(())
}

impl WaitSources<'_> {
    pub(in crate::blocks::retirement) fn check_registry(&self) -> Result<(), AsyncError> {
        validate_keys(self.domain, self.keys)?;
        if matches!(self.receiver.transaction, WaitTransaction::Poisoned) {
            return Err(AsyncError::SourceChanged);
        }
        if !Arc::ptr_eq(&self.domain.identity, &self.receiver.domain)
            || !self
                .domain
                .wait_receiver
                .as_ref()
                .is_some_and(|id| Arc::ptr_eq(id, &self.receiver.identity))
            || !self.counter.owns(&self.receiver.timer)
            || self.receiver.inputs.len() + 1 != self.keys.len()
            || self.domain.wait_committed.len() != self.keys.len()
            || self
                .receiver
                .inputs
                .iter()
                .enumerate()
                .any(|(index, input)| {
                    self.receiver.inputs[..index]
                        .iter()
                        .any(|other| other.source == input.source)
                })
            || self
                .keys
                .iter()
                .filter(|key| key.kind == WaitSourceKind::LocalTimeout)
                .count()
                != 1
            || !self.keys.iter().any(|key| {
                key.key.id == self.receiver.timeout_source
                    && key.kind == WaitSourceKind::LocalTimeout
            })
            || self.receiver.inputs.iter().any(|input| {
                !input.wire.live.load(Ordering::Acquire)
                    || !self.keys.iter().any(|key| {
                        key.key.id == input.source && key.kind != WaitSourceKind::LocalTimeout
                    })
            })
        {
            return Err(AsyncError::WrongProducer);
        }
        if self.domain.pending.iter().any(|event| match event.kind {
            PendingKind::InterruptLevel {
                generation,
                sequence,
                ..
            } => {
                !self
                    .receiver
                    .inputs
                    .iter()
                    .any(|input| input.source == event.source)
                    || self.domain.wait_committed.get(&event.source)
                        != Some(&(generation, sequence))
            }
            PendingKind::WaitDeadline {
                generation,
                sequence,
                ..
            } => {
                event.source != self.receiver.timeout_source
                    || self.domain.wait_committed.get(&event.source)
                        != Some(&(generation, sequence))
            }
            _ => true,
        }) {
            return Err(AsyncError::UnsupportedPending);
        }
        Ok(())
    }

    pub(in crate::blocks::retirement) fn check_hosted_irq_profile(&self) -> Result<(), AsyncError> {
        self.check_registry()?;
        if self.keys.len() != 2
            || self
                .keys
                .iter()
                .filter(|key| key.kind == WaitSourceKind::Irq)
                .count()
                != 1
            || self.keys.iter().any(|key| key.kind == WaitSourceKind::Fiq)
        {
            return Err(AsyncError::RegisteredProducer);
        }
        Ok(())
    }
    /// Called after the wait settles, with the memory exclusion reacquired and
    /// the PE retained. A deasserted line may leave a wake episode but cannot
    /// produce a pending IRQ receipt.
    pub(in crate::blocks::retirement) fn pending_irq_receipt(
        &mut self,
    ) -> Result<Option<PendingIrqReceipt<'_>>, AsyncError> {
        self.check_hosted_irq_profile()?;
        self.check_idle_wait()?;
        self.drain_inputs()?;
        let mut inputs = Vec::new();
        inputs
            .try_reserve(self.receiver.inputs.len())
            .map_err(|_| AsyncError::Capacity)?;
        for event in &self.domain.pending {
            if let PendingKind::InterruptLevel {
                level: true,
                generation,
                sequence,
                ..
            } = event.kind
                && self.domain.registered.get(&event.source) == Some(&SourceClass::Irq)
            {
                inputs.push((event.source, generation, sequence));
            }
        }
        if inputs.is_empty() {
            return Ok(None);
        }
        let receipt = PendingIrqReceipt {
            domain: &*self.domain,
            receiver: &*self.receiver,
            keys: self.keys,
            inputs,
        };
        receipt.validate()?;
        Ok(Some(receipt))
    }
    fn check_idle_wait(&self) -> Result<(), AsyncError> {
        self.check_registry()?;
        if !matches!(self.receiver.transaction, WaitTransaction::Idle) {
            return Err(AsyncError::SourceChanged);
        }
        Ok(())
    }
    fn begin_wait(&mut self, platform: &Arc<()>, generation: u64) -> Result<(), AsyncError> {
        self.check_idle_wait()?;
        self.receiver.transaction = WaitTransaction::Active {
            platform: Arc::clone(platform),
            generation,
        };
        Ok(())
    }
    fn validate_wait(&self, platform: &Arc<()>, generation: u64) -> Result<(), AsyncError> {
        self.check_registry()?;
        match &self.receiver.transaction {
            WaitTransaction::Active {
                platform: actual,
                generation: current,
            } if Arc::ptr_eq(actual, platform) && *current == generation => Ok(()),
            _ => Err(AsyncError::SourceChanged),
        }
    }
    fn finish_wait(&mut self, platform: &Arc<()>, generation: u64) -> Result<(), AsyncError> {
        self.validate_wait(platform, generation)?;
        self.receiver.transaction = WaitTransaction::Idle;
        Ok(())
    }
    fn abandon_wait(&mut self, platform: &Arc<()>) {
        if matches!(&self.receiver.transaction,
            WaitTransaction::Active { platform: actual, .. } if Arc::ptr_eq(actual, platform))
        {
            self.receiver.transaction = WaitTransaction::Poisoned;
        }
    }
    pub(in crate::blocks::retirement) fn counter_view(
        &mut self,
    ) -> Result<hosted::CounterView<'_>, AsyncError> {
        self.check_registry()?;
        Ok(self.counter.view())
    }

    /// Commit first, then acknowledge the sampled state. The domain keeps the
    /// generation and sequence even if acknowledgment races.
    pub(in crate::blocks::retirement) fn drain_inputs(
        &mut self,
    ) -> Result<Vec<InputCommit>, AsyncError> {
        self.check_registry()?;
        let mut commits = Vec::new();
        commits
            .try_reserve(self.receiver.inputs.len())
            .map_err(|_| AsyncError::Capacity)?;
        for input in &self.receiver.inputs {
            let sampled = input.wire.state.load(Ordering::Acquire);
            if let Some(accepted) = commit_input(self.domain, input, sampled)? {
                commits.push(acknowledge_input(input, accepted));
            }
        }
        Ok(commits)
    }

    pub(in crate::blocks::retirement) fn interrupt_pending(&self) -> Result<bool, AsyncError> {
        self.check_registry()?;
        Ok(self
            .domain
            .pending
            .iter()
            .any(|event| matches!(event.kind, PendingKind::InterruptLevel { level: true, .. })))
    }
    pub(in crate::blocks::retirement) fn wake_observation(
        &self,
    ) -> Result<Option<InterruptWake>, AsyncError> {
        self.check_registry()?;
        let mut inputs = Vec::new();
        inputs
            .try_reserve(self.receiver.inputs.len())
            .map_err(|_| AsyncError::Capacity)?;
        for event in &self.domain.pending {
            if let PendingKind::InterruptLevel {
                level,
                wake,
                generation,
                ..
            } = event.kind
                && (level || wake)
            {
                inputs.push((event.source, generation));
            }
        }
        Ok((!inputs.is_empty()).then(|| InterruptWake {
            domain: Arc::clone(&self.domain.identity),
            receiver: Arc::clone(&self.receiver.identity),
            inputs,
        }))
    }
    /// Called by retirement only; this does not acknowledge the IRQ.
    fn presented_irq_wake(&self) -> Result<Option<PresentedIrqWake>, AsyncError> {
        self.check_hosted_irq_profile()?;
        let mut inputs = Vec::new();
        inputs
            .try_reserve(self.receiver.inputs.len())
            .map_err(|_| AsyncError::Capacity)?;
        for event in &self.domain.pending {
            if let PendingKind::InterruptLevel {
                level: true,
                generation,
                ..
            } = event.kind
                && self.domain.registered.get(&event.source) == Some(&SourceClass::Irq)
            {
                inputs.push((event.source, generation));
            }
        }
        Ok((!inputs.is_empty()).then(|| PresentedIrqWake {
            wake: InterruptWake {
                domain: Arc::clone(&self.domain.identity),
                receiver: Arc::clone(&self.receiver.identity),
                inputs,
            },
        }))
    }
    fn settle_presented_irq_wake(&mut self, receipt: PresentedIrqWake) -> Result<(), AsyncError> {
        self.check_hosted_irq_profile()?;
        if !Arc::ptr_eq(&receipt.wake.domain, &self.domain.identity)
            || !Arc::ptr_eq(&receipt.wake.receiver, &self.receiver.identity)
            || receipt.wake.inputs.is_empty()
            || receipt.wake.inputs.iter().any(|&(source, generation)|
                !self.domain.pending.iter().any(|event| event.source == source && matches!(event.kind,
                    PendingKind::InterruptLevel { level: true, generation: current, .. } if current == generation)))
        { return Err(AsyncError::SourceChanged); }
        self.settle_wake(receipt.wake)
    }

    pub(in crate::blocks::retirement) fn settle_wake(
        &mut self,
        observation: InterruptWake,
    ) -> Result<(), AsyncError> {
        self.check_registry()?;
        if !Arc::ptr_eq(&observation.domain, &self.domain.identity) || !Arc::ptr_eq(&observation.receiver, &self.receiver.identity)
            || observation.inputs.iter().any(|(source, generation)| !self.domain.pending.iter().any(|event|
                event.source == *source && matches!(event.kind, PendingKind::InterruptLevel { generation: actual, .. } if actual == *generation))) {
            return Err(AsyncError::SourceChanged);
        }
        for (source, _) in observation.inputs {
            if let Some(event) = self
                .domain
                .pending
                .iter_mut()
                .find(|event| event.source == source)
                && let PendingKind::InterruptLevel { wake, .. } = &mut event.kind
            {
                *wake = false;
            }
        }
        Ok(())
    }

    pub(in crate::blocks::retirement) fn arm_deadline(
        &mut self,
        ticks: u64,
    ) -> Result<hosted::Arm, WaitError> {
        self.check_registry().map_err(WaitError::Domain)?;
        if self
            .domain
            .pending
            .iter()
            .any(|event| event.source == self.receiver.timeout_source)
        {
            return Err(WaitError::Domain(AsyncError::PendingEvent));
        }
        self.receiver.timer.arm(ticks).map_err(WaitError::Counter)
    }
    pub(in crate::blocks::retirement) fn cancel_deadline(
        &mut self,
        arm: &hosted::Arm,
    ) -> Result<(), WaitError> {
        self.check_registry().map_err(WaitError::Domain)?;
        if self
            .domain
            .pending
            .iter()
            .any(|event| event.source == self.receiver.timeout_source)
        {
            return Err(WaitError::Domain(AsyncError::PendingEvent));
        }
        self.receiver.timer.cancel(arm).map_err(WaitError::Counter)
    }
    pub(in crate::blocks::retirement) fn sample_counter(
        &mut self,
    ) -> Result<hosted::Sample, hosted::Error> {
        self.counter.sample()
    }
    pub(in crate::blocks::retirement) fn requested_sleep(
        &self,
        sample: &hosted::Sample,
    ) -> Result<core::time::Duration, hosted::Error> {
        self.receiver.timer.requested_sleep(sample)
    }
    pub(in crate::blocks::retirement) fn commit_deadline(
        &mut self,
        sample: &hosted::Sample,
    ) -> Result<Option<DeadlineCommit>, WaitError> {
        self.check_registry().map_err(WaitError::Domain)?;
        let Some(expiration) = self
            .receiver
            .timer
            .poll(sample)
            .map_err(WaitError::Counter)?
        else {
            return Ok(None);
        };
        self.receiver
            .timer
            .validate(&expiration)
            .map_err(WaitError::Counter)?;
        let source = self.receiver.timeout_source;
        let (previous, _) = *self
            .domain
            .wait_committed
            .get(&source)
            .ok_or(WaitError::Domain(AsyncError::WrongProducer))?;
        if expiration.generation() <= previous {
            return Err(WaitError::Domain(AsyncError::PendingEvent));
        }
        let sequence = self
            .domain
            .next_event
            .checked_add(1)
            .ok_or(WaitError::Domain(AsyncError::SequenceExhausted))?;
        self.domain
            .pending
            .try_reserve(1)
            .map_err(|_| WaitError::Domain(AsyncError::Capacity))?;
        self.domain.pending.push_back(PendingEvent {
            source,
            kind: PendingKind::WaitDeadline {
                generation: expiration.generation(),
                observed_ticks: expiration.observed_ticks(),
                sequence,
            },
        });
        *self
            .domain
            .wait_committed
            .get_mut(&source)
            .expect("validated timeout registration") = (expiration.generation(), sequence);
        self.domain.next_event = sequence;
        Ok(Some(DeadlineCommit {
            domain: Arc::clone(&self.domain.identity),
            receiver: Arc::clone(&self.receiver.identity),
            source,
            expiration,
        }))
    }
    pub(in crate::blocks::retirement) fn settle_deadline(
        &mut self,
        commit: DeadlineCommit,
    ) -> Result<(), WaitError> {
        self.check_registry().map_err(WaitError::Domain)?;
        if !Arc::ptr_eq(&commit.domain, &self.domain.identity)
            || !Arc::ptr_eq(&commit.receiver, &self.receiver.identity)
            || commit.source != self.receiver.timeout_source
        {
            return Err(WaitError::Domain(AsyncError::SourceChanged));
        }
        self.receiver
            .timer
            .validate(&commit.expiration)
            .map_err(WaitError::Counter)?;
        let position = self.domain.pending.iter().position(|event| event.source == commit.source
            && matches!(event.kind, PendingKind::WaitDeadline { generation, .. } if generation == commit.expiration.generation()))
            .ok_or(WaitError::Domain(AsyncError::SourceChanged))?;
        self.receiver
            .timer
            .consume(commit.expiration)
            .map_err(WaitError::Counter)?;
        self.domain.pending.remove(position);
        Ok(())
    }
}

struct AcceptedInput {
    sampled: u64,
    generation: u64,
    sequence: u64,
    level: bool,
    wake: bool,
}
fn commit_input(
    domain: &mut SoftwareAsyncDomain,
    input: &Input,
    sampled: u64,
) -> Result<Option<AcceptedInput>, AsyncError> {
    let generation = sampled >> GENERATION_SHIFT;
    let (previous, previous_sequence) = *domain
        .wait_committed
        .get(&input.source)
        .ok_or(AsyncError::WrongProducer)?;
    if generation < previous {
        return Err(AsyncError::SourceChanged);
    }
    if generation == 0 {
        return Ok(None);
    }
    let level = sampled & LEVEL != 0;
    let wake = sampled & WAKE != 0;
    let sequence = if generation == previous {
        previous_sequence
    } else {
        let sequence = domain
            .next_event
            .checked_add(1)
            .ok_or(AsyncError::SequenceExhausted)?;
        let position = domain
            .pending
            .iter()
            .position(|event| event.source == input.source);
        let retained_wake = position.is_some_and(|position| {
            matches!(
                domain.pending[position].kind,
                PendingKind::InterruptLevel { wake: true, .. }
            )
        });
        if position.is_none() {
            domain
                .pending
                .try_reserve(1)
                .map_err(|_| AsyncError::Capacity)?;
        }
        let event = PendingEvent {
            source: input.source,
            kind: PendingKind::InterruptLevel {
                level,
                wake: wake || retained_wake,
                generation,
                sequence,
            },
        };
        if let Some(position) = position {
            domain.pending[position] = event;
        } else {
            domain.pending.push_back(event);
        }
        *domain
            .wait_committed
            .get_mut(&input.source)
            .expect("validated registration") = (generation, sequence);
        domain.next_event = sequence;
        sequence
    };
    Ok(Some(AcceptedInput {
        sampled,
        generation,
        sequence,
        level,
        wake,
    }))
}
fn acknowledge_input(input: &Input, accepted: AcceptedInput) -> InputCommit {
    let acknowledgment = if input
        .wire
        .state
        .compare_exchange(
            accepted.sampled,
            accepted.sampled & !WAKE,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
    {
        Acknowledgment::ExactGeneration
    } else {
        Acknowledgment::NewPublication
    };
    InputCommit {
        source: input.source,
        generation: accepted.generation,
        sequence: accepted.sequence,
        level: accepted.level,
        wake: accepted.wake,
        acknowledgment,
    }
}

#[derive(Debug)]
pub(in crate::blocks::retirement) enum WaitError {
    Domain(AsyncError),
    Counter(hosted::Error),
}

#[cfg(test)]
mod tests;

mod platform;
pub(in crate::blocks::retirement) use platform::{
    Completion as HostedWaitCompletion, Error as HostedWaitError, HostedIrqResources,
    HostedWaitPlatform, Poll as WaitPoll, Preparation as WaitPreparation,
};
