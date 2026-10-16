//! Debug and CTI event sources of a software PE.
use super::*;
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// A permanent registration key. Injecting still requires the domain's
/// exclusive borrow.
pub(in crate::blocks::retirement) struct DebugSourceKey(SourceKey);

/// Explicit software routing by retained registrations. Empty targets means an
/// unconnected CTI output, not absence of the registered producer or event.
/// Other-PE/domain targets are not accepted by this serialized first route.
pub(in crate::blocks::retirement) struct CtiRoute {
    pub output_slot: usize,
    pub target_slots: Vec<usize>,
}

pub(in crate::blocks::retirement) struct DebugSources<'pe> {
    domain: &'pe mut SoftwareAsyncDomain,
    keys: &'pe [DebugSourceKey],
}

/// An unapplied cross-halt. Committing it re-checks the identity, registration
/// and sequence under the domain's exclusive borrow.
pub(in crate::blocks::retirement) struct PreparedCrossHalt {
    identity: Arc<()>,
    source: u64,
    sequence: u64,
    targets: Vec<u64>,
}
#[derive(Debug)]
pub(in crate::blocks::retirement) struct CrossHaltReceipt {
    pub sequence: u64,
    pub delivered_targets: usize,
}

/// A queued external instruction (not fetched from a guest PC). The consumer
/// settles the raw EDITR decision before treating it as executed.
#[derive(Debug)]
pub(in crate::blocks::retirement) struct EditrSource {
    identity: Arc<()>,
    source: u64,
    sequence: u64,
    word: u32,
}
impl EditrSource {
    pub(in crate::blocks::retirement) fn word(&self) -> u32 {
        self.word
    }
    pub(in crate::blocks::retirement) fn source(&self) -> u64 {
        self.source
    }
    pub(in crate::blocks::retirement) fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl SoftwareAsyncDomain {
    pub(in crate::blocks::retirement) fn register_debug(
        &mut self,
    ) -> Result<DebugSourceKey, AsyncError> {
        Ok(DebugSourceKey(self.register(SourceClass::Debug)?))
    }
    pub(in crate::blocks::retirement) fn enqueue_editr(
        &mut self,
        key: &DebugSourceKey,
        word: u32,
    ) -> Result<(), AsyncError> {
        if !Arc::ptr_eq(&self.identity, &key.0.domain)
            || self.registered.get(&key.0.id) != Some(&SourceClass::Debug)
        {
            return Err(AsyncError::WrongProducer);
        }
        let sequence = self
            .next_event
            .checked_add(1)
            .ok_or(AsyncError::SequenceExhausted)?;
        self.pending
            .try_reserve(1)
            .map_err(|_| AsyncError::Capacity)?;
        self.next_event = sequence;
        self.pending.push_back(PendingEvent {
            source: key.0.id,
            kind: PendingKind::Editr { word, sequence },
        });
        Ok(())
    }
    pub(in crate::blocks::retirement) fn lease_debug_sources<'pe>(
        &'pe mut self,
        keys: &'pe [DebugSourceKey],
    ) -> Result<DebugSources<'pe>, AsyncError> {
        let lease = DebugSources { domain: self, keys };
        lease.check_registry()?;
        Ok(lease)
    }
}

impl DebugSources<'_> {
    /// Queue software-debug input on the route of a key borrowed from this
    /// domain.
    pub(in crate::blocks::retirement) fn enqueue_editr_slot(
        &mut self,
        slot: usize,
        word: u32,
    ) -> Result<(), AsyncError> {
        self.check_registry()?;
        let key = self.keys.get(slot).ok_or(AsyncError::WrongProducer)?;
        self.domain.enqueue_editr(key, word)
    }

    pub(in crate::blocks::retirement) fn check_registry(&self) -> Result<(), AsyncError> {
        for (index, key) in self.keys.iter().enumerate() {
            if !Arc::ptr_eq(&self.domain.identity, &key.0.domain)
                || self.domain.registered.get(&key.0.id) != Some(&SourceClass::Debug)
                || self.keys[..index]
                    .iter()
                    .any(|other| other.0.id == key.0.id)
            {
                return Err(AsyncError::WrongProducer);
            }
        }
        // Allocation-free under an active instruction; no producer can vanish
        // from the universe because its queue is empty or its handle was dropped.
        if self.keys.len() != self.domain.registered.len()
            || self
                .domain
                .registered
                .values()
                .any(|class| *class != SourceClass::Debug)
        {
            return Err(AsyncError::RegisteredProducer);
        }
        if self
            .domain
            .pending
            .iter()
            .any(|event| !self.keys.iter().any(|key| key.0.id == event.source))
        {
            return Err(AsyncError::WrongProducer);
        }
        Ok(())
    }
    pub(in crate::blocks::retirement) fn qualify_normal_boundary(&self) -> Result<(), AsyncError> {
        self.check_registry()?;
        if !self.domain.pending.is_empty() {
            return Err(AsyncError::PendingEvent);
        }
        Ok(())
    }
    pub(in crate::blocks::retirement) fn prepare_cross_halt(
        &mut self,
        route: &CtiRoute,
    ) -> Result<PreparedCrossHalt, AsyncError> {
        self.check_registry()?;
        let source = self
            .keys
            .get(route.output_slot)
            .ok_or(AsyncError::WrongProducer)?
            .0
            .id;
        let mut targets = Vec::new();
        targets
            .try_reserve(route.target_slots.len())
            .map_err(|_| AsyncError::Capacity)?;
        for slot in &route.target_slots {
            let target = self.keys.get(*slot).ok_or(AsyncError::WrongProducer)?.0.id;
            if targets.contains(&target) {
                return Err(AsyncError::WrongProducer);
            }
            targets.push(target);
        }
        let sequence = self
            .domain
            .cross_halt_sequence
            .checked_add(1)
            .ok_or(AsyncError::SequenceExhausted)?;
        // All allocations and target qualification precede the first published
        // output. The same-domain commit then has no fallible delivery step.
        self.domain
            .cross_halt_outputs
            .try_reserve(1)
            .map_err(|_| AsyncError::Capacity)?;
        self.domain
            .pending
            .try_reserve(targets.len())
            .map_err(|_| AsyncError::Capacity)?;
        Ok(PreparedCrossHalt {
            identity: Arc::clone(&self.domain.identity),
            source,
            sequence,
            targets,
        })
    }
    pub(in crate::blocks::retirement) fn publish_cross_halt(
        &mut self,
        plan: PreparedCrossHalt,
    ) -> Result<CrossHaltReceipt, AsyncError> {
        self.check_registry()?;
        if !Arc::ptr_eq(&self.domain.identity, &plan.identity)
            || self.domain.cross_halt_sequence.checked_add(1) != Some(plan.sequence)
            || self.domain.registered.get(&plan.source) != Some(&SourceClass::Debug)
            || plan
                .targets
                .iter()
                .any(|id| self.domain.registered.get(id) != Some(&SourceClass::Debug))
        {
            return Err(AsyncError::SourceChanged);
        }
        // A prepared recipe may survive release/reacquisition of the lease.
        // Refuse before the first output if intervening injection consumed the
        // reserved space; no allocation is allowed after output publication.
        if self.domain.cross_halt_outputs.capacity() - self.domain.cross_halt_outputs.len() < 1
            || self.domain.pending.capacity() - self.domain.pending.len() < plan.targets.len()
        {
            return Err(AsyncError::Capacity);
        }
        // The CTI output is committed before its configured target inputs and
        // stays in the ledger even when unconnected.
        let delivered_targets = plan.targets.len();
        self.domain.cross_halt_sequence = plan.sequence;
        self.domain.cross_halt_outputs.push(CrossHaltOutput {
            source: plan.source,
            sequence: plan.sequence,
            targets: plan.targets,
        });
        let output = self
            .domain
            .cross_halt_outputs
            .last()
            .expect("just appended CTI output");
        for target in &output.targets {
            self.domain.pending.push_back(PendingEvent {
                source: *target,
                kind: PendingKind::CrossHalt {
                    sequence: output.sequence,
                },
            });
        }
        Ok(CrossHaltReceipt {
            sequence: output.sequence,
            delivered_targets,
        })
    }
    /// Observation does not dequeue a pending instruction or halting event.
    pub(in crate::blocks::retirement) fn next_editr(
        &self,
    ) -> Result<Option<EditrSource>, AsyncError> {
        self.check_registry()?;
        match self.domain.pending.front() {
            None => Ok(None),
            Some(PendingEvent {
                source,
                kind: PendingKind::Editr { word, sequence },
            }) => Ok(Some(EditrSource {
                identity: Arc::clone(&self.domain.identity),
                source: *source,
                word: *word,
                sequence: *sequence,
            })),
            Some(_) => Err(AsyncError::UnsupportedPending),
        }
    }
    /// Consume once the consumer has validated the request and its Ignore,
    /// Overrun or Execute disposition. Cross-halt inputs are never discarded.
    pub(in crate::blocks::retirement) fn consume_editr(
        &mut self,
        source: &EditrSource,
    ) -> Result<(), AsyncError> {
        self.check_registry()?;
        if !Arc::ptr_eq(&self.domain.identity, &source.identity) {
            return Err(AsyncError::WrongProducer);
        }
        match self.domain.pending.front() {
            Some(PendingEvent {
                source: id,
                kind: PendingKind::Editr { word, sequence },
            }) if *id == source.source && *word == source.word && *sequence == source.sequence => {
                self.domain.pending.pop_front();
                Ok(())
            }
            _ => Err(AsyncError::SourceChanged),
        }
    }
}

#[cfg(test)]
mod tests;

impl SoftwareAsyncDomain {
    /// The pending and output ledger after execution, for reporting.
    pub(in crate::blocks::retirement) fn debug_observation(&self) -> String {
        format!(
            "registered={:?};pending={:?};cross_halt_outputs={:?}",
            self.registered,
            self.pending
                .iter()
                .map(|event| (event.source, event.kind))
                .collect::<Vec<_>>(),
            self.cross_halt_outputs
                .iter()
                .map(|output| (output.source, output.sequence, &output.targets))
                .collect::<Vec<_>>()
        )
    }
}
