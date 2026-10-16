//! Actual declared-software debug/CTI producers in the existing PE domain.
//! No second registry, callback, copied pending bank, or external-hardware claim.
use super::*;
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// Original sticky registration key. It contains no domain writer; every
/// injector still requires the same actual domain's exclusive mutable borrow.
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

/// Unapplied, non-Clone recipe; it owns no authority. Commit requires the same
/// actual exclusive domain lease and rechecks identity/registration/sequence.
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

/// Actual queued external instruction, not a fetched guest-PC/source identity.
/// The canonical consumer retains the original domain loan and must settle the
/// exact raw EDITR decision before interpreting this as an executed instruction.
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
    /// Serialized retained software-debug input. The route names one original
    /// key borrowed by this actual complete-domain lease; no integer grants a
    /// foreign producer/domain association and no writer bypasses this borrow.
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
        // The actual typed CTI output is committed before its configured target
        // inputs. It remains in the domain's ledger even when unconnected.
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
    /// Consume only after the canonical consumer has qualified the exact raw
    /// request and actual Ignore/Overrun/Execute disposition. This grants no PE
    /// execution/PC/ITR authority and never discards a CrossHalt input event.
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
mod tests {
    use super::*;
    fn fresh() -> SoftwareAsyncDomain {
        unsafe { SoftwareAsyncDomain::fresh_software_pe() }
    }
    #[test]
    fn unconnected_output_remains_real_registered_effect() {
        let mut domain = fresh();
        let source = domain.register_debug().unwrap();
        assert!(matches!(
            domain.lease_no_sources(),
            Err(AsyncError::RegisteredProducer)
        ));
        {
            let keys = [source];
            let mut lease = domain.lease_debug_sources(&keys).unwrap();
            let route = CtiRoute {
                output_slot: 0,
                target_slots: vec![],
            };
            let plan = lease.prepare_cross_halt(&route).unwrap();
            let receipt = lease.publish_cross_halt(plan).unwrap();
            assert_eq!(receipt.sequence, 1);
            assert_eq!(receipt.delivered_targets, 0);
            assert_eq!(lease.domain.cross_halt_outputs.len(), 1);
            assert_eq!(
                lease.domain.cross_halt_outputs[0].source,
                lease.keys[0].0.id
            );
            assert!(lease.domain.pending.is_empty());
        }
        assert!(matches!(
            domain.lease_no_sources(),
            Err(AsyncError::RegisteredProducer)
        ));
    }
    #[test]
    fn configured_target_input_is_retained_and_not_discarded_as_editr() {
        let mut domain = fresh();
        let output = domain.register_debug().unwrap();
        let target = domain.register_debug().unwrap();
        let keys = [output, target];
        let mut lease = domain.lease_debug_sources(&keys).unwrap();
        let plan = lease
            .prepare_cross_halt(&CtiRoute {
                output_slot: 0,
                target_slots: vec![1],
            })
            .unwrap();
        lease.publish_cross_halt(plan).unwrap();
        assert_eq!(
            lease.domain.pending.front().unwrap().source,
            lease.keys[1].0.id
        );
        assert!(matches!(
            lease.next_editr(),
            Err(AsyncError::UnsupportedPending)
        ));
        assert_eq!(lease.domain.pending.len(), 1);
        assert_eq!(
            lease.qualify_normal_boundary(),
            Err(AsyncError::PendingEvent)
        );
    }
    #[test]
    fn all_registered_producers_and_exact_input_source_remain_bound() {
        let mut domain = fresh();
        let source = domain.register_debug().unwrap();
        domain.enqueue_editr(&source, 0xd6bf03e0).unwrap();
        let keys = [source];
        {
            let mut lease = domain.lease_debug_sources(&keys).unwrap();
            let event = lease.next_editr().unwrap().unwrap();
            assert_eq!(event.word(), 0xd6bf03e0);
            assert_eq!(event.sequence(), 1);
            lease.consume_editr(&event).unwrap();
            assert_eq!(lease.consume_editr(&event), Err(AsyncError::SourceChanged));
            assert!(lease.domain.pending.is_empty());
        }
        let hidden = domain.register(SourceClass::Irq).unwrap();
        drop(hidden);
        assert!(matches!(
            domain.lease_debug_sources(&[]),
            Err(AsyncError::RegisteredProducer)
        ));
    }
}

#[cfg(test)]
mod domain_identity_tests {
    use super::*;
    #[test]
    fn colliding_numeric_source_sequence_word_never_cross_domains() {
        let mut a = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
        let mut b = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
        let ak = [a.register_debug().unwrap()];
        let bk = [b.register_debug().unwrap()];
        a.enqueue_editr(&ak[0], 0xd6bf03e0).unwrap();
        b.enqueue_editr(&bk[0], 0xd6bf03e0).unwrap();
        let event = a
            .lease_debug_sources(&ak)
            .unwrap()
            .next_editr()
            .unwrap()
            .unwrap();
        {
            let mut lease = b.lease_debug_sources(&bk).unwrap();
            assert_eq!(lease.consume_editr(&event), Err(AsyncError::WrongProducer));
            assert!(lease.next_editr().unwrap().is_some());
        }
        // The original keys survive lease release and certify later injections.
        b.enqueue_editr(&bk[0], 0xd6bf03e0).unwrap();
        assert!(b.lease_debug_sources(&bk).is_ok());
    }
}

impl SoftwareAsyncDomain {
    /// Descriptive original pending/output ledger after the executable scope.
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
