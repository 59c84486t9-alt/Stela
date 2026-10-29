//! Retained CPU participants, independent of a board's PMGR record resolver.
//! A caller must supply the positively qualified physical domain and exact PE
//! membership. Neither record names, byte 2 nor MPIDR core-type bits select it.
use alloc::{collections::BTreeMap, vec, vec::Vec};
use stela_contracts::{bus::LifecycleState, processor::ProcessorTarget};

/// Original domain identity and initial state supplied by the board. This API
/// establishes neither the firmware handoff image nor its hardware mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessorBinding {
    pub domain: u64,
    pub target: ProcessorTarget,
    pub initial: LifecycleState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessorChange {
    pub domain: u64,
    pub state: LifecycleState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessorPowerError {
    NoProcessors,
    EmptyTransaction,
    DuplicateDomain(u64),
    UnknownDomain(u64),
    EmptyCluster(u64),
    UnknownPe {
        domain: u64,
        pe: usize,
    },
    DuplicatePe {
        domain: u64,
        pe: usize,
    },
    SupplyLossUnqualified(u64),
    ResetUnqualified(u64),
    RetentionCapabilityChanged(u64),
    StalePlan,
    MembershipChanged,
    RevisionExhausted,
    OwnerCount {
        expected: usize,
        actual: usize,
    },
    MissingLiveOwner(usize),
    UnexpectedLiveOwner(usize),
    NativeStateExhausted(&'static str),
    CanonicalMemory {
        pe: usize,
        status: stela_compiler::context::memory::MemoryStatus,
    },
    Publication(super::publication::PublicationError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Domain {
    target: ProcessorTarget,
    state: LifecycleState,
}

/// Immutable checked transaction. It cannot be constructed or altered by a
/// caller. Settlement rechecks its revision and complete starting membership.
/// A controller must settle it before acknowledging a request to the guest.
#[derive(Debug)]
pub struct PreparedProcessorPower {
    revision: u64,
    processors: usize,
    before: BTreeMap<u64, Domain>,
    after: BTreeMap<u64, Domain>,
    affected: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PauseChange {
    pub pe: usize,
    pub paused: bool,
}

impl PreparedProcessorPower {
    pub(super) fn affected(&self) -> &[usize] {
        &self.affected
    }
}

/// A checked exclusive lease over the actual participant inventory. While
/// native-dispatch preflight runs, no caller can replace its revision or
/// membership. Dropping it without commit has no effect.
pub(super) struct Settlement<'a> {
    processors: &'a mut Processors,
    after: BTreeMap<u64, Domain>,
    paused: Vec<bool>,
    changes: Vec<PauseChange>,
}

impl Settlement<'_> {
    pub(super) fn changes(&self) -> &[PauseChange] {
        &self.changes
    }

    pub(super) fn paused(&self, pe: usize) -> bool {
        self.paused[pe]
    }

    pub(super) fn commit(self) -> Vec<PauseChange> {
        self.processors.domains = self.after;
        self.processors.paused = self.paused;
        self.processors.revision += 1;
        self.changes
    }
}

/// Scheduler-owned participant inventory. No binding means no lifecycle
/// qualification; existing PEs keep their original execution behavior.
#[derive(Debug)]
pub struct Processors {
    count: usize,
    revision: u64,
    domains: BTreeMap<u64, Domain>,
    paused: Vec<bool>,
}

fn retained(domain: u64, state: LifecycleState) -> Result<(), ProcessorPowerError> {
    if !state.powered {
        return Err(ProcessorPowerError::SupplyLossUnqualified(domain));
    }
    if state.reset {
        return Err(ProcessorPowerError::ResetUnqualified(domain));
    }
    Ok(())
}

impl Processors {
    pub fn new(count: usize) -> Result<Self, ProcessorPowerError> {
        if count == 0 {
            return Err(ProcessorPowerError::NoProcessors);
        }
        Ok(Self {
            count,
            revision: 0,
            domains: BTreeMap::new(),
            paused: vec![false; count],
        })
    }

    pub fn count(&self) -> usize {
        self.count
    }

    /// Whether at least one qualified core/cluster clock or quiesce input
    /// inhibits this PE. An IRQ/event cannot bypass that input.
    pub fn paused(&self, pe: usize) -> Option<bool> {
        self.paused.get(pe).copied()
    }

    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Validate every binding before changing any domain or PE. The starting
    /// state is explicit; clock/quiesce retains state even when supply-off
    /// retention capability is false. Supply loss/reset always refuse here.
    pub fn prepare_bindings(
        &self,
        bindings: &[ProcessorBinding],
    ) -> Result<PreparedProcessorPower, ProcessorPowerError> {
        if bindings.is_empty() {
            return Err(ProcessorPowerError::EmptyTransaction);
        }
        let mut after = self.domains.clone();
        for binding in bindings {
            let domain = binding.domain;
            if after.contains_key(&domain) {
                return Err(ProcessorPowerError::DuplicateDomain(domain));
            }
            let members = binding.target.members();
            if members.is_empty() {
                return Err(ProcessorPowerError::EmptyCluster(domain));
            }
            for (index, &pe) in members.iter().enumerate() {
                if pe >= self.count {
                    return Err(ProcessorPowerError::UnknownPe { domain, pe });
                }
                if members[..index].contains(&pe) {
                    return Err(ProcessorPowerError::DuplicatePe { domain, pe });
                }
            }
            retained(domain, binding.initial)?;
            after.insert(
                domain,
                Domain {
                    target: binding.target.clone(),
                    state: binding.initial,
                },
            );
        }
        self.plan(after, bindings.iter().map(|binding| binding.domain))
    }

    pub fn prepare(
        &self,
        changes: &[ProcessorChange],
    ) -> Result<PreparedProcessorPower, ProcessorPowerError> {
        if changes.is_empty() {
            return Err(ProcessorPowerError::EmptyTransaction);
        }
        let mut after = self.domains.clone();
        for (index, change) in changes.iter().enumerate() {
            if changes[..index]
                .iter()
                .any(|old| old.domain == change.domain)
            {
                return Err(ProcessorPowerError::DuplicateDomain(change.domain));
            }
            let domain = after
                .get_mut(&change.domain)
                .ok_or(ProcessorPowerError::UnknownDomain(change.domain))?;
            retained(change.domain, change.state)?;
            if change.state.retention != domain.state.retention {
                return Err(ProcessorPowerError::RetentionCapabilityChanged(
                    change.domain,
                ));
            }
            domain.state = change.state;
        }
        self.plan(after, changes.iter().map(|change| change.domain))
    }

    fn plan(
        &self,
        after: BTreeMap<u64, Domain>,
        requested: impl Iterator<Item = u64>,
    ) -> Result<PreparedProcessorPower, ProcessorPowerError> {
        self.revision
            .checked_add(1)
            .ok_or(ProcessorPowerError::RevisionExhausted)?;
        // Preserve complete requested membership, even when its effective
        // pause state does not change because another domain still gates it.
        let mut affected = Vec::new();
        for domain in requested {
            affected.extend_from_slice(after[&domain].target.members());
        }
        affected.sort_unstable();
        affected.dedup();
        Ok(PreparedProcessorPower {
            revision: self.revision,
            processors: self.count,
            before: self.domains.clone(),
            after,
            affected,
        })
    }

    /// Check without mutation. In particular a plan cannot silently replace
    /// another participant's membership even at the same transaction revision.
    pub fn check(&self, plan: &PreparedProcessorPower) -> Result<(), ProcessorPowerError> {
        if plan.revision != self.revision {
            return Err(ProcessorPowerError::StalePlan);
        }
        if plan.processors != self.count || plan.before != self.domains {
            return Err(ProcessorPowerError::MembershipChanged);
        }
        Ok(())
    }

    pub(super) fn settlement(
        &mut self,
        plan: PreparedProcessorPower,
    ) -> Result<Settlement<'_>, ProcessorPowerError> {
        self.check(&plan)?;
        let mut paused = vec![false; self.count];
        for domain in plan.after.values() {
            if !domain.state.clocked || domain.state.quiesced {
                for &pe in domain.target.members() {
                    paused[pe] = true;
                }
            }
        }
        let changes = paused
            .iter()
            .enumerate()
            .filter(|&(pe, paused)| self.paused[pe] != *paused)
            .map(|(pe, &paused)| PauseChange { pe, paused })
            .collect();
        Ok(Settlement {
            processors: self,
            after: plan.after,
            paused,
            changes,
        })
    }

    #[cfg(test)]
    fn settle(
        &mut self,
        plan: PreparedProcessorPower,
    ) -> Result<Vec<PauseChange>, ProcessorPowerError> {
        Ok(self.settlement(plan)?.commit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTIVE: LifecycleState = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: false,
    };
    const GATED: LifecycleState = LifecycleState {
        clocked: false,
        ..ACTIVE
    };
    fn core(domain: u64, pe: usize) -> ProcessorBinding {
        ProcessorBinding {
            domain,
            target: ProcessorTarget::Core { pe },
            initial: ACTIVE,
        }
    }

    #[test]
    fn an_empty_inventory_or_transaction_never_establishes_coverage() {
        assert!(matches!(
            Processors::new(0),
            Err(ProcessorPowerError::NoProcessors)
        ));
        let processors = Processors::new(1).unwrap();
        assert!(matches!(
            processors.prepare_bindings(&[]),
            Err(ProcessorPowerError::EmptyTransaction)
        ));
        assert!(matches!(
            processors.prepare(&[]),
            Err(ProcessorPowerError::EmptyTransaction)
        ));
        assert_eq!(processors.domain_count(), 0);
        assert_eq!(processors.paused(1), None);
    }

    #[test]
    fn abandoning_the_checked_lease_keeps_the_revision_and_inventory_unchanged() {
        let mut processors = Processors::new(2).unwrap();
        let bind = processors
            .prepare_bindings(&[core(1, 0), core(2, 1)])
            .unwrap();
        processors.settle(bind).unwrap();
        let changes = [ProcessorChange {
            domain: 1,
            state: GATED,
        }];
        let abandoned = processors.prepare(&changes).unwrap();
        let still_valid = processors.prepare(&changes).unwrap();
        let lease = processors.settlement(abandoned).unwrap();
        assert_eq!(
            lease.changes(),
            [PauseChange {
                pe: 0,
                paused: true
            }]
        );
        drop(lease);
        assert_eq!(processors.paused(0), Some(false));
        processors.settle(still_valid).unwrap();
        assert_eq!(processors.paused(0), Some(true));
        assert_eq!(processors.paused(1), Some(false));
    }

    #[test]
    fn all_bindings_are_checked_before_any_inventory_change() {
        let mut processors = Processors::new(8).unwrap();
        for invalid in [
            core(2, 8),
            ProcessorBinding {
                target: ProcessorTarget::Cluster { members: vec![] },
                ..core(2, 0)
            },
            ProcessorBinding {
                target: ProcessorTarget::Cluster {
                    members: vec![2, 2],
                },
                ..core(2, 0)
            },
            ProcessorBinding {
                initial: LifecycleState {
                    reset: true,
                    ..ACTIVE
                },
                ..core(2, 0)
            },
            ProcessorBinding {
                initial: LifecycleState {
                    powered: false,
                    retention: true,
                    ..ACTIVE
                },
                ..core(2, 0)
            },
            core(1, 1),
        ] {
            assert!(processors.prepare_bindings(&[core(1, 0), invalid]).is_err());
            assert_eq!(processors.domain_count(), 0);
            assert!((0..8).all(|pe| processors.paused(pe) == Some(false)));
        }
        let plan = processors.prepare_bindings(&[core(1, 0)]).unwrap();
        processors.settle(plan).unwrap();
        assert_eq!(processors.domain_count(), 1);
        assert!(processors.prepare_bindings(&[core(1, 0)]).is_err());
    }

    #[test]
    fn overlapping_core_cluster_inputs_require_every_blocker_to_release() {
        let mut processors = Processors::new(8).unwrap();
        let cluster = ProcessorBinding {
            domain: 9,
            target: ProcessorTarget::Cluster {
                members: vec![0, 1, 2, 3],
            },
            initial: ACTIVE,
        };
        let plan = processors.prepare_bindings(&[core(1, 0), cluster]).unwrap();
        processors.settle(plan).unwrap();
        let plan = processors
            .prepare(&[
                ProcessorChange {
                    domain: 1,
                    state: GATED,
                },
                ProcessorChange {
                    domain: 9,
                    state: LifecycleState {
                        quiesced: true,
                        ..ACTIVE
                    },
                },
            ])
            .unwrap();
        assert!(
            (0..8).all(|pe| processors.paused(pe) == Some(false)),
            "preflight is immutable"
        );
        let changes = processors.settle(plan).unwrap();
        assert_eq!(changes.len(), 4);
        let plan = processors
            .prepare(&[ProcessorChange {
                domain: 9,
                state: ACTIVE,
            }])
            .unwrap();
        processors.settle(plan).unwrap();
        assert_eq!(processors.paused(0), Some(true));
        assert_eq!(processors.paused(1), Some(false));
        let plan = processors
            .prepare(&[ProcessorChange {
                domain: 1,
                state: ACTIVE,
            }])
            .unwrap();
        assert_eq!(
            processors.settle(plan).unwrap(),
            [PauseChange {
                pe: 0,
                paused: false
            }]
        );
    }

    #[test]
    fn complete_transactions_refuse_unknown_destructive_and_duplicate_inputs() {
        let mut processors = Processors::new(2).unwrap();
        let plan = processors
            .prepare_bindings(&[core(1, 0), core(2, 1)])
            .unwrap();
        processors.settle(plan).unwrap();
        for invalid in [
            ProcessorChange {
                domain: 3,
                state: ACTIVE,
            },
            ProcessorChange {
                domain: 2,
                state: LifecycleState {
                    powered: false,
                    ..ACTIVE
                },
            },
            ProcessorChange {
                domain: 2,
                state: LifecycleState {
                    reset: true,
                    ..ACTIVE
                },
            },
            ProcessorChange {
                domain: 2,
                state: LifecycleState {
                    retention: true,
                    ..ACTIVE
                },
            },
            ProcessorChange {
                domain: 1,
                state: GATED,
            },
        ] {
            assert!(
                processors
                    .prepare(&[
                        ProcessorChange {
                            domain: 1,
                            state: GATED
                        },
                        invalid
                    ])
                    .is_err()
            );
            assert_eq!(processors.paused(0), Some(false));
        }
    }

    #[test]
    fn stale_or_different_membership_plans_never_partially_commit() {
        let mut first = Processors::new(2).unwrap();
        let mut second = Processors::new(2).unwrap();
        let plan = first.prepare_bindings(&[core(1, 0)]).unwrap();
        first.settle(plan).unwrap();
        let plan = second.prepare_bindings(&[core(1, 1)]).unwrap();
        second.settle(plan).unwrap();
        let wrong = first
            .prepare(&[ProcessorChange {
                domain: 1,
                state: GATED,
            }])
            .unwrap();
        assert_eq!(
            second.settle(wrong),
            Err(ProcessorPowerError::MembershipChanged)
        );
        assert_eq!(second.paused(1), Some(false));
        let stale = first
            .prepare(&[ProcessorChange {
                domain: 1,
                state: GATED,
            }])
            .unwrap();
        let next = first
            .prepare(&[ProcessorChange {
                domain: 1,
                state: ACTIVE,
            }])
            .unwrap();
        first.settle(next).unwrap();
        assert_eq!(first.settle(stale), Err(ProcessorPowerError::StalePlan));
        assert_eq!(first.paused(0), Some(false));
    }
}
