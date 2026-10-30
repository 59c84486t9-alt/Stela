//! Complete-consumer accounting before enabling a PMGR lifecycle control.
//!
//! Callers supply the original firmware's full domain graph and every original
//! resource's separate clock/power requirements, including inherited controller,
//! nub, mapper and firmware-endpoint dependencies. The caller also accounts for
//! implicit consumers: this module cannot infer them from absent metadata.
//! Generation-specific ID/die encodings and ADT records are decoded by the board
//! reader before this boundary. No application identity participates.
//!
//! A result is a binding candidate only when every required consumer has
//! clock, power, quiesce and reset sinks. Positive unavailable admission evidence
//! checks controller state alone, without claiming functional support or
//! removing those consumers from the inventory. This module never enables controls or
//! delivers lifecycle events. A DART-only consumer list is not a full inventory.
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

/// A normalized firmware device ID, with its physical die kept explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomainId {
    pub die: u8,
    pub device: u16,
}

/// An original PMGR device record. Virtual domains have no register;
/// all parents remain dependencies even when this domain is physical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    /// Original firmware identity; aliases keep their separate names.
    pub name: String,
    pub id: DomainId,
    pub address: Option<u64>,
    pub parents: [Option<DomainId>; 4],
}

/// Handlers registered by the machine for one resource. These are
/// obligations for the whole physical domain, irrespective of whether its
/// original property was called clock-gates or power-gates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LifecycleSinks {
    pub clock: bool,
    pub power: bool,
    pub quiesce: bool,
    pub reset: bool,
}

impl LifecycleSinks {
    pub fn complete(self) -> bool {
        self.clock && self.power && self.quiesce && self.reset
    }
}

/// Functional-device admission is independent of the PMGR controller. Only
/// positive preparation evidence can declare a resource unavailable; missing
/// compatible/owner metadata alone leaves its lifecycle obligations required.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Admission {
    #[default]
    Required,
    Unavailable,
}

/// One original resource. Distinct inherited views and protocol endpoints keep
/// their names; proven views of one owner may share its sink.
#[derive(Debug, Clone, Copy)]
pub struct Consumer<'a> {
    /// Stable identity within this complete inventory. ADT sibling names
    /// need not be unique and cannot identify physical resource views.
    pub id: usize,
    pub name: &'a str,
    pub clocks: &'a [DomainId],
    pub power: &'a [DomainId],
    pub sinks: LifecycleSinks,
    pub admission: Admission,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerCoverage {
    pub id: usize,
    pub name: String,
    pub clock: bool,
    pub power: bool,
    pub sinks: LifecycleSinks,
    pub admission: Admission,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainCoverage {
    pub address: u64,
    pub consumers: Vec<ConsumerCoverage>,
}

impl DomainCoverage {
    /// True when no inventoried resource names this register or any domain
    /// beneath it: the machine places no model behind it, so its controller
    /// state completes with no client to deliver lifecycle edges to. Every
    /// placed model's resource is inventoried, so hardware behind such a
    /// domain is unmodeled and its own accesses refuse.
    pub fn controller_only(&self) -> bool {
        self.consumers.is_empty()
    }

    /// True for a nonempty set with every required consumer connected. The
    /// caller must establish inventory completeness and positive unavailable
    /// admission evidence; this never grants functional-device support.
    pub fn bindable(&self) -> bool {
        !self.consumers.is_empty()
            && self
                .consumers
                .iter()
                .all(|c| c.admission == Admission::Unavailable || c.sinks.complete())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageError {
    DuplicateDomain(DomainId),
    Misaligned(u64),
    MissingParent { domain: DomainId, parent: DomainId },
    ParentCycle(DomainId),
    AliasCycle(u64),
    EmptyConsumer,
    DuplicateConsumer(usize),
    UnknownRequirement { consumer: String, domain: DomainId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Physical(u64),
    Virtual(DomainId),
}

impl Domain {
    fn key(&self) -> Key {
        self.address.map_or(Key::Virtual(self.id), Key::Physical)
    }
}

/// Return one sorted entry per physical register, including registers with
/// no consumers (never [`DomainCoverage::bindable`], but
/// [`DomainCoverage::controller_only`]). Aliases share an entry and the
/// union of their parent requirements, so a consumer through one alias also
/// prevents an unsafe binding of another alias's parent.
pub fn analyze(
    domains: &[Domain],
    consumers: &[Consumer<'_>],
) -> Result<Vec<DomainCoverage>, CoverageError> {
    let mut ids = BTreeMap::new();
    for domain in domains {
        if let Some(address) = domain.address
            && !address.is_multiple_of(4)
        {
            return Err(CoverageError::Misaligned(address));
        }
        if ids.insert(domain.id, domain).is_some() {
            return Err(CoverageError::DuplicateDomain(domain.id));
        }
    }
    let mut raw = BTreeMap::new();
    for domain in domains {
        let mut parents = BTreeSet::new();
        for parent in domain.parents.into_iter().flatten() {
            if !ids.contains_key(&parent) {
                return Err(CoverageError::MissingParent {
                    domain: domain.id,
                    parent,
                });
            }
            parents.insert(parent);
        }
        raw.insert(domain.id, parents);
    }
    check_cycles(&raw).map_err(CoverageError::ParentCycle)?;

    // Normalize physical aliases before computing any reverse closure.
    let mut graph: BTreeMap<Key, BTreeSet<Key>> = BTreeMap::new();
    let mut coverage: BTreeMap<u64, BTreeMap<usize, ConsumerCoverage>> = BTreeMap::new();
    for domain in domains {
        let key = domain.key();
        let parents = graph.entry(key).or_default();
        for parent in domain.parents.into_iter().flatten() {
            let parent = ids[&parent].key();
            if parent != key {
                parents.insert(parent);
            }
        }
        if let Some(address) = domain.address {
            coverage.entry(address).or_default();
        }
    }
    check_cycles(&graph).map_err(|key| match key {
        Key::Physical(address) => CoverageError::AliasCycle(address),
        Key::Virtual(id) => CoverageError::ParentCycle(id),
    })?;

    let mut consumers_seen = BTreeSet::new();
    for consumer in consumers {
        if consumer.name.is_empty() {
            return Err(CoverageError::EmptyConsumer);
        }
        if !consumers_seen.insert(consumer.id) {
            return Err(CoverageError::DuplicateConsumer(consumer.id));
        }
        for (clock, requirements) in [(true, consumer.clocks), (false, consumer.power)] {
            let mut closure = BTreeSet::new();
            for id in requirements {
                let domain = ids
                    .get(id)
                    .ok_or_else(|| CoverageError::UnknownRequirement {
                        consumer: consumer.name.into(),
                        domain: *id,
                    })?;
                reachable(domain.key(), &graph, &mut closure);
            }
            for key in closure {
                if let Key::Physical(address) = key {
                    let record = coverage
                        .get_mut(&address)
                        .expect("physical graph node")
                        .entry(consumer.id)
                        .or_insert_with(|| ConsumerCoverage {
                            id: consumer.id,
                            name: consumer.name.into(),
                            clock: false,
                            power: false,
                            sinks: consumer.sinks,
                            admission: consumer.admission,
                        });
                    if clock {
                        record.clock = true;
                    } else {
                        record.power = true;
                    }
                }
            }
        }
    }
    Ok(coverage
        .into_iter()
        .map(|(address, consumers)| DomainCoverage {
            address,
            consumers: consumers.into_values().collect(),
        })
        .collect())
}

fn reachable<K: Copy + Ord>(key: K, graph: &BTreeMap<K, BTreeSet<K>>, seen: &mut BTreeSet<K>) {
    let mut pending = alloc::vec![key];
    while let Some(key) = pending.pop() {
        if seen.insert(key) {
            pending.extend(graph[&key].iter().copied());
        }
    }
}

fn check_cycles<K: Copy + Ord>(graph: &BTreeMap<K, BTreeSet<K>>) -> Result<(), K> {
    let mut active = BTreeSet::new();
    let mut finished = BTreeSet::new();
    for &root in graph.keys() {
        if finished.contains(&root) {
            continue;
        }
        let mut pending = alloc::vec![(root, false)];
        while let Some((key, leaving)) = pending.pop() {
            if leaving {
                active.remove(&key);
                finished.insert(key);
            } else if !finished.contains(&key) {
                if !active.insert(key) {
                    return Err(key);
                }
                pending.push((key, true));
                pending.extend(graph[&key].iter().rev().map(|&parent| (parent, false)));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
