//! Complete-consumer accounting before enabling a PMGR lifecycle control.
//!
//! Callers supply the original firmware's full domain graph and every original
//! resource's separate clock/power requirements, including inherited controller,
//! nub, mapper and firmware-endpoint dependencies. The caller also accounts for
//! implicit consumers: this module cannot infer them from absent metadata.
//! Generation-specific ID/die encodings and ADT records are decoded by the board
//! reader before this boundary. No application identity participates.
//!
//! A result is a binding candidate only when every required consumer has actual
//! clock, power, quiesce and reset sinks. Positive unavailable admission evidence
//! qualifies controller state alone, without claiming functional support or
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
/// both parents remain dependencies even when this domain is physical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    /// Original firmware identity; aliases retain their separate names.
    pub name: String,
    pub id: DomainId,
    pub address: Option<u64>,
    pub parents: [Option<DomainId>; 2],
}

/// Actual handlers registered by the machine for one resource. These are
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
/// their names; proven views of one owner may share its actual sink.
#[derive(Debug, Clone, Copy)]
pub struct Consumer<'a> {
    pub name: &'a str,
    pub clocks: &'a [DomainId],
    pub power: &'a [DomainId],
    pub sinks: LifecycleSinks,
    pub admission: Admission,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerCoverage {
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
    DuplicateConsumer(String),
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
/// no consumers (which are never bindable). Aliases share an entry and the
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
    let mut coverage: BTreeMap<u64, BTreeMap<String, ConsumerCoverage>> = BTreeMap::new();
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

    let mut names = BTreeSet::new();
    for consumer in consumers {
        if consumer.name.is_empty() {
            return Err(CoverageError::EmptyConsumer);
        }
        if !names.insert(consumer.name) {
            return Err(CoverageError::DuplicateConsumer(consumer.name.into()));
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
                        .entry(consumer.name.into())
                        .or_insert_with(|| ConsumerCoverage {
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
mod tests {
    use super::*;
    const COMPLETE: LifecycleSinks = LifecycleSinks {
        clock: true,
        power: true,
        quiesce: true,
        reset: true,
    };
    const NONE: LifecycleSinks = LifecycleSinks {
        clock: false,
        power: false,
        quiesce: false,
        reset: false,
    };
    fn id(device: u16) -> DomainId {
        DomainId { die: 0, device }
    }
    fn domain(device: u16, address: Option<u64>, parents: &[u16]) -> Domain {
        let mut result = Domain {
            name: String::new(),
            id: id(device),
            address,
            parents: [None; 2],
        };
        for (slot, &parent) in result.parents.iter_mut().zip(parents) {
            *slot = Some(id(parent));
        }
        result
    }
    fn consumer<'a>(
        name: &'a str,
        clocks: &'a [DomainId],
        power: &'a [DomainId],
        sinks: LifecycleSinks,
    ) -> Consumer<'a> {
        Consumer {
            name,
            clocks,
            power,
            sinks,
            admission: Admission::Required,
        }
    }
    #[test]
    fn unavailable_resources_preserve_requirements_without_claiming_sinks_or_waiving_admitted_clients()
     {
        let domains = [
            domain(1, Some(0x100), &[]),
            domain(2, Some(0x200), &[1]),
            domain(3, Some(0x300), &[]),
        ];
        let requirements = [id(2)];
        let mut absent = consumer("unavailable", &requirements, &[], NONE);
        absent.admission = Admission::Unavailable;
        let native = consumer("native", &requirements, &[], COMPLETE);
        let parent = [id(1)];
        let unknown = consumer("required", &[], &parent, NONE);
        let coverage = analyze(&domains, &[absent, native]).unwrap();
        assert!(coverage[..2].iter().all(DomainCoverage::bindable));
        assert!(!coverage[2].bindable()); // No positive admission evidence.
        assert!(
            coverage[0]
                .consumers
                .iter()
                .any(|c| c.name == "unavailable" && !c.sinks.complete() && c.clock)
        );
        let coverage = analyze(&domains, &[absent, native, unknown]).unwrap();
        assert!(!coverage[0].bindable());
        assert!(coverage[1].bindable());
        let coverage = analyze(&domains, &[absent]).unwrap();
        assert!(coverage[..2].iter().all(DomainCoverage::bindable));
        assert!(!coverage[0].consumers[0].sinks.complete());
    }

    #[test]
    fn physical_and_virtual_parents_include_all_consumers_and_separate_gate_kinds() {
        let domains = [
            domain(1, Some(0x100), &[]),
            domain(2, Some(0x200), &[1]),
            domain(3, None, &[2, 1]),
            domain(4, Some(0x300), &[3]),
            domain(5, Some(0x400), &[]),
        ];
        let clocks = [id(4)];
        let power = [id(2)];
        let consumers = [
            consumer("dart", &clocks, &[], COMPLETE),
            consumer("usb", &[], &power, NONE),
        ];
        let result = analyze(&domains, &consumers).unwrap();
        assert_eq!(
            result.iter().map(|r| r.address).collect::<Vec<_>>(),
            [0x100, 0x200, 0x300, 0x400]
        );
        for shared in &result[..2] {
            assert_eq!(shared.consumers.len(), 2);
            assert_eq!(shared.consumers[0].name, "dart");
            assert!(shared.consumers[0].clock && !shared.consumers[0].power);
            assert!(!shared.consumers[1].clock && shared.consumers[1].power);
            assert!(!shared.bindable());
        }
        assert!(result[2].bindable());
        assert!(result[3].consumers.is_empty() && !result[3].bindable());
    }
    #[test]
    fn aliases_merge_parent_dependencies_and_partial_sinks_never_enable_controls() {
        let domains = [
            domain(1, Some(0x100), &[]),
            domain(2, Some(0x200), &[]),
            domain(3, Some(0x300), &[1]),
            domain(4, Some(0x300), &[2]),
        ];
        let required = [id(3), id(3)];
        for missing in [
            LifecycleSinks {
                clock: false,
                ..COMPLETE
            },
            LifecycleSinks {
                power: false,
                ..COMPLETE
            },
            LifecycleSinks {
                quiesce: false,
                ..COMPLETE
            },
            LifecycleSinks {
                reset: false,
                ..COMPLETE
            },
        ] {
            let consumers = [consumer("firmware-endpoint", &required, &required, missing)];
            let result = analyze(&domains, &consumers).unwrap();
            assert_eq!(result.len(), 3);
            for record in result {
                assert_eq!(
                    record.consumers.len(),
                    1,
                    "aliases and repeated requirements deduplicate"
                );
                assert!(record.consumers[0].clock && record.consumers[0].power);
                assert!(!record.bindable());
            }
        }
    }
    #[test]
    fn die_qualified_ids_never_merge_without_a_shared_physical_address() {
        let mut second = domain(1, Some(0x200), &[]);
        second.id.die = 1;
        let requirements = [second.id];
        let domains = [domain(1, Some(0x100), &[]), second];
        let result = analyze(
            &domains,
            &[consumer("die1-dart", &[], &requirements, COMPLETE)],
        )
        .unwrap();
        assert!(!result[0].bindable());
        assert!(result[1].bindable());
    }
    #[test]
    fn deep_firmware_graphs_use_bounded_call_stack_and_keep_every_ancestor() {
        let domains = (0..4096)
            .map(|device| Domain {
                name: String::new(),
                id: id(device),
                address: Some(0x1000 + u64::from(device) * 4),
                parents: [
                    if device == 4095 {
                        None
                    } else {
                        Some(id(device + 1))
                    },
                    None,
                ],
            })
            .collect::<Vec<_>>();
        let requirements = [id(0)];
        let result = analyze(
            &domains,
            &[consumer("deep-client", &requirements, &[], COMPLETE)],
        )
        .unwrap();
        assert_eq!(result.len(), 4096);
        assert!(result.iter().all(DomainCoverage::bindable));
    }

    #[test]
    fn missing_cycles_duplicates_and_unaccounted_resources_refuse() {
        let base = domain(1, Some(0x100), &[]);
        assert_eq!(
            analyze(&[base.clone(), base.clone()], &[]),
            Err(CoverageError::DuplicateDomain(id(1)))
        );
        assert_eq!(
            analyze(&[domain(1, Some(0x101), &[])], &[]),
            Err(CoverageError::Misaligned(0x101))
        );
        assert!(matches!(
            analyze(&[domain(1, None, &[2])], &[]),
            Err(CoverageError::MissingParent { .. })
        ));
        assert!(matches!(
            analyze(&[domain(1, None, &[2]), domain(2, Some(0x100), &[1])], &[]),
            Err(CoverageError::ParentCycle(_))
        ));
        // Raw IDs are acyclic, but PA aliases expose an impossible supply cycle.
        assert!(matches!(
            analyze(
                &[
                    domain(1, Some(0x100), &[2]),
                    domain(2, Some(0x200), &[]),
                    domain(3, Some(0x200), &[4]),
                    domain(4, Some(0x100), &[])
                ],
                &[]
            ),
            Err(CoverageError::AliasCycle(_))
        ));
        let unknown = [id(2)];
        assert!(matches!(
            analyze(
                core::slice::from_ref(&base),
                &[consumer("dart", &unknown, &[], COMPLETE)]
            ),
            Err(CoverageError::UnknownRequirement { .. })
        ));
        assert_eq!(
            analyze(
                core::slice::from_ref(&base),
                &[consumer("", &[], &[], COMPLETE)]
            ),
            Err(CoverageError::EmptyConsumer)
        );
        assert_eq!(
            analyze(
                &[base],
                &[
                    consumer("same", &[], &[], COMPLETE),
                    consumer("same", &[], &[], COMPLETE)
                ]
            ),
            Err(CoverageError::DuplicateConsumer("same".into()))
        );
    }
}
