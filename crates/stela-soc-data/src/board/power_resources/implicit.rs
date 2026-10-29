//! Positive SoC supply associations which the original ADT does not encode as
//! gate properties. These facts select physical hardware, never resource names.
//! Linux a0ff06b3a7bd3aa0cd99d0294e60b3ed28c9bfac, t8112.dtsi and
//! t8112-pmgr.dtsi independently associate these three apertures with their
//! power-state registers. See docs/research/pmgr-lifecycle.md for source windows.
//! Association does not establish initial state or implement a lifecycle sink.
use super::{Domain, DomainId, Node, PowerOwner, PowerStates, ResourceInventory};
use alloc::{format, string::String, vec::Vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Binding {
    compatible: &'static str,
    physical: u64,
    bytes: u64,
    domain: DomainId,
    register: u64,
}

const T8112: [Binding; 3] = [
    Binding {
        compatible: "aic,2",
        physical: 0x2_3b0c_0000,
        bytes: 0x2_0000,
        domain: DomainId {
            die: 0,
            device: 0x11,
        },
        register: 0x2_3b70_0108,
    },
    Binding {
        compatible: "gpio,t8101",
        physical: 0x2_3c10_0000,
        bytes: 0x10_0000,
        domain: DomainId {
            die: 0,
            device: 0x14,
        },
        register: 0x2_3b70_0120,
    },
    Binding {
        compatible: "gpio,t8101",
        physical: 0x2_3d1f_0000,
        bytes: 0x4000,
        domain: DomainId {
            die: 0,
            device: 0x105,
        },
        register: 0x2_3d28_0080,
    },
];

/// Constructed only after matching original compatible, complete register view,
/// SoC-specific physical supply and canonical hardware owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Requirement {
    resource: usize,
    binding: Binding,
}

pub(super) fn resolve(
    pmgr: &Node<'_>,
    domains: &[Domain],
    inventory: &ResourceInventory<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<Vec<Requirement>, String> {
    // A fallback list containing another PMGR profile does not establish
    // this exact physical association.
    if pmgr
        .property("compatible")
        .map(|raw| raw.strip_suffix(&[0]).unwrap_or(raw))
        != Some(b"pmgr1,t8112".as_slice())
    {
        return Ok(Vec::new());
    }
    let mut requirements = Vec::new();
    for binding in T8112 {
        if !domains
            .iter()
            .any(|domain| domain.id == binding.domain && domain.address == Some(binding.register))
        {
            continue;
        }
        let mut candidate = None;
        for (resource, (node, entry)) in
            inventory.nodes.iter().zip(&inventory.resources).enumerate()
        {
            if entry.owner != Some(PowerOwner::Mmio(binding.physical))
                || !node.compatible(binding.compatible)
                || node.property("reg").is_none_or(|raw| raw.len() != 16)
            {
                continue;
            }
            let Some(ranges) = node.pairs("reg") else {
                continue;
            };
            let [(address, bytes)] = ranges.as_slice() else {
                continue;
            };
            let complete_view = if inventory.ranges.is_empty() {
                *address == binding.physical
            } else {
                let end = address.checked_add(*bytes);
                let mut views = inventory.ranges.iter().filter(|&&(child, _, size)| {
                    end.is_some_and(|end| child < end && *address < child.saturating_add(size))
                });
                views.next().is_some_and(|&(child, parent, size)| {
                    views.next().is_none()
                        && child.checked_add(size).is_some()
                        && *address >= child
                        && address - child <= size
                        && *bytes <= size - (address - child)
                        && parent.checked_add(address - child) == Some(binding.physical)
                })
            };
            if *bytes != binding.bytes
                || !complete_view
                || translate(*address, *bytes) != Some(binding.physical)
            {
                continue;
            }
            if candidate.replace(resource).is_some() {
                return Err(format!(
                    "PMGR implicit physical owner {:#x} has ambiguous resource views",
                    binding.physical
                ));
            }
        }
        if let Some(resource) = candidate {
            requirements.push(Requirement { resource, binding });
        }
    }
    Ok(requirements)
}

pub(super) fn power_requirements(states: &PowerStates) -> Result<Vec<Vec<DomainId>>, String> {
    let mut power = states
        .resources
        .iter()
        .map(|resource| resource.power.clone())
        .collect::<Vec<_>>();
    for requirement in &states.implicit {
        let binding = requirement.binding;
        let valid = states
            .resources
            .get(requirement.resource)
            .is_some_and(|resource| resource.owner == Some(PowerOwner::Mmio(binding.physical)))
            && states.domains.iter().any(|domain| {
                domain.id == binding.domain && domain.address == Some(binding.register)
            });
        if !valid {
            return Err(
                "PMGR implicit ownership differs from the qualified physical inventory".into(),
            );
        }
        let gates = &mut power[requirement.resource];
        gates.push(binding.domain);
        gates.sort_unstable();
        gates.dedup();
    }
    Ok(power)
}

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
pub(in crate::board) mod fixture_support {
    use super::*;
    use crate::board::{
        fixture_support::{ImplicitSupplyFixture, flat_fixture_extent},
        power_resources::inventory_with_nodes,
    };
    use stela_contracts::adt::encode;
    /// Explicit physical bus for synthetic full-PA fixture records.
    pub(super) fn flat_bus(children: &[alloc::vec::Vec<u8>]) -> alloc::vec::Vec<u8> {
        let ranges = [0u64, 0, 1u64 << 40]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<alloc::vec::Vec<_>>();
        stela_contracts::adt::encode(&[("name", b"arm-io"), ("ranges", &ranges)], children)
    }

    pub(super) fn bank(binding: Binding) -> Vec<u8> {
        let reg = [binding.physical, binding.bytes]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        // Deliberately identical display names; physical views select owners.
        encode(
            &[
                ("name", b"same"),
                ("compatible", binding.compatible.as_bytes()),
                ("reg", &reg),
            ],
            &[],
        )
    }

    pub(super) fn domains() -> Vec<Domain> {
        T8112
            .iter()
            .map(|binding| Domain {
                name: String::new(),
                id: binding.domain,
                address: Some(binding.register),
                parents: [None; 4],
            })
            .collect()
    }

    pub(super) fn states(
        bytes: &[u8],
        compatible: &str,
        domains: Vec<Domain>,
    ) -> Result<PowerStates, String> {
        let pmgr_bytes = encode(
            &[("name", b"pmgr"), ("compatible", compatible.as_bytes())],
            &[],
        );
        let root = Node::root(bytes).unwrap();
        let inventory = inventory_with_nodes(&root)?;
        let implicit = resolve(
            &Node::root(&pmgr_bytes).unwrap(),
            &domains,
            &inventory,
            &flat_fixture_extent(&Some),
        )?;
        Ok(PowerStates {
            blocks: domains
                .iter()
                .filter_map(|domain| domain.address.map(|address| (address, 4)))
                .collect(),
            registers: domains.iter().filter_map(|domain| domain.address).collect(),
            domains,
            resources: inventory.resources,
            implicit,
        })
    }

    pub(super) fn fixture() -> Vec<u8> {
        let mut children = T8112.map(bank).to_vec();
        children.push(encode(
            &[("name", b"pmgr"), ("compatible", b"pmgr1,t8112")],
            &[],
        ));
        flat_bus(&children)
    }
    pub(in crate::board) fn complete_fixture() -> (PowerStates, [ImplicitSupplyFixture; 3]) {
        (
            states(&fixture(), "pmgr1,t8112", domains()).unwrap(),
            T8112.map(|v| ImplicitSupplyFixture {
                physical: v.physical,
                bytes: v.bytes,
                register: v.register,
            }),
        )
    }
}
