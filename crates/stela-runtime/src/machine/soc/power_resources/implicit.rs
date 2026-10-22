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
mod tests {
    /// Explicit physical bus for synthetic full-PA fixture records.
    fn flat_bus(children: &[alloc::vec::Vec<u8>]) -> alloc::vec::Vec<u8> {
        let ranges = [0u64, 0, 1u64 << 40]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<alloc::vec::Vec<_>>();
        crate::machine::adt::encode(&[("name", b"arm-io"), ("ranges", &ranges)], children)
    }

    use super::*;
    use crate::machine::soc::tests::flat_fixture_extent;
    use crate::machine::{adt::encode, soc::power_resources::inventory_with_nodes};
    use crate::platform::apple::pmgr::coverage::{self, Admission, Consumer, LifecycleSinks};
    use alloc::vec;

    fn bank(binding: Binding) -> Vec<u8> {
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

    fn domains() -> Vec<Domain> {
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

    fn states(bytes: &[u8], compatible: &str, domains: Vec<Domain>) -> Result<PowerStates, String> {
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

    fn fixture() -> Vec<u8> {
        let mut children = T8112.map(bank).to_vec();
        children.push(encode(
            &[("name", b"pmgr"), ("compatible", b"pmgr1,t8112")],
            &[],
        ));
        flat_bus(&children)
    }

    #[test]
    fn exact_physical_requirements_preserve_original_inventory_and_stable_ids() {
        let bytes = fixture();
        let mut states = states(&bytes, "pmgr1,t8112", domains()).unwrap();
        assert_eq!(states.implicit.len(), 3);
        let original = states.resources.clone();
        assert_eq!(states.apply_admission(&bytes, &[]), Ok(0));
        assert_eq!(states.resources, original);
        assert!(
            states
                .resources
                .iter()
                .all(|resource| resource.clocks.is_empty() && resource.power.is_empty())
        );
        let power = states.power_requirements().unwrap();
        let consumers = states
            .resources
            .iter()
            .enumerate()
            .map(|(id, resource)| Consumer {
                id,
                name: &resource.name,
                clocks: &resource.clocks,
                power: &power[id],
                admission: resource.admission,
                sinks: LifecycleSinks::default(),
            })
            .collect::<Vec<_>>();
        let coverage = coverage::analyze(&states.domains, &consumers).unwrap();
        for binding in T8112 {
            let record = coverage
                .iter()
                .find(|record| record.address == binding.register)
                .unwrap();
            assert!(
                !record.bindable(),
                "candidate ownership alone is not a sink"
            );
            assert_eq!(record.consumers.len(), 1);
            let resource = &states.resources[record.consumers[0].id];
            assert_eq!(resource.owner, Some(PowerOwner::Mmio(binding.physical)));
            assert_eq!(resource.admission, Admission::Required);
        }
        states.resources[1].owner = None;
        assert!(states.power_requirements().is_err());
    }

    #[test]
    fn another_soc_aperture_geometry_compatible_or_domain_cannot_inherit_a_binding() {
        for compatible in [
            "pmgr1,t8103",
            "pmgr1,t6000",
            "pmgr1,t6020",
            "pmgr1,t8122",
            "pmgr1,t8103\0pmgr1,t8112",
            "pmgr1,t8112\0pmgr1,t8103",
        ] {
            assert!(
                states(&fixture(), compatible, domains())
                    .unwrap()
                    .implicit
                    .is_empty()
            );
        }
        for binding in T8112 {
            for changed in [
                Binding {
                    physical: binding.physical + 0x4000,
                    ..binding
                },
                Binding {
                    bytes: binding.bytes - 4,
                    ..binding
                },
                Binding {
                    compatible: "unqualified-bank",
                    ..binding
                },
            ] {
                let bytes = flat_bus(&[bank(changed)]);
                assert!(
                    states(&bytes, "pmgr1,t8112", domains())
                        .unwrap()
                        .implicit
                        .is_empty()
                );
            }
            for (id, address) in [
                (binding.domain, binding.register + 8),
                (
                    DomainId {
                        die: 1,
                        ..binding.domain
                    },
                    binding.register,
                ),
            ] {
                let bytes = flat_bus(&[bank(binding)]);
                let domain = Domain {
                    id,
                    address: Some(address),
                    name: String::new(),
                    parents: [None; 4],
                };
                assert!(
                    states(&bytes, "pmgr1,t8112", vec![domain])
                        .unwrap()
                        .implicit
                        .is_empty()
                );
            }
            let bytes = flat_bus(&[bank(binding), bank(binding)]);
            assert!(
                states(&bytes, "pmgr1,t8112", domains())
                    .unwrap_err()
                    .contains("ambiguous")
            );
        }
    }

    #[test]
    fn endpoint_translation_alone_cannot_hide_an_internal_aperture_hole() {
        let bytes = fixture();
        let root = Node::root(&bytes).unwrap();
        let mut inventory = inventory_with_nodes(&root).unwrap();
        let binding = T8112[0];
        inventory.ranges = vec![
            (binding.physical, binding.physical, 0x4000),
            (
                binding.physical + 0x8000,
                binding.physical + 0x8000,
                binding.bytes - 0x8000,
            ),
        ];
        let pmgr = encode(&[("compatible", b"pmgr1,t8112")], &[]);
        let requirements = resolve(
            &Node::root(&pmgr).unwrap(),
            &domains(),
            &inventory,
            &flat_fixture_extent(&Some),
        )
        .unwrap();
        assert!(requirements.is_empty());
        // A complete affine mapping cannot qualify an overlapping fragment
        // whose priority could change an interior byte's translation.
        inventory.ranges = vec![
            (binding.physical, binding.physical, binding.bytes),
            (binding.physical + 0x4000, 0x1000, 0x4000),
        ];
        assert!(
            resolve(
                &Node::root(&pmgr).unwrap(),
                &domains(),
                &inventory,
                &flat_fixture_extent(&Some)
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn partial_trailing_register_cells_cannot_qualify_an_exact_native_view() {
        for binding in T8112 {
            for trailing in [1, 4, 8, 15, 16] {
                let mut reg = [binding.physical, binding.bytes]
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
                    .collect::<Vec<_>>();
                reg.resize(reg.len() + trailing, 0);
                let node = encode(
                    &[
                        ("name", b"same"),
                        ("compatible", binding.compatible.as_bytes()),
                        ("reg", &reg),
                    ],
                    &[],
                );
                let bytes = flat_bus(&[node]);
                assert!(
                    states(&bytes, "pmgr1,t8112", domains())
                        .unwrap()
                        .implicit
                        .is_empty()
                );
            }
        }
    }

    #[test]
    fn implicit_consumers_keep_all_physical_alias_and_parent_obligations() {
        let mut states = states(&fixture(), "pmgr1,t8112", domains()).unwrap();
        let parent = DomainId {
            die: 0,
            device: 0x200,
        };
        let alias = DomainId {
            die: 0,
            device: 0x201,
        };
        states.domains.extend([
            Domain {
                name: "parent".into(),
                id: parent,
                address: Some(0x1000),
                parents: [None; 4],
            },
            Domain {
                name: "alias".into(),
                id: alias,
                address: Some(T8112[0].register),
                parents: [Some(parent), None, None, None],
            },
        ]);
        states.resources.push(super::super::PowerResource {
            name: "unqualified shared client".into(),
            clocks: vec![alias],
            power: vec![],
            owner: None,
            admission: Admission::Required,
        });
        let power = states.power_requirements().unwrap();
        let consumers = states
            .resources
            .iter()
            .enumerate()
            .map(|(id, resource)| Consumer {
                id,
                name: &resource.name,
                clocks: &resource.clocks,
                power: &power[id],
                admission: resource.admission,
                sinks: LifecycleSinks {
                    clock: resource.owner.is_some(),
                    power: true,
                    quiesce: true,
                    reset: true,
                },
            })
            .collect::<Vec<_>>();
        let coverage = coverage::analyze(&states.domains, &consumers).unwrap();
        for address in [0x1000, T8112[0].register] {
            let record = coverage
                .iter()
                .find(|record| record.address == address)
                .unwrap();
            assert!(!record.bindable());
            assert_eq!(record.consumers.len(), 2);
            assert!(
                record
                    .consumers
                    .iter()
                    .any(|consumer| consumer.name == "unqualified shared client")
            );
        }
    }

    #[test]
    fn actual_aic_and_gpio_hooks_receive_only_their_qualified_supply() {
        use crate::machine::apple::Range;
        use crate::machine::{
            apple::AppleDevices,
            engine::Devices,
            soc::{AicLayout, AuxGpioBank, GpioBank},
        };
        let states = states(&fixture(), "pmgr1,t8112", domains()).unwrap();
        let mut board = AppleDevices::new();
        board
            .add_aic(T8112[0].physical, 1152, AicLayout::aic2(0x8000, 0))
            .unwrap();
        for (index, binding) in T8112[1..].iter().enumerate() {
            let bank = GpioBank {
                profile: crate::platform::apple::gpio::Profile::T8101,
                no_restore_pins: alloc::vec::Vec::new(),
                physical: binding.physical,
                bytes: binding.bytes,
                pins: 32,
                groups: 1,
                phandle: index as u32 + 1,
                lines: vec![16 + index as u16],
                i2c_lines: vec![],
            };
            if index == 0 {
                board.add_gpio(&bank, &[], &[]).unwrap();
            } else {
                board
                    .add_aux_gpio(&AuxGpioBank {
                        name: "same".into(),
                        bank,
                        client_pins: vec![],
                    })
                    .unwrap();
            }
        }
        let blocks = states
            .blocks
            .iter()
            .map(|&(physical, bytes)| Range { physical, bytes })
            .collect::<Vec<_>>();
        board.add_power_states(&blocks, &states.registers).unwrap();
        board.connect_power_resources(&states, &[], &[]).unwrap();
        assert!(board.power_refusals().is_empty());
        for binding in T8112 {
            board.write(0, binding.register, 4, 4, 0).unwrap();
            assert!(board.read(0, binding.physical, 4, 0).is_err());
            for other in T8112.into_iter().filter(|other| other != &binding) {
                assert!(board.read(0, other.physical, 4, 0).is_ok());
            }
            let before = board.read(0, binding.register, 4, 0).unwrap();
            for destructive in [0, 0x8000_040f] {
                assert!(board.write(0, binding.register, 4, destructive, 0).is_err());
                assert_eq!(board.read(0, binding.register, 4, 0), Ok(before));
            }
            board.write(0, binding.register, 4, 15, 0).unwrap();
            assert!(board.read(0, binding.physical, 4, 0).is_ok());
        }
    }

    #[test]
    #[ignore = "requires pinned original J473 ADT; no Apple image is committed"]
    fn original_j473_supplies_match_all_three_physical_owners() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_TEST_PMGR_ADT").expect("original J473 ADT"))
            .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let root = Node::root(&bytes).unwrap();
        let states = super::super::power_states(
            &root,
            &|address, bytes| {
                root.child("arm-io")
                    .unwrap()
                    .translate_range(address, bytes)
            },
            0x8112,
        )
        .unwrap()
        .unwrap();
        assert_eq!(states.registers.len(), 153);
        assert_eq!(states.implicit.len(), 3);
        let power = states.power_requirements().unwrap();
        for requirement in &states.implicit {
            assert!(states.resources[requirement.resource].power.is_empty());
            assert!(states.resources[requirement.resource].clocks.is_empty());
            assert_eq!(power[requirement.resource], [requirement.binding.domain]);
        }
    }
}
