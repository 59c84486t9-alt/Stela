use super::fixture_support::*;

use super::*;
use crate::board::fixture_support::flat_fixture_extent;
use alloc::vec;
use {crate::board::power_resources::inventory_with_nodes, stela_contracts::adt::encode};
use {
    crate::pmgr::coverage, crate::pmgr::coverage::Admission, crate::pmgr::coverage::Consumer,
    crate::pmgr::coverage::LifecycleSinks,
};

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
            clocks: resource.activated_clocks(),
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
                .to_string()
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
    // A complete affine mapping cannot check an overlapping fragment
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
fn partial_trailing_register_cells_cannot_check_an_native_view() {
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
        clock_role: crate::board::ClockRole::Consumer,
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
            clocks: resource.activated_clocks(),
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
#[ignore = "oracle: STELA_TEST_PMGR_ADT"]
fn original_j473_supplies_match_all_three_physical_owners() {
    use stela_crypto::{Sha256, digest::Digest};
    let bytes =
        std::fs::read(std::env::var("STELA_TEST_PMGR_ADT").expect("original J473 ADT")).unwrap();
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
