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
        parents: [None; 4],
    };
    for (slot, &parent) in result.parents.iter_mut().zip(parents) {
        *slot = Some(id(parent));
    }
    result
}
fn consumer<'a>(
    id: usize,
    name: &'a str,
    clocks: &'a [DomainId],
    power: &'a [DomainId],
    sinks: LifecycleSinks,
) -> Consumer<'a> {
    Consumer {
        id,
        name,
        clocks,
        power,
        sinks,
        admission: Admission::Required,
    }
}
#[test]
fn repeated_display_names_preserve_distinct_consumers_and_sink_obligations() {
    let requirement = [id(1)];
    let result = analyze(
        &[domain(1, Some(0x100), &[])],
        &[
            consumer(0, "/arm-io/repeated", &requirement, &[], COMPLETE),
            consumer(1, "/arm-io/repeated", &[], &requirement, NONE),
        ],
    )
    .unwrap();
    assert_eq!(result[0].consumers.len(), 2);
    assert_eq!(result[0].consumers[0].id, 0);
    assert_eq!(result[0].consumers[1].id, 1);
    assert!(result[0].consumers[0].clock);
    assert!(!result[0].consumers[0].power);
    assert!(!result[0].consumers[1].clock);
    assert!(result[0].consumers[1].power);
    assert!(!result[0].bindable());
}

#[test]
fn unavailable_consumers_do_not_waive_required_lifecycle_sinks() {
    let domains = [
        domain(1, Some(0x100), &[]),
        domain(2, Some(0x200), &[1]),
        domain(3, Some(0x300), &[]),
    ];
    let requirements = [id(2)];
    let mut absent = consumer(0, "unavailable", &requirements, &[], NONE);
    absent.admission = Admission::Unavailable;
    let native = consumer(1, "native", &requirements, &[], COMPLETE);
    let parent = [id(1)];
    let unknown = consumer(2, "required", &[], &parent, NONE);
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
        consumer(3, "dart", &clocks, &[], COMPLETE),
        consumer(4, "usb", &[], &power, NONE),
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
    assert!(result[3].controller_only() && !result[2].controller_only());
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
        let consumers = [consumer(
            5,
            "firmware-endpoint",
            &required,
            &required,
            missing,
        )];
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
fn die_checked_ids_never_merge_without_a_shared_physical_address() {
    let mut second = domain(1, Some(0x200), &[]);
    second.id.die = 1;
    let requirements = [second.id];
    let domains = [domain(1, Some(0x100), &[]), second];
    let result = analyze(
        &domains,
        &[consumer(6, "die1-dart", &[], &requirements, COMPLETE)],
    )
    .unwrap();
    assert!(!result[0].bindable());
    assert!(result[1].bindable());
}

#[test]
fn third_and_fourth_parent_supplies_participate_in_full_coverage_and_cycle_checks() {
    let mut domains = (1..=4)
        .map(|id| domain(id, Some(u64::from(id) * 0x100), &[]))
        .collect::<Vec<_>>();
    domains.push(domain(5, Some(0x500), &[1, 2, 3, 4]));
    let requirements = [id(5)];
    let consumers = [consumer(
        7,
        "four-supply-client",
        &requirements,
        &[],
        COMPLETE,
    )];
    let result = analyze(&domains, &consumers).unwrap();
    assert_eq!(result.len(), 5);
    assert!(result.iter().all(DomainCoverage::bindable));
    domains[3].parents[3] = Some(id(5));
    assert!(matches!(
        analyze(&domains, &consumers),
        Err(CoverageError::ParentCycle(_))
    ));
    domains[3].parents[3] = Some(id(6));
    assert_eq!(
        analyze(&domains, &consumers),
        Err(CoverageError::MissingParent {
            domain: id(4),
            parent: id(6)
        })
    );
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
                None,
                None,
            ],
        })
        .collect::<Vec<_>>();
    let requirements = [id(0)];
    let result = analyze(
        &domains,
        &[consumer(8, "deep-client", &requirements, &[], COMPLETE)],
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
            &[consumer(9, "dart", &unknown, &[], COMPLETE)]
        ),
        Err(CoverageError::UnknownRequirement { .. })
    ));
    assert_eq!(
        analyze(
            core::slice::from_ref(&base),
            &[consumer(10, "", &[], &[], COMPLETE)]
        ),
        Err(CoverageError::EmptyConsumer)
    );
    assert_eq!(
        analyze(
            &[base],
            &[
                consumer(1000, "same", &[], &[], COMPLETE),
                consumer(1000, "different-name-same-identity", &[], &[], COMPLETE)
            ]
        ),
        Err(CoverageError::DuplicateConsumer(1000))
    );
}
