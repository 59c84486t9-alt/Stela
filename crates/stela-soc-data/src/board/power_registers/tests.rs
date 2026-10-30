use super::super::*;
use super::*;
use stela_contracts::refuse;

fn optional_fixture(performance: &[u8], extra: &[(&str, &[u8])]) -> Vec<u8> {
    use stela_contracts::adt::encode;
    let reg = [0x1000u64, 0x1000]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect::<Vec<_>>();
    let clusters = 0u32.to_le_bytes();
    let mut properties = alloc::vec![
        ("name", b"pmgr".as_slice()),
        ("compatible", b"pmgr1,t8103".as_slice()),
        ("reg", reg.as_slice()),
        ("clusters", clusters.as_slice()),
        ("perf-regs", performance),
    ];
    properties.extend_from_slice(extra);
    encode(&[("name", b"arm-io")], &[encode(&properties, &[])])
}

fn direct_performance_group() -> [u8; 16] {
    let mut group = [0; 16];
    group[8..10].copy_from_slice(&4u16.to_le_bytes());
    group[12] = 3;
    group[13] = 1;
    group
}

#[test]
fn an_unqualified_optional_bank_preserves_independent_performance_placement() {
    let group = direct_performance_group();
    let bytes = optional_fixture(&group, &[("bridge-reg-index", &0u32.to_le_bytes())]);
    let io = Node::root(&bytes).unwrap();
    let parsed = pmgr_registers(&io, &|address, _| Some(address), 0x8103).unwrap();
    assert_eq!(parsed.performance.len(), 1);
    assert_eq!(parsed.performance[0].physical, 0x1000);
    assert!(parsed.clusters.is_empty());
    assert!(parsed.bridges.is_empty());
    assert!(
        parsed
            .refusals
            .iter()
            .any(|r| r.bank == PmgrBank::CpuClusters)
    );
    assert!(parsed.refusals.iter().any(|r| r.bank == PmgrBank::Bridges));
    assert!(
        !parsed
            .refusals
            .iter()
            .any(|r| r.bank == PmgrBank::Performance)
    );
}

#[test]
fn known_bridge_references_are_validated_even_when_native_layout_is_unqualified() {
    let one = 1u32.to_le_bytes();
    let three = 3u32.to_le_bytes();
    let index = 0u32.to_le_bytes();
    let group = direct_performance_group();
    let mut dependency = [0; 76];
    dependency[4] = 1; // Outside the one-bank source table.
    for (header, dependencies, valid) in [
        ([0, 0, 0, 0], &[][..], true),
        ([0, 0, 0, 1], &[][..], false),
        ([0, 0, 0, 0], &dependency[..], false),
    ] {
        let bytes = optional_fixture(
            &group,
            &[
                ("bridge-reg-index", &index),
                ("#bridges", &one),
                ("bridge-settings-version", &one),
                ("bridge-counter-version", &three),
                ("bridge-counters", &header),
                ("device-bridges", dependencies),
            ],
        );
        let io = Node::root(&bytes).unwrap();
        let result = pmgr_registers(&io, &|address, _| Some(address), 0x8103);
        if valid {
            let parsed = result.unwrap();
            assert!(parsed.bridges.is_empty());
            assert!(parsed.refusals.iter().any(|r| r.bank == PmgrBank::Bridges));
            assert_eq!(parsed.performance.len(), 1);
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn unsupported_performance_semantics_are_named_without_a_register_model() {
    let mut group = direct_performance_group();
    group[12] = 1;
    let bytes = optional_fixture(&group, &[]);
    let io = Node::root(&bytes).unwrap();
    let parsed = pmgr_registers(&io, &|address, _| Some(address), 0x8103).unwrap();
    assert!(parsed.performance.is_empty());
    assert_eq!(
        parsed
            .refusals
            .iter()
            .filter(|r| r.bank == PmgrBank::Performance)
            .count(),
        1
    );
}

#[test]
fn malformed_advertised_records_are_fatal_even_beside_an_unsupported_bank() {
    for (name, malformed) in [
        ("hw-dpe-reg", alloc::vec![0; 39]),
        ("events", alloc::vec![0; 23]),
        ("bridge-counters", alloc::vec![0; 3]),
        ("device-bridges", alloc::vec![0; 75]),
        ("bridge-reg-index", alloc::vec![0; 3]),
    ] {
        let mut group = direct_performance_group();
        group[12] = 1;
        let bytes = optional_fixture(&group, &[(name, &malformed)]);
        let io = Node::root(&bytes).unwrap();
        assert!(
            pmgr_registers(&io, &|address, _| Some(address), 0x8103).is_err(),
            "{name}"
        );
    }
    let group = direct_performance_group();
    let bytes = optional_fixture(&group[..15], &[]);
    let io = Node::root(&bytes).unwrap();
    assert!(pmgr_registers(&io, &|address, _| Some(address), 0x8103).is_err());
}

#[test]
fn performance_bank_capacity_is_independent_of_byte_sized_source_selectors() {
    use stela_contracts::adt::encode;
    let mut group = direct_performance_group();
    group[8..10].copy_from_slice(&306u16.to_le_bytes());
    let mut source = [0; PMGR_DEVICE];
    source[0] = 0x20;
    source[8] = 255;
    let bytes = encode(
        &[
            ("name", b"pmgr"),
            ("perf-regs", &group),
            ("devices", &source),
        ],
        &[],
    );
    let node = Node::root(&bytes).unwrap();
    let banks = performance_banks(&node, &[Some((0x1000, 0x10000))]).unwrap();
    assert_eq!(banks[0].selectors, [255]);
}

#[test]
fn a_supported_family_with_an_invalid_register_reference_is_not_degraded() {
    let mut group = direct_performance_group();
    group[..4].copy_from_slice(&1u32.to_le_bytes());
    let bytes = optional_fixture(&group, &[]);
    let io = Node::root(&bytes).unwrap();
    assert!(pmgr_registers(&io, &|address, _| Some(address), 0x8103).is_err());
    let bytes = optional_fixture(&direct_performance_group(), &[]);
    let io = Node::root(&bytes).unwrap();
    assert!(pmgr_registers(&io, &|_, _| None, 0x8103).is_err());
}

#[test]
fn special_acc_events_use_the_dt_selector_and_cluster_type() {
    use stela_contracts::adt::encode;
    let mut e = [0u8; 24];
    e[2] = 2;
    e[6] = 12;
    let mut p = [0u8; 24];
    p[2] = 7;
    p[6] = 24;
    let data = [e, p].concat();
    let tree = encode(&[("events", &data)], &[]);
    assert_eq!(
        acc_events(&Node::root(&tree).unwrap(), 2).unwrap(),
        vec![vec![12], vec![24]]
    );
    assert!(acc_events(&Node::root(&tree).unwrap(), 1).is_err());
    p[6] = 27;
    let tree = encode(&[("events", &p)], &[]);
    assert!(acc_events(&Node::root(&tree).unwrap(), 2).is_err());
}

#[test]
fn bridge_headers_configs_axi_and_dependencies_place_the_translated_window() {
    use stela_contracts::adt::encode;
    let cells = |v: &[u32]| v.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>();
    let mut config = [0u8; 36];
    config[1] = 7;
    let mut dependency = [0u8; 76];
    dependency[3] = 9;
    let tree = encode(
        &[
            ("bridge-reg-index", &cells(&[1])),
            ("#bridges", &cells(&[1])),
            ("bridge-settings-version", &cells(&[1])),
            ("bridge-counter-version", &cells(&[3])),
            ("bridge-counters", &[0, 0x80, 0, 1]),
            ("bridge-counter-configs", &config),
            ("axi2af-axi-config", &[0, 0x20, 0x18, 8]),
            ("device-bridges", &dependency),
        ],
        &[],
    );
    let n = Node::root(&tree).unwrap();
    let fields: &[&[(u64, u32)]] = &[&[(0, 0x103)]];
    let banks = place_bridges(&n, &[None, Some((0x6_8c00_0000, 0x1000000))], Some(fields)).unwrap();
    assert_eq!(banks[0].physical, 0x6_8c00_0000);
    assert_eq!(banks[0].devices, vec![9]);
    assert_eq!(banks[0].configs, vec![config]);
    assert_eq!(banks[0].axi, Some([0, 0x20, 0x18, 8]));
    assert!(place_bridges(&n, &[None, Some((0, 0x100))], Some(fields)).is_err());
    assert!(place_bridges(&n, &[None], Some(fields)).is_err());
    assert!(place_bridges(&n, &[], None).is_err());
}

#[test]
fn soc_dpe_samples_are_absolute_and_checked_against_the_selected_dt_bank() {
    use stela_contracts::adt::encode;
    let mut sample = [0u8; 40];
    sample[..8].copy_from_slice(&0x5_0000_2708u64.to_le_bytes());
    sample[16..24].copy_from_slice(&[0x1d, 0, 1, 0, 1, 1, 1, 64]);
    let tree = encode(&[("hw-dpe-reg", &sample)], &[]);
    let node = Node::root(&tree).unwrap();
    let bank = place_soc_dpe(&node, &[Some((0x5_0000_0000, 0x8000))], 0).unwrap();
    assert_eq!(bank.samples, vec![(0x2708, true)]);
    assert_eq!(bank.physical, 0x5_0000_0000);
    assert!(place_soc_dpe(&node, &[Some((0, 0x8000))], 0).is_err());
    assert!(place_soc_dpe(&node, &[Some((0x5_0000_0000, 0x3000))], 0).is_err());
}

#[test]
fn soc_power_roles_use_dt_ranges_and_refuse_short_or_overflowed_ranges() {
    let kinds = [
        crate::power::Kind::Volman,
        crate::power::Kind::Marker,
        crate::power::Kind::Gpce,
        crate::power::Kind::Gating,
        crate::power::Kind::Tvm,
    ];
    for kind in kinds {
        let reg = [None, Some((0x5_0000_0000, 0x20000))];
        assert_eq!(
            place_power_banks(&reg, &[(1, kind)]).unwrap(),
            vec![PowerBank {
                physical: 0x5_0000_0000,
                kind
            }]
        );
        assert!(place_power_banks(&[None], &[(1, kind)]).is_err());
        assert!(place_power_banks(&[Some((0, 0))], &[(0, kind)]).is_err());
        assert!(place_power_banks(&[Some((u64::MAX - 3, 0x20000))], &[(0, kind)]).is_err());
    }
}

#[test]
fn wake_masks_derive_the_bank_and_validate_dt_sources_without_assuming_reset_masks() {
    use stela_contracts::adt::encode;
    let layout = SOCS
        .iter()
        .find(|soc| soc.chip_id == 0x8112)
        .unwrap()
        .wake_masks
        .unwrap();
    let mut reg = [None; 5];
    reg[4] = Some((0x2_3d00_4000, 0x1000));
    let named = |id: u32, name: &[u8]| {
        let mut entry = [0u8; 36];
        entry[..4].copy_from_slice(&id.to_le_bytes());
        entry[4..4 + name.len()].copy_from_slice(name);
        entry
    };
    let source = |id: u32| named(id, b"");
    let records = [source(14), source(157)].concat();
    let tree = encode(&[("ap-wake-sources", &records)], &[]);
    let found = wake_bank(&Node::root(&tree).unwrap(), &reg, layout).unwrap();
    assert_eq!(
        found,
        WakeBank {
            physical: 0x2_3d00_4008,
            valid: layout.valid,
            sources: vec![14, 157],
            smc_wake: None,
        }
    );
    // J473AP names the SMC's wake of the AP source 81.
    let records = [named(14, b"AOP.GPIO.IRQ6"), named(81, b"SMC.CPUWakeupAP")].concat();
    let tree = encode(&[("ap-wake-sources", &records)], &[]);
    let found = wake_bank(&Node::root(&tree).unwrap(), &reg, layout).unwrap();
    assert_eq!(found.smc_wake, Some(81));
    reg[4] = Some((0x5_0000_0000, 0x1000));
    assert_eq!(
        wake_bank(&Node::root(&tree).unwrap(), &reg, layout)
            .unwrap()
            .physical,
        0x5_0000_0008
    );
    for invalid in [
        source(255).to_vec(),
        source(256).to_vec(),
        [source(14), source(14)].concat(),
        records[..35].to_vec(),
    ] {
        let tree = encode(&[("ap-wake-sources", &invalid)], &[]);
        assert!(wake_bank(&Node::root(&tree).unwrap(), &reg, layout).is_err());
    }
    reg[4] = Some((0, wake::OFFSET + wake::BYTES - 1));
    assert!(wake_bank(&Node::root(&tree).unwrap(), &reg, layout).is_err());
    reg[4] = Some((u64::MAX - wake::OFFSET, 0x1000));
    assert!(wake_bank(&Node::root(&tree).unwrap(), &reg, layout).is_err());
    reg[4] = None;
    assert!(wake_bank(&Node::root(&tree).unwrap(), &reg, layout).is_err());
}

#[test]
fn perf_groups_derive_sparse_selectors_from_each_dt_record_kind() {
    use stela_contracts::adt::encode;
    let group = |index: u32, offset: u32, count: u16, class: u8| {
        let mut entry = [0u8; 16];
        entry[..4].copy_from_slice(&index.to_le_bytes());
        entry[4..8].copy_from_slice(&offset.to_le_bytes());
        entry[8..10].copy_from_slice(&count.to_le_bytes());
        entry[12] = class;
        entry
    };
    let mut device = [0u8; PMGR_DEVICE];
    device[0] = 0x20;
    device[8] = 9;
    device[9] = 0;
    let source = |bytes: &[u8]| {
        let mut entry = [0u8; 24];
        entry[..bytes.len()].copy_from_slice(bytes);
        entry
    };
    let groups = [
        group(1, 0x34000, 256, 3),
        group(0, 0x58000, 256, 0),
        group(0, 0x78000, 12, 0),
    ]
    .concat();
    let clocks = [source(&[24, 0, 1]), source(&[25, 0, 0])].concat();
    let domains = [source(&[0, 31, 0]), source(&[0, 0, 0])].concat();
    let events = [
        source(&[0, 0, 1, 80, 41, 0, 40, 0]),
        source(&[15, 0, 5, 52, 1, 2, 0, 2]),
        source(&[0, 0, 0, 1, 0, 0, 120, 1]),
        source(&[0, 0, 2, 96, 0, 0, 0, 0]),
        source(&[0, 0, 7, 101, 0, 0, 12, 0]),
        source(&[0, 1, 0, 128, 0, 0, 50, 1]),
    ]
    .concat();
    let tree = |groups: &[u8], clocks: &[u8]| {
        encode(
            &[
                ("perf-regs", groups),
                ("devices", &device),
                ("clocks", clocks),
                ("power-domains", &domains),
                ("events", &events),
            ],
            &[],
        )
    };
    let reg = [
        Some((0x2_3b70_0000, 0xcc000)),
        Some((0x2_3d28_0000, 0x7c000)),
    ];
    let data = tree(&groups, &clocks);
    let node = Node::root(&data).unwrap();
    assert_eq!(
        performance_banks(&node, &reg).unwrap(),
        vec![
            PerfBank {
                physical: 0x2_3d2b_4000,
                selectors: vec![9, 24, 31, 40, 41]
            },
            PerfBank {
                physical: 0x2_3b75_8000,
                selectors: vec![120]
            },
            PerfBank {
                physical: 0x2_3b77_8000,
                selectors: vec![0, 1]
            },
        ]
    );
    for invalid in [
        groups[..47].to_vec(),
        {
            let mut bad = groups.clone();
            bad[13] = 2;
            bad
        },
        {
            let mut bad = groups.clone();
            bad[15] = 2;
            bad
        },
        {
            let mut bad = groups.clone();
            bad[12] = 1;
            bad
        },
        {
            let mut bad = groups.clone();
            bad[..4].copy_from_slice(&3u32.to_le_bytes());
            bad
        },
    ] {
        let data = tree(&invalid, &clocks);
        assert!(performance_banks(&Node::root(&data).unwrap(), &reg).is_err());
    }
    for invalid in [
        clocks[..47].to_vec(),
        source(&[12, 2, 1]).to_vec(),
        source(&[0, 3, 1]).to_vec(),
    ] {
        let data = tree(&groups, &invalid);
        assert!(performance_banks(&Node::root(&data).unwrap(), &reg).is_err());
    }
    assert!(performance_banks(&node, &[Some((0, 0x100)), reg[1]]).is_err());
    assert!(performance_banks(&node, &[Some((u64::MAX - 0x58000, 0xcc000)), reg[1]]).is_err());
    let relocated = [
        Some((0x5_0000_0000, 0xcc000)),
        Some((0x6_0000_0000, 0x7c000)),
    ];
    let placed = performance_banks(&node, &relocated).unwrap();
    assert_eq!(placed[0].physical, 0x6_0003_4000);
    assert_eq!(placed[1].physical, 0x5_0005_8000);
}

#[test]
fn cpu_start_registers_follow_the_pmgr_node_with_registers() {
    use stela_contracts::adt::encode;
    let z = |text: &str| [text.as_bytes(), &[0]].concat();
    let reg = |base: u64, bytes: u64| [base.to_le_bytes(), bytes.to_le_bytes()].concat();
    let io = |pmgr: &str, pmgr_reg: Option<(u64, u64)>, child: Option<(u64, u64)>| {
        let (name, compatible) = (z("pmgr"), z(pmgr));
        let pmgr_reg = pmgr_reg.map(|(base, bytes)| reg(base, bytes));
        let mut properties: Vec<(&str, &[u8])> = vec![("name", &name), ("compatible", &compatible)];
        if let Some(pmgr_reg) = &pmgr_reg {
            properties.push(("reg", pmgr_reg));
        }
        let mut children = vec![encode(&properties, &[])];
        if let Some((base, bytes)) = child {
            children.push(encode(
                &[
                    ("name", &z("pmgr-child")),
                    ("compatible", &z("pmgr2,t8152")),
                    ("reg", &reg(base, bytes)),
                ],
                &[],
            ));
        }
        let io = encode(&[("name", &z("arm-io"))], &children);
        encode(&[("name", &z("device-tree"))], &[io])
    };
    let place = |tree: &[u8], chip_id, clusters: &[u64]| {
        let processors: Vec<Identity> = clusters
            .iter()
            .map(|&cluster| Identity {
                midr: 0,
                mpidr: 0x8000_0000 | cluster << 8,
                clock: None,
                caches: None,
            })
            .collect();
        let root = Node::root(tree).unwrap();
        let io = root.child("arm-io").unwrap();
        let translate = |address: u64, _| Some(address + 0x2_0000_0000);
        cpu_start(&io, &translate, chip_id, &processors)
    };
    let m6 = io("pmgr2,arch", None, Some((0x1_0070_0000, 0xd0000)));
    assert_eq!(place(&m6, 0x8152, &[0, 1]), Ok(Some((0x3_0073_4000, 2))));
    assert_eq!(
        place(&io("pmgr2,arch", None, None), 0x8152, &[0, 1]),
        Err(refuse!(
            "/arm-io/pmgr is pmgr2,arch without /arm-io/pmgr-child"
        ))
    );
    let short = io("pmgr2,arch", None, Some((0x1_0070_0000, 0x34008)));
    assert_eq!(
        place(&short, 0x8152, &[0, 1]),
        Err(refuse!(
            "/arm-io/pmgr-child reg[0] does not hold the CPU start registers"
        ))
    );
    // An M3 (J613AP `reg[0]` 0xc070_0000 for 0xcc000 bytes) without a
    // modeled PMGR still has its CPU start registers.
    let m3 = io("pmgr1,t8122", Some((0xc070_0000, 0xcc000)), None);
    assert_eq!(place(&m3, 0x8122, &[0, 1]), Ok(Some((0x2_c073_4000, 2))));
    // Another SoC's PMGR is not the row's.
    assert_eq!(place(&m3, 0x8132, &[0, 1]), Ok(None));
}
