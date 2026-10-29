use super::super::{PowerStates, domain_id, inventory, validate_power_graph};
use super::*;
use alloc::{string::ToString, vec};
use {
    crate::pmgr::coverage::Admission, crate::pmgr::coverage::Domain, stela_contracts::adt::encode,
};

fn words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}
fn tree(
    binding: Option<&[u8]>,
    compatible: &str,
    power: &[u32],
    child_clock: &[u32],
    foreign: bool,
) -> Vec<u8> {
    let reg = [0x1000u64, 0x1000]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect::<Vec<_>>();
    let child = encode(
        &[("name", b"nub"), ("clock-gates", &words(child_clock))],
        &[],
    );
    let pmgr = encode(
        &[
            ("name", b"provider"),
            ("compatible", compatible.as_bytes()),
            ("reg", &reg),
            ("AAPL,phandle", &words(&[0x99])),
            ("clock-gates", &words(&[197, 198, 199, 200])),
            ("power-gates", &words(power)),
        ],
        &[child],
    );
    let foreign = encode(
        &[
            ("name", b"unrelated"),
            ("clock-gates", &words(if foreign { &[197] } else { &[] })),
        ],
        &[],
    );
    let mut props = vec![
        ("name", &b"arm-io"[..]),
        ("compatible", &b"arm-io,t6000"[..]),
        ("clock-gates", &b"\x01\0\0\0"[..]),
    ];
    if let Some(binding) = binding {
        props.push(("function-clock_gate", binding));
    }
    let io = encode(&props, &[pmgr, foreign]);
    encode(&[("name", b"device-tree")], &[io])
}
fn states(bytes: &[u8]) -> PowerStates {
    PowerStates {
        blocks: vec![],
        registers: vec![0x1000],
        domains: vec![Domain {
            id: domain_id(1),
            name: "declared ancestor".into(),
            address: Some(0x1000),
            parents: [None; 4],
        }],
        resources: inventory(&Node::root(bytes).unwrap()).unwrap(),
        implicit: vec![],
    }
}
fn selected(states: &PowerStates) -> &super::super::PowerResource {
    states
        .resources
        .iter()
        .find(|resource| matches!(resource.clock_role, ClockRole::PmgrProvider(_)))
        .unwrap()
}

#[test]
fn each_checked_provider_pair_requires_its_matching_bus_and_binding() {
    let binding = words(&[0x99, 0x636c6b47]);
    for (bus, controller) in PROVIDER_BINDINGS {
        let mut bytes = tree(Some(&binding), controller, &[], &[], false);
        let start = bytes
            .windows(b"arm-io,t6000".len())
            .position(|raw| raw == b"arm-io,t6000")
            .unwrap();
        bytes[start..start + bus.len()].copy_from_slice(bus.as_bytes());
        let root = Node::root(&bytes).unwrap();
        let resources = inventory(&root).unwrap();
        let role = resources
            .iter()
            .find(|r| matches!(r.clock_role, ClockRole::PmgrProvider(_)))
            .unwrap();
        assert_eq!(
            role.clocks,
            [
                domain_id(1),
                domain_id(197),
                domain_id(198),
                domain_id(199),
                domain_id(200)
            ]
        );
        assert_eq!(role.activated_clocks(), [domain_id(1)]);
    }
    for controller in ["pmgr1,t6020", "pmgr1,t6021", "pmgr1,t9999"] {
        let bytes = tree(Some(&binding), controller, &[], &[], false);
        let root = Node::root(&bytes).unwrap();
        assert!(provider(&root).unwrap().is_none());
    }
}

#[test]
fn provider_preserves_published_ids_and_only_activates_real_ancestors() {
    let binding = words(&[0x99, 0x636c6b47]);
    let bytes = tree(Some(&binding), "pmgr1,t6000", &[], &[], false);
    let states = states(&bytes);
    let provider = selected(&states);
    assert_eq!(provider.clocks, [1, 197, 198, 199, 200].map(domain_id));
    assert_eq!(provider.activated_clocks(), [domain_id(1)]);
    let ClockRole::PmgrProvider(role) = &provider.clock_role else {
        unreachable!()
    };
    assert_eq!(role.phandle(), 0x99);
    assert_eq!(provider.admission, Admission::Required);
    let child = states
        .resources
        .iter()
        .find(|resource| resource.name.ends_with("/nub"))
        .unwrap();
    assert_eq!(child.clock_role, ClockRole::Consumer);
    assert_eq!(child.clocks, [domain_id(1)]);
    assert_eq!(validate_power_graph(&states), Ok(()));
    // Neither provider role nor absent own start gates manufactures a
    // source state or a lifecycle sink for its inherited supply.
    let mut missing = states.clone();
    missing.domains.clear();
    missing.registers.clear();
    assert!(validate_power_graph(&missing).is_err());
    assert!(
        states
            .resources
            .iter()
            .all(|resource| resource.owner.is_none())
    );
}

#[test]
fn normal_consumers_child_gates_and_provider_power_remain_enforced() {
    let binding = words(&[0x99, 0x636c6b47]);
    for (power, child_clock, foreign) in [
        (&[197][..], &[][..], false),
        (&[][..], &[197][..], false),
        (&[][..], &[][..], true),
    ] {
        let bytes = tree(Some(&binding), "pmgr1,t6000", power, child_clock, foreign);
        let states = states(&bytes);
        assert!(matches!(
            selected(&states).clock_role,
            ClockRole::PmgrProvider(_)
        ));
        let error = validate_power_graph(&states).unwrap_err();
        assert!(error.contains("197"), "{error}");
    }
}

#[test]
fn compatible_or_names_cannot_replace_function_provider_binding() {
    for binding in [
        None,
        Some(words(&[0x98, 0x636c6b47])),
        Some(words(&[0x99, 0x12345678])),
    ] {
        let bytes = tree(binding.as_deref(), "pmgr1,t6000", &[], &[], false);
        let states = states(&bytes);
        assert!(
            states
                .resources
                .iter()
                .all(|resource| resource.clock_role == ClockRole::Consumer)
        );
        assert!(validate_power_graph(&states).unwrap_err().contains("197"));
    }
    let binding = words(&[0x99, 0x636c6b47]);
    let mut foreign_bus = tree(Some(&binding), "pmgr1,t6000", &[], &[], false);
    let at = foreign_bus
        .windows(b"arm-io,t6000".len())
        .position(|raw| raw == b"arm-io,t6000")
        .unwrap();
    foreign_bus[at..at + b"arm-io,t8112".len()].copy_from_slice(b"arm-io,t8112");
    let foreign_states = states(&foreign_bus);
    assert!(
        foreign_states
            .resources
            .iter()
            .all(|resource| resource.clock_role == ClockRole::Consumer)
    );
    assert!(validate_power_graph(&foreign_states).is_err());
    let bytes = tree(Some(&binding), "pmgr1,t8112", &[], &[], false);
    let states = states(&bytes);
    assert!(
        states
            .resources
            .iter()
            .all(|resource| resource.clock_role == ClockRole::Consumer)
    );
    assert!(validate_power_graph(&states).is_err());
}

#[test]
fn malformed_or_ambiguous_provider_inputs_and_changed_role_refuse() {
    for raw in [
        vec![],
        words(&[0x99]),
        [words(&[0x99, 0x636c6b47]), vec![1]].concat(),
        words(&[0, 0x636c6b47]),
    ] {
        let bytes = tree(Some(&raw), "pmgr1,t6000", &[], &[], false);
        assert!(inventory(&Node::root(&bytes).unwrap()).is_err());
    }
    let binding = words(&[0x99, 0x636c6b47]);
    let bytes = tree(Some(&binding), "pmgr1,t6000", &[], &[], false);
    let mut states = states(&bytes);
    let before = states.clone();
    let at = states
        .resources
        .iter()
        .position(|resource| matches!(resource.clock_role, ClockRole::PmgrProvider(_)))
        .unwrap();
    states.resources[at].clock_role = ClockRole::Consumer;
    assert!(
        states
            .apply_admission(&bytes, &[])
            .unwrap_err()
            .contains("differs")
    );
    assert_eq!(
        states.resources[at].admission,
        before.resources[at].admission
    );
    let reg = [0x1000u64, 0x1000]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect::<Vec<_>>();
    let p = encode(
        &[
            ("name", b"a"),
            ("compatible", b"pmgr1,t6000"),
            ("AAPL,phandle", &words(&[0x99])),
            ("reg", &reg),
        ],
        &[],
    );
    let other = encode(&[("name", b"b"), ("AAPL,phandle", &words(&[0x99]))], &[]);
    let io = encode(
        &[
            ("name", b"arm-io"),
            ("compatible", b"arm-io,t6000"),
            ("function-clock_gate", &binding),
        ],
        &[p, other],
    );
    let bytes = encode(&[("name", b"device-tree")], &[io]);
    assert!(
        inventory(&Node::root(&bytes).unwrap())
            .unwrap_err()
            .contains("ambiguous")
    );
}

#[test]
#[ignore = "oracle: STELA_T6000_MCC_DEVICE_TREE"]
fn original_j314s_pmgr_publishes_self_indices_without_activating_a_self_clock() {
    let input = std::env::var("STELA_T6000_MCC_DEVICE_TREE").expect("explicit original ADT input");
    let bytes = std::fs::read(&input).unwrap();
    assert_eq!(
        stela_formats::sha256(&bytes),
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
    );
    let root = Node::root(&bytes).unwrap();
    let io = root.child("arm-io").unwrap();
    let node = io.child("pmgr").unwrap();
    let states = super::super::source_power_states(&root, &node, &|address, bytes| {
        io.translate_range(address, bytes)
    })
    .unwrap();
    assert_eq!(states.domains.len(), 355);
    let provider = selected(&states);
    assert_eq!(provider.name, "/arm-io/pmgr".to_string());
    assert_eq!(provider.clocks, [197, 198, 199, 200].map(domain_id));
    assert!(provider.activated_clocks().is_empty());
    assert_eq!(validate_power_graph(&states), Ok(()));
    assert!(
        states
            .domains
            .iter()
            .all(|domain| ![197, 198, 199, 200].contains(&domain.id.device))
    );
    assert!(
        states
            .resources
            .iter()
            .filter(|resource| resource.name != "/arm-io/pmgr")
            .all(|resource| resource.clock_role == ClockRole::Consumer)
    );
    let mut checked = states.clone();
    assert_eq!(checked.apply_admission(&bytes, &[]), Ok(0));
    assert_eq!(checked, states);
}
/// Pins the selected constructor/start/super/receiver family, rather than
/// treating missing numeric DeviceIDs as evidence of a passive provider.

#[test]
#[ignore = "oracle: STELA_TEST_PMGR_M1_KERNELCACHE, STELA_TEST_PMGR_M2_KERNELCACHE"]
fn original_m1_m2_pro_max_provider_start_uses_the_io_service_superclass() {
    for (variable, hash, windows, pointers) in [
        (
            "STELA_TEST_PMGR_M1_KERNELCACHE",
            "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90",
            &[
                (
                    0x2b0c17c,
                    0xf78,
                    "54179ac07c9aa7bc3f6ce802913f105ef1b889c3097fb6e428dce34d4788aa90",
                ),
                (
                    0x53fc7b4,
                    0xdc,
                    "c918c75f21fe4bd8719371229fee5f4adef4eae75ec8a81dbcc9062fa4b7d48f",
                ),
                (
                    0x2e3fbd0,
                    0x20,
                    "bbbc704f8793362e1e461532fe9b18f6b8d185c42eb25ee58cf1cc72c3bdefc9",
                ),
                (
                    0x2e3fbf0,
                    0xd4,
                    "a9968f386be6354b23ccaa41a9c4dd3aba13b81da53068a8cb31dfced374d158",
                ),
            ][..],
            &[
                (0x1367620, 0x80113c6802b0c17cu64), // AppleT6000PMGR::start
                (0x1369df8, 0x80113c6802b0c17cu64), // AppleT6001PMGR::start
                (0x1246900, 0x80113c68053fc7b4u64), // ApplePMGRBase::start
            ][..],
        ),
        (
            "STELA_TEST_PMGR_M2_KERNELCACHE",
            "ef4712e54102b35c11665c46fa7543a3fafc0c419723f583cb0ac891016f531a",
            &[
                (
                    0x2b3111c,
                    0xf78,
                    "fbad15dba43654f8d970074d1feeaf07a36d91fc179a70d7d7ad2f42da382e2a",
                ),
                (
                    0x5418ce8,
                    0xdc,
                    "81bdfdbfb267a7ec5243e59b350b1912a82ffe1c1747d72d86c2eeec4447e1c0",
                ),
                (
                    0x2ec4520,
                    0x20,
                    "cb1a32f630dc5a6dc2c95cae73121f42b468c071378e625c997803dbc80bc1be",
                ),
                (
                    0x2ec4540,
                    0xd4,
                    "a9968f386be6354b23ccaa41a9c4dd3aba13b81da53068a8cb31dfced374d158",
                ),
            ][..],
            &[
                (0x1352870, 0x80113c6802b3111cu64), // AppleT6020PMGR::start
                (0x1353b48, 0x80113c6802b3111cu64), // AppleT6021PMGR::start
                (0x12773e0, 0x80113c6805418ce8u64), // ApplePMGRBase::start
            ][..],
        ),
    ] {
        let bytes = std::fs::read(std::env::var(variable).unwrap()).unwrap();
        assert_eq!(stela_formats::sha256(&bytes), hash);
        for &(offset, length, expected) in windows {
            assert_eq!(
                stela_formats::sha256(&bytes[offset..offset + length]),
                expected
            );
        }
        for &(offset, expected) in pointers {
            assert_eq!(
                u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                expected
            );
        }
    }
}
#[test]
#[ignore = "oracle: STELA_TEST_PMGR_M1_KERNELCACHE"]
fn original_provider_start_and_clock_receiver_source_is_pinned() {
    let input =
        std::env::var("STELA_TEST_PMGR_M1_KERNELCACHE").expect("explicit original KC input");
    let bytes = std::fs::read(input).unwrap();
    assert_eq!(
        stela_formats::sha256(&bytes),
        "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90"
    );
    // Full original functions: cached metadata, no-op processDevice,
    // selected provider start/super/init, handle binding and later use.
    for (offset, length, expected) in [
        (
            0x1c6d250,
            0x8,
            "d33fdb74881bcff46b1cf4fc3e20479b1882e0e683789e80e6d650554066a1aa",
        ), // armio_process_device
        (
            0x1c6ebc0,
            0x64c,
            "197cadb9f664a0c2293977c615fbdf10d3e35e97d67dd24715aab7affa0a67e1",
        ), // armdevice_init
        (
            0x1c6e5f8,
            0x110,
            "cc54a3cacbeb11da548c202e6143093ae22271471e2f35abb8abc971fda62c3d",
        ), // armdevice_enable_clock
        (
            0x2e3f5c4,
            0x40c,
            "817fb4a8846edb8215ad41b3c3f1745d3a6ececcd22254285f7815b59b465d9c",
        ), // t600xio_start
        (
            0x2e3fbd0,
            0x20,
            "bbbc704f8793362e1e461532fe9b18f6b8d185c42eb25ee58cf1cc72c3bdefc9",
        ), // t600xio_process_device
        (
            0x2e3fbf0,
            0xd4,
            "a9968f386be6354b23ccaa41a9c4dd3aba13b81da53068a8cb31dfced374d158",
        ), // t600xio_enable_clock
        (
            0x2b5e364,
            0x38,
            "54d01b50e0e0acb0efd36385fa50573adbe5ec0a163a27fa6e9956a4d3bd2076",
        ), // pmgr_base_constructor
        (
            0x2b0bddc,
            0x1d0,
            "bd6700a082a356993e9199581ce617087441680e81da6f38bddeca0d117c27b8",
        ), // pmgr_constructor
        (
            0x2b0c17c,
            0xf78,
            "54179ac07c9aa7bc3f6ce802913f105ef1b889c3097fb6e428dce34d4788aa90",
        ), // pmgr_start
        (
            0x53fc7b4,
            0xe0,
            "6d3432cc9c3d1f09f0891e2a5997dc7c0a5bf967bbffa2942feac3e85c8e7169",
        ), // ioservice_start
        (
            0x2ef569c,
            0x4f0,
            "80554946546277370a0b7d4d9731b25aaa9ba5558b3d2122e65b9dc982108b5e",
        ), // t6000_init_driver
        (
            0x2b148d4,
            0x7f48,
            "69673cb487510ef1c4c55815433c6a546366562c45df25dc5231c55161b642bf",
        ), // base_init_driver
        (
            0x2b0fc44,
            0x1a0,
            "55cb4223dcb64ac82883321106df519148b75ede9c8f470bfd668b1acdc3543d",
        ), // clock_function_factory_entry
        (
            0x2b10118,
            0x50,
            "366ca3fe0548a5477cb3d820aea144f90e1ab32656ed818ba2d97ef414ea56fc",
        ), // clock_function_factory_selector
        (
            0x2b102cc,
            0x10,
            "8ac8861ddc82ab80512cc3dd237aa35905de3afe046742468f9d5f05e4e135ab",
        ), // clock_function_return
        (
            0x2b553d8,
            0x64,
            "f0a6d3315f213c81a194ed356b993633ee8c9cfa7e14cfba385023d6448886a4",
        ), // clock_function_bind
        (
            0x2b551e4,
            0x1f4,
            "1a6609f29d72aa34974302d623c0b852a95d4da7ff8158844afc991c6c227780",
        ), // clock_function_call
        (
            0x2b407d0,
            0x19c,
            "7d1238aebd1bcabef757a3db6fb769ec5a885ef3b80775ff736cac9485bf5c3e",
        ), // enable_device
        (
            0x2b4096c,
            0x88,
            "a4d4d8a8b8b23722ac9293acff03dbbfdab9b69d2abf1431968e533006381c7f",
        ), // enable_device_gated
        (
            0x2b20e70,
            0x90,
            "b220c387181e5bc34be6ba7577e7647dc5124041428fdbc121cab8ccd4c5435e",
        ), // device_id_lookup
        (
            0x2b1fd24,
            0x18,
            "006d1c913997b6f4d6ece3c3256e2b95a0dec9021769d0d9e8248bc8abe6d588",
        ), // effective_device_id
    ] {
        assert_eq!(
            stela_formats::sha256(&bytes[offset..offset + length]),
            expected
        );
    }
    // Selected vtable and GOT bindings, including PMGR super-start
    // to IOService::start. Authenticated source pointers are kept intact.
    for (offset, expected) in [
        (0x13156b0, 0x80113c6802b0c17cu64), // selected_t6000_start
        (0x1315d78, 0x8011e86802ef569cu64), // selected_t6000_init
        (0x1246900, 0x80113c68053fc7b4u64), // pmgr_super_start
        (0x13156a0, 0x80117d59053fc894u64), // selected_t6000_register_service
        (0xf8dd90, 0x8011d07d01c6e5f8u64),  // armdevice_clock
        (0x12f8db0, 0x801161db02e3fbf0u64), // t600xio_clock
        (0x1241a38, 0x8041754702b551e4u64), // clock_handle_call
        (0x1315a08, 0x80115a1702b407d0u64), // selected_pmrg_enable
        (0x1302c68, 0x10000000f8ca60u64),   // t600xio_process_super_vtable
        (0x133e068, 0x10000001239c20u64),   // t6000_init_super_vtable
        (0xf8d350, 0x8011a9f001c6d250u64),  // t600xio_process_super
        (0x123a8e8, 0x8011e86802b148d4u64), // t6000_init_super
    ] {
        assert_eq!(
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
            expected
        );
    }
}
