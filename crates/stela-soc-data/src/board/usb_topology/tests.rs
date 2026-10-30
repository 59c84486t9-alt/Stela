use super::super::*;
use super::*;
use crate::board::fixture_support::{flat_fixture_extent, tree, tree_with_io};

#[test]
fn compatible_admission_checks_the_full_list() {
    for (name, list) in [
        (
            "i2c,t8101",
            b"i2c,t8101\0i2c,s5l8940x\0iic,soft\0".as_slice(),
        ),
        ("i2c,t6000", b"i2c,t6000\0i2c,s5l8940x\0iic,soft\0"),
        ("i2c,t6020", b"i2c,t6020\0i2c,s5l8940x\0iic,soft\0"),
    ] {
        assert!(i2c_compatible(name, None));
        assert!(i2c_compatible(name, Some(list)));
    }
    for (name, list) in [
        (
            "usb-drd,t8103",
            b"usb-drd,t6000\0usb-drd,t8103\0".as_slice(),
        ),
        ("usb-drd,t8112", b"usb-drd,t6020\0usb-drd,t8112\0"),
        ("usb-drd,t8122", b"usb-drd,t8122"),
    ] {
        assert!(usb_controller_compatible(name, None));
        assert!(usb_controller_compatible(name, Some(list)));
    }
    assert!(atc_phy_compatible(
        ATC_PHY,
        Some(b"atc-phy,t6020\0atc-phy,t8112\0")
    ));
    assert!(atc_phy_compatible(
        "atc-phy,t6000",
        Some(b"atc-phy,t6000\0")
    ));
    for (name, accepts) in [
        (
            "i2c,t8101",
            i2c_compatible as fn(&str, Option<&[u8]>) -> bool,
        ),
        ("usb-drd,t8112", usb_controller_compatible),
        (ATC_PHY, atc_phy_compatible),
    ] {
        for list in [
            format!("unknown\0{name}\0").into_bytes(),
            format!("{name}\0unknown\0").into_bytes(),
            format!("{name}\0\0unknown\0").into_bytes(),
            [b"\xff\0".as_slice(), name.as_bytes()].concat(),
        ] {
            assert!(!accepts(name, Some(&list)), "{name}: {list:?}");
        }
    }
    assert!(!i2c_compatible(
        "i2c,t8101",
        Some(b"i2c,t9999\0i2c,t8101\0")
    ));
    assert!(!i2c_compatible(
        "i2c,t8101",
        Some(b"i2c,s5l8940x\0i2c,t8101\0")
    ));
    assert!(!i2c_compatible("i2c,s5l8940x", None));
    assert!(!i2c_compatible("iic,soft", None));
    assert!(!usb_controller_compatible(
        "usb-drd,t8112",
        Some(b"usb-drd,t9999\0usb-drd,t8112\0")
    ));
    assert!(!usb_controller_compatible(
        "usb-drd,t8112",
        Some(b"usb-drd,t8103\0usb-drd,t8112\0")
    ));
    assert!(!atc_phy_compatible(
        ATC_PHY,
        Some(b"atc-phy,t9999\0atc-phy,t8112\0")
    ));
    assert!(!atc_phy_compatible(
        ATC_PHY,
        Some(b"atc-phy,t8112\0atc-phy,t6020\0")
    ));
    // A supplied property must contain the requested model name.
    assert!(!i2c_compatible("i2c,t6000", Some(b"i2c,t8101\0")));
    assert!(!usb_controller_compatible(
        "usb-drd,t6020",
        Some(b"usb-drd,t8112\0")
    ));
    assert!(!atc_phy_compatible(
        "atc-phy,t6000",
        Some(b"atc-phy,t8112\0")
    ));
}

#[test]
fn typec_placement_distinguishes_i2c_addresses_from_mmio_and_preserves_phy_aliases() {
    use stela_contracts::adt::encode;
    let c = |v: &[u32]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
    let r = |v: &[u64]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
    let hpm = |name: &[u8], address: u32, rid: u32, personality: Option<&[u8]>| {
        let mut properties = vec![("name", name), ("compatible", b"usbc,cd3217\0".as_slice())];
        let address = c(&[address]);
        let (provider, port, rid) = (c(&[0x9b]), c(&[1]), c(&[rid]));
        properties.extend([
            ("hpm-iic-addr", address.as_slice()),
            ("iicProvider", provider.as_slice()),
            ("port-number", port.as_slice()),
            ("rid", rid.as_slice()),
        ]);
        properties.extend(personality.map(|p| ("usbc-fw-personality", p)));
        encode(&properties, &[])
    };
    let manager = encode(
        &[
            ("name", b"hpmBusManager\0"),
            ("compatible", b"usbc,manager\0"),
            ("reg", &c(&[0x6b, 2500, 0, 0])),
            ("AAPL,phandle", &c(&[0x9b])),
            ("interrupt-parent", &c(&[0x6a])),
            ("interrupts", &c(&[8, 1])),
        ],
        &[
            hpm(b"hpm0\0", 0x38, 0, Some(b"HPM,47\0")),
            hpm(b"hpm1\0", 0x3f, 1, None),
            hpm(b"hpm3\0", 0x3c, 3, None),
            hpm(b"hpm2\0", 0x3b, 2, Some(b"HPM,47-P23\0")),
        ],
    );
    let gpio = GpioBank {
        profile: crate::gpio::Profile::T8101,
        no_restore_pins: Vec::new(),
        physical: 0x23c100000,
        bytes: 0x100000,
        pins: 213,
        groups: 7,
        phandle: 0x6a,
        lines: vec![199],
        i2c_lines: vec![],
    };
    let i2c_with = |compatible: &[u8]| {
        encode(
            &[
                ("name", b"i2c0\0"),
                ("compatible", compatible),
                ("reg", &r(&[0x35010000, 0x4000])),
                ("interrupt-parent", &c(&[0x63])),
                ("interrupts", &c(&[761])),
            ],
            core::slice::from_ref(&manager),
        )
    };
    let i2c = i2c_with(b"i2c,t8101\0");
    let mut views = vec![(0x383000000, 0x4000); 29];
    views[0] = (0x382a90000, 0x4000);
    views[1] = (0x382800000, 0x4000);
    views[2] = (0x383020000, 0x4000);
    views[4] = (0x383002000, 0x4000);
    let phy_views = |compatible: &[u8], views: &[(u64, u64)]| {
        encode(
            &[
                ("name", b"atc-phy0\0"),
                ("compatible", compatible),
                ("AAPL,phandle", &c(&[0xa2])),
                ("port-number", &c(&[1])),
                (
                    "reg",
                    &r(&views.iter().flat_map(|&(a, n)| [a, n]).collect::<Vec<_>>()),
                ),
            ],
            &[],
        )
    };
    let phy = |compatible: &[u8]| phy_views(compatible, &views);
    let usb = encode(
        &[
            ("name", b"usb-drd0\0"),
            ("device_type", b"usb-drd\0"),
            ("atc-phy-parent", &c(&[0xa2])),
            (
                "reg",
                &r(&[
                    0x382280000,
                    0x11800,
                    0x382200000,
                    0x4000,
                    0x38228c000,
                    0x5800,
                    0x382a84000,
                    0x4000,
                    0x382800000,
                    0x4000,
                ]),
            ),
        ],
        &[],
    );
    // ACIO also references the PHY, but is not its USB pipehandler.
    let acio = encode(
        &[
            ("name", b"acio0\0"),
            ("device_type", b"acio\0"),
            ("atc-phy-parent", &c(&[0xa2])),
            ("reg", &r(&[0x381f00000, 0x100000])),
        ],
        &[],
    );
    let io = encode(
        &[("name", b"arm-io\0")],
        &[i2c.clone(), phy(b"atc-phy,t8112\0"), usb.clone(), acio],
    );
    let translate = |a| Some(if a < 0x100000000 { a + 0x200000000 } else { a });
    let place = |io: &[u8], aic, gpio| {
        typec_devices(
            &Node::root(io).unwrap(),
            &flat_fixture_extent(&translate),
            aic,
            gpio,
        )
    };
    let (buses, phys) = place(&io, 0x63, Some(&gpio)).unwrap();
    assert_eq!(buses[0].device.physical, 0x235010000);
    assert_eq!(buses[0].device.irq, 761);
    // Every die shares the manager's GPIO line; a die that names no
    // image runs the one of the flash-updated die below it in rid order.
    let hpm = |address, port, image: &str| I2cAddress {
        address,
        compatible: HPM.into(),
        interrupt: Some(8),
        firmware: Some(image.into()),
        port,
    };
    assert_eq!(
        buses[0].targets,
        [
            I2cAddress {
                address: 0x6b,
                compatible: HPM_MANAGER.into(),
                interrupt: Some(8),
                firmware: None,
                port: None,
            },
            hpm(0x38, Some(1), "HPM,47"),
            hpm(0x3f, Some(1), "HPM,47"),
            hpm(0x3c, Some(1), "HPM,47-P23"),
            hpm(0x3b, Some(1), "HPM,47-P23"),
        ]
    );
    // A board with these buses carries each image its dies run, once.
    let mut with_buses = board(&tree(
        0x8112,
        "Apple M2",
        ["uart-1,samsung", "wdt,s5l8960x", "aic,2"],
    ))
    .unwrap();
    assert!(with_buses.firmware_files().is_empty());
    with_buses.i2cs = buses.clone();
    assert_eq!(
        with_buses.firmware_files(),
        ["USB-C_HPM,47.bin", "USB-C_HPM,47-P23.bin"]
    );
    // The manager's line must be a visible AP GPIO pin.
    assert!(place(&io, 0x63, None).is_err());
    assert_eq!(phys[0].usb2, (0x382a90000, 0x4000));
    assert_eq!(phys[0].core, (0x383000000, atc_phy::CORE_BYTES));
    assert_eq!(phys[0].pipe, Some((0x382a84000, 0x4000)));
    assert_eq!(phys[0].events, (0x382800000, 0x4000));
    assert_eq!(phys[0].views, views);
    assert!(place(&io, 0x99, Some(&gpio)).is_err());
    assert!(
        typec_devices(
            &Node::root(&io).unwrap(),
            &flat_fixture_extent(&|_| None),
            0x63,
            Some(&gpio)
        )
        .is_err()
    );
    for compatible in [
        I2C,
        HPM_MANAGER,
        HPM,
        ATC_PHY,
        "atc-phy,t6020",
        "atc-phy,t8103",
    ] {
        assert!(models(compatible, |_| None));
    }
    // The T6020 layout has the 28 views the T8112's starts with; its
    // first compatible, not the T8112 one it also lists, selects it.
    let t6020 = |views: &[(u64, u64)]| {
        encode(
            &[("name", b"arm-io\0")],
            &[
                i2c.clone(),
                phy_views(b"atc-phy,t6020\0atc-phy,t8112\0", views),
                usb.clone(),
            ],
        )
    };
    let (_, phys) = place(&t6020(&views[..ATC_PHY_BASE_VIEWS]), 0x63, Some(&gpio)).unwrap();
    assert_eq!(phys[0].core, (0x383000000, atc_phy::CORE_BYTES));
    assert_eq!(phys[0].events, (0x382800000, 0x4000));
    assert!(place(&t6020(&views), 0x63, Some(&gpio)).is_err());
    // A PHY no controller names keeps its event block, without a
    // pipehandler.
    let alone = encode(
        &[("name", b"arm-io\0")],
        &[i2c.clone(), phy(b"atc-phy,t8112\0")],
    );
    let (_, phys) = place(&alone, 0x63, Some(&gpio)).unwrap();
    assert_eq!(
        (phys[0].pipe, phys[0].events),
        (None, (0x382800000, 0x4000))
    );
    for compatible in [
        b"i2c,t6000\0i2c,s5l8940x\0iic,soft\0".as_slice(),
        b"i2c,t6020\0i2c,s5l8940x\0iic,soft\0",
    ] {
        let bytes = encode(&[("name", b"arm-io\0")], &[i2c_with(compatible)]);
        let (controllers, _) = place(&bytes, 0x63, Some(&gpio)).unwrap();
        assert_eq!(controllers, buses);
    }
    for compatible in [
        b"i2c,t9999\0i2c,t8101\0".as_slice(),
        b"i2c,t8101\0i2c,t9999\0",
        b"unknown\0i2c,t8101\0",
    ] {
        let bytes = encode(&[("name", b"arm-io\0")], &[i2c_with(compatible)]);
        assert!(
            place(&bytes, 0x63, Some(&gpio))
                .unwrap_err()
                .to_string()
                .contains("qualified compatible list")
        );
    }
    for compatible in [
        b"atc-phy,t9999\0atc-phy,t8112\0".as_slice(),
        b"atc-phy,t8112\0atc-phy,t9999\0",
        b"unknown\0atc-phy,t8112\0",
    ] {
        let bytes = encode(&[("name", b"arm-io\0")], &[phy(compatible)]);
        assert!(
            place(&bytes, 0x63, Some(&gpio))
                .unwrap_err()
                .to_string()
                .contains("qualified compatible list")
        );
    }
    let t6000 = encode(
        &[("name", b"arm-io\0")],
        &[phy_views(b"atc-phy,t6000\0", &views[..ATC_PHY_BASE_VIEWS])],
    );
    let (_, phys) = place(&t6000, 0x63, None).unwrap();
    assert_eq!(phys.len(), 1);
    assert_eq!(phys[0].phandle, 0xa2);
    assert_eq!(phys[0].core, (0x383000000, atc_phy::CORE_BYTES));
    // The retimer's register protocol is undetermined: hidden, not refused.
    assert!(!models(RETIMER, |_| None));
    // Hidden PHYs are not parsed or mapped because reg survives.
    let io = encode(&[("name", b"arm-io\0")], &[i2c, phy(b"hidden\0"), usb]);
    assert!(place(&io, 0x63, Some(&gpio)).unwrap().1.is_empty());
}

#[test]
fn usb_placement_uses_identity_ranges_mapper_and_all_interrupts() {
    use stela_contracts::adt::encode;
    let words = |cells: &[u32]| {
        cells
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let pairs = |cells: &[(u64, u64)]| {
        cells
            .iter()
            .flat_map(|&(a, b)| [a, b])
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let ranges = [
        (0x382280000, 0x11800),
        (0x382200000, 0x4000),
        (0x38228c000, 0x5800),
        (0x382a84000, 0x4000),
        (0x382800000, 0x4000),
        (0x382a80000, 0x4000),
        (0x382000000, 0x4000),
        (0x382080000, 0x4000),
        (0x38228d000, 0x4000),
    ];
    let mapper = encode(
        &[
            ("name", b"mapper-usb0\0"),
            ("compatible", b"iommu-mapper\0"),
            ("reg", &words(&[1])),
            ("AAPL,phandle", &words(&[0xa4])),
        ],
        &[],
    );
    // One-instance fixture: the independent Type-C worker owns the
    // production two-instance USB DART layout and SID remap.
    let dart = encode(
        &[
            ("name", b"dart-usb0\0"),
            ("compatible", b"dart,t8110\0"),
            ("reg", &pairs(&[(0x382f00000, 0x4000)])),
            ("instance", b"TRAD\0\0\0\0DART\0\0\0\0"),
            ("sid-count", &words(&[16])),
            ("interrupts", &words(&[1035])),
        ],
        &[mapper],
    );
    let usb_with = |compatible: &[u8], ranges: &[(u64, u64)], parent: u32, irqs: &[u32]| {
        encode(
            &[
                ("name", b"usb-drd0\0"),
                ("compatible", compatible),
                ("reg", &pairs(ranges)),
                ("iommu-parent", &words(&[parent])),
                ("interrupts", &words(irqs)),
                ("port-number", &words(&[1])),
                ("atc-phy-parent", &words(&[0xa2])),
            ],
            &[],
        )
    };
    let usb = |ranges: &[(u64, u64)], parent, irqs: &[u32]| {
        usb_with(b"usb-drd,t8112\0", ranges, parent, irqs)
    };
    let irqs = [1031, 1032, 1033, 1034, 990];
    let tree = |usb| {
        tree_with_io(
            0x8112,
            "Apple M2",
            [UART, WATCHDOG, "aic,2"],
            &[],
            &[dart.clone(), usb],
        )
    };
    let found = board(&tree(usb(&ranges, 0xa4, &irqs))).unwrap();
    assert_eq!(
        found.usbs,
        [UsbController {
            ranges,
            irqs,
            iommu: 0,
            phandle: None,
            mapper: 0xa4,
            mapper_context: 1,
            stream: 1,
            port: 1,
            retention: false,
            phy: 0xa2,
        }]
    );
    for (compatible, bytes) in [
        (b"usb-drd,t8103\0".as_slice(), 0x1800),
        (b"usb-drd,t6000\0usb-drd,t8103\0", 0x1800),
        (b"usb-drd,t6020\0usb-drd,t8112\0", 0x5800),
        (b"usb-drd,t8122\0", 0x5800),
    ] {
        let mut family_ranges = ranges;
        family_ranges[2].1 = bytes;
        let family = board(&tree(usb_with(compatible, &family_ranges, 0xa4, &irqs))).unwrap();
        assert_eq!(family.usbs.len(), 1);
        assert_eq!(family.usbs[0].ranges, family_ranges);
        family_ranges[2].1 = if bytes == 0x1800 { 0x5800 } else { 0x1800 };
        assert!(board(&tree(usb_with(compatible, &family_ranges, 0xa4, &irqs))).is_err());
    }
    assert!(
        board(&tree(usb_with(
            b"usb-drd,t8103\0usb-drd,t8112\0",
            &ranges,
            0xa4,
            &irqs,
        )))
        .is_err()
    );
    assert_eq!(found.darts[0].instances[0].physical, 0x382f00000);
    for compatible in [
        b"usb-drd,t8132\0".as_slice(),
        b"usb-drd,t8142\0",
        b"usb-drd,t8152\0",
        b"usb-drd,t9999\0usb-drd,generic\0",
        b"usb-drd,t9999\0usb-drd,t8112\0",
        b"usb-drd,t8112\0usb-drd,t9999\0",
        b"unknown\0usb-drd,t8112\0",
    ] {
        let bytes = usb_with(compatible, &ranges, 0xa4, &irqs);
        let node = Node::root(&bytes).unwrap();
        assert!(
            usb_controller(&node, &flat_fixture_extent(&Some), &found.darts)
                .unwrap_err()
                .to_string()
                .contains("qualified USB DRD layout")
        );
    }
    let bytes = usb(&ranges, 0xa4, &irqs);
    let node = Node::root(&bytes).unwrap();
    let mut routes = found.darts.clone();
    routes[0].profile = crate::dart::Profile::T6000;
    routes[0].remap = vec![(0, 1)];
    routes[0].sids = vec![1, 3];
    let routed = usb_controller(&node, &flat_fixture_extent(&Some), &routes).unwrap();
    assert_eq!(
        (routed.mapper, routed.mapper_context, routed.stream),
        (0xa4, 1, 0)
    );
    routes[0].sids = vec![0, 3];
    assert!(
        usb_controller(&node, &flat_fixture_extent(&Some), &routes)
            .unwrap_err()
            .to_string()
            .contains("SID set")
    );
    routes[0].sids = vec![1, 3];
    routes[0].mappers.push((0xa4, 3));
    assert!(
        usb_controller(&node, &flat_fixture_extent(&Some), &routes)
            .unwrap_err()
            .to_string()
            .contains("ambiguous")
    );
    // Every controller is placed, in DeviceTree order; a malformed
    // second one names itself.
    let second = encode(
        &[
            ("name", b"usb-drd1\0"),
            ("compatible", b"usb-drd,t8112\0"),
            ("reg", &pairs(&ranges)),
            ("iommu-parent", &words(&[0xa4])),
            ("interrupts", &words(&irqs)),
            ("port-number", &words(&[2])),
            ("atc-phy-parent", &words(&[0xa3])),
        ],
        &[],
    );
    let pair = |second| {
        tree_with_io(
            0x8112,
            "Apple M2",
            [UART, WATCHDOG, "aic,2"],
            &[],
            &[dart.clone(), usb(&ranges, 0xa4, &irqs), second],
        )
    };
    let ports: Vec<_> = board(&pair(second))
        .unwrap()
        .usbs
        .iter()
        .map(|u| u.port)
        .collect();
    assert_eq!(ports, [1, 2]);
    let unnumbered = encode(
        &[
            ("name", b"usb-drd1\0"),
            ("compatible", b"usb-drd,t8112\0"),
            ("reg", &pairs(&ranges)),
            ("iommu-parent", &words(&[0xa4])),
            ("interrupts", &words(&irqs)),
        ],
        &[],
    );
    assert_eq!(
        board(&pair(unnumbered)).unwrap_err().to_string(),
        "usb-drd1 has no Type-C port number"
    );
    assert!(models(USB_DRD, |_| None));
    assert!(board(&tree(usb(&ranges, 0xff, &irqs))).is_err());
    assert!(board(&tree(usb(&ranges, 0xa4, &irqs[..4]))).is_err());
    let mut bad = ranges;
    bad[2].0 += 4;
    assert!(board(&tree(usb(&bad, 0xa4, &irqs))).is_err());
    let mut bad = ranges;
    bad[0].1 = u64::MAX;
    assert!(board(&tree(usb(&bad, 0xa4, &irqs))).is_err());
}
