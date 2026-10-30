use super::fixture_support::*;
use super::power_resources::PMGR_DEVICE;
use stela_contracts::refuse;

use super::*;

#[test]
fn family_models_validate_the_supplied_compatible_property() {
    for (name, valid, invalid) in [
        (
            I2C,
            b"i2c,t8101\0i2c,s5l8940x\0iic,soft\0".as_slice(),
            b"i2c,t9999\0i2c,t8101\0".as_slice(),
        ),
        (
            USB_DRD,
            b"usb-drd,t6020\0usb-drd,t8112\0",
            b"usb-drd,t9999\0usb-drd,t8112\0",
        ),
        (
            ATC_PHY,
            b"atc-phy,t6020\0atc-phy,t8112\0",
            b"atc-phy,t9999\0atc-phy,t8112\0",
        ),
    ] {
        assert!(models(name, |_| None));
        assert!(models(name, |key| (key == "compatible").then_some(valid)));
        assert!(!models(name, |key| (key == "compatible").then_some(invalid)));
        let unknown_fallback = [name.as_bytes(), b"\0unknown\0"].concat();
        assert!(!models(name, |key| (key == "compatible")
            .then_some(unknown_fallback.as_slice())));
    }
    assert!(!models("i2c,s5l8940x", |_| None));
    assert!(!models("iic,soft", |_| None));
}

/// The M4 and later maps fill CTRR-A to D; a template group iBoot leaves
/// empty describes none.

#[test]
fn coresight_lock_uses_the_dt_component_base_and_stays_inside_its_region() {
    assert_eq!(
        place_coresight(3, &[(0x2_1001_0000, 0x300c8)]).unwrap(),
        CoreSight {
            cpu: 3,
            physical: 0x2_1001_0000,
            bytes: 0x300c8
        }
    );
    let mut component = place_coresight(3, &[(0x2_1001_0000, 0x300c8)]).unwrap();
    assert_eq!(component.pc_sampler(), Some(0x2_1004_0000));
    component.bytes = coresight::UTT_OFFSET + coresight::PC_SAMPLE + 7;
    assert_eq!(component.pc_sampler(), None);
    component.bytes += 1;
    assert_eq!(component.pc_sampler(), Some(0x2_1004_0000));
    for pairs in [
        vec![],
        vec![(0x2_1001_0001, 0x3c8)],
        vec![(0, 0)],
        vec![(0, 0x3c8)],
        vec![(u64::MAX - 0xfff, 4)],
    ] {
        assert!(place_coresight(0, &pairs).is_err());
    }
}

#[test]
fn dart_supply_ids_and_retention_come_from_dt_properties() {
    use stela_contracts::adt::encode;
    let reg = [0x35004000u64, 0x4000]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect::<Vec<_>>();
    let tree = |gates: &[u8], retention: bool, no_sleep: bool| {
        let mut props = vec![
            ("compatible", b"dart,t8110\0".as_slice()),
            ("reg", reg.as_slice()),
            ("instance", b"TRAD\0\0\0\0DART\0\0\0\0".as_slice()),
            ("sid-count", &b"\x10\0\0\0"[..]),
            ("interrupts", &b"\x01\x03\0\0"[..]),
            ("power-gates", gates),
        ];
        if retention {
            props.push(("retention", &[]));
        }
        if no_sleep {
            props.push(("no-sleep", &[]));
        }
        encode(&props, &[])
    };
    // A second die's device carries its die in the word's top nibble.
    let gates = [0x212u32, 0x1000_0216]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let encoded = tree(&gates, true, false);
    let node = Node::root(&encoded).unwrap();
    let dart = iommu(&node, &flat_fixture_extent(&|a| Some(a + 0x2_0000_0000))).unwrap();
    assert_eq!(
        dart.power_gates,
        [
            DomainId {
                die: 0,
                device: 0x212
            },
            DomainId {
                die: 1,
                device: 0x216
            }
        ]
    );
    assert!(dart.retention);
    for encoded in [
        tree(&gates[..3], false, false),
        tree(&u32::MAX.to_le_bytes(), false, false),
        tree(&0x0001_0212u32.to_le_bytes(), false, false),
        tree(&gates, true, true),
    ] {
        assert!(iommu(&Node::root(&encoded).unwrap(), &flat_fixture_extent(&Some)).is_err());
    }
}

#[test]
fn watchdog_side_words_use_independent_translated_dt_ranges() {
    use stela_contracts::adt::encode;
    let reg = [
        0x1000u64, 0x4000, 0xc218, 4, 0x8008, 4, 0x800c, 4, 0x8020, 4,
    ]
    .into_iter()
    .flat_map(u64::to_le_bytes)
    .collect::<Vec<_>>();
    let trigger = [0x10020304u32, 2, 0xf, 1, 0x10120304, 2, 0xf, 1]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let bit = |n: u32| n.to_le_bytes();
    let (zero, two) = (bit(0), bit(2));
    let tree = encode(
        &[
            ("reg", &reg),
            ("panic-save-flag-bit", &zero),
            ("panic-forcepoweroff-flag-bit", &two),
            ("trigger-config", &trigger),
        ],
        &[],
    );
    let n = Node::root(&tree).unwrap();
    assert_eq!(
        watchdog_side(&n, &flat_fixture_extent(&|a| Some(a + 0x2_0000_0000))).unwrap(),
        Some(WatchdogSide {
            words: vec![0x2_0000_c218, 0x2_0000_8008, 0x2_0000_800c, 0x2_0000_8020],
            // Trigger words are absolute physical addresses.
            triggers: vec![(0x2_1002_0304, 0xf, 1), (0x2_1012_0304, 0xf, 1)],
        })
    );
    assert!(watchdog_side(&n, &flat_fixture_extent(&|_| None)).is_err());
    let tree = encode(&[("reg", &reg), ("panic-save-flag-bit", &zero)], &[]);
    // reg[4] needs its force-power-off flag bit.
    assert!(watchdog_side(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some)).is_err());
    let tree = encode(
        &[
            ("reg", &reg[..48]),
            ("panic-save-flag-bit", &32u32.to_le_bytes()),
        ],
        &[],
    );
    assert!(watchdog_side(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some)).is_err());
    let tree = encode(&[("reg", &reg[..48]), ("panic-save-flag-bit", &zero)], &[]);
    assert_eq!(
        watchdog_side(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some))
            .unwrap()
            .unwrap()
            .words,
        [0xc218, 0x8008]
    );
    let tree = encode(&[("reg", &reg[..16])], &[]);
    assert_eq!(
        watchdog_side(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some)).unwrap(),
        None
    );
}

#[test]
#[ignore = "oracle: STELA_TEST_GPIO_DT"]
fn original_j314s_ap_gpio_checks_without_auxiliary_or_lifecycle_claims() {
    let data = std::fs::read(std::env::var("STELA_TEST_GPIO_DT").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&data),
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
    );
    let root = Node::root(&data).unwrap();
    let io = root.child("arm-io").unwrap();
    let bank = gpio_bank(
        &io,
        &|address, bytes| io.translate_range(address, bytes),
        130,
    )
    .unwrap()
    .unwrap();
    assert_eq!(bank.profile, crate::gpio::Profile::S5l8960x);
    assert_eq!(
        (
            bank.physical,
            bank.bytes,
            bank.pins,
            bank.groups,
            bank.phandle
        ),
        (0x39b028000, 0x4000, 255, 7, 136)
    );
    assert_eq!(bank.lines, [427, 428, 429, 430, 431, 432, 433]);
    assert_eq!(bank.no_restore_pins, [114, 115, 119]);
    for name in ["aop-gpio0", "nub-gpio0", "smc-gpio"] {
        let node = io.child(name).unwrap();
        assert!(gpio_profile(|key| node.property(key)).is_none());
    }
    assert_eq!(
        io.child("spi1").unwrap().cells32("function-spi_cs0"),
        Some(vec![136, GPIO_FUNCTION, 33, 0x10001])
    );
}

#[test]
fn rtbuddy_endpoint_selection_uses_protocol_and_rejects_ambiguity() {
    use stela_contracts::adt::encode;
    let endpoint = |name: &str, compatible: &str| {
        let name = [name.as_bytes(), &[0]].concat();
        let compatible = [compatible.as_bytes(), &[0]].concat();
        encode(&[("name", &name), ("compatible", &compatible)], &[])
    };
    for name in ["iop-gfx-nub", "iop-gfx-nub0", "arbitrary-label"] {
        let data = encode(&[], &[endpoint(name, RTBUDDY)]);
        let root = Node::root(&data).unwrap();
        assert_eq!(
            rtbuddy_nub(&root, "GFX").unwrap().property("name"),
            Some([name.as_bytes(), &[0]].concat().as_slice())
        );
    }
    let missing = encode(&[], &[endpoint("iop-gfx-nub", "unknown")]);
    assert!(rtbuddy_nub(&Node::root(&missing).unwrap(), "GFX").is_err());
    let duplicate = encode(&[], &[endpoint("a", RTBUDDY), endpoint("b", RTBUDDY)]);
    assert!(
        rtbuddy_nub(&Node::root(&duplicate).unwrap(), "GFX")
            .err()
            .unwrap()
            .to_string()
            .contains("ambiguous")
    );
    let child = encode(
        &[
            ("compatible", b"iop-nub,rtbuddy-v2\0"),
            ("remote-only", b""),
        ],
        &[],
    );
    let data = encode(&[], &[child]);
    assert!(
        rtbuddy_nub(&Node::root(&data).unwrap(), "GFX")
            .err()
            .unwrap()
            .to_string()
            .contains("remote-only")
    );
}

#[test]
fn rtbuddy_nubs_the_ap_does_not_wait_for_refuse() {
    use stela_contracts::adt::encode;
    let name = b"iop-pmp-nub ".to_vec();
    let set = 1u32.to_le_bytes().to_vec();
    let plain = encode(&[("name", &name)], &[]);
    assert!(awaited_nub(&Node::root(&plain).unwrap(), "PMP").is_ok());
    for flag in UNAWAITED_NUB {
        let data = encode(&[("name", &name), (flag, &set)], &[]);
        let error = awaited_nub(&Node::root(&data).unwrap(), "PMP").unwrap_err();
        assert!(error.to_string().contains(flag));
    }
}

#[test]
fn the_gfx_role_claims_a_native_rtkit_nub_and_waits_for_gpu_admission() {
    let gfx_role = |key: &str| (key == "role").then_some(b"GFX\0".as_slice());
    let claim = ROLE_MODELS
        .iter()
        .find(|claim| claim.compatible == ASC && claim.property == ("role", b"GFX\0"))
        .unwrap();
    assert_eq!(claim.children.len(), 1);
    assert_eq!(claim.children[0].compatible, RTBUDDY);
    let preloaded = |name| {
        claim.children[0]
            .boot_properties
            .iter()
            .any(|&(key, _)| key == name)
    };
    assert!(preloaded("pre-loaded") && preloaded("running"));
    // The coprocessor, the GPU and its firmware mapper are admitted
    // together; the SEP and SMC claims are untouched.
    assert_eq!(models(ASC, gfx_role), GPU_ADMITTED);
    assert_eq!(
        model_children(ASC, gfx_role).len(),
        usize::from(GPU_ADMITTED)
    );
    for gpu in [
        "gpu,t8112",
        "gpu,t8103",
        "gpu,t6000",
        "gpu,t6020",
        "gpu,t6021",
        "gpu,t6022",
    ] {
        assert_eq!(models(gpu, |_| None), GPU_ADMITTED);
    }
    // A GPU whose family the firmware model does not implement stays
    // hidden.
    assert!(!models("gpu,t8122", |_| None));
    assert!(!models("gpu,t6041", |_| None));
    assert_eq!(models(GFX_MAPPER, |_| None), GPU_ADMITTED);
    assert!(!models(ASC, |key| (key == "role").then_some(b"GFX2\0".as_slice())));
    assert!(models(SEP, |key| (key == "role").then_some(b"SEP\0".as_slice())));
    assert!(models(ASC, |key| (key == "role").then_some(b"SMC\0".as_slice())));
}

#[test]
fn a_board_takes_its_chip_and_pes_from_the_device_tree() {
    // J473AP (Mac14,3): cpu0-3 Blizzard E cores, cpu4-7 Avalanche P cores.
    let layout: Vec<(u8, u32)> = (0..8)
        .map(|cpu| {
            (
                if cpu < 4 { b'E' } else { b'P' },
                ((cpu / 4) << 8) | (cpu % 4),
            )
        })
        .collect();
    let found = cpus(0x8112, "Apple M2", &layout_of(&layout)).unwrap();
    assert_eq!(
        (found.chip, found.aic),
        (Chip::AppleM2, Some(("aic,2", 0x8000)))
    );
    let identities = found.processors;
    assert_eq!(
        identities[0],
        Identity {
            midr: 0x611f_0320,
            mpidr: 0x8000_0000,
            clock: Some(2_424_000_000),
            caches: Some(
                Caches::split_unified(cache(128 << 10, 8), cache(64 << 10, 8), cache(4 << 20, 16))
                    .unwrap()
            ),
        }
    );
    assert_eq!(
        identities[7],
        Identity {
            midr: 0x611f_0330,
            mpidr: 0x8001_0103,
            clock: Some(3_504_000_000),
            caches: Some(
                Caches::split_unified(
                    cache(192 << 10, 6),
                    cache(128 << 10, 8),
                    cache(16 << 20, 16)
                )
                .unwrap()
            ),
        }
    );
    // The level 2's capacity is the cpu node's.
    let mut sizeless = layout_of(&layout);
    sizeless[5].l2_bytes = None;
    assert!(cpus(0x8112, "Apple M2", &sizeless).is_err());
    // J604AP (Mac16,1): six M4 E cores and four P cores.
    let layout = [(b'E', 0), (b'E', 5), (b'P', 0x100), (b'P', 0x103)];
    let found = cpus(0x8132, "Apple M4", &layout_of(&layout)).unwrap();
    assert_eq!(
        (found.chip, found.aic),
        (Chip::AppleM4, Some(("aic,3", AIC3_EVENT)))
    );
    let identities = found.processors;
    assert_eq!(identities[1].midr, 0x611f_0520);
    assert_eq!(
        identities[3],
        Identity {
            midr: 0x611f_0530,
            mpidr: 0x8001_0103,
            clock: None,
            caches: Some(
                Caches::split_unified(
                    cache(192 << 10, 6),
                    cache(128 << 10, 8),
                    cache(16 << 20, 16)
                )
                .unwrap()
            ),
        }
    );
    // An M2 Pro's AIC2 has its event register at +0xc000.
    assert_eq!(
        cpus(0x6020, "Apple M2 Pro", &layout_of(&layout))
            .unwrap()
            .aic,
        Some(("aic,2", 0xc000))
    );
    // The M3's AICv3 has it at +0x40000; J613AP has four E and four P
    // cores, within the M3's eight CPU slots (an M4's six E cores are
    // not).
    let j613 = [(b'E', 0), (b'E', 3), (b'P', 0x100), (b'P', 0x103)];
    assert_eq!(
        cpus(0x8122, "Apple M3", &layout_of(&j613)).unwrap().aic,
        Some(("aic,3", 0x40000))
    );
    assert!(
        cpus(0x8122, "Apple M3", &layout_of(&layout))
            .unwrap_err()
            .to_string()
            .contains("CPU slots")
    );
    assert_eq!(dram_base(0x8112), Ok(0x8_0000_0000));
    assert_eq!(dram_base(0x6021), Ok(0x100_0000_0000));
    for chip_id in [0x8132, 0x8140, 0x8142, 0x8152] {
        assert_eq!(dram_base(chip_id), Ok(0x100_0000_0000));
    }
    assert!(dram_base(0x8101).is_err());
    // Every ApChipID and name pair appears once, and the rows of one
    // ApChipID share its chip-level facts.
    for (index, soc) in SOCS.iter().enumerate() {
        for other in SOCS[index + 1..]
            .iter()
            .filter(|o| o.chip_id == soc.chip_id)
        {
            assert_ne!(other.name, soc.name);
            assert_eq!(
                (other.chip, other.pmgr, other.aic, other.dram_base),
                (soc.chip, soc.pmgr, soc.aic, soc.dram_base)
            );
            assert_eq!(
                (other.lockdown, other.limits, other.cpu_start),
                (soc.lockdown, soc.limits, soc.cpu_start)
            );
            assert_eq!(
                (other.memory_cache, other.clusters, other.aon_fuses),
                (soc.memory_cache, soc.clusters, soc.aon_fuses)
            );
        }
    }
}

#[test]
fn the_m6_kernel_bounds_its_cpus() {
    // Twelve PEs at J873gAP's affinities (its 0x102..0x105 are M cores).
    let mut j873g: Vec<(u8, u32)> = (0..6).map(|core| (b'E', core)).collect();
    j873g.extend((0..6).map(|core| (b'P', 0x100 + core)));
    let m6 = cpus(0x8152, "Apple M6", &layout_of(&j873g)).unwrap();
    assert_eq!(m6.processors.len(), 12);
    assert_eq!(m6.processors[11].mpidr, 0x8001_0105);
    j873g.push((b'P', 0x106));
    assert!(
        cpus(0x8152, "Apple M6", &layout_of(&j873g))
            .unwrap_err()
            .to_string()
            .contains("MAX_CPUS")
    );
}

#[test]
fn a_board_without_evidence_refuses() {
    let one = layout_of(&[(b'E', 0)]);
    // M2 Ultra: two M2 Max dies, the second die's P cores at Aff1 9.
    let ultra = cpus(
        0x6022,
        "Apple M2 Ultra",
        &layout_of(&[(b'E', 0x800), (b'P', 0x903)]),
    )
    .unwrap();
    assert_eq!(ultra.processors[0].mpidr, 0x8000_0800);
    assert_eq!(ultra.processors[1].mpidr, 0x8001_0903);
    assert_eq!(ultra.processors[1].midr, 0x611f_0390);
    // A SoC without a row.
    assert_eq!(
        cpus(0x8101, "Apple A14", &one),
        Err(refuse!(
            "ApChipID 0x8101 (Apple A14) has no public MIDR part"
        ))
    );
    assert!(cpus(0x8112, "Apple M2 Pro", &one).is_err());
    assert!(cpus(0x8112, "Apple M2", &[]).is_err());
    // The M6's M cores and a second die's affinity.
    assert_eq!(
        cpus(0x8152, "Apple M6", &layout_of(&[(b'M', 0)])),
        Err(refuse!("Apple M6 cluster type M has no public MIDR part"))
    );
    assert!(cpus(0x6031, "Apple M3 Max", &layout_of(&[(b'P', 0x1000)])).is_err());
}

#[test]
fn a_board_states_its_dram_base_or_takes_its_socs() {
    use stela_contracts::adt::encode;
    let z = |text: &str| [text.as_bytes(), &[0]].concat();
    let with_base = |base: Option<&[u8]>| {
        let mcc = base.map(|base| encode(&[("name", &z("mcc")), ("dram-base", base)], &[]));
        encode(
            &[("name", &z("device-tree"))],
            &[encode(&[("name", &z("arm-io"))], mcc.as_slice())],
        )
    };
    let m3 = 0x8122;
    let stated = 0x100_0000_0000_u64.to_le_bytes();
    // An M3 board states its base; an M5 board states none and takes its
    // SoC's.
    assert_eq!(
        board_dram_base(&with_base(Some(&stated)), m3),
        Ok(0x100_0000_0000)
    );
    assert_eq!(
        board_dram_base(&with_base(None), 0x8142),
        Ok(0x100_0000_0000)
    );
    assert!(board_dram_base(&with_base(None), 0x8101).is_err());
    // The M2's board states none and takes its SoC's base; a stated base
    // must agree with it.
    assert_eq!(board_dram_base(&with_base(None), 0x8112), Ok(0x8_0000_0000));
    assert!(board_dram_base(&with_base(Some(&stated)), 0x8112).is_err());
    assert!(board_dram_base(&with_base(Some(&[0; 4])), m3).is_err());
}

#[test]
fn board_intake_requires_exact_complete_device_tree_bytes() {
    let tree = tree(
        0x8112,
        "Apple M2",
        ["uart-1,samsung", "wdt,s5l8960x", "aic,2"],
    );
    assert!(board(&tree).is_ok());
    assert!(board_dram_base(&tree, 0x8112).is_ok());
    for suffix in [0, 0xa5] {
        let mut malformed = tree.clone();
        malformed.push(suffix);
        assert!(board(&malformed).is_err());
        assert!(board_dram_base(&malformed, 0x8112).is_err());
    }
    assert!(board(&tree[..tree.len() - 1]).is_err());
    assert!(board_dram_base(&tree[..tree.len() - 1], 0x8112).is_err());
}

#[test]
fn a_device_tree_places_the_board_or_says_why_it_cannot() {
    const MODELED: [&str; 3] = ["uart-1,samsung", "wdt,s5l8960x", "aic,2"];
    let found = board(&tree(0x8112, "Apple M2", MODELED)).unwrap();
    assert_eq!(found.cpus.chip, Chip::AppleM2);
    assert_eq!(found.cpus.processors[1].mpidr, 0x8001_0100);
    assert_eq!(
        found.uart,
        Device {
            physical: 0x2_3520_0000,
            bytes: 0x4000,
            irq: 739
        }
    );
    assert_eq!(found.watchdog.irq, 379);
    assert_eq!(
        found.coresight,
        vec![
            CoreSight {
                cpu: 0,
                physical: 0x2_1001_0000,
                bytes: 0x300c8
            },
            CoreSight {
                cpu: 1,
                physical: 0x2_1101_0000,
                bytes: 0x300c8
            },
        ]
    );
    // Each PE's cpu-impl-reg and each cluster's cpm-impl-reg, once.
    let block = |name, physical, control, cpu| LockdownBlock {
        name,
        physical,
        bytes: 0x9010,
        control,
        cpu,
    };
    assert_eq!(
        found.lockdown,
        [
            block("cpu-impl-reg", 0x2_1005_0000, 0x5000, Some(0)),
            block("cpm-impl-reg", 0x2_10e4_0000, 0x9000, None),
            block("cpu-impl-reg", 0x2_1105_0000, 0x5000, Some(1)),
            block("cpm-impl-reg", 0x2_11e4_0000, 0x9000, None),
        ]
    );
    // Each PE's sampler counters, in its cpu-impl-reg.
    let layout = crate::core_counters::layout(0x8112).unwrap();
    assert_eq!(
        found.counters,
        [
            CounterBlock {
                cpu: 0,
                physical: 0x2_1005_0000,
                layout
            },
            CounterBlock {
                cpu: 1,
                physical: 0x2_1105_0000,
                layout
            },
        ]
    );
    // The UART's input 739 is the highest that names the AIC.
    assert_eq!(
        found.aic,
        InterruptController {
            physical: 0x2_3b0c_0000,
            inputs: 740,
            layout: AicLayout::aic2(0x8000, 0)
        }
    );
    // The M1's AICv1 has its event register in its core block.
    let m1 = board(&tree(
        0x8103,
        "Apple M1",
        ["uart-1,samsung", "wdt,s5l8960x", "aic,1"],
    ))
    .unwrap();
    assert_eq!(
        (m1.cpus.chip, m1.aic.layout),
        (Chip::AppleM1, AicLayout::V1)
    );
    // The M1's SPTM locks the same blocks at the same offsets.
    assert_eq!(m1.lockdown, found.lockdown);
    assert_eq!(
        board(&tree(0x8103, "Apple M1", MODELED)),
        Err(refuse!("/arm-io/aic is not aic,1, the modeled device"))
    );
    assert_eq!(
        board(&tree(
            0x8112,
            "Apple M2",
            ["uart-2", "wdt,s5l8960x", "aic,2"]
        )),
        Err(refuse!(
            "/arm-io/uart0 is not uart-1,samsung, the modeled device"
        ))
    );
    assert_eq!(
        board(&tree(0x8122, "Apple M3", MODELED)),
        Err(refuse!("/arm-io/aic is not aic,3, the modeled device"))
    );
    assert!(board(&[0; 4]).is_err());
}

/// J473AP's `dart-sio` and the AES engine behind its `mapper-aes`.
#[test]
fn a_board_places_its_darts_and_the_aes_engine_behind_one() {
    use stela_contracts::adt::encode;
    const MODELED: [&str; 3] = ["uart-1,samsung", "wdt,s5l8960x", "aic,2"];
    let z = |text: &str| [text.as_bytes(), &[0]].concat();
    let u32s = |cells: &[u32]| {
        cells
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let u64s = |cells: &[u64]| {
        cells
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let mapper = |name: &str, phandle: u32, stream: u32| {
        encode(
            &[
                ("name", &z(name)),
                ("compatible", &z(IOMMU_MAPPER)),
                ("AAPL,phandle", &u32s(&[phandle])),
                ("reg", &u32s(&[stream])),
            ],
            &[],
        )
    };
    let instance = [b"TRAD".as_slice(), &[0; 4], b"DART", &[0; 4]].concat();
    let dart = |instance: &[u8], reg: &[u64]| {
        encode(
            &[
                ("name", &z("dart-sio")),
                ("compatible", &z(DART)),
                ("reg", &u64s(reg)),
                ("instance", instance),
                ("sid-count", &u32s(&[16])),
                ("interrupts", &u32s(&[0x301])),
            ],
            &[mapper("mapper-sio", 0x89, 0), mapper("mapper-aes", 0x8a, 1)],
        )
    };
    let aes = |parent: u32| {
        encode(
            &[
                ("name", &z("aes")),
                ("compatible", &z(AES)),
                ("reg", &u64s(&[0x3500_c000, 0x4000, 0x3d2d_c000, 0x8000])),
                ("interrupts", &u32s(&[0x2f7])),
                ("iommu-parent", &u32s(&[parent])),
                ("aes-version", &u32s(&[3])),
            ],
            &[],
        )
    };
    let sio = dart(&instance, &[0x3500_4000, 0x4000]);
    let found = board(&tree_with_io(
        0x8112,
        "Apple M2",
        MODELED,
        &[],
        &[sio.clone(), aes(0x8a)],
    ))
    .unwrap();
    assert_eq!(
        found.darts,
        [Iommu {
            profile: crate::dart::Profile::T8110,
            instances: vec![DartInstance {
                physical: 0x2_3500_4000,
                bytes: 0x4000,
                number: 0,
                reg_index: 0,
                owner: *b"DART\0\0\0\0"
            }],
            sids: vec![],
            remap: vec![],
            vm_base: 0,
            streams: 16,
            irq: 0x301,
            mappers: vec![(0x89, 0), (0x8a, 1)],
            apf: None,
            clock_gates: Vec::new(),
            power_gates: Vec::new(),
            retention: false,
            smmu: None,
        }]
    );
    assert_eq!(
        found.aes,
        Some(AesEngine {
            phandle: None,
            mapper: 0x8a,
            mapper_context: 1,
            instance: 0,
            ranges: [(0x2_3500_c000, 0x4000), (0x2_3d2d_c000, 0x8000)],
            dkey: None,
            config: crate::aes::Config {
                version: 3,
                address_width: crate::aes::DEFAULT_ADDRESS_WIDTH,
                key_disable: crate::aes::KeyDisable {
                    bytes: 0x8000,
                    word: 0,
                    keys: [None; 3],
                },
            },
            irq: 0x2f7,
            iommu: 0,
            stream: 1,
        })
    );
    // J773g: version 5 with its DKey range, 42-bit addresses and a
    // disable word per key.
    let m4 = |reg: &[u64], version: u32, gid1: &[u8]| {
        encode(
            &[
                ("name", &z("aes")),
                ("compatible", &z(AES)),
                ("reg", &u64s(reg)),
                ("interrupts", &u32s(&[0x425])),
                ("iommu-parent", &u32s(&[0x8a])),
                ("aes-version", &u32s(&[version])),
                ("address-width", &u32s(&[42])),
                ("sioaesdisable-offset", &u32s(&[0])),
                ("sioaesdisableuid1-offset", &u32s(&[0x40])),
                ("sioaesdisablegid0-offset", &u32s(&[0x44])),
                ("sioaesdisablegid1-offset", gid1),
            ],
            &[],
        )
    };
    let three = [
        0x3500_c000,
        0x4000,
        0x3d2d_c000,
        0x8000,
        0x3d07_8000,
        0x4000,
    ];
    let parse = |node: Vec<u8>| {
        board(&tree_with_io(
            0x8112,
            "Apple M2",
            MODELED,
            &[],
            &[sio.clone(), node],
        ))
        .map(|board| board.aes.unwrap())
    };
    let wide = parse(m4(&three, 5, &u32s(&[0x48]))).unwrap();
    assert_eq!(wide.dkey, Some((0x2_3d07_8000, 0x4000)));
    assert_eq!(
        wide.config,
        crate::aes::Config {
            version: 5,
            address_width: 42,
            key_disable: crate::aes::KeyDisable {
                bytes: 0x8000,
                word: 0,
                keys: [Some(0x40), Some(0x44), Some(0x48)],
            },
        }
    );
    assert_eq!(
        parse(m4(&three[..4], 5, &u32s(&[0x48]))),
        Err(refuse!("/arm-io/aes aes-version 5 has 2 register ranges"))
    );
    assert_eq!(
        parse(m4(&three, 3, &u32s(&[0x48]))),
        Err(refuse!("/arm-io/aes aes-version 3 has 3 register ranges"))
    );
    assert_eq!(
        parse(m4(&three, 5, &u32s(&[0x48, 0]))),
        Err(refuse!(
            "/arm-io/aes sioaesdisablegid1-offset is not one 32-bit cell"
        ))
    );
    assert_eq!(
        parse(m4(&three, 5, &u32s(&[0x44]))),
        Err(refuse!("/arm-io/aes: AES key-disable words overlap"))
    );
    assert_eq!(
        board(&tree_with_io(
            0x8112,
            "Apple M2",
            MODELED,
            &[],
            &[sio, aes(0x99)]
        )),
        Err(refuse!(
            "/arm-io/aes iommu-parent 0x99 is no modeled DART's mapper"
        ))
    );
    let bytes = tree_with_io(
        0x8112,
        "Apple M2",
        MODELED,
        &[],
        &[dart(&instance, &[0x35004000, 0x4000]), aes(0x8a)],
    );
    let io = Node::root(&bytes).unwrap().child("arm-io").unwrap();
    let mut routes = found.darts.clone();
    routes[0].profile = crate::dart::Profile::T6000;
    routes[0].remap = vec![(3, 1)];
    routes[0].sids = vec![0, 1, 15];
    let routed = aes_engine(&io, &flat_fixture_extent(&Some), &routes)
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            routed.instance,
            routed.mapper,
            routed.mapper_context,
            routed.stream
        ),
        (0, 0x8a, 1, 3)
    );
    let good = routes[0].clone();
    routes[0].mappers.push((0x8a, 2));
    assert!(
        aes_engine(&io, &flat_fixture_extent(&Some), &routes)
            .unwrap_err()
            .to_string()
            .contains("ambiguous")
    );
    routes[0] = good.clone();
    routes.push(good.clone());
    assert!(
        aes_engine(&io, &flat_fixture_extent(&Some), &routes)
            .unwrap_err()
            .to_string()
            .contains("ambiguous")
    );
    routes.pop();
    routes[0] = good.clone();
    routes[0].sids = vec![0, 15];
    assert!(
        aes_engine(&io, &flat_fixture_extent(&Some), &routes)
            .unwrap_err()
            .to_string()
            .contains("SID set")
    );
    routes[0] = good.clone();
    routes[0].streams = 1;
    assert!(
        aes_engine(&io, &flat_fixture_extent(&Some), &routes)
            .unwrap_err()
            .to_string()
            .contains("outside the native profile")
    );
    routes[0] = good.clone();
    routes[0].instances.push(good.instances[0].clone());
    assert!(
        aes_engine(&io, &flat_fixture_extent(&Some), &routes)
            .unwrap_err()
            .to_string()
            .contains("multi-instance")
    );
    routes[0].instances.clear();
    assert!(aes_engine(&io, &flat_fixture_extent(&Some), &routes).is_err());
    // An APF beside the DART needs its slice count.
    let dapf = [instance.as_slice(), b"FPAD", &[0; 4], b"DART", &[0; 4]].concat();
    let pmp = dart(&dapf, &[0x3b30_0000, 0x4000, 0x3b30_4000, 0x4000]);
    assert_eq!(
        board(&tree_with_io(0x8112, "Apple M2", MODELED, &[], &[pmp])),
        Err(refuse!(
            "/arm-io/dart-sio has no n-apfs-instance-0 slice count"
        ))
    );
    let three = dart(
        &[dapf.as_slice(), &dapf[16..]].concat(),
        &[
            0x3b30_0000,
            0x4000,
            0x3b30_4000,
            0x4000,
            0x3b30_8000,
            0x4000,
        ],
    );
    assert_eq!(
        board(&tree_with_io(0x8112, "Apple M2", MODELED, &[], &[three])),
        Err(refuse!(
            "/arm-io/dart-sio has unsupported instance kinds, numbering or APF topology"
        ))
    );
}

#[test]
fn darts_decode_distinct_windows_and_validate_stream_maps() {
    use stela_contracts::adt::encode;
    let cells = |values: &[u32]| {
        values
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let pairs = |values: &[u64]| {
        values
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let descriptors = [
        b"TRAD".as_slice(),
        &0u32.to_le_bytes(),
        b"DARTLLT\0",
        b"TRAD",
        &1u32.to_le_bytes(),
        b"DARTBLK\0",
    ]
    .concat();
    let reg = pairs(&[0x382f00000, 0x4000, 0x382f80000, 0x4000]);
    let build = |instance: &[u8], regs: &[u8], sids: &[u32], remap: &[u8]| {
        encode(
            &[
                ("name", b"dart-usb0\0"),
                ("compatible", b"dart,t8110\0"),
                ("reg", regs),
                ("instance", instance),
                ("sid-count", &cells(&[16])),
                ("interrupts", &cells(&[1035])),
                ("sid", &cells(sids)),
                ("remap", remap),
            ],
            &[encode(
                &[
                    ("name", b"mapper-usb0\0"),
                    ("compatible", b"iommu-mapper\0"),
                    ("reg", &cells(&[1])),
                    ("AAPL,phandle", &cells(&[0xa4])),
                ],
                &[],
            )],
        )
    };
    let bytes = build(&descriptors, &reg, &[1, 14], &[0, 1, 0, 0]);
    let found = iommu(
        &Node::root(&bytes).unwrap(),
        &flat_fixture_extent(&|a| Some(a)),
    )
    .unwrap();
    assert_eq!(
        found.instances,
        vec![
            DartInstance {
                physical: 0x382f00000,
                bytes: 0x4000,
                number: 0,
                reg_index: 0,
                owner: *b"DARTLLT\0"
            },
            DartInstance {
                physical: 0x382f80000,
                bytes: 0x4000,
                number: 1,
                reg_index: 1,
                owner: *b"DARTBLK\0"
            },
        ]
    );
    assert_eq!(found.mappers, [(0xa4, 1)]);
    assert_eq!(found.sids, [1, 14]);
    assert_eq!(found.remap, [(0, 1)]);
    for bad in [
        build(&descriptors[..7], &reg, &[1, 14], &[0, 1, 0, 0]),
        build(&descriptors[..31], &reg, &[1, 14], &[0, 1, 0, 0]),
        build(&descriptors, &reg, &[1, 16], &[0, 1, 0, 0]),
        build(&descriptors, &reg, &[1, 1], &[0, 1, 0, 0]),
        build(&descriptors, &reg, &[1, 14], &[0, 1, 1, 2]),
        build(&descriptors, &reg, &[1, 14], &[0, 16, 0, 0]),
        build(&descriptors, &reg, &[1, 14], &[0, 1]),
        build(
            &descriptors,
            &pairs(&[0x382f00000, 0x4000, 0x382f00000, 0x4000]),
            &[1, 14],
            &[0, 1, 0, 0],
        ),
    ] {
        assert!(
            iommu(
                &Node::root(&bad).unwrap(),
                &flat_fixture_extent(&|a| Some(a))
            )
            .is_err()
        );
    }
    let mut bad = descriptors.clone();
    bad[20..24].copy_from_slice(&0u32.to_le_bytes());
    let bytes = build(&bad, &reg, &[1, 14], &[0, 1, 0, 0]);
    assert!(
        iommu(
            &Node::root(&bytes).unwrap(),
            &flat_fixture_extent(&|a| Some(a))
        )
        .is_err()
    );
    assert!(
        iommu(
            &Node::root(&build(&descriptors, &reg, &[1, 14], &[0, 1, 0, 0])).unwrap(),
            &flat_fixture_extent(&|_| None)
        )
        .is_err()
    );
}

/// J473AP ANS gate ancestry and virtual clock IDs, decoded from
/// ps-regs/devices. Virtual clocks have no hardware power-state word.
#[test]
fn ans_power_gates_are_placed_and_virtual_clocks_do_not_invent_registers() {
    use stela_contracts::adt::encode;
    let words = |v: &[u32]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
    let pairs = |v: &[u64]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
    let mut devices = Vec::new();
    for (id, flags, index, block) in [
        (37u16, 0x29u32, 21, 6),
        (89, 1, 9, 8),
        (120, 0x21, 5, 9),
        (125, 0x21, 10, 9),
        (332, 0x10, 0, 0),
        (333, 0x10, 0, 0),
        (334, 0x30, 0, 0),
    ] {
        let mut entry = [0; PMGR_DEVICE];
        entry[..4].copy_from_slice(&flags.to_le_bytes());
        entry[10] = index;
        entry[11] = block;
        entry[26..28].copy_from_slice(&id.to_le_bytes());
        devices.extend(entry);
    }
    let mut blocks = [0; 30];
    for (block, offset) in [(6, 0x100), (8, 0x300), (9, 0x400)] {
        blocks[block * 3 + 1] = offset;
    }
    let pmgr = encode(
        &[
            ("name", b"pmgr"),
            ("compatible", PMGR.as_bytes()),
            ("reg", &pairs(&[0x3b70_0000, 0xcc000])),
            ("ps-regs", &words(&blocks)),
            ("devices", &devices),
        ],
        &[],
    );
    let bytes = encode(&[("name", b"arm-io")], &[pmgr]);
    let found = power_states(
        &Node::root(&bytes).unwrap(),
        &flat_fixture_extent(&|a| Some(a + 0x2_0000_0000)),
        0x8112,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        found.registers,
        [0x2_3b70_01a8, 0x2_3b70_0348, 0x2_3b70_0428, 0x2_3b70_0450]
    );
}

/// CPU devices in a block at the PMGR's first range and a device in a
/// block at its second, with a virtual device that has no register.
#[test]
fn a_pmgr_places_each_devices_power_state_register() {
    use stela_contracts::adt::encode;
    const MODELED: [&str; 3] = ["uart-1,samsung", "wdt,s5l8960x", "aic,2"];
    let z = |text: &str| [text.as_bytes(), &[0]].concat();
    let u32s = |cells: &[u32]| {
        cells
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let u64s = |cells: &[u64]| {
        cells
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let device = |flags: u32, index: u8, block: u8, name: &str| {
        let mut entry = [0u8; PMGR_DEVICE];
        entry[..4].copy_from_slice(&flags.to_le_bytes());
        (entry[10], entry[11]) = (index, block);
        entry[26..28].copy_from_slice(&(u16::from(index) + 1).to_le_bytes());
        if flags & PMGR_VIRTUAL != 0 {
            entry[4..6].copy_from_slice(&1u16.to_le_bytes());
        }
        entry[32..32 + name.len()].copy_from_slice(name.as_bytes());
        entry
    };
    let devices = [
        device(0x2_0000, 0, 1, "ECPU0"),
        device(0x2_0000, 3, 1, "ECPU3"),
        device(PMGR_VIRTUAL, 7, 0, "VIRT"),
        device(0, 2, 0, "SBR"),
    ]
    .concat();
    // J473AP's: the power-state blocks, each cluster's register window
    // (5, 14) and the range its performance-state table lies in (8,
    // 17), and the eFuses (36).
    let mut reg = [[0x3b70_0000, 0xcc000]; 37];
    reg[1] = [0x3d28_0000, 0x7c000];
    reg[4] = [0x3d00_4000, 0x1000];
    reg[5] = [0x10e2_0000, 0x2000];
    reg[7] = [0x10e4_0000, 0x9000];
    reg[10] = [0x1005_0000, 0x10000];
    reg[8] = [0x10e5_0000, 0xe8_1000];
    reg[14] = [0x11e2_0000, 0x2000];
    reg[16] = [0x11e4_0000, 0xb000];
    reg[19] = [0x1105_0000, 0x10000];
    reg[17] = [0x11e5_0000, 0xe8_1000];
    reg[29] = [0x3b20_8000, 0x8000];
    reg[30] = [0x3b70_0000, 0x20000];
    reg[31] = [0x3b72_8000, 0x1000];
    reg[32] = [0x3b72_4000, 0x1000];
    reg[34] = [0x3b78_0000, 0x4000];
    reg[35] = [0x3b76_0000, 0x4000];
    reg[36] = [0x3d2c_8000, 0x4000];
    let reg = reg.concat();
    let energy_record = |address: u64| {
        let mut record = [0u8; 40];
        record[..8].copy_from_slice(&address.to_le_bytes());
        record[16..24].copy_from_slice(&[0, 0, 1, 0, 0, 1, 0, 64]);
        record
    };
    let energy = [
        energy_record(0x2_10e4_8000),
        energy_record(0x2_1005_9000),
        energy_record(0x2_11e4_8000),
        energy_record(0x2_1105_9000),
    ]
    .concat();
    let mut perf_group = [0u8; 16];
    perf_group[..4].copy_from_slice(&1u32.to_le_bytes());
    perf_group[4..8].copy_from_slice(&0x34000u32.to_le_bytes());
    perf_group[8..10].copy_from_slice(&256u16.to_le_bytes());
    perf_group[12] = 3;
    let mut clock = [0u8; 24];
    clock[..3].copy_from_slice(&[24, 0, 1]);
    let pmgr_with = |reg: &[u64]| {
        encode(
            &[
                ("name", &z("pmgr")),
                ("compatible", &z(PMGR)),
                ("reg", &u64s(reg)),
                ("ps-regs", &u32s(&[1, 0x4000, 0x3ff, 0, 0, 0x3ff])),
                ("devices", &devices),
                ("hw-dpe-reg", &energy),
                ("perf-regs", &perf_group),
                ("clocks", &clock),
            ],
            &[],
        )
    };
    // A cluster window the PMGR does not place, or an eFuse block of
    // another size, refuses.
    for (index, entry) in [(10, [0x10e2_0000, 0x1000]), (72, [0x3d2c_8000, 0x1000])] {
        let mut other = reg.clone();
        other[index..index + 2].copy_from_slice(&entry);
        let tree = tree_with_io(0x8112, "Apple M2", MODELED, &[], &[pmgr_with(&other)]);
        assert!(board(&tree).is_err());
    }
    for invalid in [
        energy[..39].to_vec(),
        [energy.clone(), energy[..40].to_vec()].concat(),
        {
            let mut unsupported = energy.clone();
            unsupported[20] = 1;
            unsupported
        },
        {
            let mut unsupported = energy.clone();
            unsupported[23] = 32;
            unsupported
        },
        {
            let mut outside = energy.clone();
            outside[..8].copy_from_slice(&0x4_10e4_8000u64.to_le_bytes());
            outside
        },
    ] {
        let pmgr = encode(
            &[
                ("name", &z("pmgr")),
                ("compatible", &z(PMGR)),
                ("reg", &u64s(&reg)),
                ("hw-dpe-reg", &invalid),
            ],
            &[],
        );
        assert!(board(&tree_with_io(0x8112, "Apple M2", MODELED, &[], &[pmgr])).is_err());
    }
    let pmgr = encode(
        &[
            ("name", &z("pmgr")),
            ("compatible", &z(PMGR)),
            ("reg", &u64s(&reg)),
            ("ps-regs", &u32s(&[1, 0x4000, 0x3ff, 0, 0, 0x3ff])),
            ("devices", &devices),
            ("hw-dpe-reg", &energy),
            ("perf-regs", &perf_group),
            ("clocks", &clock),
        ],
        &[],
    );
    let found = board(&tree_with_io(0x8112, "Apple M2", MODELED, &[], &[pmgr])).unwrap();
    assert_eq!(
        found.energy,
        vec![
            EnergyBank {
                physical: 0x2_10e4_8000,
                cpm: true
            },
            EnergyBank {
                physical: 0x2_1005_9000,
                cpm: false
            },
            EnergyBank {
                physical: 0x2_11e4_8000,
                cpm: true
            },
            EnergyBank {
                physical: 0x2_1105_9000,
                cpm: false
            },
        ]
    );
    assert_eq!(
        found.performance,
        vec![PerfBank {
            physical: 0x2_3d2b_4000,
            selectors: vec![24]
        }]
    );
    assert_eq!(found.wake_masks.as_ref().unwrap().physical, 0x2_3d00_4008);
    assert_eq!(found.clusters, T8112_CLUSTERS.to_vec());
    assert_eq!(found.aon_fuses, Some((0x2_3d2c_8000, 0x4000)));
    let states = found.power_states.as_ref().unwrap();
    assert_eq!(
        states.blocks,
        vec![(0x2_3d28_4000, 0x14), (0x2_3b70_0000, 0x1c)]
    );
    assert_eq!(
        states.registers,
        vec![0x2_3b70_0000, 0x2_3b70_0018, 0x2_3d28_4010]
    );
    assert_eq!(
        states
            .domains
            .iter()
            .map(|domain| (domain.id.device, domain.address))
            .collect::<Vec<_>>(),
        [
            (1, Some(0x2_3b70_0000)),
            (4, Some(0x2_3b70_0018)),
            (8, None),
            (3, Some(0x2_3d28_4010))
        ]
    );
    assert_eq!(states.domains[2].parents[0].unwrap().device, 1);
    // Without the PMGR's compatible, nothing is placed.
    assert_eq!(
        board(&tree(0x8112, "Apple M2", MODELED))
            .unwrap()
            .power_states,
        None
    );
}

#[test]
#[ignore = "oracle: STELA_TEST_DART_DT"]
fn original_j314s_sep_preserves_sole_trad_with_sixteen_sid_capacity() {
    let data = std::fs::read(std::env::var("STELA_TEST_DART_DT").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&data),
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
    );
    let root = Node::root(&data).unwrap();
    let io = root.child("arm-io").unwrap();
    let node = io.child("dart-sep").unwrap();
    assert_eq!(node.first_u32("sids"), Some(0x8001));
    let darts = [iommu(&node, &|address, bytes| io.translate_range(address, bytes)).unwrap()];
    let dart = &darts[0];
    assert_eq!(dart.profile, crate::dart::Profile::T6000);
    assert_eq!(dart.streams, 16);
    assert_eq!(dart.sids, [0, 15]);
    assert_eq!(dart.instances.len(), 1);
    assert!(dart.remap.is_empty());
    let sep = sep_device(
        &root,
        &io,
        &|address, bytes| io.translate_range(address, bytes),
        &darts,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        (sep.iommu, sep.instance, sep.mapper_context, sep.stream),
        (0, 0, 0, 0)
    );
    assert_eq!(dart.mappers, [(sep.mapper, 0)]);
    println!("source-qualified SEP route: {sep:?}; dart={dart:?}");
}

#[test]
fn mpidr_composition_preserves_ep_identities_and_rejects_unknown_coordinates() {
    for soc in SOCS {
        for (kind, aff2) in [(b'E', 0u64), (b'P', 1), (b'M', 4)] {
            // The T6050 has no E cores and the earlier SoCs no M cores.
            let Some(core) = soc.cores.iter().find(|core| core.cluster_type == kind) else {
                continue;
            };
            // Include both dies, sparse cores and the upper declared
            // affinity boundary; this field does not define core count.
            for reg in [0, 3, 0x100, 0x105, 0x800, 0x905, 0x1205, 0xffff] {
                assert_eq!(
                    core.mpidr(reg),
                    Some(0x8000_0000 | aff2 << 16 | u64::from(reg))
                );
            }
        }
    }
    let m_core = *core_types(0x8152)
        .unwrap()
        .iter()
        .find(|core| core.cluster_type == b'M')
        .unwrap();
    for bit in 16..32 {
        assert_eq!(m_core.mpidr(0x102 | 1 << bit), None);
    }
    assert_eq!(
        CoreType {
            mpidr_aff2: None,
            ..m_core
        }
        .mpidr(0x102),
        None
    );
    for aff2 in [8, 0x80, 0xff] {
        assert_eq!(
            CoreType {
                mpidr_aff2: Some(aff2),
                ..m_core
            }
            .mpidr(0x102),
            None
        );
    }
}

/// The CPU start registers sit in `/arm-io/pmgr` `reg[0]`, or in
/// `/arm-io/pmgr-child` `reg[0]` under the M6's `pmgr2,arch`, with a
/// start word for each cluster (J873GAP: `pmgr-child` `reg[0]` is
/// 0x1_0070_0000 for 0xd0000 bytes, two clusters).

#[test]
fn core_requirements_keep_unknown_m6_capabilities_explicit() {
    let soc = SOCS.iter().find(|soc| soc.chip_id == 0x8152).unwrap();
    assert_eq!(soc.cpu_start, Some(CPU_START_T8112));
    let cores = core_types(0x8152).unwrap();
    assert_eq!(
        cores
            .iter()
            .map(|core| core.cluster_type)
            .collect::<Vec<_>>(),
        b"EPM"
    );
    let m_core = cores.iter().find(|core| core.cluster_type == b'M').unwrap();
    assert_eq!(m_core.midr_part, None);
    assert_eq!(m_core.mpidr_aff2, Some(4));
    assert_eq!(m_core.mpidr(0x102), Some(0x8004_0102));
    assert_eq!(m_core.operating_points, None);
    assert!(m_core.caches.is_none());
    assert_eq!(midr_part(0x8152, b'M'), None);
    assert_eq!(level1_caches(0x8152, b'M'), None);
    assert_eq!(operating_points(0x8152), None);
    // Three core types describe two physical clusters; there is no
    // synthetic extra cluster or E/P fallback for an M PE.
    let processors = [
        Processor {
            cluster_type: b'E',
            reg: 0,
            l2_bytes: Some(8 << 20),
        },
        Processor {
            cluster_type: b'P',
            reg: 0x100,
            l2_bytes: Some(20 << 20),
        },
        Processor {
            cluster_type: b'M',
            reg: 0x102,
            l2_bytes: Some(20 << 20),
        },
    ];
    assert!(topology::validate(&processors).is_ok());
    assert_eq!(
        cpus(0x8152, "Apple M6", &processors),
        Err(refuse!("Apple M6 cluster type M has no public MIDR part"))
    );
}

#[test]
fn cpu_binding_rejects_aliasing_affinities_before_synthetic_type_bits() {
    let processors = [
        Processor {
            cluster_type: b'E',
            reg: 0,
            l2_bytes: Some(4 << 20),
        },
        Processor {
            cluster_type: b'P',
            reg: 0,
            l2_bytes: Some(4 << 20),
        },
    ];
    assert_eq!(
        cpus(0x8112, "Apple M2", &processors),
        Err(refuse!("duplicate CPU affinity reg 0x0"))
    );
}
#[test]
#[ignore = "oracle: STELA_TEST_ANS_DT"]
fn original_j314s_ans_geometry_and_handoff_check_independently_of_whole_board() {
    let data = std::fs::read(std::env::var("STELA_TEST_ANS_DT").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&data),
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
    );
    let root = Node::root(&data).unwrap();
    let io = root.child("arm-io").unwrap();
    let security = root
        .child("defaults")
        .unwrap()
        .property("nvme-iboot-sptm-security")
        .is_some();
    let placement = ans_controller(
        &io,
        &|address, bytes| io.translate_range(address, bytes),
        security,
    )
    .unwrap()
    .unwrap();
    assert_eq!(placement.geometry.handoff_entries(), 253);
    assert_eq!(placement.geometry.ring_entries(), 254);
    assert_eq!(placement.geometry.tag_slots(), 253);
    assert_eq!(placement.interrupts, [1070, 1069, 1072, 1071]);
    assert_eq!(placement.completion_irq, 1613);
    assert_eq!(
        placement.clock_gates,
        [DomainId {
            die: 0,
            device: 481
        }]
    );
    assert_eq!(placement.power_gates, [DomainId { die: 0, device: 71 }]);
    assert!(placement.sart_exclusive_bounds);
    assert_eq!(placement.vdma, None);
    assert_eq!(placement.sart_idle, placement.nvme.0 + 0x13e8);
    assert_eq!(placement.namespaces.len(), 3);
    assert_eq!(placement.namespaces[2].blocks, 32768);
    assert!(!models(ASC, |_| None)); // No whole-board/other ASC admission.
}
