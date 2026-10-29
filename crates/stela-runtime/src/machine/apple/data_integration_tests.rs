//! Board metadata exercised through actual stateful Runtime device models.
use super::{DcpextDma, DcpextNub};
use crate::platform::apple::cluster::t6000::{Complex, T6000};
use crate::platform::apple::power::t6000::native;
use alloc::{vec, vec::Vec};
use stela_contracts::{Chip, adt::Node};
use stela_contracts::{caches::Caches, identity::Identity};
use stela_soc_data::aic::AicLayout;
use stela_soc_data::board::fixture_support::cache_fixture as cache;
use stela_soc_data::board::fixture_support::*;
use stela_soc_data::board::t6000_pmgr::Descriptor;
use stela_soc_data::board::*;
#[test]
#[ignore = "oracle: STELA_TEST_DART_DT"]
fn original_j314s_external_output_preserves_native_routes_and_identity() {
    let data = std::fs::read(std::env::var("STELA_TEST_DART_DT").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&data),
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
    );
    let root = Node::root(&data).unwrap();
    let io = root.child("arm-io").unwrap();
    let ranges = io.ranges().unwrap();
    let translate = |offset| {
        ranges
            .iter()
            .find(|(child, _, bytes)| (*child..child + bytes).contains(&offset))
            .map(|(child, parent, _)| parent + (offset - child))
    };
    let darts = ["dart-dispext0", "dart-dcpext0"].map(|name| {
        parse_iommu_fixture(&io.child(name).unwrap(), &|address, bytes| {
            io.translate_range(address, bytes)
        })
        .unwrap()
    });
    assert_eq!(darts[0].instances.len(), 1);
    assert_eq!(darts[0].smmu, Some((0x2_8930_0000, 0x4000)));
    assert_eq!(darts[0].instances[0].physical, 0x2_8930_4000);
    assert_eq!(darts[1].instances[0].physical, 0x2_8930_c000);
    assert_eq!(darts[0].irq, 873);
    assert_eq!(darts[1].irq, 873);
    assert_eq!(darts[1].remap, [(5, 0)]);
    let dcp = parse_dcp_fixture(&io, &translate, &darts).unwrap().unwrap();
    assert_eq!(dcp.role, "DCPEXT0");
    assert_eq!(
        dcp.identity,
        stela_soc_data::dcp::ExternalIdentity::Numbered(0)
    );
    assert_eq!(
        (dcp.iommu, dcp.instance, dcp.mapper_context, dcp.stream),
        (1, 0, 0, 5)
    );
    assert_eq!((dcp.surface, dcp.surface_instance), (Some((0, 0)), Some(0)));
    assert_eq!(dcp.mapper, 0x109);
    assert_eq!(
        dcp.surface_routes,
        [
            DcpMapperRoute {
                mapper: 0x103,
                iommu: 0,
                instance: 0,
                mapper_context: 0,
                stream: 0
            },
            DcpMapperRoute {
                mapper: 0x104,
                iommu: 0,
                instance: 0,
                mapper_context: 4,
                stream: 4
            },
        ]
    );
    println!(
        "original DCP owner metadata: firmware={:?}/{:#x}, pipe={:?}, routes={:?}",
        dcp.phandle, dcp.mapper, dcp.surface_phandle, dcp.surface_routes
    );
    assert_eq!(dcp.wrapper, (0x2_89c0_0000, 0x6c000));
    assert_eq!(
        dcp.regions,
        [
            ("dispext0", (0x2_8800_0000, 0x3000000)),
            ("dispext0", (0x2_8932_0000, 0x4000)),
            ("dispext0", (0x2_8934_4000, 0x4000)),
            ("dispext0", (0x2_8980_0000, 0x800000)),
            ("dispext0", (0x2_8e3d_0000, 0x4000)),
        ]
    );
    let mut devices = crate::machine::apple::AppleDevices::new();
    let mut owners = Vec::new();
    for dart in darts {
        let native = dart
            .instances
            .iter()
            .map(|i| crate::machine::apple::Range {
                physical: i.physical,
                bytes: i.bytes,
            })
            .collect::<Vec<_>>();
        let ids = devices
            .add_dart_group_for_profile(
                dart.profile,
                &native,
                usize::from(dart.streams),
                Some(stela_contracts::interrupt::AicInput::new(
                    0,
                    dart.irq as u16,
                )),
                None,
            )
            .unwrap();
        if let Some((physical, bytes)) = dart.smmu {
            devices
                .add_dart_smmu(ids[0], crate::machine::apple::Range { physical, bytes })
                .unwrap();
        }
        owners.extend(ids);
    }
    use crate::machine::apple::{Range, Scanout, ScanoutFormat, ScanoutMode};
    struct Screen;
    impl Scanout for Screen {
        fn mode(&self) -> ScanoutMode {
            ScanoutMode {
                width: 1,
                height: 1,
                format: ScanoutFormat::Bgra8888,
            }
        }
        fn present(&mut self, _: &[u8]) -> Result<(), &'static str> {
            panic!("mount is not a frame")
        }
    }
    devices
        .add_dcpext(
            DcpextNub {
                wrapper: Range {
                    physical: dcp.wrapper.0,
                    bytes: dcp.wrapper.1,
                },
                interrupts: dcp.interrupts,
                quiesced: dcp.quiesced,
                role: dcp.role,
                identity: dcp.identity,
            },
            alloc::boxed::Box::new(Screen),
            DcpextDma {
                link: (owners[1], dcp.stream as usize),
                window: dcp.window,
                surface: Some((owners[0], dcp.surface.unwrap().1 as usize)),
            },
            stela_formats::builds::DEFAULT,
        )
        .unwrap();
    let regions = dcp
        .regions
        .iter()
        .map(|&(name, (physical, bytes))| (name, Range { physical, bytes }))
        .collect::<Vec<_>>();
    devices
        .add_display_with_darts(&regions, dcp.role, &owners)
        .unwrap();
    // Full original views and their actual nested owners mount together;
    // this is not evidence of original firmware execution or a frame.
}

/// ApChipID 0x6050's rows follow the `product-soc-name` its template
/// gives each variant: the Pro's Sotra S parts, the Max's and the
/// Ultra's Sotra C parts, the second die at Aff1 16 to 18. The M cores
/// refuse for their unestablished caches; the chip ID alone names no row.
#[test]
fn the_t6050_rows_follow_the_template_soc_name() {
    use stela_engine::machine::identification;
    use stela_engine::machine::timer::agt;
    assert_eq!(chip(0x6050), Some(Chip::AppleM5));
    assert!(agt::present(Chip::AppleM5) && identification::memory_tagging(Chip::AppleM5));
    assert!(name(0x6050).is_none() && core_types(0x6050).is_none());
    assert_eq!(midr_part(0x6050, b'P'), None);
    let p_core = |soc: &str, reg: u32| {
        let cpus = cpus(0x6050, soc, &layout_of(&[(b'P', reg)])).unwrap();
        assert_eq!(cpus.chip, Chip::AppleM5);
        (cpus.processors[0].midr, cpus.processors[0].mpidr)
    };
    assert_eq!(p_core("Apple M5 Pro", 0x200), (0x611f_0650, 0x8001_0200));
    assert_eq!(p_core("Apple M5 Max", 0x205), (0x611f_0690, 0x8001_0205));
    assert_eq!(p_core("Apple M5 Ultra", 0x1205), (0x611f_0690, 0x8001_1205));
    // The M cores report the E cores' level 1 caches (`hw.perflevel1`).
    let m_core = cpus(0x6050, "Apple M5 Pro", &layout_of(&[(b'M', 0)])).unwrap();
    assert_eq!(
        m_core.processors[0],
        Identity {
            midr: 0x611f_0640,
            mpidr: 0x8004_0000,
            clock: None,
            caches: Some(
                Caches::split_unified(cache(128 << 10, 8), cache(64 << 10, 8), cache(4 << 20, 16))
                    .unwrap()
            ),
        }
    );
    assert_eq!(
        cpus(0x6050, "Apple M5", &layout_of(&[(b'P', 0x200)])),
        Err(
            "ApChipID 0x6050 is Apple M5 Pro or Apple M5 Max or Apple M5 Ultra, but the \
             DeviceTree names Apple M5"
                .into()
        )
    );
    // The template's 36 PEs fill the kernel's slots; a 37th refuses.
    let mut template = Vec::new();
    for die in [0, 0x1000] {
        for (kind, cluster) in [(b'M', 0), (b'M', 0x100), (b'P', 0x200)] {
            template.extend((0..6).map(|core| (kind, die | cluster | core)));
        }
    }
    assert_eq!(T6050_FIXTURE_LIMITS.check(&layout_of(&template)), Ok(()));
    template.push((b'P', 0x1206));
    assert!(
        T6050_FIXTURE_LIMITS
            .check(&layout_of(&template))
            .unwrap_err()
            .contains("MAX_CPUS")
    );
}

/// The A18 Pro takes the M4's CPU profile with its own parts, so every
/// chip-keyed feature is the M4's: the Apple generic timer, CTRR-C/D and
/// CTXR, no memory tagging and the M4's maintenance words (DC INCPA4K,
/// operation 25 and `0x00201401`, not operation 26). J700AP's four E and
/// two P cores fill its kernel's six CPU slots.
#[test]
fn the_a18_pro_takes_the_m4_cpu_profile() {
    use stela_engine::machine::identification;
    use stela_engine::machine::timer::agt;
    assert_eq!(chip(0x8140), Some(Chip::AppleM4));
    assert_eq!(name(0x8140), Some("Apple A18 Pro"));
    assert_eq!(midr_part(0x8140, b'E'), Some(0x60));
    assert_eq!(midr_part(0x8140, b'P'), Some(0x61));
    assert!(agt::present(Chip::AppleM4));
    assert_eq!(
        stela_contracts::ctrr::generation(Chip::AppleM4),
        Some(stela_contracts::ctrr::Generation::Ctrr3)
    );
    assert!(!identification::memory_tagging(Chip::AppleM4));
    assert!(Chip::AppleM4 < Chip::AppleM5);
    assert_eq!(template_variant(0x8140), Some("h17p"));
    assert_eq!(template_variant(0x8132), None);
    let j700 = [
        (b'E', 0),
        (b'E', 1),
        (b'E', 2),
        (b'E', 3),
        (b'P', 0x100),
        (b'P', 0x101),
    ];
    let a18 = cpus(0x8140, "Apple A18 Pro", &layout_of(&j700)).unwrap();
    assert_eq!(a18.chip, Chip::AppleM4);
    assert_eq!(a18.lockdown, None);
    assert_eq!(a18.processors[0].midr, 0x611f_0600);
    assert_eq!(a18.processors[4].midr, 0x611f_0610);
    assert_eq!(a18.processors[5].mpidr, 0x8001_0101);
    let seventh = [j700.as_slice(), &[(b'P', 0x102)]].concat();
    assert!(
        cpus(0x8140, "Apple A18 Pro", &layout_of(&seventh))
            .unwrap_err()
            .contains("MAX_CPUS")
    );
}

#[test]
#[ignore = "oracle: STELA_TEST_SPMI_DT"]
fn original_j314s_spmi_parent_qualifies_all_seven_independent_resource_owners() {
    use stela_engine::machine::Devices;
    let data = std::fs::read(std::env::var("STELA_TEST_SPMI_DT").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&data),
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
    );
    let root = Node::root(&data).unwrap();
    let io = root.child("arm-io").unwrap();
    let controllers = spmi_controllers(
        &io,
        &|address, bytes| io.translate_range(address, bytes),
        130,
    )
    .unwrap();
    assert_eq!(controllers.len(), 7);
    assert_eq!(
        controllers
            .iter()
            .flat_map(|c| &c.pmus)
            .filter(|p| p.primary)
            .count(),
        1
    );
    assert_eq!(
        controllers
            .iter()
            .flat_map(|c| &c.pmus)
            .filter(|p| p.rtc.is_some())
            .count(),
        2
    );
    let mut devices = crate::machine::apple::AppleDevices::new();
    let smc = parse_smc_fixture(&root, &io, &|address, bytes| {
        io.translate_range(address, bytes)
    })
    .unwrap()
    .unwrap();
    devices
        .add_smc(&smc, stela_formats::builds::DEFAULT)
        .unwrap();
    let epoch = crate::platform::apple::pmu::RtcEpoch {
        counter: 100,
        ticks: 0,
    };
    for controller in &controllers {
        if controller
            .pmus
            .iter()
            .any(|pmu| pmu.rtc_helper.is_some() || pmu.fault_log.is_some())
        {
            assert!(
                devices.add_spmi(controller, None).is_err(),
                "no implicit resource inputs"
            );
        }
        let history = controller
            .pmus
            .iter()
            .flat_map(|pmu| {
                pmu.retained()
                    .map(|(kind, window)| (pmu.sid, kind, vec![0; usize::from(window.bytes)]))
            })
            .collect::<Vec<_>>();
        devices
            .add_spmi_with_resources(controller, None, epoch, &history)
            .unwrap();
    }
    assert_eq!(
        controllers
            .iter()
            .flat_map(|c| &c.pmus)
            .filter(|pmu| pmu.rtc_helper.is_some())
            .count(),
        1
    );
    assert!(
        devices
            .read(0, smc.wrapper.0 + 0x44, 4, epoch.counter - 1)
            .is_err()
    );
    assert_eq!(
        devices.read(0, smc.wrapper.0 + 0x44, 4, epoch.counter),
        Ok(1 << 4)
    );
    let mut bases = Vec::new();
    for controller in controllers {
        assert_eq!(
            controller.configuration.profile(),
            stela_soc_data::spmi::Profile::Gen1
        );
        assert_eq!(controller.configuration.response_vector(), 192);
        assert_eq!(controller.configuration.queue_bytes(), [256, 256]);
        for (base, bytes) in controller.banks {
            assert_eq!(bytes, 0x100);
            assert!(!bases.contains(&base));
            bases.push(base);
        }
        let (base, bytes) = controller.bank_c.unwrap();
        assert_eq!(bytes, 0x78);
        assert!(!bases.contains(&base));
        bases.push(base);
    }
    // Both original RTC register banks mount while the single primary
    // service owns the global alarm output and the resolved SMC helper
    // shares its actual oscillator. Epoch/fault history are explicitly
    // created native inputs, not observed physical reset/persistent data.
    // Autonomous sleep/wake and whole-board admission remain separate.
}

#[test]
#[ignore = "oracle: STELA_TEST_DART_DT"]
fn original_j314s_watchdog_mounts_one_shared_panic_flags_word() {
    use crate::machine::apple::AppleDevices;
    use crate::machine::apple::Range;
    use stela_engine::machine::Devices;
    let data = std::fs::read(std::env::var("STELA_TEST_DART_DT").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&data),
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
    );
    let root = Node::root(&data).unwrap();
    let io = root.child("arm-io").unwrap();
    let ranges = io.ranges().unwrap();
    let translate = |offset: u64| {
        ranges.iter().find_map(|&(child, parent, bytes)| {
            offset
                .checked_sub(child)
                .filter(|&delta| delta < bytes)
                .and_then(|delta| parent.checked_add(delta))
        })
    };
    let node = io.child("wdt").unwrap();
    let side = parse_watchdog_fixture(&node, &|address, bytes| io.translate_range(address, bytes))
        .unwrap()
        .unwrap();
    assert_eq!(
        side.words,
        [0x2922b8020, 0x2922b802c, 0x2922b8008, 0x2922b8020]
    );
    assert_eq!(node.first_u32("panic-save-flag-bit"), Some(0));
    assert_eq!(node.first_u32("panic-forcepoweroff-flag-bit"), Some(2));
    assert_eq!(side.triggers.len(), 10);
    let (offset, bytes) = node.pairs("reg").unwrap()[0];
    let mut devices = AppleDevices::new();
    devices
        .add_watchdog_with_side(
            Range {
                physical: translate(offset).unwrap(),
                bytes,
            },
            Some(&side),
            None,
            0,
        )
        .unwrap();
    devices.write(0, side.words[0], 4, 1, 0).unwrap();
    let word = devices.read(0, side.words[3], 4, 0).unwrap();
    devices.write(0, side.words[3], 4, word | 4, 0).unwrap();
    assert_eq!(devices.read(0, side.words[0], 4, 0), Ok(5));
}

#[test]
#[ignore = "oracle: STELA_TEST_PMGR_M1_ADT"]
fn original_complete_descriptor_and_sparse_ownership_have_no_fabricated_state() {
    let data = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_ADT").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&data),
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
    );
    let d = Descriptor::parse(&data, 0x6000, 8, 0).unwrap();
    assert_eq!(d.registers.len(), 241);
    assert_eq!(d.bridges.len(), 193);
    assert_eq!(d.power.registers.len(), 196);
    assert!(
        d.coverage_requirement
            .as_ref()
            .unwrap()
            .contains("device: 197")
    );
    let layout = d.layout().unwrap();
    let mut spans = Vec::new();
    for complex in [
        Complex::Efficiency,
        Complex::Performance0,
        Complex::Performance1,
    ] {
        let model = T6000::new(complex, 16, &[]).unwrap();
        for offset in model.offsets() {
            let pa = layout.acc(complex.index(), offset as u32, 8).unwrap();
            spans.push((pa, pa + 8, format!("cluster {:?} {offset:x}", complex)));
        }
    }
    for bank in &d.bridges {
        let model = stela_soc_data::bridge::Layout::t6000(
            &d.tuning.fields(bank.id).unwrap(),
            bank.header,
            &bank.configs,
            bank.axi,
        )
        .unwrap();
        for (offset, bytes) in model.spans() {
            spans.push((
                bank.view.physical + offset,
                bank.view.physical + offset + bytes,
                format!("bridge {} {offset:x}", bank.id),
            ));
        }
    }
    for word in native::controls() {
        spans.push((
            word.address,
            word.address + 4,
            format!("native {:x}", word.address),
        ));
    }
    spans.push((0x292f00000, 0x292f70000, String::from("native SRAM")));
    spans.sort_by_key(|s| s.0);
    let collisions = spans
        .windows(2)
        .filter(|s| s[0].1 > s[1].0)
        .collect::<Vec<_>>();
    println!(
        "descriptor: views={} bridges={} power={} sparse={} collisions={collisions:?}",
        d.registers.len(),
        d.bridges.len(),
        d.power.registers.len(),
        spans.len()
    );
    assert!(
        collisions.is_empty(),
        "source-qualified sparse owners overlap"
    );
}

#[test]
fn chapel_places_a_shared_alarm_byte_and_explicit_off_to_wake_history() {
    use stela_contracts::adt::encode;
    let z = |text: &str| [text.as_bytes(), &[0]].concat();
    let cells = |values: &[u32]| {
        values
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let pairs = |values: &[(u64, u64)]| {
        values
            .iter()
            .flat_map(|&(a, b)| [a, b])
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>()
    };
    // The J514sAP nub-spmi0 Chapel primary and Spitfire, trimmed.
    let tree = |wake: &[u32]| {
        let chapel = encode(
            &[
                ("name", &z("spmi-chapelL1")),
                ("compatible", b"pmu,spmi\0pmu,chapel\0"),
                ("reg", &cells(&[0xb, 3, 0, 4, 0, 0])),
                ("info-scrpad", &cells(&[0x8000, 0x2800])),
                ("info-scrpad_socd", &cells(&[0x8b00, 0x1800])),
                ("info-fault_shadow", &cells(&[0x867b, 0x10])),
                ("info-leg_scrpad", &cells(&[0xf800])),
                ("info-fault_log", &cells(&[0x2200, 7])),
                ("info-off2wake_source", &cells(wake)),
                ("info-pm_setting", &cells(&[0x2001])),
                ("info-rtc", &cells(&[0x2002])),
                ("info-clock_offset", &cells(&[0x2100, 6])),
                ("info-rtc_alarm_ctrl", &cells(&[0x2000])),
                ("info-rtc_alarm_ctrl_en_mask", &cells(&[0x40])),
                ("info-rtc_alarm_monitor_mask", &cells(&[1])),
                ("info-rtc_alarm_offset", &cells(&[0x2008])),
                ("info-rtc_alarm_event", &cells(&[0x2000])),
                ("info-rtc_alarm_event_mask", &cells(&[2])),
                ("info-rtc_irq_mask_offset", &cells(&[0x200e])),
                ("info-rtc_alarm_mask", &cells(&[1])),
                ("info-id", &cells(&[0, 10])),
                ("is-primary", &cells(&[1])),
                ("interrupt-parent", &cells(&[0x141])),
                ("interrupts", &cells(&[2])),
            ],
            &[],
        );
        let spitfire = encode(
            &[
                ("name", &z("spmi-spitfireE1")),
                ("compatible", b"pmu,spmi\0pmu,spitfire\0"),
                ("reg", &cells(&[0x9, 3, 0, 4, 0, 0])),
                ("info-fault_log", &cells(&[0x1000, 4])),
                ("info-id", &cells(&[0, 10])),
            ],
            &[],
        );
        let spmi = encode(
            &[
                ("name", &z("nub-spmi0")),
                ("compatible", &z(SPMI)),
                ("gen", &cells(&[2])),
                ("queue-depth", &cells(&[256, 256])),
                ("AAPL,phandle", &cells(&[0x141])),
                (
                    "reg",
                    &pairs(&[(0x3d71_4000, 0x4000), (0x3d70_4000, 0x4000)]),
                ),
                ("interrupt-parent", &cells(&[0x141, 0x63, 0x141])),
                ("interrupts", &cells(&[0x100, 0x180, 0x119, 0x104])),
            ],
            &[chapel, spitfire],
        );
        encode(&[("name", &z("arm-io"))], &[spmi])
    };
    let translate = |offset| Some(0x2_0000_0000 + offset);
    let bytes = tree(&[0x281c, 2]);
    let io = Node::root(&bytes).unwrap();
    let [controller] = &spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).unwrap()[..]
    else {
        panic!("one controller");
    };
    let [chapel, spitfire] = &controller.pmus[..] else {
        panic!("two PMUs");
    };
    assert!(chapel.rtc.unwrap().shares_event());
    let window = |base, bytes| stela_soc_data::pmu::Window { base, bytes };
    assert_eq!(
        chapel.retained().collect::<Vec<_>>(),
        [
            (stela_soc_data::pmu::Retained::FaultLog, window(0x2200, 7)),
            (stela_soc_data::pmu::Retained::WakeSource, window(0x281c, 2)),
        ]
    );
    assert_eq!(spitfire.retained().count(), 1);
    let cold = |pmus: &[SpmiPmu]| {
        pmus.iter()
            .flat_map(|pmu| {
                pmu.retained()
                    .map(|(kind, window)| (pmu.sid, kind, vec![0; usize::from(window.bytes)]))
            })
            .collect::<Vec<_>>()
    };
    let epoch = crate::platform::apple::pmu::RtcEpoch {
        counter: 0,
        ticks: 0,
    };
    let mut history = cold(&controller.pmus);
    let mut devices = crate::machine::apple::AppleDevices::new();
    assert!(
        devices
            .add_spmi_with_resources(controller, None, epoch, &history[..2])
            .is_err()
    );
    history[1].2.pop();
    assert!(
        devices
            .add_spmi_with_resources(controller, None, epoch, &history)
            .is_err()
    );
    let history = cold(&controller.pmus);
    devices
        .add_spmi_with_resources(controller, None, epoch, &history)
        .unwrap();
    // Inside scratch it is scratch storage; a partial alias refuses.
    let bytes = tree(&[0x8100, 2]);
    let io = Node::root(&bytes).unwrap();
    let controllers = spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).unwrap();
    assert_eq!(controllers[0].pmus[0].wake_source, None);
    let bytes = tree(&[0x7fff, 2]);
    let io = Node::root(&bytes).unwrap();
    assert!(spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).is_err());
}

#[test]
fn actual_aic_and_gpio_hooks_receive_only_their_qualified_supply() {
    use crate::machine::apple::AppleDevices;
    use crate::machine::apple::Range;
    use stela_engine::machine::engine::Devices;
    use stela_soc_data::board::AuxGpioBank;
    use stela_soc_data::board::GpioBank;
    let (states, bindings) = implicit_state_fixture();
    let mut board = AppleDevices::new();
    board
        .add_aic(bindings[0].physical, 1152, AicLayout::aic2(0x8000, 0))
        .unwrap();
    for (index, binding) in bindings[1..].iter().enumerate() {
        let bank = GpioBank {
            profile: stela_soc_data::gpio::Profile::T8101,
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
    for binding in bindings {
        board.write(0, binding.register, 4, 4, 0).unwrap();
        assert!(board.read(0, binding.physical, 4, 0).is_err());
        for other in bindings.into_iter().filter(|other| other != &binding) {
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
