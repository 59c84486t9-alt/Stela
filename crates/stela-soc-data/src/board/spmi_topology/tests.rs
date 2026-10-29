use super::super::*;
use super::*;
use crate::board::fixture_support::flat_fixture_extent;

#[test]
fn spmi_placement_reads_banks_aic_line_and_pmu_windows() {
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
    // The J473AP pmu-main and its controller, trimmed.
    let tree = |offset: &[u32]| {
        let pmu = encode(
            &[
                ("name", &z("pmu-main")),
                ("compatible", b"pmu,spmi\0pmu,stowe\0"),
                ("reg", &cells(&[0xe, 3, 0, 4, 0, 0])),
                ("info-scrpad", &cells(&[0x8000, 0x2800])),
                ("info-scrpad_socd", &cells(&[0x8b00, 0x1800])),
                ("info-scrpad_lpm_ctrl", &cells(&[0xa7dc])),
                ("info-leg_scrpad", &cells(&[0xf700])),
                ("info-fault_log", &cells(&[0xfa00, 5])),
                ("info-pm_setting", &cells(&[0xf801])),
                ("info-rtc", &cells(&[0xf802])),
                ("info-clock_offset", &cells(offset)),
                ("info-rtc_alarm_ctrl", &cells(&[0xf800])),
                ("info-rtc_alarm_ctrl_en_mask", &cells(&[0x40])),
                ("info-rtc_alarm_monitor_mask", &cells(&[1])),
                ("is-primary", &cells(&[1])),
                ("info-rtc_alarm_offset", &cells(&[0xf808])),
                ("info-rtc_alarm_event", &cells(&[0xf80c])),
                ("info-rtc_irq_mask_offset", &cells(&[0xf80e])),
                ("info-rtc_alarm_mask", &cells(&[0x1])),
            ],
            &[],
        );
        // Hidden: the loader removed its compatible.
        let btm = encode(&[("name", &z("btm")), ("reg", &cells(&[0xe]))], &[]);
        let spmi = encode(
            &[
                ("name", &z("nub-spmi0")),
                ("compatible", &z(SPMI)),
                ("gen", &cells(&[2])),
                ("queue-depth", &cells(&[256, 256])),
                ("AAPL,phandle", &cells(&[0xae])),
                (
                    "reg",
                    &pairs(&[(0x3d71_4000, 0x4000), (0x3d70_4000, 0x4000)]),
                ),
                ("interrupt-parent", &cells(&[0xae, 0x63, 0xae])),
                ("interrupts", &cells(&[0x100, 0x180, 0x119, 0x104])),
            ],
            &[pmu, btm],
        );
        encode(&[("name", &z("arm-io"))], &[spmi])
    };
    let translate = |offset| Some(0x2_0000_0000 + offset);
    let bytes = tree(&[0xf900, 6]);
    let io = Node::root(&bytes).unwrap();
    let [controller] = &spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).unwrap()[..]
    else {
        panic!("one controller");
    };
    assert_eq!(
        controller.banks,
        [(0x2_3d71_4000, 0x4000), (0x2_3d70_4000, 0x4000)]
    );
    assert_eq!(controller.irq, 0x180);
    let [pmu] = &controller.pmus[..] else {
        panic!("one visible PMU");
    };
    assert_eq!(pmu.sid, 0xe);
    assert!(pmu.primary);
    assert_eq!(pmu.alarm_monitor, 1);
    assert_eq!(pmu.interrupt, None);
    let window = |base, bytes| crate::pmu::Window { base, bytes };
    assert_eq!(
        pmu.windows,
        [
            window(0x8000, 0x2800),
            window(0xf700, crate::pmu::LEGACY_SCRATCH_BYTES),
            window(0xf801, 1),
        ]
    );
    assert_eq!(pmu.fault_log, Some(window(0xfa00, 5)));
    assert_eq!(pmu.rtc_helper, None);
    let rtc = pmu.rtc.unwrap();
    assert_eq!(
        (rtc.upcount, rtc.clock_offset, rtc.alarm_enable),
        (0xf802, crate::pmu::ClockOffset::Register(0xf900), 0x40)
    );
    // J473AP gives no event mask: the driver's default holds.
    assert_eq!((rtc.event_mask, rtc.interrupt_mask), (0x1, 0x1));
    // A clock offset that is not six bytes refuses.
    let bytes = tree(&[0xf900, 4]);
    let io = Node::root(&bytes).unwrap();
    assert!(spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).is_err());
}

#[test]
fn an_rtc_without_a_clock_offset_register_keeps_it_in_the_legacy_scratchpad() {
    use stela_contracts::adt::encode;
    let z = |text: &str| [text.as_bytes(), &[0]].concat();
    let cells = |values: &[u32]| {
        values
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<_>>()
    };
    // The J700AP Baku pmu-main, trimmed: no `info-clock_offset`.
    let node = |legacy: bool| {
        let mut properties: Vec<(&str, Vec<u8>)> = alloc::vec![
            ("name", z("pmu-main")),
            ("compatible", b"pmu,spmi\0pmu,baku\0".to_vec()),
            ("reg", cells(&[0xe, 3, 0, 4, 0, 0])),
            ("info-scrpad", cells(&[0x8000, 0x1000])),
            ("info-pm_setting", cells(&[0xf801])),
            ("info-rtc", cells(&[0xf802])),
            ("info-rtc_alarm_ctrl", cells(&[0xf800])),
            ("info-rtc_alarm_ctrl_en_mask", cells(&[0x40])),
            ("info-rtc_alarm_monitor_mask", cells(&[1])),
            ("info-rtc_alarm_offset", cells(&[0xf808])),
            ("info-rtc_alarm_event", cells(&[0xf80c])),
            ("info-rtc_irq_mask_offset", cells(&[0xf80e])),
            ("info-rtc_alarm_mask", cells(&[1])),
        ];
        if legacy {
            properties.push(("info-leg_scrpad", cells(&[0xf700])));
        }
        let properties: Vec<(&str, &[u8])> = properties
            .iter()
            .map(|(name, value)| (*name, value.as_slice()))
            .collect();
        let pmu = encode(&properties, &[]);
        encode(&[("name", &z("arm-io"))], &[pmu])
    };
    let bytes = node(true);
    let io = Node::root(&bytes).unwrap();
    let pmu = spmi_pmu(&io.children().unwrap()[0], &io).unwrap();
    assert_eq!(
        pmu.rtc.unwrap().clock_offset,
        crate::pmu::ClockOffset::LegacyScratch(0xf700)
    );
    let bytes = node(false);
    let io = Node::root(&bytes).unwrap();
    assert!(spmi_pmu(&io.children().unwrap()[0], &io).is_err());
}

#[test]
fn a_firmware_mailbox_names_its_vector_registers_and_doorbell() {
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
    // J604AP-shaped Club and Jerez-shaped secondary: `interrupts` holds the
    // output and the mailbox vector `fw-mcom-int-index` selects.
    let tree = |pmus: &[(&[u32], Option<u32>, bool)]| {
        let children: Vec<Vec<u8>> = pmus
            .iter()
            .enumerate()
            .map(|(sid, &(vectors, index, addresses))| {
                let mut properties: Vec<(&str, Vec<u8>)> = alloc::vec![
                    ("name", z("pmu")),
                    ("compatible", b"pmu,spmi\0pmu,club\0".to_vec()),
                    ("reg", cells(&[sid as u32 + 0xd, 3, 0, 4, 0, 0])),
                    ("info-fault_log", cells(&[0x1000, 5])),
                    ("interrupt-parent", cells(&[0x146])),
                    ("interrupts", cells(vectors)),
                ];
                if let Some(index) = index {
                    properties.push(("fw-mcom-int-index", cells(&[index])));
                }
                if addresses {
                    properties.push(("fw-mcom-address", cells(&[0x2860])));
                    properties.push(("fw-host-irq-address", cells(&[0x2808])));
                }
                let properties: Vec<(&str, &[u8])> = properties
                    .iter()
                    .map(|(name, value)| (*name, value.as_slice()))
                    .collect();
                encode(&properties, &[])
            })
            .collect();
        let spmi = encode(
            &[
                ("name", &z("nub-spmi1")),
                ("compatible", &z(SPMI)),
                ("gen", &cells(&[3])),
                ("queue-depth", &cells(&[256, 256])),
                ("AAPL,phandle", &cells(&[0x146])),
                (
                    "reg",
                    &pairs(&[
                        (0x8861_4000, 0x4000),
                        (0x8860_4000, 0x4000),
                        (0x8860_0000, 0x4000),
                    ]),
                ),
                ("interrupt-parent", &cells(&[0x146, 0x63, 0x146])),
                ("interrupts", &cells(&[0x100, 0x206, 0x119, 0x104])),
            ],
            &children,
        );
        encode(&[("name", &z("arm-io"))], &[spmi])
    };
    let translate = |offset| Some(0x1_0000_0000 + offset);
    let parse = |pmus: &[(&[u32], Option<u32>, bool)]| {
        let bytes = tree(pmus);
        let io = Node::root(&bytes).unwrap();
        spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63)
            .map(|controllers| controllers[0].pmus.clone())
    };
    let pmus = parse(&[(&[2, 62], Some(1), true), (&[126], Some(0), true)]).unwrap();
    assert_eq!(pmus[0].interrupt, Some(2));
    assert_eq!(
        pmus[0].mailbox,
        Some(FirmwareMailbox {
            registers: 0x2860,
            doorbell: 0x2808,
            vector: Some(62)
        })
    );
    assert_eq!(pmus[1].interrupt, None);
    assert_eq!(pmus[1].mailbox.unwrap().vector, Some(126));
    // T6030 Chapel declares the registers without a vector.
    let pmus = parse(&[(&[2], None, true)]).unwrap();
    assert_eq!(
        (pmus[0].interrupt, pmus[0].mailbox.unwrap().vector),
        (Some(2), None)
    );
    for invalid in [
        &[(&[2, 62][..], None, true)][..],
        &[(&[2, 62], Some(2), true)],
        &[(&[2, 62], Some(1), false)],
        &[(&[2, 2], Some(1), true)],
        &[(&[2, 0x100], Some(1), true)],
        &[(&[2, 62], Some(1), true), (&[62], Some(0), true)],
        &[(&[2, 62, 63], Some(1), true)],
    ] {
        assert!(parse(invalid).is_err());
    }
}

#[test]
fn a_pmu_output_needs_no_rtc_but_the_primary_service_does() {
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
    // A J504AP-shaped pmu-aux (Vale) on its own controller, trimmed.
    let tree = |primary: u32| {
        let pmu = encode(
            &[
                ("name", &z("pmu-aux")),
                ("compatible", b"pmu,spmi\0pmu,vale\0"),
                ("reg", &cells(&[0xe, 3, 0, 4, 0, 0])),
                ("info-scrpad", &cells(&[0xa000, 0x800])),
                ("info-leg_scrpad", &cells(&[0xbb00])),
                ("info-fault_log", &cells(&[0x1800, 3])),
                ("info-id", &cells(&[0, 10])),
                ("is-primary", &cells(&[primary])),
                ("interrupt-parent", &cells(&[0x110])),
                ("interrupts", &cells(&[2])),
            ],
            &[],
        );
        let spmi = encode(
            &[
                ("name", &z("nub-spmi1")),
                ("compatible", &z(SPMI)),
                ("gen", &cells(&[2])),
                ("queue-depth", &cells(&[256, 256])),
                ("AAPL,phandle", &cells(&[0x110])),
                (
                    "reg",
                    &pairs(&[(0x3d81_4000, 0x4000), (0x3d80_4000, 0x4000)]),
                ),
                ("interrupt-parent", &cells(&[0x110, 0x63, 0x110])),
                ("interrupts", &cells(&[0x100, 0x184, 0x119, 0x104])),
            ],
            &[pmu],
        );
        encode(&[("name", &z("arm-io"))], &[spmi])
    };
    let translate = |offset| Some(0x2_0000_0000 + offset);
    let bytes = tree(0);
    let io = Node::root(&bytes).unwrap();
    let controllers = spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).unwrap();
    let pmu = &controllers[0].pmus[0];
    assert_eq!(
        (pmu.primary, pmu.interrupt, pmu.rtc),
        (false, Some(2), None)
    );
    let bytes = tree(1);
    let io = Node::root(&bytes).unwrap();
    assert!(spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).is_err());
}

#[test]
fn gen3_and_gen4_spmi_controllers_place_their_arbiter_bank() {
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
    // The J813AP nub-spmi0, trimmed.
    let tree = |generation: u32, reg: &[(u64, u64)]| {
        let spmi = encode(
            &[
                ("name", &z("nub-spmi0")),
                ("compatible", &z(SPMI)),
                ("gen", &cells(&[generation])),
                ("queue-depth", &cells(&[256, 256])),
                ("AAPL,phandle", &cells(&[0x106])),
                ("reg", &pairs(reg)),
                ("interrupt-parent", &cells(&[0x106, 0x9c, 0x106])),
                (
                    "interrupts",
                    &cells(&[0x100, 0x248, 0x119, 0x104, 0x110, 0x111]),
                ),
            ],
            &[],
        );
        encode(&[("name", &z("arm-io"))], &[spmi])
    };
    let translate = |offset| Some(0x1_0000_0000 + offset);
    let banks = [
        (0x7871_4000, 0x4000),
        (0x7870_4000, 0x4000),
        (0x7870_0000, 0x4000),
    ];
    for (generation, profile) in [
        (3, crate::spmi::Profile::Gen3),
        (4, crate::spmi::Profile::Gen4),
    ] {
        let bytes = tree(generation, &banks);
        let io = Node::root(&bytes).unwrap();
        let [controller] =
            &spmi_controllers(&io, &flat_fixture_extent(&translate), 0x9c).unwrap()[..]
        else {
            panic!("one controller");
        };
        assert_eq!(controller.configuration.profile(), profile);
        assert_eq!(
            controller.banks,
            [(0x1_7871_4000, 0x4000), (0x1_7870_4000, 0x4000)]
        );
        assert_eq!(controller.bank_c, Some((0x1_7870_0000, 0x4000)));
        assert_eq!(controller.irq, 0x248);
        // The handler fails without reg[2].
        let bytes = tree(generation, &banks[..2]);
        let io = Node::root(&bytes).unwrap();
        assert!(spmi_controllers(&io, &flat_fixture_extent(&translate), 0x9c).is_err());
    }
    let bytes = tree(5, &banks);
    let io = Node::root(&bytes).unwrap();
    assert!(spmi_controllers(&io, &flat_fixture_extent(&translate), 0x9c).is_err());
}
