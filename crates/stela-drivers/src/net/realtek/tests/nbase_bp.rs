// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Nbase bp cases.
use super::*;

#[test]
fn nbase_bp_phy_preserves_distinct_indirect_masks_and_does_not_inherit_cp() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for id in [0xc800, 0xc840, 0xc841, 0xc862, 0xc890] {
        let time = Time::default();
        let model = Model::nbase(&time);
        {
            let mut s = model.state.borrow_mut();
            s.phy_ocp.insert(0xa406, id);
            s.g_parameters.extend([(0x8010, 0xabcd), (0x8174, 0xa123)]);
            s.n_parameters.extend([(0x8088, 0x1278), (0x808f, 0x34ab)]);
        }
        let mut hw = Hardware::new(&model, &time, revision(66), 0);
        assert_eq!(hw.configure_phy(Some(&script), false).unwrap(), None);
        let s = model.state.borrow();
        assert_eq!(s.g_parameters[&0x8010], 0xa3cd);
        assert_eq!(s.g_parameters[&0x8174], 0x9923);
        assert_eq!(s.n_parameters[&0x8088], 0x9078);
        assert_eq!(s.n_parameters[&0x808f], 0x90ab);
        assert!(!s.g_parameters.contains_key(&0x81b8));
        assert!(!s.n_parameters.contains_key(&0x807f));
        assert_eq!(s.phy_ocp[&0xa400], 0x1200);
        assert_eq!(s.phy_ocp[&NBASE_AN_CONTROL] & 0x1180, 0x80);
        assert_eq!(s.phy_ocp[&PHY_OCP_EEE_ADV], 0);
        assert_eq!(s.phy_ocp[&NBASE_EEE_ADV2], 0);
        let first = |reg, value| {
            s.writes
                .iter()
                .position(|(r, v, _)| {
                    *r == PHY_OCP && *v == (ACCESS | (u32::from(reg) << 15) | u32::from(value))
                })
                .unwrap()
        };
        assert!(first(0xa42cu16, 0xa55au16) < first(0xa436, 0x8010));
    }
}

#[test]
fn nbase_bp_management_uses_its_own_namespace_mask_order_and_no_ep_ack_loop() {
    for enabled in [false, true] {
        let time = Time::default();
        let mut model = Model::nbase(&time);
        model.ep_mode = Some(66);
        model.ep_ready_delay = None;
        {
            let mut s = model.state.borrow_mut();
            s.oob.extend([
                (0x128, u32::from(enabled)),
                (0x14, 0xaabb_cc77),
                (0x18, 0x1234_5678),
                (0x10, 0x8765_4321),
            ]);
            s.eri.extend([
                (0x14, 0x1111_2222),
                (0x18, 0x3333_4444),
                (0x10, 0x5555_6666),
            ]);
        }
        let hw = Hardware::new(&model, &time, revision(66), 0);
        hw.initialize_modern().unwrap();
        hw.reset().unwrap();
        hw.ep_start().unwrap();
        let s = model.state.borrow();
        assert_eq!(s.oob[&0x14], 0xaabb_cc05);
        assert_eq!(s.oob[&0x18], 0x1234_5600);
        assert_eq!(s.oob[&0x10], 0x8765_4301);
        assert_eq!(s.eri[&0x14], 0x1111_2222);
        assert_eq!(s.eri[&0x18], 0x3333_4444);
        assert_eq!(s.eri[&0x10], 0x5555_6666);
        let commands: Vec<_> = s
            .writes
            .iter()
            .filter_map(|(r, v, _)| (*r == ERI_ADDRESS).then_some(*v))
            .collect();
        assert_eq!(
            commands,
            vec![0x0002_f128, 0x8002_1014, 0x8002_1018, 0x8002_1010]
        );
        assert!(!s.writes.iter().any(|(r, _, _)| matches!(
            *r,
            IBCR0 | IBCR2 | IBISR0 | PHY_OCP | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW
        )));
        assert!(time.now() < 10_000);
    }
    for nth in 1..=4 {
        let time = Time::default();
        let mut model = Model::nbase(&time);
        model.fail_eri_at = nth;
        let hw = Hardware::new(&model, &time, revision(66), 0);
        assert_eq!(hw.ep_start(), Err(BlockError::Timeout));
        let s = model.state.borrow();
        assert_eq!(s.eri_commands, nth);
        assert!(
            !s.writes
                .iter()
                .any(|(r, _, _)| matches!(*r, PHY_OCP | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
        );
    }
    for port in [ERI_ADDRESS, ERI_DATA] {
        let time = Time::default();
        let mut model = Model::nbase(&time);
        model.failed_read = Some(port);
        let hw = Hardware::new(&model, &time, revision(66), 0);
        assert_eq!(hw.ep_start(), Err(BlockError::Device { status: u32::MAX }));
    }
}
