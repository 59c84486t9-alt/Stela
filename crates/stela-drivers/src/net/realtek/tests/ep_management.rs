// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Ep management cases.
use super::*;

#[test]
fn ep_cmac_stop_acknowledges_w1c_before_shared_fifo_and_is_bounded_on_failure() {
    for version in [51, 52] {
        let time = Time::default();
        let model = Model::ep(&time, version, false);
        let hw = Hardware::new(&model, &time, revision(version), 0);
        hw.initialize_modern().unwrap();
        let s = model.state.borrow();
        assert_eq!(s.bytes[IBCR0], 0x84);
        assert_eq!(s.bytes[IBCR2], 0x84);
        assert_eq!(s.bytes[IBISR0] & 0x20, 0);
        let at = |reg| s.writes.iter().position(|(r, _, _)| *r == reg).unwrap();
        assert!(at(IBCR2) < at(IBISR0));
        assert!(at(IBISR0) < at(IBCR0));
        assert!(at(IBCR0) < at(MISC));
        assert!(time.now() >= 100_000);
        drop(s);
        let time = Time::default();
        let mut model = Model::ep(&time, version, false);
        model.cmac_ready_delay = None;
        let hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(hw.initialize_modern(), Err(BlockError::Timeout));
        assert_eq!(time.now(), 100_000_000);
        assert_eq!(model.state.borrow().writes, [(IBCR2, 0x84, 1)]);
        let time = Time::default();
        let mut model = Model::ep(&time, version, false);
        model.failed_read = Some(IBISR0);
        let hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            hw.initialize_modern(),
            Err(BlockError::Device { status: 255 })
        );
        assert_eq!(model.state.borrow().writes, [(IBCR2, 0x84, 1)]);
    }
}

#[test]
fn ep_oob_namespace_fp_base_masks_and_conditional_ack_are_real_and_fallible() {
    for version in [51, 52] {
        for enabled in [false, true] {
            let time = Time::default();
            let model = Model::ep(&time, version, enabled);
            {
                let mut s = model.state.borrow_mut();
                s.oob.extend([(0x180, 0xaabb_cc00), (0x30, 0x7654_3202)]);
                s.eri.extend([(0x180, 0x1122_3344), (0x30, 0x5566_7788)]);
            }
            let hw = Hardware::new(&model, &time, revision(version), 0);
            hw.ep_start().unwrap();
            let s = model.state.borrow();
            assert_eq!(s.oob[&0x180], 0xaabb_cc05);
            assert_eq!(s.oob[&0x30], 0x7654_3203);
            assert_eq!(s.eri[&0x180], 0x1122_3344);
            assert_eq!(s.eri[&0x30], 0x5566_7788);
            assert_eq!(s.oob.get(&0x124).copied().unwrap_or(0) & 1 != 0, enabled);
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, PHY_OCP | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
            );
        }
        let time = Time::default();
        let mut model = Model::ep(&time, version, true);
        model.ep_ready_delay = None;
        let hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(hw.ep_start(), Err(BlockError::Timeout));
        assert!(time.now() < 310_000);
        assert_eq!(model.state.borrow().oob[&0x180] & 0xff, 5);
        for port in [ERI_ADDRESS, ERI_DATA] {
            let time = Time::default();
            let mut model = Model::ep(&time, version, true);
            model.failed_read = Some(port);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.ep_start(), Err(BlockError::Device { status: u32::MAX }));
        }
    }
}

#[test]
fn ep_and_fp_phy_masks_and_pwm_paths_are_distinct_without_early_mac_firmware() {
    for version in [51, 52] {
        let time = Time::default();
        let model = Model::ep(&time, version, false);
        {
            let mut s = model.state.borrow_mut();
            for address in [0x8084, 0x80f3, 0x80d7, 0x808b, 0x809b, 0x80ad, 0x80b0] {
                s.g_parameters.insert(address, 0xffff);
            }
            s.phy_ocp
                .extend([(0xbcc8, 0xffff), (0xc422, 0xffff), (0xa430, 0xffff)]);
        }
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(hw.configure_phy(None, false).unwrap(), None);
        let s = model.state.borrow();
        assert_eq!(s.phy_ocp[&0xa400], 0x1200);
        assert_eq!(s.phy_ocp[&0xa5d0], 0);
        assert!(!s.writes.iter().any(|(r, _, _)| *r == MAC_OCP));
        if version == 51 {
            assert_eq!(s.g_parameters[&0x80f3], 0x8bff);
            assert_eq!(s.g_parameters[&0x80d7], 0x84ff);
            assert_eq!(s.g_parameters[&0x8084], 0x9fff);
            assert_eq!(s.phy_ocp[&0xc422], 0xdfff);
            assert_eq!(s.phy_ocp[&0xbcc8], 0xfeff);
            assert_eq!(s.phy_ocp[&0xbc84], 0xed);
            assert_eq!(s.phy_ocp[&0xbcd8], 0x1065);
        } else {
            assert_eq!(s.g_parameters[&0x808b], 0xcbff);
            assert_eq!(s.g_parameters[&0x809b], 0xb7ff);
            assert_eq!(s.g_parameters[&0x80ad], 0x9fff);
            assert_eq!(s.g_parameters[&0x80b0], 0x93ff);
            assert_eq!(s.g_parameters[&0x8011] & 0x800, 0x800);
            assert_eq!(s.g_parameters[&0x8016] & 0x400, 0x400);
            assert_eq!(s.phy_ocp[&0xa4a2] & 0x200, 0x200);
            assert_eq!(s.phy_ocp[&0xa428] & 0x80, 0x80);
            assert!(!s.phy_ocp.contains_key(&0xbcd8));
        }
    }
}
