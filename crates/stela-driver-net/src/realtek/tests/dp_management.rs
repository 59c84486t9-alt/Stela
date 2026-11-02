// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Dp management cases.
use super::*;

#[test]
fn dp_mdio_guard_preserves_identity_and_relocks_on_timeout() {
    for version in [28, 31] {
        let time = Time::default();
        let mut model = Model::dp(&time, version, false);
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(hw.phy_read(3).unwrap(), 0xc800);
        assert_eq!(
            hw.configure_phy(None, false).unwrap(),
            Some(Warning::DpPhyIdentityCorrected {
                reported: 0x001c_c800,
                selected: 0x001c_c912
            })
        );
        assert_eq!(hw.phy_read(3).unwrap(), 0xc800);
        {
            let s = model.state.borrow();
            assert_eq!(s.phy[&(0, 3)], 0xc800);
            assert_eq!(s.phy[&(0, 14)], 0); // RTL8211B resume quirk.
            assert_eq!(s.phy[&(0, 0)], 0x1200);
            assert_eq!(
                Model::raw32(&s, DP_MDIO_GATE) & DP_MDIO_GATED,
                DP_MDIO_GATED
            );
            if version == 28 {
                assert_eq!(s.phy[&(1, 0x17)], 0x0cc0);
                assert_eq!(s.extended[&(0x2d, 0x18)], 0x40);
                assert_eq!(s.phy[&(0, 0x0d)] & 0x20, 0x20);
            } else {
                assert!(!s.phy.contains_key(&(1, 0x17)));
            }
        }
        model.fault = Some(PHY_ACCESS);
        let hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(hw.phy_read(3), Err(BlockError::Timeout));
        assert_eq!(model.read32(DP_MDIO_GATE) & DP_MDIO_GATED, DP_MDIO_GATED);
        let model = Model::dp(&time, version, false);
        model.state.borrow_mut().phy.insert((0, 3), 0xc913);
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            hw.configure_phy(None, false),
            Err(Error::UnsupportedPhy(0x001c_c913))
        );
        let model = Model::dp(&time, version, false);
        model.state.borrow_mut().phy.insert((0, 3), 0xc912);
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(hw.configure_phy(None, false).unwrap(), None);
    }
}

#[test]
fn dp_dash_start_notifies_both_modes_and_requires_enabled_management_acknowledgement() {
    for version in [28, 31] {
        for dash in [false, true] {
            let time = Time::default();
            let model = Model::dp(&time, version, dash);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            hw.dp_start().unwrap();
            let s = model.state.borrow();
            assert_eq!(s.eri[&0xe8] & 0xff, 5);
            assert_eq!(s.dp_ocp[&0x30], 1);
            let reg = if version == 31 { 0xb8 } else { 0x10 };
            assert_eq!(s.dp_ocp[&reg] & (1 << 11) != 0, dash);
            if dash {
                assert!(time.now() >= 20_000);
            } else {
                assert!(time.now() < 1_000);
            }
            assert!(
                !s.writes.iter().any(|(r, _, _)| matches!(
                    *r,
                    PHY_ACCESS | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW
                ))
            );
        }
        let time = Time::default();
        let mut model = Model::dp(&time, version, true);
        model.dp_ready_delay = None;
        let hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(hw.dp_start(), Err(BlockError::Timeout));
        assert!(time.now() < 110_000);
        assert_eq!(model.state.borrow().eri[&0xe8] & 0xff, 5); // No blind stop/retry.
    }
}

#[test]
fn dp_incomplete_notification_is_not_retried_even_if_it_later_completes() {
    for version in [28, 31] {
        let time = Time::default();
        let mut model = Model::dp(&time, version, true);
        model.fail_dp_at = 2;
        {
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.dp_start(), Err(BlockError::Timeout));
        }
        assert_eq!(model.state.borrow().dp_commands, 2);
        let count = model.state.borrow().writes.len();
        model.fail_dp_at = usize::MAX;
        time.delay(50_000).unwrap();
        model.read32(DP_OCP_ACCESS);
        assert_eq!(model.state.borrow().dp_ocp[&0x30], 1);
        assert_eq!(model.state.borrow().writes.len(), count);
        assert_eq!(model.state.borrow().eri[&0xe8] & 0xff, 5);
    }
}

#[test]
fn dp_exact_mac_settings_preserve_ephy_bits_and_publish_only_after_management_ready() {
    use crate::bus::dma::TestRegion;
    for version in [28, 31] {
        assert!(revision(version).implemented());
        assert!(revision(version).firmware.is_none());
        let time = Time::default();
        let model = Model::dp(&time, version, true);
        {
            let mut s = model.state.borrow_mut();
            s.ephy.fill(0xabcd);
            s.bytes[CONFIG3] = 0xff;
            s.bytes[CONFIG4] = 0xff;
            s.eri.insert(0xe8, 0xdead_be00);
            s.dp_ocp.insert(0x30, 0xdead_be00);
        }
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        hw.reset().unwrap();
        hw.dp_start().unwrap();
        hw.configure_phy(None, false).unwrap();
        hw.reset().unwrap();
        hw.configure_mac(None).unwrap();
        {
            let s = model.state.borrow();
            assert_eq!(s.eri[&0xe8], 0xdead_be05);
            assert_eq!(s.dp_ocp[&0x30], 0xdead_be01);
            assert_eq!(s.bytes[CONFIG3] & 4, 0);
            assert_eq!(s.bytes[CONFIG4], if version == 31 { 0xfe } else { 0xff });
            assert_eq!(s.bytes[EARLY_TX], 0x3f);
            assert_eq!(s.bytes[CONFIG_LOCK], 0);
            if version == 28 {
                for (reg, clear, set) in [
                    (0xb, 0, 0x48),
                    (0x19, 0x20, 0x50),
                    (0xc, 0x100, 0x20),
                    (0x10, 4, 0),
                ] {
                    assert_eq!(s.ephy[reg], (0xabcd & !clear) | set);
                }
            } else {
                assert_eq!(s.ephy, [0xabcd; 32]);
                assert!(!s.writes.iter().any(|(r, _, _)| *r == EPHY_ACCESS));
            }
            let notified = s
                .writes
                .iter()
                .position(|(r, v, _)| *r == DP_OCP_ACCESS && *v == 0x8000_1030)
                .unwrap();
            let phy = s
                .writes
                .iter()
                .position(|(r, _, _)| *r == PHY_ACCESS)
                .unwrap();
            assert!(notified < phy);
            assert!(!s.writes.iter().any(|(r, v, _)| matches!(
                *r,
                TX_HIGH | TX_LOW | RX_HIGH | RX_LOW
            ) || (*r == COMMAND
                && *v == u32::from(ENABLE))));
        }
        let mut dma = TestRegion::new(200_000 * 8);
        let mut rx = Ring::new(&mut dma, true).unwrap();
        let mut tx = Ring::new(&mut dma, true).unwrap();
        rx.initialize(true);
        tx.initialize(false);
        publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])).unwrap();
        assert_eq!(model.read32(RX_CONFIG), (1 << 15) | (7 << 8) | 0x0e);
        let s = model.state.borrow();
        let at = |reg| s.writes.iter().position(|(r, _, _)| *r == reg).unwrap();
        assert!(at(TX_HIGH) < at(TX_LOW));
        assert!(at(RX_HIGH) < at(RX_LOW));
        assert!(
            s.writes
                .iter()
                .rposition(|(r, v, _)| *r == COMMAND && *v == u32::from(ENABLE))
                .unwrap()
                > at(RX_LOW)
        );
        assert!(time.now() >= 90_000);
    }
}

#[test]
fn dp_management_gate_and_mac_errors_fail_before_dma_publication() {
    for version in [28, 31] {
        for port in [DP_OCP_ACCESS, DP_OCP_DATA, ERI_ADDRESS] {
            let time = Time::default();
            let mut model = Model::dp(&time, version, true);
            model.failed_read = Some(port);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.dp_start(), Err(BlockError::Device { status: u32::MAX }));
            assert!(
                !model.state.borrow().writes.iter().any(|(r, _, _)| matches!(
                    *r,
                    PHY_ACCESS | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW
                ))
            );
        }
        let time = Time::default();
        let mut model = Model::dp(&time, version, false);
        model.failed_read = Some(DP_MDIO_GATE);
        let hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(hw.phy_read(2), Err(BlockError::Device { status: u32::MAX }));
        assert!(model.state.borrow().writes.is_empty());
        let time = Time::default();
        let mut model = Model::dp(&time, version, false);
        model.fault = Some(if version == 28 {
            EPHY_ACCESS
        } else {
            CSI_ADDRESS
        });
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            hw.configure_mac(None),
            Err(Error::Device(BlockError::Timeout))
        );
        assert_eq!(model.read8(CONFIG_LOCK), 0);
        assert!(
            !model
                .state
                .borrow()
                .writes
                .iter()
                .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
        );
    }
}

#[test]
fn dp_phy_failure_blocks_page_cleanup_and_further_transactions_after_late_state_change() {
    for version in [28, 31] {
        let time = Time::default();
        let mut model = Model::dp(&time, version, false);
        model.fail_phy_at = 15;
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            hw.configure_phy(None, false),
            Err(Error::Device(BlockError::Timeout))
        );
        assert_eq!(model.state.borrow().mdio_commands, 15);
        let writes = model.state.borrow().writes.len();
        // Model a late command result, including a changed current page.
        time.delay(50_000).unwrap();
        {
            let mut s = model.state.borrow_mut();
            s.pending = None;
            s.page = 7;
            Model::store32(&mut s, PHY_ACCESS, ACCESS | 0xc800);
        }
        assert!(hw.phy_read(3).is_err());
        assert!(hw.phy_write(PHY_PAGE, 0).is_err());
        assert_eq!(model.state.borrow().writes.len(), writes);
        assert_eq!(model.state.borrow().page, 7);
        assert_eq!(model.read32(DP_MDIO_GATE) & DP_MDIO_GATED, DP_MDIO_GATED);
    }
}
