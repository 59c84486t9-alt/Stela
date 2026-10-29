// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Modern protocol cases.
use super::*;

#[test]
fn modern_ocp_protocol_preserves_data_bit15_and_uses_independent_physical_addresses() {
    use firmware::ScriptIo;
    for version in [40, 42, 44] {
        let time = Time::default();
        let model = Model::modern(&time);
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        hw.phy_write(PHY_PAGE, 0x0a43).unwrap();
        hw.phy_write(0x10, 0x8001).unwrap();
        hw.phy_write(0x0f, 0xffff).unwrap();
        hw.phy_write(0x1e, 0x9876).unwrap();
        assert_eq!(hw.phy_read(0x10).unwrap(), 0x8001);
        assert_eq!(hw.phy_read(0x0f).unwrap(), 0xffff);
        let s = model.state.borrow();
        assert_eq!(s.phy_ocp[&0xa430], 0x8001);
        assert_eq!(s.phy_ocp[&0xa42e], 0xffff);
        assert_eq!(s.phy_ocp[&0xa44c], 0x9876);
        drop(s);
        hw.mac_ocp_write(0xe8de, 0xffff).unwrap();
        assert_eq!(hw.mac_ocp_read(0xe8de).unwrap(), 0xffff);
        assert_eq!(model.state.borrow().mac[&0xe8de], 0xffff);
        assert!(!model.state.borrow().mac.contains_key(&0xe8df));
        hw.write(true, PHY_PAGE, 0x0f80).unwrap();
        hw.write(true, 0, 0x8123).unwrap();
        assert_eq!(hw.read(true, 0).unwrap(), 0x8123);
        assert_eq!(model.state.borrow().mac[&0xf800], 0x8123);
        hw.restore();
        hw.phy_write(PHY_PAGE, 0).unwrap();
        assert_eq!(hw.phy_read(2).unwrap(), 0x001c);
    }
}

#[test]
fn mac40_bmcr_quirk_precedes_each_phy_ocp_write_and_fails_before_power_transition() {
    for (control, expected) in [
        (0x0800, 0x03ff_ffff),
        (0x1000, u32::MAX),
        (0x8800, u32::MAX),
    ] {
        let time = Time::default();
        let model = Model::modern(&time);
        model.state.borrow_mut().eri.insert(0x1a8, u32::MAX);
        let hw = Hardware::new(&model, &time, revision(40), 0);
        hw.phy_write(PHY_CONTROL, control).unwrap();
        let s = model.state.borrow();
        assert_eq!(s.eri[&0x1a8], expected);
        let last_eri = s
            .writes
            .iter()
            .rposition(|(r, _, _)| *r == ERI_ADDRESS)
            .unwrap();
        let phy = s.writes.iter().position(|(r, _, _)| *r == PHY_OCP).unwrap();
        assert!(last_eri < phy);
    }
    let time = Time::default();
    let mut model = Model::modern(&time);
    model.fault = Some(ERI_ADDRESS);
    let hw = Hardware::new(&model, &time, revision(40), 0);
    assert_eq!(hw.phy_write(PHY_CONTROL, 0x1000), Err(BlockError::Timeout));
    assert!(
        !model
            .state
            .borrow()
            .writes
            .iter()
            .any(|(r, _, _)| *r == PHY_OCP)
    );
    let model = Model::modern(&time);
    let hw = Hardware::new(&model, &time, revision(42), 0);
    hw.phy_write(PHY_CONTROL, 0x1000).unwrap();
    assert!(
        !model
            .state
            .borrow()
            .writes
            .iter()
            .any(|(r, _, _)| *r == ERI_ADDRESS)
    );
}

#[test]
fn modern_initial_ownership_requires_both_empty_fifos_and_two_fresh_shared_ready_events() {
    for version in [40, 42, 44, 46] {
        let time = Time::default();
        let model = Model::modern(&time);
        model.state.borrow_mut().mac.insert(0xe8de, 0xffff);
        let hw = Hardware::new(&model, &time, revision(version), 0);
        hw.initialize_modern().unwrap();
        let s = model.state.borrow();
        assert_eq!(s.mac[&0xe8de], 0xbfff);
        assert_eq!(s.bytes[MCU] & 0x82, 2);
        assert_eq!(s.bytes[COMMAND] & ENABLE, 0);
        assert!(time.now() >= 3_800);
        assert!(
            !s.writes
                .iter()
                .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
        );
        drop(s);
        for broken in [TX_CONFIG, MCU, MAC_OCP] {
            let time = Time::default();
            let mut model = Model::modern(&time);
            if broken == TX_CONFIG {
                Model::store32(&mut model.state.borrow_mut(), TX_CONFIG, 0);
            }
            if broken == MCU {
                model.state.borrow_mut().bytes[MCU] = 0x20;
            }
            if broken == MAC_OCP {
                model.shared_ready_delay = None;
            }
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.initialize_modern(), Err(BlockError::Timeout));
            assert!(time.now() < 15_000);
            assert!(
                !model
                    .state
                    .borrow()
                    .writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, PHY_OCP | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
            );
        }
    }
}

#[test]
fn modern_required_protocol_failures_never_become_warnings_or_publish_dma() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for version in [40, 42, 44, 46] {
        for port in [PHY_OCP, ERI_ADDRESS, EPHY_ACCESS, CSI_ADDRESS] {
            let time = Time::default();
            let mut model = Model::modern(&time);
            model.fault = Some(port);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            if port == PHY_OCP {
                assert_eq!(
                    hw.configure_phy(Some(&script), false),
                    Err(Error::Device(BlockError::Timeout))
                );
            } else {
                assert_eq!(
                    hw.configure_mac(None),
                    Err(Error::Device(BlockError::Timeout))
                );
                assert_eq!(model.read8(CONFIG_LOCK), 0);
            }
            assert!(
                !model
                    .state
                    .borrow()
                    .writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
            );
        }
        let time = Time::default();
        let mut model = Model::modern(&time);
        model.failed_read = Some(MAC_OCP);
        let hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            hw.initialize_modern(),
            Err(BlockError::Device { status: u32::MAX })
        );
        let model = Model::modern(&time);
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            hw.configure_phy(None, false),
            Err(Error::Script(if version == 46 {
                "RTL8168H/M requires firmware"
            } else {
                "RTL8168G/8411B requires firmware"
            }))
        );
        model.state.borrow_mut().phy_ocp.insert(0xa406, 0xc912);
        assert_eq!(
            hw.configure_phy(Some(&script), false),
            Err(Error::UnsupportedPhy(0x001c_c912))
        );
    }
    let time = Time::default();
    let mut model = Model::modern(&time);
    model.failed_read = Some(PHY_OCP);
    let hw = Hardware::new(&model, &time, revision(40), 0);
    assert_eq!(hw.phy_read(2), Err(BlockError::Device { status: u32::MAX }));
    assert!(hw.phy_ocp_read(1).is_err());
    assert!(hw.mac_ocp_write(1, 0).is_err());
}
