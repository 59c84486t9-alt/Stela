// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! F revisions cases.
use super::*;

#[test]
fn f_phy_sequences_preserve_distinct_green_tuning_masks_and_refuse_external_phy() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for version in [35, 36, 38] {
        let time = Time::default();
        let model = Model::ready(&time);
        {
            let mut s = model.state.borrow_mut();
            for parameter in [
                0x8b54, 0x8b55, 0x8b5d, 0x8b5e, 0x8b67, 0x8b70, 0x8b79, 0x8b80, 0x8b85, 0x8b86,
                0x8a7c, 0x8a7f, 0x8a82, 0x8a85, 0x8a88,
            ] {
                s.parameters.insert(parameter, 0xffff);
            }
            s.extended.insert((0x20, 0x15), 0xffff);
            s.extended.insert((0x2d, 0x18), 0x8000);
            s.phy.insert((2, 8), 0xffff);
            s.phy.insert((3, 0x19), 0xffff);
            s.phy.insert((3, 0x10), 0xffff);
        }
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        hw.configure_phy(Some(&script), false).unwrap();
        let s = model.state.borrow();
        assert_eq!(s.page, 0);
        assert_eq!(s.phy[&(0, 0)], 0x1200);
        assert_eq!(s.phy[&(0, 0x16)], 0xa55a);
        assert_eq!(s.extended[&(0x2d, 0x18)], 0x8010);
        if version != 36 {
            assert_eq!(s.parameters[&0x8b55], 0);
            assert_eq!(s.parameters[&0x8b79], 0xaa00);
            assert_eq!(
                s.extended[&(0x78, 0x19)],
                if version == 35 { 0xfb } else { 0xaa }
            );
            assert_eq!(s.phy[&(3, 9)], 0xa20f);
        } else {
            assert_eq!(s.parameters[&0x8b55], 0xffff);
            assert!(!s.extended.contains_key(&(0x78, 0x19)));
        }
        if version == 38 {
            assert_eq!(s.parameters[&0x8b54], 0xf7ff);
            assert_eq!(s.parameters[&0x8a7c], 0xfeff);
            assert_eq!(s.parameters[&0x8a88], 0xfeff);
            assert_eq!(s.phy[&(3, 0x19)], 0xfffe);
            assert_eq!(s.phy[&(3, 0x10)], 0xfbff);
        }
        drop(s);
        let model = Model::ready(&time);
        model.state.borrow_mut().phy.insert((0, 3), 0xc912);
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            hw.configure_phy(Some(&script), false),
            Err(Error::UnsupportedPhy(0x001c_c912))
        );
        assert!(!model.state.borrow().phy.contains_key(&(0, 0x16)));
    }
}

#[test]
fn f_mac_starts_use_distinct_ephy_fifo_and_l1_sequences() {
    for version in [35, 36, 38] {
        let time = Time::default();
        let model = Model::ready(&time);
        {
            let mut s = model.state.borrow_mut();
            s.ephy.fill(0xffff);
            s.bytes[CONFIG3] = 0xff;
            s.bytes[CONFIG4] = 0xff;
            s.bytes[CONFIG5] = 0xff;
            s.bytes[0x1b] = 0xff;
            s.eri.insert(0x1b0, 0xffff);
        }
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        hw.configure_mac(None).unwrap();
        let s = model.state.borrow();
        assert_eq!(s.bytes[CONFIG_LOCK], 0);
        assert_eq!(s.bytes[CONFIG5] & 9, 0);
        assert_eq!(s.eri[&0xc8], 0x0010_0002);
        assert_eq!(s.eri[&0xd0], 0x60);
        assert_eq!(s.eri[&0x1d0] & 0x12, 0x12);
        assert_eq!(s.eri[&0x1b0] & 3, 0);
        assert_eq!(s.ephy[6], 0xff3f);
        assert_eq!(s.bytes[EARLY_TX], 0x27);
        if version == 38 {
            assert_eq!(s.eri[&0xd4], 0x0c00);
            assert_eq!(s.ephy[0xf], 0x5200);
            assert_eq!(s.bytes[CONFIG3] & 2, 0);
            assert_eq!(s.bytes[0x1b], 0xff);
        } else {
            assert_eq!(s.eri[&0xd4], 0x1f00);
            assert_eq!(s.ephy[8], 0xfffe);
            assert_eq!(s.bytes[0x1b] & 7, 0);
        }
    }
}

#[test]
fn f_station_prefers_eri_with_validity_fallback_and_propagates_access_errors() {
    for version in [35, 36, 38] {
        let time = Time::default();
        let mut model = Model::ready(&time);
        {
            let mut s = model.state.borrow_mut();
            s.eri.insert(0xe0, 0x0504_0302);
            s.eri.insert(0xe4, 0x0706);
            Model::store32(&mut s, MAC0, 0x1514_1312);
            Model::store32(&mut s, MAC4, 0x1716);
        }
        let hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(read_station(&hw).unwrap(), Mac([2, 3, 4, 5, 6, 7]));
        model.state.borrow_mut().eri.insert(0xe0, 0);
        model.state.borrow_mut().eri.insert(0xe4, 0);
        assert_eq!(
            read_station(&hw).unwrap(),
            Mac([0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
        );
        model.fault = Some(ERI_ADDRESS);
        let hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(read_station(&hw), Err(BlockError::Timeout));
    }
}

#[test]
fn f_and_8411_link_patches_have_distinct_100m_values_and_filter_reset_rules() {
    for version in [35, 36, 38] {
        for speed in [0x10, 8, 4] {
            let time = Time::default();
            let model = Model::ready(&time);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            link_patch(&hw, speed | 2).unwrap();
            let s = model.state.borrow();
            assert_eq!(s.eri[&0x1bc], if speed == 0x10 { 0x11 } else { 0x1f });
            assert_eq!(
                s.eri[&0x1dc],
                if speed == 0x10 || (version == 38 && speed == 8) {
                    5
                } else {
                    0x3f
                }
            );
            assert_eq!(s.eri.contains_key(&0xdc), version == 38);
        }
    }
}

#[test]
fn f_required_firmware_mdio_and_mac_protocol_faults_remain_explicit() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for version in [35, 36, 38] {
        let time = Time::default();
        let model = Model::ready(&time);
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert!(matches!(
            hw.configure_phy(None, false),
            Err(Error::Script(_))
        ));
        for nth in [15, 30, 45] {
            let time = Time::default();
            let mut model = Model::ready(&time);
            model.fail_phy_at = nth;
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_phy(Some(&script), false),
                Err(Error::Device(BlockError::Timeout))
            );
            assert_ne!(model.state.borrow().phy[&(0, 0)], 0x1200);
        }
        let ports = &[CSI_ADDRESS, EPHY_ACCESS, ERI_ADDRESS];
        for &port in ports {
            let time = Time::default();
            let mut model = Model::ready(&time);
            model.fault = Some(port);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_mac(None),
                Err(Error::Device(BlockError::Timeout))
            );
            let s = model.state.borrow();
            assert_eq!(s.bytes[CONFIG_LOCK], 0);
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW | COMMAND))
            );
        }
    }
}
