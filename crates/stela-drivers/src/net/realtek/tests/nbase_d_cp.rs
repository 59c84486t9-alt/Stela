// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Nbase d cp cases.
use super::*;

#[test]
fn nbase_d_k_9151a_cp_exact_firmware_and_phy_paths_preserve_cp_only_effects() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for xid in [0x688, 0x689, 0x68a, 0x68b, 0x708] {
        let revision = revision::detect(xid << 20).unwrap();
        assert!(revision.implemented());
        assert!(revision::pci_family(0x8125, revision));
        assert!(!revision::pci_family(0x8126, revision));
        for id in [0xc800, 0xc840, 0xc841, 0xc862, 0xc890] {
            let time = Time::default();
            let model = Model::nbase(&time);
            {
                let mut s = model.state.borrow_mut();
                s.phy_ocp.extend([
                    (0xa406, id),
                    (0xa5b4, 0xffff),
                    (0xad0e, 0xa5ff),
                    (0xad78, 0x20),
                    (0xa430, 0x84),
                    (0xa442, 0x20),
                    (NBASE_AN_CONTROL, 0xffff),
                ]);
                s.n_parameters.insert(0x807f, 0x12a5);
            }
            let mut hw = Hardware::new(&model, &time, revision, 2);
            assert_eq!(hw.configure_phy(Some(&script), false).unwrap(), None);
            let s = model.state.borrow();
            assert_eq!(s.phy_ocp[&0xa5b4], 0x7fff);
            assert_eq!(s.phy_ocp[&0xa442] & 0x800, 0x800);
            assert_eq!(s.phy_ocp[&0xa430] & 4, 0);
            assert_eq!(s.phy_ocp[&0xa432] & 0x10, 0x10);
            assert_eq!(s.phy_ocp[&NBASE_AN_CONTROL], 0xeeff);
            assert_eq!(s.phy_ocp[&PHY_OCP_EEE_ADV], 0);
            assert_eq!(s.phy_ocp[&NBASE_EEE_ADV2], 0);
            assert_eq!(s.phy_ocp[&0xa400], 0x1200);
            let firmware = s
                .writes
                .iter()
                .position(|(r, v, _)| *r == PHY_OCP && *v == 0xd216_a55a)
                .unwrap();
            let gphy = s
                .writes
                .iter()
                .position(|(r, v, _)| *r == PHY_OCP && *v == 0xd221_0820)
                .unwrap();
            assert!(firmware < gphy);
            if revision.version == 65 {
                assert_eq!(s.phy_ocp[&0xad0e], 0xa58b);
                assert_eq!(s.phy_ocp[&0xad78], 0x30);
                assert_eq!(s.n_parameters[&0x807f], 0x53a5);
                assert_eq!(s.phy_ocp[&0xa430] & 3, 3);
                assert_eq!(s.phy_ocp[&0xa442] & 0x80, 0x80);
                for (address, value) in [
                    (0x81b8, 0xb4),
                    (0x81ba, 0xe4),
                    (0x81c5, 0x104),
                    (0x81d0, 0x54d),
                ] {
                    assert_eq!(s.g_parameters[&address], value);
                }
            } else {
                assert_eq!(s.phy_ocp[&0xad0e], 0xa5ff);
                assert_eq!(s.phy_ocp[&0xad78], 0x20);
                assert_eq!(s.n_parameters[&0x807f], 0x12a5);
                assert!(s.g_parameters.is_empty());
            }
        }
    }
}

#[test]
fn nbase_d_cp_id_capability_external_and_required_firmware_failures_are_explicit() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for version in [64, 65, 66, 70] {
        for id in [0xc800, 0xc840, 0xc841, 0xc862, 0xc890] {
            for rejected in 0..4 {
                let time = Time::default();
                let mut model = Model::nbase(&time);
                model.state.borrow_mut().phy_ocp.insert(0xa406, id);
                match rejected {
                    0 => {
                        model.state.borrow_mut().phy_ocp.insert(0xa616, 0x70);
                    }
                    1 => model.internal_nbase = false,
                    2 => {
                        model.state.borrow_mut().phy_ocp.insert(0xa406, 0xc861);
                    }
                    _ => {}
                }
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                let result = hw.configure_phy((rejected != 3).then_some(&script), false);
                assert!(matches!(
                    result,
                    Err(Error::UnsupportedPhy(_)) | Err(Error::Script(_))
                ));
                let s = model.state.borrow();
                assert!(s.n_parameters.is_empty());
                assert!(s.g_parameters.is_empty());
                assert!(
                    !s.writes
                        .iter()
                        .any(|(r, v, _)| (*r == PHY_OCP && *v == 0xd216_a55a)
                            || matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                );
            }
        }
    }
}

#[test]
fn nbase_d_cp_required_command_failures_abort_before_enable_or_dma() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for version in [64, 65, 66, 70] {
        for id in [0xc800, 0xc840, 0xc841, 0xc862, 0xc890] {
            let time = Time::default();
            let model = Model::nbase(&time);
            model.state.borrow_mut().phy_ocp.insert(0xa406, id);
            Hardware::new(&model, &time, revision(version), 0)
                .configure_phy(Some(&script), false)
                .unwrap();
            let total = model.state.borrow().phy_ocp_commands;
            for nth in [20, total / 2, total - 3] {
                let time = Time::default();
                let mut model = Model::nbase(&time);
                model.state.borrow_mut().phy_ocp.insert(0xa406, id);
                model.fail_phy_ocp_at = nth;
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(
                    hw.configure_phy(Some(&script), false),
                    Err(Error::Device(BlockError::Timeout))
                );
                let s = model.state.borrow();
                assert_ne!(s.phy_ocp[&0xa400], 0x1200);
                assert!(
                    !s.writes
                        .iter()
                        .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                );
            }
        }
        for fault in 0..4 {
            let time = Time::default();
            let mut model = Model::nbase(&time);
            Model::store32(&mut model.state.borrow_mut(), MISC, RXDV_GATED);
            match fault {
                0 => model.fault = Some(CSI_ADDRESS),
                1 => model.failed_read = Some(MAC_OCP),
                2 => model.failed_read = Some(0x1880),
                _ => {
                    model.state.borrow_mut().mac.insert(0xe00e, 1 << 13);
                }
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 2);
            assert!(hw.configure_mac(None).is_err());
            let s = model.state.borrow();
            assert_eq!(s.bytes[CONFIG_LOCK], 0);
            assert_ne!(Model::raw32(&s, MISC) & RXDV_GATED, 0);
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
            );
        }
    }
}

#[test]
fn nbase_d_cp_bp_mac_has_no_ephy_table_and_publishes_source_rx_and_legacy_dma() {
    use crate::bus::dma::RegionAllocator;
    for xid in [0x688, 0x689, 0x68a, 0x68b, 0x708, 0x681] {
        let revision = revision::detect(xid << 20).unwrap();
        let time = Time::default();
        let model = Model::nbase(&time);
        {
            let mut s = model.state.borrow_mut();
            s.mac
                .extend([(0xeb58, 0xffff), (0xe614, 0xffff), (0xe63e, 0xffff)]);
            s.ephy.fill(0xa55a);
        }
        let mut hw = Hardware::new(&model, &time, revision, 2);
        hw.initialize_modern().unwrap();
        hw.configure_mac(None).unwrap();
        {
            let s = model.state.borrow();
            assert_eq!(s.mac[&0xeb58], 0xfffe);
            assert_eq!(s.mac[&0xe614], 0xfbff);
            assert_eq!(s.mac[&0xe63e], 0xf3ef);
            assert!(s.ephy.iter().all(|v| *v == 0xa55a));
            assert!(!s.writes.iter().any(|(r, _, _)| *r == EPHY_ACCESS));
            assert!(s.writes.contains(&(0xafc, 0, 4)));
            assert!(!s.writes.iter().any(|(r, _, _)| *r == 0x7a));
            assert!(s.writes.contains(&(CSI_ADDRESS, 0x0002_f70c, 4)));
        }
        let mut backing = vec![0u64; 200_000];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives both rings and has no other accesses.
        let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
        let mut rx = Ring::new(&mut dma, true).unwrap();
        let mut tx = Ring::new(&mut dma, true).unwrap();
        rx.initialize(true);
        tx.initialize(false);
        publish(&hw, &rx, &tx, read_station(&hw).unwrap()).unwrap();
        assert_eq!(
            model.read32(RX_CONFIG),
            (8 << 27) | (7 << 8) | (1 << 11) | 0xe
        );
        assert_eq!(model.read32(TX_CONFIG) & (1 << 7), 0);
    }
}
