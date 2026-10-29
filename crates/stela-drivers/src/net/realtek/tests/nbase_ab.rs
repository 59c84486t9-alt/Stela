// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Nbase ab cases.
use super::*;

#[test]
fn nbase_a_b_phy_capability_internal_probe_tuning_and_advertisement_are_exact() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for version in [61, 63] {
        for id in [0xc800, 0xc840] {
            let time = Time::default();
            let model = Model::nbase(&time);
            {
                let mut s = model.state.borrow_mut();
                s.phy_ocp.insert(0xa406, id);
                s.phy_ocp.insert(NBASE_AN_CONTROL, 0xffff);
                s.phy_ocp.insert(NBASE_EEE_ADV2, 0xffff);
                s.n_parameters.insert(0x8551, 0xab);
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.configure_phy(Some(&script), false).unwrap(), None);
            let s = model.state.borrow();
            assert_eq!(s.phy_ocp[&0xa400], 0x1200);
            assert_eq!(s.phy_ocp[&NBASE_AN_CONTROL], 0xeeff);
            assert_eq!(s.phy_ocp[&NBASE_EEE_ADV2], 0);
            assert_eq!(s.phy_ocp[&PHY_OCP_EEE_ADV], 0);
            if version == 61 {
                assert_eq!(s.n_parameters[&0x80a2], 0x153);
                assert_eq!(s.n_parameters[&0x809c], 0x153);
                assert_eq!(s.g_parameters[&0x8257], 0x20f);
                assert_eq!(s.g_parameters[&0x80ea], 0x7843);
                assert_eq!(
                    s.writes
                        .iter()
                        .filter(|(r, v, _)| *r == PHY_OCP && *v == 0xd21c_0000)
                        .count(),
                    25
                );
            } else {
                assert_eq!(s.n_parameters[&0x80f5], 0x760e);
                assert_eq!(s.n_parameters[&0x8107], 0x360e);
                assert_eq!(s.n_parameters[&0x8551], 0x08ab);
                for address in [
                    0x8044, 0x804a, 0x8050, 0x8056, 0x805c, 0x8062, 0x8068, 0x806e, 0x8074, 0x807a,
                ] {
                    assert_eq!(s.g_parameters[&address], 0x2417);
                }
            }
        }
    }
    for version in [61, 63] {
        for rejected in 0..3 {
            let time = Time::default();
            let mut model = Model::nbase(&time);
            match rejected {
                0 => {
                    model.state.borrow_mut().phy_ocp.insert(0xa616, 0x70);
                }
                1 => model.internal_nbase = false,
                _ => {
                    model.state.borrow_mut().phy_ocp.insert(0xa406, 0xc912);
                }
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert!(matches!(
                hw.configure_phy(Some(&script), false),
                Err(Error::UnsupportedPhy(_))
            ));
            assert!(model.state.borrow().n_parameters.is_empty());
        }
    }
}

#[test]
fn nbase_a_b_mac_selects_legacy_dma_and_preserves_distinct_masks_before_publish() {
    use crate::bus::dma::RegionAllocator;
    for version in [61, 63] {
        let time = Time::default();
        let model = Model::nbase(&time);
        {
            let mut s = model.state.borrow_mut();
            s.ephy.fill(0xa55a);
            s.mac.extend([
                (0xeb58, 0xffff),
                (0xe614, 0xffff),
                (0xe63e, 0xffff),
                (0xe040, 0xffff),
                (0xeb62, 0xffff),
            ]);
        }
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        hw.initialize_modern().unwrap();
        hw.configure_mac(None).unwrap();
        {
            let s = model.state.borrow();
            assert_eq!(s.mac[&0xeb58], 0xfffe);
            assert_eq!(s.mac[&0xe614], if version == 61 { 0xfbff } else { 0xfaff });
            assert_eq!(s.mac[&0xe63e], if version == 61 { 0xf3ef } else { 0xf3cf });
            assert_eq!(
                u16::from_le_bytes(
                    s.bytes[NBASE_EEE_TXIDLE..NBASE_EEE_TXIDLE + 2]
                        .try_into()
                        .unwrap()
                ),
                1546
            );
            assert_eq!(
                s.writes
                    .iter()
                    .filter(|(r, v, _)| *r == EPHY_ACCESS && *v & ACCESS != 0)
                    .count(),
                if version == 61 { 12 } else { 6 }
            );
            if version == 61 {
                assert_eq!(s.ephy[3], 0xab66);
                assert_eq!(s.ephy[0], 0x9455);
            } else {
                assert_eq!(s.ephy[2], 0xa56a);
            }
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
            );
        }
        let mut backing = vec![0u64; 200_000];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains alive and has no other descriptor accesses.
        let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
        let mut rx = Ring::new(&mut dma, true).unwrap();
        let mut tx = Ring::new(&mut dma, true).unwrap();
        rx.initialize(true);
        tx.initialize(false);
        publish(&hw, &rx, &tx, read_station(&hw).unwrap()).unwrap();
        assert_eq!(
            model.read32(RX_CONFIG),
            (8 << 27) | (7 << 8) | 0xe | if version == 63 { 1 << 11 } else { 0 }
        );
        assert_eq!(model.read32(TX_CONFIG) & (1 << 7), 0);
    }
}

#[test]
fn nbase_required_phy_and_mac_failures_abort_before_dma_for_both_ids() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for version in [61, 63] {
        for id in [0xc800, 0xc840] {
            let time = Time::default();
            let model = Model::nbase(&time);
            model.state.borrow_mut().phy_ocp.insert(0xa406, id);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            hw.configure_phy(Some(&script), false).unwrap();
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
                assert_ne!(model.state.borrow().phy_ocp[&0xa400], 0x1200);
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
        for fault in 0..5 {
            let time = Time::default();
            let mut model = Model::nbase(&time);
            Model::store32(&mut model.state.borrow_mut(), MISC, RXDV_GATED);
            match fault {
                0 => model.fault = Some(EPHY_ACCESS),
                1 => model.fault = Some(CSI_ADDRESS),
                2 => model.failed_read = Some(MAC_OCP),
                3 => model.failed_read = Some(0x1880),
                _ => {
                    model.state.borrow_mut().mac.insert(0xe00e, 1 << 13);
                }
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            let expected = match fault {
                2 => BlockError::Device { status: u32::MAX },
                3 => BlockError::Device { status: 65535 },
                _ => BlockError::Timeout,
            };
            assert_eq!(hw.configure_mac(None), Err(Error::Device(expected)));
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
fn nbase_backup_station_and_runtime_tx_lpi_failure_do_not_guess_recovery() {
    for version in [61, 63, 64, 65, 66, 70] {
        let time = Time::default();
        let model = Model::nbase(&time);
        let hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(read_station(&hw).unwrap(), Mac([2, 3, 4, 5, 6, 7]));
        {
            let mut s = model.state.borrow_mut();
            Model::store32(&mut s, NBASE_MAC0_BACKUP, 1);
            Model::store32(&mut s, MAC0, 0x1514_1312);
            Model::store32(&mut s, MAC4, 0x1716);
        }
        assert_eq!(
            read_station(&hw).unwrap(),
            Mac([0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
        );
        let mut model = Model::nbase(&time);
        model.failed_read = Some(NBASE_MAC0_BACKUP);
        let hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            read_station(&hw),
            Err(BlockError::Device { status: u32::MAX })
        );
        let mut model = Model::nbase(&time);
        model.fail_mac_address = Some(0xe040);
        model.state.borrow_mut().phy_ocp.insert(0xa402, 0x792d);
        let mut link = RuntimeLink::default();
        {
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(link.update(&hw), Err(BlockError::Device { status: 255 }));
        }
        let writes = model.state.borrow().writes.len();
        model.fail_mac_address = None;
        time.delay(50_000);
        let hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(link.update(&hw), Err(BlockError::Device { status: 255 }));
        assert_eq!(model.state.borrow().writes.len(), writes);
    }
}
