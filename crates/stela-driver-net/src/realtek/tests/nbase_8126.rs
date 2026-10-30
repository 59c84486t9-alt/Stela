// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Nbase 8126 cases.
use super::*;

#[test]
fn nbase_8126_phy_uses_common_eee_only_and_advertises_observed_5g_capability() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for xid in [0x649, 0x64a] {
        for id in [0xc800, 0xc840, 0xc841, 0xc862, 0xc890] {
            for (capability, advertised, geee) in [(0x2070, 0xeeff, 0), (0x6070, 0xefff, 0x10)] {
                let time = Time::default();
                let model = Model::nbase(&time);
                model.state.borrow_mut().phy_ocp.extend([
                    (0xa406, id),
                    (0xa616, capability),
                    (0xa432, geee),
                    (NBASE_AN_CONTROL, 0xffff),
                ]);
                let revision = revision::detect(xid << 20).unwrap();
                assert!(revision.implemented());
                assert!(revision::pci_family(0x8126, revision));
                assert!(!revision::pci_family(0x8125, revision));
                let mut hw = Hardware::new(&model, &time, revision, 0);
                assert_eq!(hw.configure_phy(Some(&script), false).unwrap(), None);
                let s = model.state.borrow();
                assert_eq!(s.phy_ocp[&NBASE_AN_CONTROL], advertised);
                assert_eq!(s.phy_ocp[&0xa432], geee); // No 8125-specific GEEE bit4 write.
                assert_eq!(s.phy_ocp[&0xa400], 0x1200);
                assert_eq!(s.phy_ocp[&PHY_OCP_EEE_ADV], 0);
                assert_eq!(s.phy_ocp[&NBASE_EEE_ADV2], 0);
                assert_eq!(s.phy_ocp[&0xa5b4] & 0x8000, 0);
                assert!(s.g_parameters.is_empty());
                assert!(s.n_parameters.is_empty());
            }
        }
    }
}

#[test]
fn nbase_8126_start_masks_clock_csi_and_legacy_dma_are_distinct() {
    use crate::bus::dma::RegionAllocator;
    for xid in [0x649, 0x64a] {
        let time = Time::default();
        let model = Model::nbase(&time);
        {
            let mut s = model.state.borrow_mut();
            s.bytes[CONFIG2] = 0x80;
            s.bytes[0x34] = 0x28;
            s.bytes[0xd8] = 0x56;
            s.mac.extend([
                (0xe614, 0xffff),
                (0xe63e, 0xffff),
                (0xea1c, 0xffff),
                (0xeb58, 0xffff),
            ]);
            s.csi
                .extend([((2, 0x890), 0xabcdef79), ((2, 0x70c), 0x12785634)]);
        }
        let revision = revision::detect(xid << 20).unwrap();
        let mut hw = Hardware::new(&model, &time, revision, 2);
        hw.initialize_modern().unwrap();
        hw.ep_start().unwrap();
        hw.configure_mac(None).unwrap();
        {
            let s = model.state.borrow();
            assert_eq!(s.bytes[CONFIG2], 0x80);
            assert_eq!(s.bytes[0x34], 0);
            assert_eq!(s.bytes[0xd8], 0x54);
            assert!(s.writes.contains(&(0x34, 0x20, 1))); // CLKREQ bit3 cleared before INT_CFG0 reset.
            assert_eq!(s.mac[&0xe614], 0xfcff);
            assert_eq!(s.mac[&0xe63e], 0xf3ef);
            assert_eq!(s.mac[&0xea1c], 0xfcf9);
            assert_eq!(s.mac[&0xeb58], 0xfffe);
            assert_eq!(s.csi[&(2, 0x890)], 0xabcdef78);
            assert_eq!(s.csi[&(2, 0x70c)], 0x27785634);
            assert!(s.writes.contains(&(0xa7c, 0, 4)));
            assert!(s.writes.contains(&(0x7a, 0, 2)));
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, _, _)| *r == 0xa80 || *r == EPHY_ACCESS || *r == ERI_ADDRESS)
            );
            let at = |cmd| {
                s.writes
                    .iter()
                    .position(|(r, v, _)| *r == CSI_ADDRESS && *v == cmd)
                    .unwrap()
            };
            assert!(at(0x8002_f890) < at(0x0002_f70c));
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
    }
}

#[test]
fn nbase_8126_csi_phases_and_new_mmio_faults_abort_before_dma() {
    for nth in 1..=4 {
        let time = Time::default();
        let mut model = Model::nbase(&time);
        model.fail_csi_at = nth;
        let mut hw = Hardware::new(&model, &time, revision(70), 2);
        assert_eq!(
            hw.configure_mac(None),
            Err(Error::Device(BlockError::Timeout))
        );
        let s = model.state.borrow();
        assert_eq!(s.csi_commands, nth);
        assert_eq!(s.bytes[CONFIG_LOCK], 0);
        assert!(
            !s.writes
                .iter()
                .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
        );
    }
    for address in [0x890, 0x70c] {
        let time = Time::default();
        let model = Model::nbase(&time);
        model.state.borrow_mut().csi.insert((2, address), u32::MAX);
        let mut hw = Hardware::new(&model, &time, revision(70), 2);
        assert_eq!(
            hw.configure_mac(None),
            Err(Error::Device(BlockError::Device { status: u32::MAX }))
        );
        let s = model.state.borrow();
        assert_eq!(s.bytes[CONFIG_LOCK], 0);
        assert!(!s.writes.iter().any(
            |(r, v, _)| *r == CSI_ADDRESS && *v == (ACCESS | 0x2f000 | u32::from(address))
        ));
    }
    for address in [0x34, 0xd8] {
        let time = Time::default();
        let mut model = Model::nbase(&time);
        model.failed_read = Some(address);
        let mut hw = Hardware::new(&model, &time, revision(70), 0);
        assert_eq!(
            hw.configure_mac(None),
            Err(Error::Device(BlockError::Device { status: 255 }))
        );
        assert_eq!(model.state.borrow().bytes[CONFIG_LOCK], 0);
    }
}
