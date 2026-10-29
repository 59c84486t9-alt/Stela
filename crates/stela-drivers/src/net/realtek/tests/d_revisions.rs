// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! D revisions cases.
use super::*;

#[test]
fn d_revisions_apply_exact_efuse_tuning_and_firmware_only_after_readiness() {
    for (version, sentinel) in [(25, 0xbf00), (26, 0xb300)] {
        for efuse in [0xb1, 0] {
            for low in [0x006c, 0x0070] {
                let time = Time::default();
                let model = Model::ready(&time);
                {
                    let mut s = model.state.borrow_mut();
                    s.efuse = efuse;
                    s.parameters.insert(0x001b, sentinel);
                    s.phy.insert((2, 0x0d), 0x5000 | low);
                    s.phy.insert((2, 2), 0xffff);
                    s.phy.insert((2, 3), 0xffff);
                    s.phy.insert((2, 0x0b), 0xffff);
                    s.phy.insert((2, 0x0c), 0xffff);
                }
                // Independent script writes a distinctive page-zero marker.
                let bytes = 0x8016_a55au32.to_le_bytes();
                let script = Script::parse(&bytes).unwrap();
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                hw.configure_phy(Some(&script), false).unwrap();
                let s = model.state.borrow();
                assert_eq!(s.page, 0);
                assert_eq!(s.phy[&(1, 6)], 0x4064);
                assert_eq!(s.phy[&(3, 0x12)], 0xf49f);
                assert_eq!(s.parameters[&0x8332], 0x5561);
                let tune = if efuse == 0xb1 {
                    0x669a
                } else if version == 25 {
                    0x6662
                } else {
                    0x2642
                };
                assert_eq!(s.phy[&(2, 5)], tune);
                assert_eq!(s.parameters[&0x8330], tune);
                assert_eq!(s.phy[&(2, 2)], 0xf9ff);
                assert_eq!(s.phy[&(2, 3)], 0x1fff);
                if version == 25 {
                    assert_eq!(s.phy[&(2, 0x0b)], 0xff10);
                    assert_eq!(s.phy[&(2, 0x0c)], 0xa2ff);
                    assert_eq!(s.phy[&(2, 0x0f)] & 0x10, 0x10);
                } else {
                    assert_eq!(s.phy[&(2, 0x0b)], 0xffff);
                    assert_eq!(s.phy[&(2, 0x0c)], 0xffff);
                    assert_eq!(s.phy[&(2, 0x0f)] & 0x17, 0x17);
                }
                assert_eq!(s.phy[&(0, 0x16)], 0xa55a);
                assert_eq!(s.phy[&(0, 0)], 0x1200);
                let ramp: Vec<_> = s
                    .writes
                    .iter()
                    .filter(|(r, v, _)| *r == PHY_ACCESS && *v & 0xffff_ff00 == 0x800d_5000)
                    .map(|(_, v, _)| *v as u16)
                    .collect();
                if efuse == 0xb1 && low != 0x6c {
                    assert!(ramp.starts_with(&[
                        0x5065, 0x5066, 0x5067, 0x5068, 0x5069, 0x506a, 0x506b, 0x506c
                    ]));
                } else {
                    assert!(!ramp.contains(&0x5065));
                }
            }
        }
    }
}

#[test]
fn d_revisions_refuse_unready_phy_missing_firmware_and_efuse_faults() {
    for version in [25, 26] {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for fault in [false, true] {
            let time = Time::default();
            let mut model = Model::ready(&time);
            if fault {
                model.fault = Some(EFUSE_ACCESS);
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            let error = hw.configure_phy(Some(&script), false).unwrap_err();
            if fault {
                assert_eq!(error, Error::Device(BlockError::Timeout));
            } else {
                assert_eq!(
                    error,
                    Error::Script("RTL8168D PHY is not ready for firmware")
                );
            }
            let s = model.state.borrow();
            assert_eq!(s.page, 0);
            assert!(!s.phy.contains_key(&(0, 0x16)));
            assert_ne!(s.phy[&(0, 0)], 0x1200);
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, v, _)| *r == COMMAND && *v == u32::from(ENABLE))
            );
        }
        let time = Time::default();
        let model = Model::ready(&time);
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            hw.configure_phy(None, false),
            Err(Error::Script("RTL8168D requires firmware"))
        );
    }
    let time = Time::default();
    let model = Model::ready(&time);
    let hw = Hardware::new(&model, &time, revision(25), 0);
    assert!(hw.efuse_read(0x400).is_err());
    assert!(model.state.borrow().writes.is_empty());
}

#[test]
fn d_mac_start_clears_stale_jumbo_state_and_uses_single_fetch_receive_configuration() {
    use crate::bus::dma::RegionAllocator;
    for version in [25, 26] {
        let mut backing = vec![0u64; 200_000];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives all descriptor use and has no other accesses.
        let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
        let mut rx = Ring::new(&mut dma, true).unwrap();
        let mut tx = Ring::new(&mut dma, true).unwrap();
        rx.initialize(true);
        tx.initialize(false);
        let time = Time::default();
        let model = Model::ready(&time);
        model.state.borrow_mut().bytes[CONFIG3] = 0xff;
        model.state.borrow_mut().bytes[CONFIG4] = 0xff;
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        hw.configure_mac(None).unwrap();
        assert_eq!(model.read8(CONFIG3) & 4, 0);
        assert_eq!(model.read8(CONFIG4) & 2, 0);
        assert_eq!(model.read8(CONFIG_LOCK), 0);
        publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])).unwrap();
        assert_eq!(model.read32(RX_CONFIG), (1 << 15) | (7 << 8) | 0x0e);
    }
}

#[test]
fn d_revision_mdio_and_failed_efuse_reads_propagate_for_each_accepted_phy() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for (version, sentinel) in [(25, 0xbf00), (26, 0xb300)] {
        for id in [0xc800, 0xc912] {
            for nth in [20, 45, 70] {
                let time = Time::default();
                let mut model = Model::ready(&time);
                {
                    let mut s = model.state.borrow_mut();
                    s.phy.insert((0, 3), id);
                    s.parameters.insert(0x001b, sentinel);
                    s.efuse = 0xb1;
                }
                model.fail_phy_at = nth;
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(
                    hw.configure_phy(Some(&script), false),
                    Err(Error::Device(BlockError::Timeout))
                );
                assert_ne!(model.state.borrow().phy[&(0, 0)], 0x1200);
            }
        }
        let time = Time::default();
        let mut model = Model::ready(&time);
        model.failed_read = Some(EFUSE_ACCESS);
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            hw.configure_phy(Some(&script), false),
            Err(Error::Device(BlockError::Device { status: u32::MAX }))
        );
        assert_eq!(model.state.borrow().page, 0);
    }
}
