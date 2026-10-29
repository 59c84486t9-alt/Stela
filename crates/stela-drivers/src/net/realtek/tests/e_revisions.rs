// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! E revisions cases.
use super::*;

#[test]
fn e_phy_programs_exact_analogue_state_with_observable_unsupported_optional_cleanup() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for version in [32, 33] {
        let time = Time::default();
        let model = Model::ready(&time);
        {
            let mut s = model.state.borrow_mut();
            s.parameters.insert(0x8b85, 0xffff);
            s.extended.insert((0x20, 0x15), 0xffff);
            s.extended.insert((0x2d, 0x18), 0x8000);
            s.phy.insert((2, 8), 0xffff);
            // Sentinel register values: no C22 MMD substitute may touch them.
            s.phy.insert((0, 13), 0x7711);
            s.phy.insert((0, 14), 0x8822);
        }
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            hw.configure_phy(Some(&script), false),
            Ok(Some(Warning::EeeAdvertisementDisableUnavailable))
        );
        let s = model.state.borrow();
        assert_eq!(s.parameters[&0x8b80], 0xc896);
        assert_eq!(s.parameters[&0x8b85], 0xdfff);
        assert_eq!(s.phy[&(1, 0xb)], 0x6c20);
        assert_eq!(s.phy[&(3, 0x14)], 0x6420);
        assert_eq!(s.phy[&(2, 8)], 0x80ff);
        assert_eq!(s.extended[&(0x2f, 0x15)], 0x1919);
        assert_eq!(s.extended[&(0xac, 0x18)], 6);
        assert_eq!(s.extended[&(0x23, 0x17)], 6);
        assert_eq!(s.extended[&(0x20, 0x15)], 0xeeff);
        assert_eq!(s.extended[&(0x2d, 0x18)], 0x8050);
        assert_eq!(s.phy[&(6, 0)], 0x5a00);
        assert_eq!(s.phy[&(0, 13)], 0x7711);
        assert_eq!(s.phy[&(0, 14)], 0x8822);
        assert_eq!(s.phy[&(0, 0)], 0x1200);
        assert_eq!(s.page, 0);
        assert!(!s.writes.iter().any(|(r, _, _)| *r == PHY_OCP));
        let message = format!("{}", Warning::EeeAdvertisementDisableUnavailable);
        assert!(message.contains("unsupported"));
        assert!(message.contains("unverified"));
    }
}

#[test]
fn e_mac_start_and_receive_modes_clear_inherited_jumbo_and_pulse_fifo_reset() {
    use crate::bus::dma::RegionAllocator;
    for version in [32, 33] {
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
        {
            let mut s = model.state.borrow_mut();
            s.ephy.fill(0xffff);
            s.bytes[CONFIG3] = 0xff;
            s.bytes[CONFIG4] = 0xff;
            s.bytes[CONFIG5] = 0xff;
        }
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        hw.configure_mac(None).unwrap();
        {
            let s = model.state.borrow();
            assert_eq!(s.ephy[0], 0xfdff);
            assert_eq!(s.ephy[3], 0xa7ff);
            assert_eq!(s.ephy[0x19], 0xfe6c);
            assert_eq!(s.bytes[CONFIG3] & 4, 0);
            assert_eq!(s.bytes[CONFIG4] & 1, 0);
            assert_eq!(s.bytes[CONFIG5] & 9, 0);
            assert_eq!(s.bytes[EARLY_TX], 0x3f);
            let misc: Vec<_> = s
                .writes
                .iter()
                .filter(|(r, _, _)| *r == MISC)
                .map(|(_, v, _)| *v)
                .collect();
            assert_eq!(misc, [1 << 29, 0]);
        }
        publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])).unwrap();
        assert_eq!(model.read32(RX_CONFIG), (1 << 15) | (7 << 8) | 0x0e);
    }
}

#[test]
fn e_warning_does_not_tolerate_required_firmware_phy_or_mac_failures() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for version in [32, 33] {
        let time = Time::default();
        let model = Model::ready(&time);
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            hw.configure_phy(None, false),
            Err(Error::Script("RTL8168E requires firmware"))
        );
        for nth in [15, 35, 55] {
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
        let time = Time::default();
        let model = Model::ready(&time);
        model.state.borrow_mut().phy.insert((0, 3), 0xc912);
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(
            hw.configure_phy(Some(&script), false),
            Err(Error::UnsupportedPhy(0x001c_c912))
        );
        for port in [CSI_ADDRESS, EPHY_ACCESS] {
            let time = Time::default();
            let mut model = Model::ready(&time);
            model.fault = Some(port);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_mac(None),
                Err(Error::Device(BlockError::Timeout))
            );
            assert_eq!(model.read8(CONFIG_LOCK), 0);
        }
    }
}
