// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Csi cases.
use super::*;

#[test]
fn csi_failed_data_read_does_not_publish_a_fabricated_config_value() {
    for version in [34, 61, 63, 64, 65, 66, 70] {
        let time = Time::default();
        let mut model = Model::nbase(&time);
        model.failed_read = Some(CSI_DATA);
        let mut hw = Hardware::new(&model, &time, revision(version), 2);
        assert_eq!(
            hw.configure_mac(None),
            Err(Error::Device(BlockError::Device { status: u32::MAX }))
        );
        let s = model.state.borrow();
        assert_eq!(s.bytes[CONFIG_LOCK], 0);
        assert!(!s.writes.iter().any(|(r, v, _)| *r == CSI_DATA
            || (*r == CSI_ADDRESS && *v & ACCESS != 0)
            || matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW)));
    }
}

#[test]
fn csi_rmw_checks_address_and_function_and_preserves_other_bytes() {
    for function in [0, 2, 7] {
        let time = Time::default();
        let model = Model::nbase(&time);
        model.state.borrow_mut().csi.extend([
            ((function, 0x890), 0xabcdef79),
            ((function, 0x70c), 0x12785634),
        ]);
        let hw = Hardware::new(&model, &time, revision(70), function);
        hw.csi_modify(0x890, 1, 0).unwrap();
        hw.latency().unwrap();
        let s = model.state.borrow();
        assert_eq!(s.csi[&(function, 0x890)], 0xabcdef78);
        assert_eq!(s.csi[&(function, 0x70c)], 0x27785634);
        for addr in [0x890u32, 0x70c] {
            let cmd = 0xf000 | addr | (u32::from(function) << 16);
            assert!(s.writes.contains(&(CSI_ADDRESS, cmd, 4)));
            assert!(s.writes.contains(&(CSI_ADDRESS, ACCESS | cmd, 4)));
        }
    }
    for (address, function) in [(0x891, 0), (0x1000, 0), (0x890, 8)] {
        let time = Time::default();
        let model = Model::nbase(&time);
        let hw = Hardware::new(&model, &time, revision(70), function);
        assert!(matches!(
            hw.csi_modify(address, 1, 0),
            Err(BlockError::Unsupported(_))
        ));
        assert!(model.state.borrow().writes.is_empty());
    }
}
