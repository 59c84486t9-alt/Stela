// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Link state cases.
use super::*;

#[test]
fn link_speed_patch_covers_each_copper_speed() {
    for (speed, first, second) in [(0x10, 0x11, 5), (8, 0x1f, 5), (4, 0x1f, 0x3f)] {
        let time = Time::default();
        let model = Model::ready(&time);
        let hw = Hardware::new(&model, &time, revision(34), 0);
        link_patch(&hw, speed | 2).unwrap();
        let s = model.state.borrow();
        assert_eq!(s.eri[&0x1bc], first);
        assert_eq!(s.eri[&0x1dc], second);
        assert_eq!(s.eri[&0xdc] & 1, 1);
    }
    let time = Time::default();
    let model = Model::ready(&time);
    let hw = Hardware::new(&model, &time, revision(34), 0);
    assert!(link_patch(&hw, 2).is_err());
    assert!(model.state.borrow().writes.is_empty());
    let mut model = Model::ready(&time);
    model.fault = Some(ERI_ADDRESS);
    let hw = Hardware::new(&model, &time, revision(34), 0);
    assert_eq!(link_patch(&hw, 0x12), Err(BlockError::Timeout));
}

#[test]
fn rtl8211b_resume_clears_its_suspend_quirk_before_powerup_and_propagates_failure() {
    for (id, fail) in [(0xc912, false), (0xc912, true), (0xc800, false)] {
        let time = Time::default();
        let mut model = Model::ready(&time);
        {
            let mut s = model.state.borrow_mut();
            s.phy.insert((0, 3), id);
            s.phy.insert((0, 14), 0x0200);
            s.phy.insert((0, PHY_CONTROL), 0x1940);
        }
        if fail {
            // Page zero, ID high, ID low, then the RTL8211B quirk write.
            model.fail_phy_at = 4;
        }
        let mut hw = Hardware::new(&model, &time, revision(18), 0);
        let result = hw.configure_phy(None, false);
        let s = model.state.borrow();
        let writes: Vec<_> = s
            .writes
            .iter()
            .filter(|(r, v, _)| *r == PHY_ACCESS && *v & ACCESS != 0)
            .map(|(_, v, _)| (((v >> 16) & 31) as u16, *v as u16))
            .collect();
        if fail {
            assert_eq!(result, Err(Error::Device(BlockError::Timeout)));
            assert_eq!(s.phy[&(0, 14)], 0x0200);
            assert_eq!(s.phy[&(0, PHY_CONTROL)], 0x1940);
            assert!(!s.phy.contains_key(&(2, 0x0c)));
            assert_eq!(writes, [(PHY_PAGE, 0), (14, 0)]);
        } else {
            assert_eq!(result, Ok(None));
            if id == 0xc912 {
                assert_eq!(s.phy[&(0, 14)], 0);
                let at = |entry| writes.iter().position(|v| *v == entry).unwrap();
                assert!(at((14, 0)) < at((PHY_CONTROL, 0x1140)));
                assert!(at((PHY_CONTROL, 0x1140)) < at((0x1d, 0x0f00)));
                assert!(at((0x1d, 0x0f00)) < at((PHY_CONTROL, 0x9140)));
                assert!(at((PHY_CONTROL, 0x9140)) < at((PHY_CONTROL, 0x1200)));
            } else {
                assert_eq!(s.phy[&(0, 14)], 0x0200);
                assert!(!writes.iter().any(|(reg, _)| *reg == 14));
            }
            assert_eq!(s.phy[&(0, PHY_CONTROL)], 0x1200);
        }
    }
}

#[test]
fn runtime_link_patch_failure_permanently_blocks_work_after_late_completion() {
    for version in [34, 35, 36, 38] {
        let time = Time::default();
        let mut model = Model::ready(&time);
        model.state.borrow_mut().bytes[PHY_STATUS] = 0x12;
        model.fail_eri_at = 2;
        let mut link = RuntimeLink::default();
        {
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(link.update(&hw), Err(BlockError::Timeout));
        }
        {
            let s = model.state.borrow();
            assert_eq!(s.eri[&0x1bc], 0x11);
            assert!(!s.eri.contains_key(&0x1dc));
            assert!(s.pending.is_some());
            assert_eq!(s.eri_commands, 2);
        }
        // The timed-out write completes after the caller has lost its
        // completion observation. Completion is not a recovery boundary.
        model.fail_eri_at = usize::MAX;
        time.delay(100).unwrap();
        model.read32(ERI_ADDRESS);
        let writes = model.state.borrow().writes.len();
        assert_eq!(model.state.borrow().eri[&0x1dc], 5);
        model.state.borrow_mut().bytes[PHY_STATUS] = 0x0a;
        let hw = Hardware::new(&model, &time, revision(version), 0);
        for _ in 0..3 {
            assert!(!link.update(&hw).unwrap_or(false)); // carrier gate
            let transmit = link.update(&hw).map(|_| model.write8(TX_POLL, POLL_NORMAL));
            assert_eq!(transmit, Err(BlockError::Timeout));
            let receive = link
                .update(&hw)
                .map(|_| panic!("descriptor access after failure"));
            assert_eq!(receive, Err(BlockError::Timeout));
        }
        assert_eq!(model.state.borrow().writes.len(), writes);
        assert_eq!(model.state.borrow().eri_commands, 2);
    }
}

#[test]
fn clock_request_uses_narrow_link_control_and_rejects_failed_config_reads() {
    struct Config {
        value: u16,
        writes: Vec<(u16, u16)>,
        failure: Option<crate::bus::pci::ConfigError>,
    }
    impl ConfigSpace for Config {
        fn read8(&self, _: u16) -> Result<u8, crate::bus::pci::ConfigError> {
            Err(crate::bus::pci::ConfigError::before_effect(
                crate::bus::pci::ConfigFailure::UnqualifiedControl,
            ))
        }
        fn read32(&self, _: u16) -> Result<u32, crate::bus::pci::ConfigError> {
            Err(crate::bus::pci::ConfigError::before_effect(
                crate::bus::pci::ConfigFailure::UnqualifiedControl,
            ))
        }
        fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
            assert_eq!(offset, 0x82);
            if let Some(error) = self.failure {
                return Err(error);
            }
            Ok(self.value)
        }
        fn write8(&mut self, _: u16, _: u8) -> Result<(), crate::bus::pci::ConfigError> {
            Err(crate::bus::pci::ConfigError::before_effect(
                crate::bus::pci::ConfigFailure::UnqualifiedControl,
            ))
        }
        fn write32(&mut self, _: u16, _: u32) -> Result<(), crate::bus::pci::ConfigError> {
            Err(crate::bus::pci::ConfigError::before_effect(
                crate::bus::pci::ConfigFailure::UnqualifiedControl,
            ))
        }
        fn write16(&mut self, offset: u16, value: u16) -> Result<(), crate::bus::pci::ConfigError> {
            self.writes.push((offset, value));
            self.value = value;
            Ok(())
        }
    }
    let mut config = Config {
        value: 0xa5fc,
        writes: Vec::new(),
        failure: None,
    };
    clock_request(&mut config, 0x82, false).unwrap();
    assert_eq!(config.value, 0xa4fc);
    clock_request(&mut config, 0x82, true).unwrap();
    assert_eq!(config.value, 0xa5fc);
    assert_eq!(config.writes, [(0x82, 0xa4fc), (0x82, 0xa5fc)]);
    config.value = u16::MAX;
    assert_eq!(
        clock_request(&mut config, 0x82, true),
        Err(BlockError::Device { status: 65535 })
    );
    assert_eq!(config.writes.len(), 2);
    let denied =
        crate::bus::pci::ConfigError::before_effect(crate::bus::pci::ConfigFailure::ForeignGrant);
    config.failure = Some(denied);
    assert_eq!(
        clock_request(&mut config, 0x82, true),
        Err(BlockError::Config(denied))
    );
    assert_eq!(config.writes.len(), 2);
}
