//! MMC controller/card fast-mode transitions and containment.
use super::*;

#[test]
fn native_hs200_hs400_and_enhanced_strobe_change_real_mmc_payloads() {
    for variant in 0..6 {
        let mode = variant % 3;
        let vcc180 = variant >= 3;
        let mut dma = TestRegion::new(128 * 1024 * 8);
        let (mut owner, card, state) = owner();
        initialize_owner(&mut owner).unwrap();
        {
            let mut hardware = card.borrow_mut();
            hardware.ext[196] = if mode == 0 { 0x13 } else { 0x53 };
            hardware.ext[184] = u8::from(mode == 2);
            hardware.ext[237] = 0x30;
            hardware.ext[253] = 0x70;
            hardware.ext[236] = 0xb0;
            if vcc180 {
                hardware.caps = CAP_180 | CAP_HIGH_SPEED | CAP_ADMA2 | 1 << 27 | 200 << 8;
                hardware.ocr_voltage = 1 << 7;
            }
            hardware.mmc_fast_checks = true;
        }
        let mut host = Host::new(
            Box::new(owner),
            clock(),
            "fast embedded MMC".into(),
            &mut dma,
            Profile::Gli9763e,
        )
        .unwrap();
        let mut disk = host.poll().unwrap().unwrap();
        let timing = if mode == 0 {
            Timing::MmcHs200
        } else {
            Timing::MmcHs400
        };
        assert_eq!(disk.info().timing, timing);
        assert_eq!(disk.info().clock_hz, 200_000_000);
        assert_eq!(disk.info().signal_voltage, SignalVoltage::V1_8);
        assert_eq!(
            disk.info().ext_csd.as_ref().unwrap()[187],
            if vcc180 {
                11
            } else if mode == 0 {
                3
            } else {
                7
            }
        );
        assert_eq!(card.borrow().tuning_commands, if mode == 2 { 0 } else { 3 });
        assert_eq!(
            Port(card.clone()).read16(HOST_CONTROL2) & UHS_MODE,
            if mode == 0 { 3 } else { 7 }
        );
        assert_eq!(state.borrow().words[&0x52c] & (1 << 8) != 0, mode == 2);
        let switches: Vec<_> = card
            .borrow()
            .commands
            .iter()
            .filter_map(|(cmd, arg, _)| {
                (*cmd == 6 && arg >> 16 & 255 == 185).then_some((arg >> 8) as u8)
            })
            .collect();
        assert_eq!(
            switches,
            match mode {
                0 => vec![2],
                1 => vec![2, 1, 3],
                _ => vec![1, 3],
            }
        );
        let mut bytes = [0xa5; 1024];
        disk.read(3, &mut bytes).unwrap();
        assert_eq!(bytes, card.borrow().disk[3 * 512..5 * 512]);
        bytes.fill(0x7a);
        disk.write(7, &bytes).unwrap();
        disk.flush().unwrap();
        assert_eq!(state.borrow().dma, vcc180);
        assert_eq!(bytes, card.borrow().disk[7 * 512..9 * 512]);
        let mut alias = disk.clone();
        disk.shutdown(true).unwrap();
        assert_eq!(alias.flush(), Err(BlockError::Unsupported(STALE)));
    }
}

#[test]
fn native_hs200_response_crc_is_tolerated_only_at_the_source_switch_status() {
    for fault in 0..9 {
        let mut dma = TestRegion::new(128 * 1024 * 8);
        let (mut owner, card, _state) = owner();
        initialize_owner(&mut owner).unwrap();
        {
            let mut hardware = card.borrow_mut();
            hardware.ext[196] = 0x13;
            hardware.mmc_fast_checks = true;
            hardware.mmc_fast_status_fault = Some(fault);
        }
        let mut host = Host::new(
            Box::new(owner),
            clock(),
            "MMC status CRC".into(),
            &mut dma,
            Profile::Gli9763e,
        )
        .unwrap();
        if [0, 6, 7, 8].contains(&fault) {
            let status = match fault {
                0 => 0x980,
                6 => 0x228000,
                7 => 0x38000,
                _ => 0x28900,
            };
            assert_eq!(host.poll().err(), Some(BlockError::Device { status }));
            assert_eq!(Port(card.clone()).read8(POWER), 0);
            let accesses = (card.borrow().reads, card.borrow().writes.len());
            assert!(host.poll().is_err());
            assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
        } else {
            let mut disk = host.poll().unwrap().unwrap();
            let mut bytes = [0xa5; 512];
            disk.read(3, &mut bytes).unwrap();
            assert_eq!(bytes, card.borrow().disk[3 * 512..4 * 512]);
            assert_eq!(card.borrow().tuning_commands, 3);
        }
    }
}

#[test]
fn native_fast_timing_tuning_or_strobe_refusal_fences_before_publication() {
    for fault in 0..5 {
        let mut dma = TestRegion::new(128 * 1024 * 8);
        let (mut owner, card, state) = owner();
        initialize_owner(&mut owner).unwrap();
        {
            let mut hardware = card.borrow_mut();
            hardware.ext[196] = if fault == 2 { 0x53 } else { 0x13 };
            hardware.ext[184] = u8::from(fault == 2);
            hardware.mmc_fast_checks = true;
            if fault == 1 {
                hardware.tuning_iterations = 41;
            }
            if fault == 3 {
                hardware.corrupt_bus_field = Some(212);
            }
            if fault == 4 {
                hardware.mmc_timing_fault = Some((2, COMMAND_TIMEOUT, true));
            }
        }
        if fault == 0 {
            state.borrow_mut().ignore_mode = Some(3);
        }
        if fault == 2 {
            state.borrow_mut().ignore_mmio = Some(0x52c);
        }
        let mut host = Host::new(
            Box::new(owner),
            clock(),
            "refused fast MMC".into(),
            &mut dma,
            Profile::Gli9763e,
        )
        .unwrap();
        assert!(host.poll().is_err());
        assert_eq!(Port(card.clone()).read8(POWER), 0);
        assert!(host.last_failure().unwrap().quarantined);
        if fault == 4 {
            assert_eq!(host.last_failure().unwrap().primary, BlockError::Timeout);
            assert!(host.last_failure().unwrap().retirement.is_some());
        }
        let accesses = (card.borrow().reads, card.borrow().writes.len());
        assert!(host.poll().is_err());
        assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
        assert!(
            !card
                .borrow()
                .commands
                .iter()
                .any(|(cmd, _, _)| matches!(cmd, 17 | 18 | 24 | 25))
        );
    }
}
