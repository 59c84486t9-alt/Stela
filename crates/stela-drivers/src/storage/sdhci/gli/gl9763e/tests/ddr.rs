//! Independent original-controller DDR52 payload and transition-failure peers.
use super::*;

#[test]
fn native_ddr52_uses_actual_sampling_pads_power_class_and_changed_pio_or_adma_payloads() {
    for vcc180 in [false, true] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: the descriptor/payload ranges outlive every host/card alias.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut owner, card, state) = owner();
        initialize_owner(&mut owner).unwrap();
        {
            let mut hardware = card.borrow_mut();
            hardware.ext[196] = 7;
            hardware.ext[238] = 0x90;
            hardware.ext[239] = 0x50;
            hardware.mmc_fast_checks = true;
            hardware.mmc_ddr52_checks = true;
            if vcc180 {
                hardware.caps = CAP_180 | CAP_HIGH_SPEED | CAP_ADMA2 | 1 << 27 | 200 << 8;
                hardware.ocr_voltage = 1 << 7;
            }
        }
        let mut host = Host::new(
            Box::new(owner),
            clock(),
            "embedded MMC DDR52".into(),
            &mut dma,
            Profile::Gli9763e,
        )
        .unwrap();
        let mut disk = host.poll().unwrap().unwrap();
        assert_eq!(disk.info().timing, Timing::MmcDdr52);
        assert_eq!(disk.info().clock_hz, 50_000_000);
        assert_eq!(disk.info().signal_voltage, SignalVoltage::V1_8);
        assert_eq!(card.borrow().ext[183], 6);
        assert_eq!(card.borrow().ext[187], if vcc180 { 9 } else { 5 });
        assert_eq!(
            Port(card.clone()).read16(HOST_CONTROL2) & (UHS_MODE | SIGNAL_180),
            4 | SIGNAL_180
        );
        assert_eq!(card.borrow().tuning_commands, 0);
        let mut bytes = vec![0xa5; 65536];
        disk.read(3, &mut bytes).unwrap();
        assert_eq!(bytes, card.borrow().disk[3 * 512..3 * 512 + 65536]);
        bytes.fill(0x39);
        disk.write(200, &bytes).unwrap();
        disk.flush().unwrap();
        assert_eq!(bytes, card.borrow().disk[200 * 512..200 * 512 + 65536]);
        assert_eq!(state.borrow().dma, vcc180);
        let mut alias = disk.clone();
        disk.shutdown(true).unwrap();
        assert_eq!(alias.flush(), Err(BlockError::Unsupported(STALE)));
    }
}

#[test]
fn native_ddr52_ignored_sampling_or_signal_change_powers_off_and_fences() {
    for voltage in [false, true] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: failed DDR transitions keep the complete original resource epoch.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut owner, card, state) = owner();
        initialize_owner(&mut owner).unwrap();
        {
            let mut hardware = card.borrow_mut();
            hardware.ext[196] = 7;
            hardware.mmc_fast_checks = true;
            hardware.mmc_ddr52_checks = true;
            if voltage {
                hardware.voltage_fault = Some(VoltageFault::Enable);
            }
        }
        if !voltage {
            state.borrow_mut().ignore_mode = Some(4);
        }
        let mut host = Host::new(
            Box::new(owner),
            clock(),
            "refused DDR52".into(),
            &mut dma,
            Profile::Gli9763e,
        )
        .unwrap();
        assert!(host.poll().is_err());
        assert_eq!(Port(card.clone()).read8(POWER), 0);
        assert!(host.last_failure().unwrap().quarantined);
        assert!(
            !card
                .borrow()
                .commands
                .iter()
                .any(|(cmd, _, _)| matches!(cmd, 17 | 18 | 24 | 25))
        );
        let accesses = (card.borrow().reads, card.borrow().writes.len());
        assert!(host.poll().is_err());
        assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
    }
}
