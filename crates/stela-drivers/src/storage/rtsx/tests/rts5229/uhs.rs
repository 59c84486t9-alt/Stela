//! Real CMD11, internal PHY, auto-tuning and payload/failure ownership.
use super::*;

#[test]
fn rts5229_cmd11_all_sdr_modes_and_tx27_tuning_drive_actual_changed_pio_payloads() {
    for (function, hz, timing) in [
        (0, 25_000_000, Timing::Sdr12),
        (1, 50_000_000, Timing::Sdr25),
        (2, 100_000_000, Timing::Sdr50),
        (3, 208_000_000, Timing::Sdr104),
    ] {
        let chip = chip(false, true, 2);
        chip.borrow_mut().card.uhs_modes = 1 << function;
        chip.borrow_mut().tuning_windows = [0xf000_001f, 0xe000_000f, 0xc000_0007];
        let mut host = make_host(&chip, true).unwrap();
        let mut card = host.poll().unwrap().unwrap();
        assert_eq!(card.info().signal_voltage, SignalVoltage::V1_8);
        assert_eq!(card.info().timing, timing);
        assert_eq!(card.info().clock_hz, hz);
        let mut bytes = [0xa5; 1024];
        card.read(3, &mut bytes).unwrap();
        assert_eq!(&bytes[..512], &chip.borrow().card.block(3));
        bytes.fill(0x6b);
        card.write(6, &bytes).unwrap();
        card.flush().unwrap();
        assert_eq!(&bytes[..512], &chip.borrow().card.block(6));
        {
            let c = chip.borrow();
            assert_eq!(c.phy[8], 0x4c64);
            assert_eq!(c.phy[0x11], 0, "no RTS522A PHY11 recipe");
            assert_eq!(c.regs[0x3d5a], 0, "no RTS522A per-pin drive array");
            assert_eq!(c.regs[0x3d5e] & 7, 1, "actual vendor1.8V source mux");
            assert_eq!(c.regs[0x3d62], 0xd9);
            if function >= 2 {
                assert_eq!(c.tuning_attempts, 97);
                assert_eq!(c.regs[0x3c2a] & 31, 27);
                assert_eq!(c.regs[0x3c2b] & 31, 0);
                assert_eq!(c.card.current_function, 1);
            } else {
                assert_eq!(c.tuning_attempts, 0);
            }
            let cmd11 = c
                .effects
                .iter()
                .position(|e| matches!(e, Effect::Command(11, 0, 8)))
                .unwrap();
            let cid = c
                .effects
                .iter()
                .position(|e| matches!(e, Effect::Command(2, 0, 8)))
                .unwrap();
            assert!(cmd11 < cid);
        }
        let mut alias = card.clone();
        card.shutdown(true).unwrap();
        let accesses = chip.borrow().accesses;
        assert!(alias.read(0, &mut bytes).is_err());
        assert_eq!(accesses, chip.borrow().accesses);
    }
}

#[test]
fn rts5229_voltage_or_tuning_failure_withholds_publication_and_requires_fresh_power_cycle() {
    for fault in 0..4 {
        let chip = chip(false, true, 2);
        {
            let mut c = chip.borrow_mut();
            c.card.uhs_modes = 8;
            match fault {
                0 => c.bad_cmd11_low = true,
                1 => c.bad_cmd11_high = true,
                2 => c.tuning_windows = [0; 3],
                _ => c.deny_v18_phy = true,
            }
        }
        let mut host = make_host(&chip, true).unwrap();
        assert!(host.poll().is_err());
        assert!(host.inner.borrow().medium.is_none());
        assert!(
            !chip
                .borrow()
                .effects
                .iter()
                .any(|e| matches!(e, Effect::Command(17 | 24, _, _)))
        );
        if fault == 3 {
            assert!(host.last_failure().unwrap().quarantined);
            assert_eq!(host.last_failure().unwrap().primary, BlockError::Timeout);
            let accesses = chip.borrow().accesses;
            assert!(host.poll().is_err());
            assert_eq!(accesses, chip.borrow().accesses);
        } else {
            {
                let mut c = chip.borrow_mut();
                c.bad_cmd11_low = false;
                c.bad_cmd11_high = false;
                c.tuning_windows = [u32::MAX; 3];
            }
            let start = chip.borrow().effects.len();
            let mut card = host.poll().unwrap().unwrap();
            {
                let c = chip.borrow();
                let effects = &c.effects[start..];
                let cmd0 = effects
                    .iter()
                    .position(|e| matches!(e, Effect::Command(0, 0, 8)))
                    .unwrap();
                assert!(effects[..cmd0].iter().any(
                    |e| matches!(e, Effect::Register(CARD_PWR_CTL, _, value) if value & 3 == 3)
                ));
            }
            let mut bytes = [0; 512];
            card.read(3, &mut bytes).unwrap();
            assert_eq!(bytes, chip.borrow().card.block(3));
        }
    }
}

#[test]
fn rts5229_real_removal_delink_or_shared_ms_during_tuning_is_not_a_phase_sample() {
    for fault in [Fault::Remove, Fault::Delink, Fault::MemoryStick] {
        let chip = chip(false, true, 0);
        {
            let mut c = chip.borrow_mut();
            c.card.uhs_modes = 8;
            c.tuning_fault = Some(fault);
        }
        let mut host = make_host(&chip, true).unwrap();
        assert!(host.poll().is_err());
        assert!(host.inner.borrow().medium.is_none());
        assert_eq!(chip.borrow().tuning_attempts, 1);
        assert!(
            !chip
                .borrow()
                .effects
                .iter()
                .any(|e| matches!(e, Effect::Command(17 | 24, _, _)))
        );
        if matches!(fault, Fault::Delink) {
            let accesses = chip.borrow().accesses;
            assert!(host.poll().is_err());
            assert_eq!(accesses, chip.borrow().accesses);
        }
    }
}
