//! Ordinary eight-pin SDR HS ordering, VCC/rate power class and failure.
use super::*;

#[test]
fn ordinary_mmc_hs_orders_host_status_clock_and_width_before_real_pio_or_adma_io() {
    for vcc180 in [false, true] {
        for variant in 0..3 {
            let mut dma = TestRegion::new(128 * 1024 * 8);
            let (mut owner, card, state) = owner();
            initialize_owner(&mut owner).unwrap();
            {
                let mut c = card.borrow_mut();
                c.ext[196] = if variant == 0 { 1 } else { 3 };
                c.ext[200..204].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
                c.mmc_sdr_hs_checks = true;
                if variant == 2 {
                    c.caps = (c.caps & !(255 << 8)) | 25 << 8;
                }
                if vcc180 {
                    c.caps = (c.caps & !CAP_330) | CAP_180 | CAP_ADMA2 | 1 << 27;
                    c.ocr_voltage = 1 << 7;
                }
            }
            let mut host = Host::new(
                Box::new(owner),
                clock(),
                "ordinary MMC HS".into(),
                &mut dma,
                Profile::Gli9763e,
            )
            .unwrap();
            let mut disk = host.poll().unwrap().unwrap();
            assert_eq!(disk.info().timing, Timing::HighSpeed);
            assert_eq!(
                disk.info().clock_hz,
                if variant == 1 { 50_000_000 } else { 25_000_000 }
            );
            let class = match (vcc180, variant == 1) {
                (true, false) => 3,
                (true, true) => 1,
                (false, false) => 7,
                (false, true) => 5,
            };
            assert_eq!(card.borrow().ext[187], class);
            let mut bytes = vec![0xa5; 65536];
            disk.read(3, &mut bytes).unwrap();
            assert_eq!(bytes, card.borrow().disk[3 * 512..3 * 512 + 65536]);
            bytes.fill(0x2e);
            disk.write(200, &bytes).unwrap();
            disk.flush().unwrap();
            assert_eq!(bytes, card.borrow().disk[200 * 512..200 * 512 + 65536]);
            assert_eq!(state.borrow().dma, vcc180);
            let mut alias = disk.clone();
            disk.shutdown(true).unwrap();
            assert_eq!(alias.flush(), Err(BlockError::Unsupported(STALE)));
        }
    }
}

#[test]
fn ordinary_mmc_hs_width_or_power_failure_powers_off_before_publication() {
    for power in [false, true] {
        let mut dma = TestRegion::new(128 * 1024 * 8);
        let (mut owner, card, _) = owner();
        initialize_owner(&mut owner).unwrap();
        {
            let mut c = card.borrow_mut();
            c.mmc_sdr_hs_checks = true;
            c.ext[202] = 0x50;
            c.corrupt_bus_field = if power { None } else { Some(212) };
            c.mmc_power_fault = power;
        }
        let mut host = Host::new(
            Box::new(owner),
            clock(),
            "refused ordinary HS".into(),
            &mut dma,
            Profile::Gli9763e,
        )
        .unwrap();
        assert!(host.poll().is_err());
        assert_eq!(Port(card.clone()).read8(POWER), 0);
        assert!(host.last_failure().unwrap().quarantined);
        if power {
            assert_eq!(host.last_failure().unwrap().primary, BlockError::Timeout);
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
