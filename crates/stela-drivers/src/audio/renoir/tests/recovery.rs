// SPDX-License-Identifier: GPL-2.0-only
//! Recovery cases.
use super::*;

#[test]
fn first_failure_survives_needs_reset_cleanup_errors_and_successful_recovery() {
    let (mut controller, device, source) = ready(1, 4096);
    assert_eq!(controller.first_error(), None);
    controller.start().unwrap();
    device.lock().unwrap().words[0x1808 / 4] |= 1 << 29;
    assert_eq!(controller.position(), Err(Error::DmaFault(1 << 29)));
    assert_eq!(controller.first_error(), Some(Error::DmaFault(1 << 29)));
    assert_eq!(controller.start(), Err(Error::NeedsReset));
    device.lock().unwrap().stop_never = true;
    assert_eq!(controller.shutdown(), Err(Error::Timeout(Phase::DmaStop)));
    assert_eq!(controller.first_error(), Some(Error::DmaFault(1 << 29)));
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    device.lock().unwrap().stop_never = false;
    // Source diagnostics remain observable even after successful cleanup.
    controller.shutdown().unwrap();
    assert_eq!(controller.first_error(), Some(Error::DmaFault(1 << 29)));
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);

    let (mut controller, device, source) = fixture(1);
    device.lock().unwrap().power_never = true;
    assert_eq!(controller.initialize(), Err(Error::Timeout(Phase::PowerOn)));
    assert_eq!(
        controller.first_error(),
        Some(Error::Timeout(Phase::PowerOn))
    );
    device.lock().unwrap().power_never = false;
    controller.initialize().unwrap();
    assert_eq!(controller.state(), State::Ready);
    assert_eq!(
        controller.first_error(),
        Some(Error::Timeout(Phase::PowerOn))
    );
    controller
        .prepare_capture(&source, CAPTURE_FORMAT, 4096)
        .unwrap();
    controller.start().unwrap();
    controller.shutdown().unwrap();
    assert_eq!(
        controller.first_error(),
        Some(Error::Timeout(Phase::PowerOn))
    );
}

#[test]
fn late_start_acknowledgement_stop_reset_and_unmap_failures_keep_owners() {
    for fault in [0, 1, 2, 3] {
        let (mut controller, device, source) = ready(1, 4096);
        if fault == 0 {
            device.lock().unwrap().fail_after_write = Some(0x2c08);
        }
        if fault == 1 {
            device.lock().unwrap().start_never = true;
        }
        let start = controller.start();
        if fault <= 1 {
            assert!(start.is_err());
            assert_eq!(controller.state(), State::Faulted);
            assert_eq!(controller.start(), Err(Error::NeedsReset));
        } else {
            start.unwrap();
        }
        if fault == 2 {
            device.lock().unwrap().stop_never = true;
        }
        if fault == 3 {
            device.lock().unwrap().reset_never = true;
        }
        if fault >= 2 {
            assert!(controller.shutdown().is_err());
        }
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        assert!(controller.capture.is_some());
        {
            let mut model = device.lock().unwrap();
            model.start_never = false;
            model.stop_never = false;
            model.reset_never = false;
            model.unmap_fail = true;
        }
        assert_eq!(
            controller.shutdown(),
            Err(Error::Dma(DmaError::InvalidationFailed))
        );
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        assert!(controller.capture.is_some());
        device.lock().unwrap().unmap_fail = false;
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn live_map_error_enable_clock_and_identity_loss_quarantine_old_pcm_and_shutdown_is_safe() {
    for fault in 0..9 {
        let (mut controller, device, source) = ready(1, 4096);
        controller.start().unwrap();
        {
            let mut model = device.lock().unwrap();
            match fault {
                0 => model.words[0x10004 / 4] ^= 1,
                1 => model.words[0x1804 / 4] &= !(1 << 29),
                2 => model.words[0x1424 / 4] = 0,
                3 => model.identity.device ^= 1,
                4 => model.words[0x1808 / 4] |= 1 << 29,
                5 => model.words[0x2c28 / 4] = 1,
                6 => model.words[0x2c2c / 4] = 3,
                7 => model.words[0x2c60 / 4] = 0,
                _ => model.words[0x2c5c / 4] ^= 1 << 3,
            }
        }
        assert!(controller.position().is_err());
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(controller.start(), Err(Error::NeedsReset));
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        if fault == 3 {
            let writes = device.lock().unwrap().writes.len();
            assert_eq!(controller.shutdown(), Err(Error::AuthorityChanged));
            assert_eq!(device.lock().unwrap().writes.len(), writes);
            device.lock().unwrap().identity.device ^= 1;
        }
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn partial_pte_write_unpublished_visibility_failure_and_reset_reconfiguration() {
    for late in [false, true] {
        let (mut controller, device, source) = fixture(1);
        controller.initialize().unwrap();
        if late {
            device.lock().unwrap().fail_after_write = Some(0x10004);
        } else {
            device.lock().unwrap().sync_fail = true;
        }
        assert!(
            controller
                .prepare_capture(&source, CAPTURE_FORMAT, 8192)
                .is_err()
        );
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(source.drops.load(Ordering::Relaxed), usize::from(!late));
        assert_eq!(controller.capture.is_some(), late);
        device.lock().unwrap().sync_fail = false;
        controller.initialize().unwrap();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        assert_eq!(device.lock().unwrap().words[0x10000 / 4], IOVA as u32);
        assert_eq!(
            device.lock().unwrap().words[0x10004 / 4],
            (IOVA >> 32) as u32 | 0x8000_0000
        );
        assert_eq!(device.lock().unwrap().words[(0x10000 + 7 * 8 + 4) / 4], 0);
        controller.start().unwrap();
        device.lock().unwrap().advance(20);
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn successful_but_late_dma_and_reset_completion_keeps_pins_until_fresh_recovery() {
    for write in [false, true] {
        for phase in [
            Phase::DmaStart,
            Phase::DmaStop,
            Phase::ResetAssert,
            Phase::ResetClear,
        ] {
            let (mut controller, device, source) = ready(1, 4096);
            if phase != Phase::DmaStart {
                controller.start().unwrap();
                device.lock().unwrap().advance(32);
            }
            let (offset, request, ready, budget) = match phase {
                Phase::DmaStart => (0x2c08, 1, 2, 100_001),
                Phase::DmaStop => (0x2c08, 2, 0, 100_001),
                Phase::ResetAssert => (0x1000, 1, 0x10001, 501),
                Phase::ResetClear => (0x1000, 0, 0, 501),
                _ => unreachable!(),
            };
            {
                let mut model = device.lock().unwrap();
                if write {
                    model.jump_write = Some((offset, request, budget));
                } else {
                    model.jump_read = Some((offset, ready, budget));
                }
            }
            let result = match phase {
                Phase::DmaStart => controller.start(),
                Phase::DmaStop => controller.stop(),
                _ => controller.shutdown(),
            };
            assert_eq!(result, Err(Error::Timeout(phase)));
            assert_eq!(controller.state(), State::Faulted);
            assert_eq!(controller.start(), Err(Error::NeedsReset));
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            assert_eq!(device.lock().unwrap().unmaps, 0);
            assert!(controller.capture.is_some());
            if phase == Phase::DmaStop {
                // A late stop must not silently advance to PDM/FIFO
                // quiet or unmap within the failed operation.
                assert_eq!(device.lock().unwrap().words[0x2c04 / 4], 1);
            }
            controller.shutdown().unwrap();
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        }
    }
    // A successful late PDM clock effect cannot enable BME or submit DMA.
    let (mut controller, device, source) = ready(1, 4096);
    device.lock().unwrap().jump_write = Some((0x2c60, 7, 100_001));
    assert_eq!(controller.start(), Err(Error::Timeout(Phase::DmaStart)));
    assert!(!device.lock().unwrap().master);
    assert!(
        !device
            .lock()
            .unwrap()
            .writes
            .iter()
            .any(|(at, value)| *at == 0x2c08 && *value == 1)
    );
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    controller.shutdown().unwrap();
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn active_drop_quarantines_real_domain_and_nonidentity_ram_pins() {
    let (mut controller, device, source) = ready(1, 4096);
    controller.start().unwrap();
    let domain_count = Arc::strong_count(&controller.domain);
    assert_eq!(domain_count, 2);
    drop(controller);
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    assert!(device.lock().unwrap().translation.is_some());
    // No fake reset/unmap is supplied for this quarantined DMA.
    device.lock().unwrap().advance(64);
    assert_eq!(device.lock().unwrap().unmaps, 0);
}
