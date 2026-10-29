// SPDX-License-Identifier: GPL-2.0-only
//! Capture, recovery and retirement behavior every direct PDM family shares.
//! Each family test module includes this file against its own model.
use super::*;

#[test]
fn pte_capture_pcm_wraps_stop_restart_and_acknowledged_release() {
    for (&revision, period) in REVISIONS.iter().cycle().zip([4096, 8192, 5000]) {
        let (mut controller, device, source) = ready(revision, period);
        let ring = period * 4;
        assert_eq!(controller.buffer_bytes(), Some(ring));
        let capture = controller.capture.as_ref().unwrap();
        // SAFETY: prepared DMA has never started; take CPU cache
        // ownership before poisoning, then start must hand it back.
        unsafe { capture.dma.sync_for_cpu(0..capture.cpu.bytes()) }.unwrap();
        for offset in 0..capture.cpu.bytes() {
            // SAFETY: DMA has not started; poison the CPU allocation.
            unsafe {
                capture
                    .cpu
                    .address(offset, 1)
                    .unwrap()
                    .as_ptr()
                    .write_volatile(0xa5)
            };
        }
        assert_eq!(controller.stop(), Err(Error::NotPrepared));
        assert_eq!(controller.state(), State::Prepared);
        controller.start().unwrap();
        assert_eq!(device.lock().unwrap().words[0x2c5c / 4], 0x6018);
        let mut untouched = [0xa5; 16];
        assert_eq!(
            controller.copy_stopped_ring(0, &mut untouched),
            Err(Error::Busy)
        );
        assert_eq!(untouched, [0xa5; 16]);
        // Coalesced period delivery and more than five real ring wraps.
        let frames = ring / 8 * 5 + 17;
        device.lock().unwrap().advance(frames);
        device.lock().unwrap().words[IRQ_STATUS / 4] |= 1 << 7;
        let position = controller.position().unwrap();
        assert_eq!(position.bytes, (frames * 8) as u64);
        assert_eq!(position.ring_offset, 17 * 8);
        assert!(position.period_pending);
        assert_eq!(device.lock().unwrap().words[IRQ_STATUS / 4], 1 << 7); // No unrelated W1C acknowledgement.
        controller.stop().unwrap();
        let mut pcm = vec![0; ring];
        controller.copy_stopped_ring(0, &mut pcm).unwrap();
        for (index, frame) in pcm.as_chunks::<8>().0.iter().enumerate() {
            let latest_frame = if index < 17 {
                ring / 8 * 5 + index
            } else {
                ring / 8 * 4 + index
            };
            assert_eq!(&frame[..4], sample(latest_frame as u64, 0).to_le_bytes());
            assert_eq!(&frame[4..], sample(latest_frame as u64, 1).to_le_bytes());
        }
        assert!(source.drops.load(Ordering::Relaxed) == 0);
        controller.start().unwrap();
        device.lock().unwrap().advance(10);
        controller.stop().unwrap();
        assert_eq!(controller.position().unwrap().bytes, 80);
        controller.shutdown().unwrap();
        assert_eq!(controller.state(), State::Shutdown);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert_eq!(device.lock().unwrap().unmaps, 1);
        assert!(controller.into_stopped().is_ok());
    }
}

#[test]
fn format_geometry_and_address_ceiling_refuse_before_dma_publication() {
    let (mut controller, device, mut source) = fixture(REVISION);
    controller.initialize().unwrap();
    let before = device.lock().unwrap().writes.len();
    for format in [
        PcmFormat {
            bits: 16,
            ..CAPTURE_FORMAT
        },
        PcmFormat {
            bits: 24,
            ..CAPTURE_FORMAT
        },
        PcmFormat {
            channels: 1,
            ..CAPTURE_FORMAT
        },
        PcmFormat {
            rate: 96_000,
            ..CAPTURE_FORMAT
        },
    ] {
        assert_eq!(
            controller.prepare_capture(&source, format, 4096),
            Err(Error::InvalidFormat)
        );
    }
    for period in [0, 4095, 4097, 8193, usize::MAX] {
        assert_eq!(
            controller.prepare_capture(&source, CAPTURE_FORMAT, period),
            Err(Error::InvalidBuffer)
        );
    }
    assert_eq!(device.lock().unwrap().writes.len(), before);
    source.geometry = 13;
    assert_eq!(
        controller.prepare_capture(&source, CAPTURE_FORMAT, 4096),
        Err(Error::InvalidBuffer)
    );
    assert_eq!(device.lock().unwrap().maps, 0);
    for (base, bytes, bits) in [
        (0, 4096, 40),
        (4097, 4096, 40),
        (1u64 << 40, 4096, 40),
        ((1u64 << 63) - 4096, 8192, 63),
    ] {
        assert_eq!(
            check_dma_range(base, bytes, bytes, bits),
            Err(Error::DmaAddress)
        );
    }
    assert_eq!(check_dma_range((1u64 << 63) - 4096, 4096, 4096, 63), Ok(()));
    controller.shutdown().unwrap();
}

#[test]
fn independent_counter_rollover_and_wrap_are_not_torn_or_truncated() {
    let (mut controller, device, _) = ready(REVISION, 4096);
    device.lock().unwrap().count = u64::MAX - 15;
    controller.start().unwrap();
    device.lock().unwrap().advance(4);
    assert_eq!(controller.position().unwrap().bytes, 32);
    controller.stop().unwrap();
    device.lock().unwrap().count = 0xffff_fff8;
    controller.start().unwrap();
    device.lock().unwrap().rollover = true;
    assert_eq!(controller.position().unwrap().bytes, 8);
    device.lock().unwrap().unstable = true;
    assert_eq!(controller.position(), Err(Error::CounterUnstable));
    assert_eq!(controller.state(), State::Faulted);
    device.lock().unwrap().unstable = false;
    controller.shutdown().unwrap();
}

#[test]
fn late_start_acknowledgement_stop_reset_and_unmap_failures_keep_owners() {
    for fault in [0, 1, 2, 3] {
        let (mut controller, device, source) = ready(REVISION, 4096);
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
fn partial_pte_write_unpublished_visibility_failure_and_reset_reconfiguration() {
    for late in [false, true] {
        let (mut controller, device, source) = fixture(REVISION);
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
            let (mut controller, device, source) = ready(REVISION, 4096);
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
    let (mut controller, device, source) = ready(REVISION, 4096);
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
fn native_read_failure_has_priority_over_clock_expiry_after_that_access() {
    let (mut controller, device, source) = ready(REVISION, 4096);
    {
        let mut model = device.lock().unwrap();
        model.fail_after_write = Some(0x2c08);
        model.jump_read = Some((0x2c08, u32::MAX, 100_001));
    }
    assert_eq!(
        controller.start(),
        Err(Error::RegisterUnavailable(DMA_ENABLE))
    );
    assert_eq!(controller.state(), State::Faulted);
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    controller.shutdown().unwrap();
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn active_drop_quarantines_real_domain_and_nonidentity_ram_pins() {
    let (mut controller, device, source) = ready(REVISION, 4096);
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
