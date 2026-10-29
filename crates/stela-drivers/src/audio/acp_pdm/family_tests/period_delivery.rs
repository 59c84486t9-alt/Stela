// SPDX-License-Identifier: GPL-2.0-only
//! Continuous period delivery and posted payload completion, shared by
//! the profiles with `PERIOD_DELIVERY`.
//! Each family test module includes this file against its own model.
use super::*;

#[test]
fn missing_payload_completion_service_refuses_before_first_dma_publication() {
    let (mut controller, device, source) = fixture(REVISION);
    device.lock().unwrap().drain_unavailable = true;
    assert_eq!(
        controller.initialize(),
        Err(Error::Dma(DmaError::DrainUnavailable))
    );
    assert_eq!(controller.state(), State::Faulted);
    assert_eq!(
        controller.first_error(),
        Some(Error::Dma(DmaError::DrainUnavailable))
    );
    assert_eq!(controller.start(), Err(Error::NeedsReset));
    assert_eq!(device.lock().unwrap().maps, 0);
    assert!(
        !device
            .lock()
            .unwrap()
            .writes
            .iter()
            .any(|(offset, _)| *offset >= 0x10000)
    );
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    device.lock().unwrap().drain_unavailable = false;
    controller.initialize().unwrap();
    controller
        .prepare_capture(&source, CAPTURE_FORMAT, 4096)
        .unwrap();
    controller.start().unwrap();
    controller.shutdown().unwrap();
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    assert_eq!(
        controller.first_error(),
        Some(Error::Dma(DmaError::DrainUnavailable))
    );
}

#[test]
fn posted_payload_requires_domain_completion_before_cpu_or_release() {
    let (mut controller, device, source) = ready(REVISION, 4096);
    controller.start().unwrap();
    device.lock().unwrap().defer_payload = true;
    device.lock().unwrap().advance(512);
    // Raw hardware progress precedes independently queued payload, but
    // this fabric has not supplied a source completed-period event.
    assert_eq!(controller.position().unwrap().bytes, 4096);
    assert_eq!(device.lock().unwrap().posted.len(), 1024);
    let mut untouched = vec![0xa5; 4096];
    assert_eq!(controller.capture_period(&mut untouched).unwrap(), None);
    assert!(untouched.iter().all(|byte| *byte == 0xa5));
    device.lock().unwrap().drain_fail = true;
    assert_eq!(
        controller.stop(),
        Err(Error::Dma(DmaError::InvalidationFailed))
    );
    assert_eq!(controller.state(), State::Faulted);
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    assert_eq!(device.lock().unwrap().unmaps, 0);
    assert_eq!(device.lock().unwrap().cpu_syncs, 0);
    assert_eq!(device.lock().unwrap().posted.len(), 1024);
    device.lock().unwrap().drain_fail = false;
    device.lock().unwrap().drain_unavailable = true;
    assert_eq!(
        controller.initialize(),
        Err(Error::Dma(DmaError::DrainUnavailable))
    );
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    assert_eq!(device.lock().unwrap().posted.len(), 1024);
    device.lock().unwrap().drain_unavailable = false;
    controller.initialize().unwrap();
    assert!(device.lock().unwrap().posted.is_empty());
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    assert_eq!(
        controller.first_error(),
        Some(Error::Dma(DmaError::InvalidationFailed))
    );
    controller
        .prepare_capture(&source, CAPTURE_FORMAT, 4096)
        .unwrap();
    controller.start().unwrap();
    device.lock().unwrap().advance(512);
    controller.stop().unwrap();
    let mut pcm = vec![0; 4096];
    let drains = device.lock().unwrap().drains;
    controller.copy_stopped_ring(0, &mut pcm).unwrap();
    assert_eq!(device.lock().unwrap().drains, drains + 1);
    assert_eq!(device.lock().unwrap().cpu_syncs, 1);
    for frame in 0..512 {
        for channel in 0..2 {
            let offset = frame * 8 + channel * 4;
            assert_eq!(
                i32::from_le_bytes(pcm[offset..offset + 4].try_into().unwrap()),
                sample((512 + frame) as u64, channel)
            );
        }
    }
    controller.shutdown().unwrap();
    assert_eq!(source.drops.load(Ordering::Relaxed), 2);
}

#[test]
fn continuous_completed_periods_cross_wraps_without_stopping_dma() {
    let (mut controller, device, source) = ready(REVISION, 4096);
    controller.start().unwrap();
    let mut pcm = vec![0xa5; 4096];
    assert_eq!(controller.capture_period(&mut pcm).unwrap(), None);
    assert!(pcm.iter().all(|byte| *byte == 0xa5));
    for period in 0..24 {
        device.lock().unwrap().advance(512);
        device.lock().unwrap().accesses.clear();
        assert_eq!(
            controller.capture_period(&mut pcm).unwrap(),
            Some(CapturePeriod {
                first_frame: period * 512,
                frames: 512
            })
        );
        let model = device.lock().unwrap();
        assert_eq!(model.words[0x2c08 / 4] & 2, 2);
        assert_eq!(model.words[0x2c04 / 4], 1);
        assert_eq!(model.cpu_syncs, 0);
        assert_eq!(model.words[IRQ_STATUS / 4] & (1 << 16), 0);
        // Source ISR acknowledges period before pointer sampling.
        let ack = model
            .accesses
            .iter()
            .position(|entry| *entry == (IRQ_STATUS, true))
            .unwrap();
        let counter = model
            .accesses
            .iter()
            .position(|entry| *entry == (0x2c18, false))
            .unwrap();
        assert!(ack < counter);
        drop(model);
        for frame in 0..512 {
            for channel in 0..2 {
                let offset = frame * 8 + channel * 4;
                assert_eq!(
                    i32::from_le_bytes(pcm[offset..offset + 4].try_into().unwrap()),
                    sample(period * 512 + frame as u64, channel)
                );
            }
        }
    }
    let model = device.lock().unwrap();
    assert_eq!(
        model
            .writes
            .iter()
            .filter(|entry| **entry == (0x2c08, 1))
            .count(),
        1
    );
    assert_eq!(
        model
            .writes
            .iter()
            .filter(|entry| **entry == (0x2c08, 2))
            .count(),
        0
    );
    drop(model);
    controller.shutdown().unwrap();
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn continuous_coalesced_irq_position_ack_and_partial_frame_are_not_fake_periods() {
    let (mut controller, device, _) = ready(REVISION, 4096);
    controller.start().unwrap();
    let mut pcm = vec![0xa5; 4096];
    // Counter progress without the source completion event is positioning,
    // never an independent grant to publish newly captured PCM.
    device.lock().unwrap().advance(512);
    device.lock().unwrap().words[IRQ_STATUS / 4] &= !(1 << 16);
    assert_eq!(controller.capture_period(&mut pcm).unwrap(), None);
    assert!(pcm.iter().all(|byte| *byte == 0xa5));
    device.lock().unwrap().advance(1024);
    assert!(controller.position().unwrap().period_pending);
    // External position polling consumed the W1C status, not completed PCM.
    assert_eq!(device.lock().unwrap().words[IRQ_STATUS / 4] & (1 << 16), 0);
    for index in 0..3 {
        assert_eq!(
            controller.capture_period(&mut pcm).unwrap(),
            Some(CapturePeriod {
                first_frame: index * 512,
                frames: 512
            })
        );
        for channel in 0..2 {
            assert_eq!(
                i32::from_le_bytes(pcm[channel * 4..channel * 4 + 4].try_into().unwrap()),
                sample(index * 512, channel)
            );
        }
    }
    assert_eq!(controller.capture_period(&mut pcm).unwrap(), None);
    device.lock().unwrap().advance(512);
    // The next hardware frame is only partly counted; no partial-frame
    // bytes are included in the completed preceding period.
    device.lock().unwrap().count += 4;
    assert_eq!(
        controller.capture_period(&mut pcm).unwrap(),
        Some(CapturePeriod {
            first_frame: 1536,
            frames: 512
        })
    );
    assert_eq!(controller.capture_period(&mut pcm).unwrap(), None);
    controller.shutdown().unwrap();
}

#[test]
fn continuous_late_or_mid_copy_overwrite_quarantines_without_consuming_bad_period() {
    for mid_copy in [false, true] {
        let (mut controller, device, source) = ready(REVISION, 4096);
        controller.start().unwrap();
        let mut pcm = vec![0xa5; 4096];
        if mid_copy {
            device.lock().unwrap().advance(512);
            let next = device.lock().unwrap().coherent_reads + 16;
            device.lock().unwrap().advance_on_coherent = Some((next, 2048));
        } else {
            device.lock().unwrap().advance(2048);
        }
        let expected = Error::CaptureOverrun {
            produced: if mid_copy { 20_480 } else { 16_384 },
            consumed: 0,
        };
        assert_eq!(controller.capture_period(&mut pcm), Err(expected));
        assert_eq!(controller.first_error(), Some(expected));
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(controller.capture_period(&mut pcm), Err(Error::NeedsReset));
        if !mid_copy {
            assert!(pcm.iter().all(|byte| *byte == 0xa5));
        }
        assert_eq!(device.lock().unwrap().cpu_syncs, 0);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        controller.initialize().unwrap();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        controller.start().unwrap();
        device.lock().unwrap().advance(512);
        assert!(controller.capture_period(&mut pcm).unwrap().is_some());
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 2);
        assert_eq!(controller.first_error(), Some(expected));
    }
}

#[test]
fn continuous_coherency_is_actual_and_invalid_destinations_have_no_effects() {
    let (mut controller, device, source) = fixture(REVISION);
    controller.initialize().unwrap();
    device.lock().unwrap().coherence_unavailable = true;
    assert_eq!(
        controller.prepare_capture(&source, CAPTURE_FORMAT, 4096),
        Err(Error::Dma(DmaError::CoherenceUnavailable))
    );
    assert_eq!(device.lock().unwrap().maps, 1);
    assert_eq!(device.lock().unwrap().unmaps, 1);
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    assert!(
        !device
            .lock()
            .unwrap()
            .writes
            .iter()
            .any(|(offset, _)| *offset >= 0x10000)
    );
    device.lock().unwrap().coherence_unavailable = false;
    controller.initialize().unwrap();
    controller
        .prepare_capture(&source, CAPTURE_FORMAT, 4096)
        .unwrap();
    controller.start().unwrap();
    let before = device.lock().unwrap().accesses.len();
    for bytes in [0, 8, 4092, 4100] {
        assert_eq!(
            controller.capture_period(&mut vec![0xa5; bytes]),
            Err(Error::InvalidBuffer)
        );
    }
    assert_eq!(device.lock().unwrap().accesses.len(), before);
    device.lock().unwrap().advance(512);
    device.lock().unwrap().coherence_unavailable = true;
    assert_eq!(
        controller.capture_period(&mut vec![0xa5; 4096]),
        Err(Error::Dma(DmaError::CoherenceUnavailable))
    );
    assert_eq!(controller.state(), State::Faulted);
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    device.lock().unwrap().coherence_unavailable = false;
    controller.shutdown().unwrap();
    assert_eq!(source.drops.load(Ordering::Relaxed), 2);
}
