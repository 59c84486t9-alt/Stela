// SPDX-License-Identifier: GPL-2.0-only
//! Streaming cases.
use super::*;

#[test]
fn continuous_actual_completed_periods_cross_wraps_without_stopping_dma() {
    let (mut controller, device, source) = ready(0x63, 4096);
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
        assert_eq!(model.words[0x1a0c / 4] & (1 << 16), 0);
        // Source ISR acknowledges period before pointer sampling.
        let ack = model
            .accesses
            .iter()
            .position(|entry| *entry == (0x1a0c, true))
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
    let (mut controller, device, _) = ready(0x63, 4096);
    controller.start().unwrap();
    let mut pcm = vec![0xa5; 4096];
    // Counter progress without the source completion event is positioning,
    // never an independent grant to publish newly captured PCM.
    device.lock().unwrap().advance(512);
    device.lock().unwrap().words[0x1a0c / 4] &= !(1 << 16);
    assert_eq!(controller.capture_period(&mut pcm).unwrap(), None);
    assert!(pcm.iter().all(|byte| *byte == 0xa5));
    device.lock().unwrap().advance(1024);
    assert!(controller.position().unwrap().period_pending);
    // External position polling consumed the W1C status, not completed PCM.
    assert_eq!(device.lock().unwrap().words[0x1a0c / 4] & (1 << 16), 0);
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
        let (mut controller, device, source) = ready(0x63, 4096);
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
    let (mut controller, device, source) = fixture(0x63);
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
