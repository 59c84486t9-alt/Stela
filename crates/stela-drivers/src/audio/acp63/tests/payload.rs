// SPDX-License-Identifier: GPL-2.0-only
//! Payload cases.
use super::*;

#[test]
fn missing_actual_payload_completion_service_refuses_before_first_dma_publication() {
    let (mut controller, device, source) = fixture(0x63);
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
fn posted_payload_requires_actual_domain_completion_before_cpu_or_release() {
    let (mut controller, device, source) = ready(0x63, 4096);
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
