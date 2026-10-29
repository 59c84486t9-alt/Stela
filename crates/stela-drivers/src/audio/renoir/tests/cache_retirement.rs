// SPDX-License-Identifier: GPL-2.0-only
//! Cache retirement cases.
use super::*;

#[test]
fn atu_cache_command_has_no_sticky_enable_or_completion_readback() {
    use crate::audio::acp_pdm::trace_assertions::assert_ring_invalidation;
    for readback in [0, 1, 0x1234_5678, u32::MAX] {
        let (mut controller, device, source) = fixture(1);
        device.lock().unwrap().atu_readback = readback;
        controller.initialize().unwrap();
        let first_program = device.lock().unwrap().writes.len();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes[first_program..],
            IOVA,
            0x0205_0000,
            4096,
            false,
        );
        controller.start().unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes[first_program..],
            IOVA,
            0x0205_0000,
            4096,
            true,
        );
        device.lock().unwrap().advance(512);
        assert!(controller.position().unwrap().period_pending);
        controller.stop().unwrap();
        let old = controller.capture.as_ref().unwrap().dma.address().unwrap();
        let before = device.lock().unwrap().resets;
        let replacement = device.lock().unwrap().writes.len();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 8192)
            .unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes[replacement..],
            IOVA,
            0x0205_0000,
            8192,
            false,
        );
        assert!(
            device.lock().unwrap().resets > before,
            "replacement needs an actual reset, not a cache request"
        );
        assert_eq!(device.lock().unwrap().unmaps, 1);
        assert_eq!(
            controller.capture.as_ref().unwrap().dma.address().unwrap(),
            old
        );
        controller.start().unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes[replacement..],
            IOVA,
            0x0205_0000,
            8192,
            true,
        );
        device.lock().unwrap().advance(1024);
        controller.stop().unwrap();
        controller.shutdown().unwrap();
        let model = device.lock().unwrap();
        assert_eq!(model.atu_reads, 0);
        assert_eq!(
            model
                .writes
                .iter()
                .copied()
                .filter(|(offset, _)| *offset == 0xc40)
                .collect::<Vec<_>>(),
            [(0xc40, 1), (0xc40, 1)],
            "exactly one request for each of the two successful preparations"
        );
        assert_eq!(model.unmaps, 2);
        assert_eq!(source.drops.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn failed_real_group_disable_keeps_the_original_published_iova_and_pins() {
    let (mut controller, device, source) = ready(1, 4096);
    controller.start().unwrap();
    device.lock().unwrap().advance(32);
    let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
    device.lock().unwrap().ignore_write = Some(0xc04);
    assert_eq!(controller.shutdown(), Err(Error::RegisterRejected(0xc04)));
    assert_eq!(
        controller.capture.as_ref().unwrap().dma.address().unwrap(),
        address
    );
    assert_eq!(device.lock().unwrap().unmaps, 0);
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    assert_eq!(device.lock().unwrap().atu_reads, 0);
    device.lock().unwrap().ignore_write = None;
    controller.shutdown().unwrap();
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn replacing_a_published_ring_cannot_retire_it_after_a_failed_actual_reset() {
    let (mut controller, device, source) = ready(1, 4096);
    controller.start().unwrap();
    device.lock().unwrap().advance(32);
    controller.stop().unwrap();
    let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
    device.lock().unwrap().reset_never = true;
    assert_eq!(
        controller.prepare_capture(&source, CAPTURE_FORMAT, 8192),
        Err(Error::Timeout(Phase::ResetClear))
    );
    assert_eq!(
        controller.capture.as_ref().unwrap().dma.address().unwrap(),
        address
    );
    assert_eq!(device.lock().unwrap().unmaps, 0);
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    device.lock().unwrap().reset_never = false;
    controller.shutdown().unwrap();
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
}
