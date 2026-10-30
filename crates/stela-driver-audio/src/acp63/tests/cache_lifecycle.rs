// SPDX-License-Identifier: GPL-2.0-only
//! Cache lifecycle cases.
use super::*;

// ATU regression matrices shared by the ACP63 and ACP70 profiles.
fn check_ps_cache_lifecycle<P: Profile>(
    (mut controller, device, source): (
        acp_pdm::Controller<Model, Time, P>,
        Arc<Mutex<Device>>,
        Source,
    ),
    readback: u32,
) {
    use crate::acp_pdm::test_support::assert_ring_invalidation;
    device.lock().unwrap().atu_readback = readback;
    controller.initialize().unwrap();
    assert!(
        !device
            .lock()
            .unwrap()
            .writes
            .iter()
            .any(|(at, _)| *at == 0xc40)
    );
    let first = device.lock().unwrap().writes.len();
    controller
        .prepare_capture(&source, CAPTURE_FORMAT, 4096)
        .unwrap();
    assert_ring_invalidation(
        &device.lock().unwrap().writes[first..],
        IOVA,
        0x0380_0000,
        4096,
        false,
    );
    controller.start().unwrap();
    assert_ring_invalidation(
        &device.lock().unwrap().writes[first..],
        IOVA,
        0x0380_0000,
        4096,
        true,
    );
    device.lock().unwrap().advance(512);
    assert!(controller.position().unwrap().period_pending);
    controller.stop().unwrap();
    let reset = device.lock().unwrap().resets;
    let replacement = device.lock().unwrap().writes.len();
    controller
        .prepare_capture(&source, CAPTURE_FORMAT, 8192)
        .unwrap();
    assert_ring_invalidation(
        &device.lock().unwrap().writes[replacement..],
        IOVA,
        0x0380_0000,
        8192,
        false,
    );
    assert!(device.lock().unwrap().resets > reset);
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    assert_eq!(device.lock().unwrap().unmaps, 1);
    let capture = controller.capture.as_ref().unwrap();
    let address = capture.dma.address().unwrap();
    let cpu = capture.cpu.address(0, 4).unwrap();
    controller.start().unwrap();
    assert_ring_invalidation(
        &device.lock().unwrap().writes[replacement..],
        IOVA,
        0x0380_0000,
        8192,
        true,
    );
    device.lock().unwrap().advance(1024);
    controller.suspend_retained(false).unwrap();
    assert_eq!(controller.state(), State::Suspended);
    {
        let model = device.lock().unwrap();
        assert_eq!(model.words[0xc04 / 4], 0);
        assert!(!model.master);
        assert_eq!(model.unmaps, 1);
    }
    let restored = device.lock().unwrap().writes.len();
    controller.resume_retained().unwrap();
    assert_ring_invalidation(
        &device.lock().unwrap().writes[restored..],
        IOVA,
        0x0380_0000,
        8192,
        false,
    );
    assert_eq!(controller.state(), State::Prepared);
    let capture = controller.capture.as_ref().unwrap();
    assert_eq!(capture.dma.address().unwrap(), address);
    assert_eq!(capture.cpu.address(0, 4).unwrap(), cpu);
    controller.start().unwrap();
    assert_ring_invalidation(
        &device.lock().unwrap().writes[restored..],
        IOVA,
        0x0380_0000,
        8192,
        true,
    );
    device.lock().unwrap().advance(1024);
    assert!(controller.position().unwrap().period_pending);
    controller.shutdown().unwrap();
    let model = device.lock().unwrap();
    assert_eq!(model.atu_reads, 0);
    assert_eq!(
        model
            .writes
            .iter()
            .copied()
            .filter(|(at, _)| *at == 0xc40)
            .collect::<Vec<_>>(),
        [(0xc40, 1), (0xc40, 1), (0xc40, 1)],
        "one command per initial/replacement/resume publication, none for stop/suspend/shutdown"
    );
    assert_eq!(model.maps, 2);
    assert_eq!(model.unmaps, 2);
    assert_eq!(source.drops.load(Ordering::Relaxed), 2);
}

#[test]
fn ps_atu_cache_command_is_write_only_and_ordered_for_all_profiles() {
    for readback in [0, 1, 0x1234_5678, u32::MAX] {
        check_ps_cache_lifecycle(fixture(0x63), readback);
        for revision in 0x70..=0x72 {
            check_ps_cache_lifecycle(fixture70(revision), readback);
        }
    }
}
