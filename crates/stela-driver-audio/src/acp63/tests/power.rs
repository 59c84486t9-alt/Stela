// SPDX-License-Identifier: GPL-2.0-only
//! Power cases.
use super::*;

#[test]
fn peer_power_request_validation_is_independent_of_completion() {
    for revision in [0x63, 0x70, 0x71, 0x72] {
        let on = if revision == 0x63 { 1 } else { 0x1f };
        for stalled in [false, true] {
            let mut device = Device::new(revision);
            device.power_never = stalled;
            device.write(0x1024, on);
            assert_eq!(device.words[0x1028 / 4], if stalled { 2 } else { 0 });
            assert_eq!(device.writes, [(0x1024, on)]);
            assert_eq!(device.resets, 0);
            assert!(!device.master);
            assert_eq!(device.maps, 0);
        }
        // A completion fault must never turn a power-off, reserved value,
        // or another generation's request into a permitted command.
        for stalled in [false, true] {
            for request in [0, 2, 3, u32::MAX, if on == 1 { 0x1f } else { 1 }] {
                let mut device = Device::new(revision);
                device.power_never = stalled;
                let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    device.write(0x1024, request);
                }));
                assert!(refused.is_err());
                assert_eq!(device.words[0x1028 / 4], 2);
                assert_eq!(device.resets, 0);
                assert!(!device.master);
                assert_eq!(device.maps, 0);
            }
        }
    }
}

#[test]
fn power_zsc_and_iova_limit_failures_do_not_publish_dma() {
    let (mut controller, device, source) = fixture(0x63);
    device.lock().unwrap().power_never = true;
    assert_eq!(controller.initialize(), Err(Error::Timeout(Phase::PowerOn)));
    assert_eq!(controller.state(), State::Faulted);
    assert!(controller.capture.is_none());
    {
        let model = device.lock().unwrap();
        assert_eq!(model.words[0x1028 / 4], 2);
        assert_eq!(model.writes, [(0x1024, 1)]);
        assert_eq!(model.resets, 0);
        assert!(!model.master);
        assert_eq!(model.maps, 0);
    }
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    assert_eq!(device.lock().unwrap().maps, 0);
    device.lock().unwrap().power_never = false;
    device.lock().unwrap().ignore_write = Some(0x1014);
    assert_eq!(
        controller.initialize(),
        Err(Error::RegisterRejected(ZSC_CONTROL))
    );
    device.lock().unwrap().ignore_write = None;
    controller.initialize().unwrap();
    // Narrow the platform ceiling before allocating anything. The real
    // model domain refuses its high IOVA; no PA fallback is permitted.
    controller.config.dma_address_bits = 32;
    assert_eq!(
        controller.prepare_capture(&source, CAPTURE_FORMAT, 4096),
        Err(Error::Dma(DmaError::AddressLimit))
    );
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    assert_eq!(device.lock().unwrap().maps, 0);
    assert!(controller.capture.is_none());
    assert!(
        !device
            .lock()
            .unwrap()
            .writes
            .iter()
            .any(|(offset, _)| *offset == 0x10000)
    );
    controller.shutdown().unwrap();
}

#[test]
fn successful_but_late_power_and_reset_accesses_do_not_advance_initialization() {
    // Both a successful request effect and its successful ready read must
    // fit the phase budget. The clock advances inside that access.
    for write in [false, true] {
        for (offset, request, ready, phase) in [
            (0x1024, 1, 0, Phase::PowerOn),
            (0x1000, 1, 0x10001, Phase::ResetAssert),
            (0x1000, 0, 0, Phase::ResetClear),
        ] {
            let (mut controller, device, source) = fixture(0x63);
            {
                let mut model = device.lock().unwrap();
                if write {
                    model.jump_write = Some((offset, request, 501));
                } else {
                    model.jump_read = Some((
                        if phase == Phase::PowerOn {
                            0x1028
                        } else {
                            offset
                        },
                        ready,
                        501,
                    ));
                }
            }
            assert_eq!(controller.initialize(), Err(Error::Timeout(phase)));
            assert_eq!(controller.state(), State::Faulted);
            assert_eq!(device.lock().unwrap().maps, 0);
            assert!(
                !device
                    .lock()
                    .unwrap()
                    .writes
                    .iter()
                    .any(|(at, _)| *at == 0x1014)
            );
            if phase == Phase::PowerOn {
                assert!(
                    !device
                        .lock()
                        .unwrap()
                        .writes
                        .iter()
                        .any(|(at, _)| *at == 0x1004)
                );
            }
            controller.initialize().unwrap();
            controller
                .prepare_capture(&source, CAPTURE_FORMAT, 4096)
                .unwrap();
            controller.start().unwrap();
            device.lock().unwrap().advance(16);
            controller.shutdown().unwrap();
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        }
    }
    // An already-on first read is still a physical phase access.
    let (mut controller, device, _) = fixture(0x63);
    {
        let mut model = device.lock().unwrap();
        model.words[0x1028 / 4] = 0;
        model.jump_read = Some((0x1028, 0, 501));
    }
    assert_eq!(controller.initialize(), Err(Error::Timeout(Phase::PowerOn)));
    assert!(device.lock().unwrap().writes.is_empty());
    controller.shutdown().unwrap();
}
