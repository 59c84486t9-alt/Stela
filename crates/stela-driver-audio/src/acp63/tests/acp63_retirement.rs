// SPDX-License-Identifier: GPL-2.0-only
//! Acp63 retirement cases.
use super::*;

#[test]
fn acp63_irq_zsc_policy_and_kept_resume_do_not_alias_a_clock_mux() {
    let (mut controller, device, source) = fixture(0x63);
    device.lock().unwrap().words[0x1a04 / 4] = 1 << 7;
    device.lock().unwrap().words[0x1a0c / 4] = 1 << 9;
    controller.initialize().unwrap();
    {
        let model = device.lock().unwrap();
        assert_eq!(model.words[0x1a04 / 4], 1 << 29);
        assert_eq!(model.words[0x1014 / 4], 0);
        assert_eq!(model.words[0x1a0c / 4], 1 << 9);
        let gate = model
            .accesses
            .iter()
            .position(|entry| *entry == (0x1a00, true))
            .unwrap();
        let control = model
            .accesses
            .iter()
            .position(|entry| *entry == (0x1a04, true))
            .unwrap();
        let zsc = model
            .accesses
            .iter()
            .position(|entry| *entry == (0x1014, true))
            .unwrap();
        let pin = model
            .accesses
            .iter()
            .position(|entry| *entry == (0x1440, false))
            .unwrap();
        assert!(gate < control && control < zsc && zsc < pin);
    }
    controller
        .prepare_capture(&source, CAPTURE_FORMAT, 4096)
        .unwrap();
    let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
    let cpu = controller
        .capture
        .as_ref()
        .unwrap()
        .cpu
        .address(0, 4)
        .unwrap();
    controller.start().unwrap();
    device.lock().unwrap().advance(512);
    let mut pcm = vec![0xa5; 4096];
    assert!(controller.capture_period(&mut pcm).unwrap().is_some());
    device.lock().unwrap().writes.clear();
    controller.suspend_held_d0().unwrap();
    {
        let model = device.lock().unwrap();
        let status = model
            .writes
            .iter()
            .position(|entry| *entry == (0x1a0c, u32::MAX))
            .unwrap();
        let control = model
            .writes
            .iter()
            .position(|entry| *entry == (0x1a04, 0))
            .unwrap();
        let gate = model
            .writes
            .iter()
            .position(|entry| *entry == (0x1a00, 0))
            .unwrap();
        let reset = model
            .writes
            .iter()
            .position(|entry| *entry == (0x1000, 1))
            .unwrap();
        let quiet = model
            .writes
            .iter()
            .position(|entry| *entry == (0x1004, 0))
            .unwrap();
        let zsc = model
            .writes
            .iter()
            .position(|entry| *entry == (0x1014, 1))
            .unwrap();
        assert!(status < control && control < gate && gate < reset && reset < quiet && quiet < zsc);
        assert_eq!(model.maps, 1);
        assert_eq!(model.unmaps, 0);
    }
    assert_eq!(controller.state(), State::Suspended);
    assert_eq!(controller.capture_period(&mut pcm), Err(Error::Suspended));
    controller.resume_held_d0().unwrap();
    assert_eq!(controller.state(), State::Prepared);
    assert_eq!(
        controller.capture.as_ref().unwrap().dma.address().unwrap(),
        address
    );
    assert_eq!(
        controller
            .capture
            .as_ref()
            .unwrap()
            .cpu
            .address(0, 4)
            .unwrap(),
        cpu
    );
    assert!(controller.capture.as_ref().unwrap().published);
    controller.start().unwrap();
    assert_eq!(controller.capture_period(&mut pcm).unwrap(), None);
    device.lock().unwrap().advance(512);
    assert_eq!(
        controller.capture_period(&mut pcm).unwrap(),
        Some(CapturePeriod {
            first_frame: 0,
            frames: 512
        })
    );
    assert_eq!(
        i32::from_le_bytes(pcm[0..4].try_into().unwrap()),
        sample(512, 0)
    );
    controller.suspend_held_d0().unwrap();
    let starts = device
        .lock()
        .unwrap()
        .writes
        .iter()
        .filter(|entry| **entry == (0x2c08, 1))
        .count();
    controller.shutdown().unwrap();
    assert_eq!(
        device
            .lock()
            .unwrap()
            .writes
            .iter()
            .filter(|entry| **entry == (0x2c08, 1))
            .count(),
        starts
    );
    assert_eq!(device.lock().unwrap().words[0x1014 / 4], 1);
    assert_eq!(device.lock().unwrap().maps, 1);
    assert_eq!(device.lock().unwrap().unmaps, 1);
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    assert!(controller.into_stopped().is_ok());
}

#[test]
fn acp63_failed_suspend_or_restore_keeps_the_original_published_epoch() {
    for restore in [false, true] {
        for fault in 0..4 {
            let (mut controller, device, source) = ready(0x63, 4096);
            controller.start().unwrap();
            if restore {
                controller.suspend_held_d0().unwrap();
            }
            let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
            let expected = {
                let mut model = device.lock().unwrap();
                if restore {
                    match fault {
                        0 => {
                            model.identity.device ^= 1;
                            Error::AuthorityChanged
                        }
                        1 => {
                            model.fail_after_write = Some(0x10004);
                            Error::RegisterUnavailable(0x10004)
                        }
                        2 => {
                            model.coherence_unavailable = true;
                            Error::Dma(DmaError::CoherenceUnavailable)
                        }
                        _ => {
                            model.ignore_write = Some(0x1014);
                            Error::RegisterRejected(ZSC_CONTROL)
                        }
                    }
                } else {
                    match fault {
                        0 => {
                            model.stop_never = true;
                            Error::Timeout(Phase::DmaStop)
                        }
                        1 => {
                            model.reset_never = true;
                            Error::Timeout(Phase::ResetClear)
                        }
                        2 => {
                            model.drain_fail = true;
                            Error::Dma(DmaError::InvalidationFailed)
                        }
                        _ => {
                            model.ignore_write = Some(0x1014);
                            Error::RegisterRejected(ZSC_CONTROL)
                        }
                    }
                }
            };
            let before = device.lock().unwrap().writes.len();
            let result = if restore {
                controller.resume_held_d0()
            } else {
                controller.suspend_held_d0()
            };
            assert_eq!(result, Err(expected));
            if restore && fault == 0 {
                assert_eq!(device.lock().unwrap().writes.len(), before);
            }
            assert_eq!(controller.state(), State::Faulted);
            assert_eq!(controller.first_error(), Some(expected));
            assert_eq!(
                controller.capture.as_ref().unwrap().dma.address().unwrap(),
                address
            );
            assert!(controller.capture.as_ref().unwrap().published);
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            assert_eq!(device.lock().unwrap().unmaps, 0);
            {
                let mut model = device.lock().unwrap();
                if restore && fault == 0 {
                    model.identity.device ^= 1;
                }
                model.coherence_unavailable = false;
                model.stop_never = false;
                model.reset_never = false;
                model.drain_fail = false;
                model.ignore_write = None;
            }
            controller.initialize().unwrap();
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
            assert_eq!(controller.first_error(), Some(expected));
            controller.shutdown().unwrap();
        }
    }
}

#[test]
fn live_acp63_pin_and_zsc_loss_are_actual_permission_failures() {
    for (offset, value) in [(0x1440, 5), (0x1014, 1)] {
        let (mut controller, device, source) = ready(0x63, 4096);
        controller.start().unwrap();
        device.lock().unwrap().words[offset / 4] = value;
        assert_eq!(controller.position(), Err(Error::AuthorityChanged));
        assert_eq!(controller.first_error(), Some(Error::AuthorityChanged));
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }
}
