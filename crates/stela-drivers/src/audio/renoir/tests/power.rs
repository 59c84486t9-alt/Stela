// SPDX-License-Identifier: GPL-2.0-only
//! Power cases.
use super::*;

#[test]
fn optional_source_power_off_has_deadlines_and_failed_gating_keeps_pins() {
    for late in 0..3 {
        let (mut controller, device, source) = ready(1, 4096);
        controller.start().unwrap();
        {
            let mut model = device.lock().unwrap();
            match late {
                0 => model.power_off_never = true,
                1 => model.jump_write = Some((0x141c, 0, 501)),
                _ => model.jump_read = Some((0x1420, 2, 501)),
            }
        }
        assert_eq!(
            controller.suspend_held_d0(true),
            Err(Error::Timeout(Phase::PowerOff))
        );
        assert_eq!(
            controller.first_error(),
            Some(Error::Timeout(Phase::PowerOff))
        );
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(device.lock().unwrap().unmaps, 0);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        device.lock().unwrap().power_off_never = false;
        controller.initialize().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        controller.shutdown().unwrap();
    }
}

#[test]
fn suspended_shutdown_reproves_power_and_reset_before_releasing_owners() {
    for power_gate in [false, true] {
        let (mut controller, device, source) = ready(1, 4096);
        controller.start().unwrap();
        controller.suspend_held_d0(power_gate).unwrap();
        let starts = device
            .lock()
            .unwrap()
            .writes
            .iter()
            .filter(|entry| **entry == (0x2c08, 1))
            .count();
        controller.shutdown().unwrap();
        assert_eq!(controller.state(), State::Shutdown);
        assert_eq!(device.lock().unwrap().words[0x1420 / 4], 0);
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
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert!(controller.into_stopped().is_ok());
    }
    let (mut controller, device, _) = fixture(1);
    controller.initialize().unwrap();
    assert_eq!(controller.resume_held_d0(), Err(Error::NotSuspended));
    controller.suspend_held_d0(false).unwrap();
    controller.resume_held_d0().unwrap();
    assert_eq!(controller.state(), State::Ready);
    assert_eq!(device.lock().unwrap().maps, 0);
    controller.shutdown().unwrap();
}

#[test]
fn successful_but_late_power_and_reset_accesses_do_not_advance_initialization() {
    // Both a successful request effect and its successful ready read must
    // fit the phase budget. The clock advances inside that access.
    for write in [false, true] {
        for (offset, request, ready, phase) in [
            (0x141c, 1, 0, Phase::PowerOn),
            (0x1000, 1, 0x10001, Phase::ResetAssert),
            (0x1000, 0, 0, Phase::ResetClear),
        ] {
            let (mut controller, device, source) = fixture(1);
            {
                let mut model = device.lock().unwrap();
                if write {
                    model.jump_write = Some((offset, request, 501));
                } else {
                    model.jump_read = Some((
                        if phase == Phase::PowerOn {
                            0x1420
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
                    .any(|(at, _)| *at == 0x1424)
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
    let (mut controller, device, _) = fixture(1);
    {
        let mut model = device.lock().unwrap();
        model.words[0x1420 / 4] = 0;
        model.jump_read = Some((0x1420, 0, 501));
    }
    assert_eq!(controller.initialize(), Err(Error::Timeout(Phase::PowerOn)));
    assert!(device.lock().unwrap().writes.is_empty());
    controller.shutdown().unwrap();
}
