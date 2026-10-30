// SPDX-License-Identifier: GPL-2.0-only
//! Recovery cases.
use super::*;

#[test]
fn first_failure_survives_needs_reset_cleanup_errors_and_successful_recovery() {
    let (mut controller, device, source) = ready(0x63, 4096);
    assert_eq!(controller.first_error(), None);
    controller.start().unwrap();
    device.lock().unwrap().words[0x1a0c / 4] |= 1 << 29;
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
fn live_faults_quarantine_old_pcm_and_allow_shutdown() {
    for fault in 0..9 {
        let (mut controller, device, source) = ready(0x63, 4096);
        controller.start().unwrap();
        {
            let mut model = device.lock().unwrap();
            match fault {
                0 => model.words[0x10004 / 4] ^= 1,
                1 => model.words[0x1a04 / 4] &= !(1 << 29),
                2 => model.words[0x1014 / 4] = 1,
                3 => model.identity.device ^= 1,
                4 => model.words[0x1a0c / 4] |= 1 << 29,
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
