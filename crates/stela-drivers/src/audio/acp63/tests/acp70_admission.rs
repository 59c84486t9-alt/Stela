// SPDX-License-Identifier: GPL-2.0-only
//! Acp70 admission cases.
use super::*;

#[test]
fn acp70_soundwire_enable_and_wake_refuse_before_whole_function_effects() {
    for offset in [0x3000, 0x3004, 0x3c00, 0x3c04, 0x1458, 0x1460] {
        let (mut controller, device, _) = fixture70(0x70);
        device.lock().unwrap().words[offset / 4] = 1;
        assert_eq!(controller.initialize(), Err(Error::Ownership));
        assert!(device.lock().unwrap().writes.is_empty());
        device.lock().unwrap().words[offset / 4] = 0;
        controller.initialize().unwrap();
        controller.shutdown().unwrap();
    }
    for offset in [0x3000, 0x3004, 0x3c00, 0x3c04, 0x1458, 0x1460] {
        let (mut controller, device, _) = fixture70(0x71);
        device.lock().unwrap().lost_read = Some(offset);
        assert_eq!(
            controller.initialize(),
            Err(Error::RegisterUnavailable(offset))
        );
        assert!(device.lock().unwrap().writes.is_empty());
        controller.shutdown().unwrap();
    }
}

#[test]
fn acp70_exact_generation_and_pin_modes_do_not_admit_acp7x_or_sdw_only() {
    use crate::audio::acp70::Ps70;
    for revision in 0..=255 {
        assert_eq!(
            Ps70::supported(Identity {
                vendor: 0x1022,
                device: 0x15e2,
                revision
            }),
            matches!(revision, 0x70..=0x72)
        );
    }
    for mode in 0..=21 {
        let (mut controller, device, _) = fixture70(0x70);
        device.lock().unwrap().words[0x1440 / 4] = mode;
        let result = controller.initialize();
        if matches!(mode, 4..=8 | 10..=14 | 17..=20) {
            result.unwrap();
        } else {
            assert_eq!(result, Err(Error::UnsupportedPinMode(mode)));
        }
        controller.shutdown().unwrap();
    }
}

#[test]
fn acp70_live_wake_or_pme_loss_and_failed_restore_preserve_published_dma() {
    for offset in [0x1458, 0x1460, 0x1400] {
        let (mut controller, device, source) = fixture70(0x72);
        controller.initialize().unwrap();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        controller.start().unwrap();
        device.lock().unwrap().words[offset / 4] ^= 1;
        assert_eq!(
            controller.position(),
            Err(if offset == 0x1400 {
                Error::AuthorityChanged
            } else {
                Error::Ownership
            })
        );
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        device.lock().unwrap().words[offset / 4] ^= 1;
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }
    for restore in [false, true] {
        let (mut controller, device, source) = fixture70(0x71);
        controller.initialize().unwrap();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        controller.start().unwrap();
        let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
        if restore {
            controller.suspend_held_d0().unwrap();
        }
        device.lock().unwrap().ignore_write = Some(0x1014);
        assert_eq!(
            if restore {
                controller.resume_held_d0()
            } else {
                controller.suspend_held_d0()
            },
            Err(Error::RegisterRejected(0x1014))
        );
        assert_eq!(
            controller.capture.as_ref().unwrap().dma.address().unwrap(),
            address
        );
        assert_eq!(device.lock().unwrap().unmaps, 0);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        device.lock().unwrap().ignore_write = None;
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }
}
