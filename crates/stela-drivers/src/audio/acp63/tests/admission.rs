// SPDX-License-Identifier: GPL-2.0-only
//! Admission cases.
use super::*;

#[test]
fn dedicated_source_child_wov_selector_soundwire_and_pin_admission_are_exact() {
    for cfg in [
        Config {
            ownership: Ownership::Unknown,
            ..config()
        },
        Config {
            ownership: Ownership::FirmwareDsp,
            ..config()
        },
        Config {
            acp_config: None,
            ..config()
        },
        Config {
            acp_config: Some(8),
            ..config()
        },
        Config {
            acp_config: Some(16),
            ..config()
        },
        Config {
            acp_config: Some(2),
            ..config()
        },
        Config {
            child: None,
            ..config()
        },
        Config {
            child: Some(DmicChild {
                address: 3,
                audio_device_type: 2,
            }),
            ..config()
        },
        Config {
            child: Some(DmicChild {
                address: 2,
                audio_device_type: 3,
            }),
            ..config()
        },
        Config {
            wov: WovObservation::Value(0),
            ..config()
        },
        Config {
            wov: WovObservation::Unavailable,
            ..config()
        },
        Config {
            soundwire: SoundWireOwnership::ActiveOrUnknown,
            ..config()
        },
        Config {
            gain: 4,
            ..config()
        },
        Config {
            dma_address_bits: 64,
            ..config()
        },
    ] {
        let device = Arc::new(Mutex::new(Device::new(0x63)));
        let clock = device.lock().unwrap().clock.clone();
        assert!(
            // SAFETY: Model and Domain keep the same mutex-serialized
            // Device and its fixture register state. The model has no
            // physical PCI or firmware actor, and no capture pages are mapped.
            unsafe {
                Controller::claim(
                    Model(device.clone()),
                    Time(clock),
                    cfg,
                    Arc::new(Domain(device.clone())),
                )
            }
            .is_err()
        );
        assert!(device.lock().unwrap().writes.is_empty());
        assert_eq!(device.lock().unwrap().maps, 0);
    }
    for wov in [WovObservation::Value(7), WovObservation::EvaluatedFailure] {
        let device = Arc::new(Mutex::new(Device::new(0x63)));
        let clock = device.lock().unwrap().clock.clone();
        // SAFETY: this model's discovered child/firmware/whole
        // function owner supplies the source-default _WOV failure policy.
        let mut controller = unsafe {
            Controller::claim(
                Model(device.clone()),
                Time(clock),
                Config {
                    wov,
                    soundwire: SoundWireOwnership::QuiescedExclusive,
                    ..config()
                },
                Arc::new(Domain(device.clone())),
            )
        }
        .unwrap();
        controller.initialize().unwrap();
        controller.shutdown().unwrap();
    }
    for revision in [0, 1, 0x50, 0x60, 0x62, 0x6f, 0x70, 0x71, 0x72] {
        assert!(!PinkSardine::supported(Identity {
            vendor: 0x1022,
            device: 0x15e2,
            revision
        }));
    }
    for mode in 0..=16 {
        let (mut controller, device, _) = fixture(0x63);
        device.lock().unwrap().words[0x1440 / 4] = mode;
        let result = controller.initialize();
        if matches!(mode, 4..=8 | 10..=14) {
            result.unwrap();
        } else {
            assert_eq!(result, Err(Error::UnsupportedPinMode(mode)));
        }
        controller.shutdown().unwrap();
    }
}
