use super::*;
use {
    crate::platform::apple::pmu::Pmu, crate::platform::apple::pmu::tests::maverick,
    crate::platform::apple::spmi::SlaveError, crate::platform::apple::spmi::SpmiSlave,
    stela_soc_data::pmu::Configuration, stela_soc_data::pmu::FirmwareSram,
};

fn ports(profile: FirmwareStartup) -> FirmwareSram {
    let base = match profile {
        FirmwareStartup::Maverick => 0xc830,
        FirmwareStartup::Monaco => 0x2820,
    };
    FirmwareSram {
        address_low: base,
        address_high: base + 1,
        data: base + 3,
        bytes: 0x3000,
        chunk: 16,
    }
}
fn pmu(profile: FirmwareStartup) -> Pmu {
    Pmu::configured(
        Configuration::new(vec![], Some(maverick()), 1)
            .unwrap()
            .with_firmware_sram(ports(profile), vec![0xa5; 0x3000])
            .unwrap()
            .with_unqualified_firmware_startup(profile)
            .unwrap()
            .with_native_firmware_loader()
            .unwrap(),
        None,
    )
    .unwrap()
}
fn prefix(pmu: &mut Pmu, profile: FirmwareStartup, metadata: u16, now: u64) {
    let (base, key, bytes) = match profile {
        FirmwareStartup::Maverick => (0xc800, 0x7001, 0x65766144u32.to_le_bytes()),
        FirmwareStartup::Monaco => (0x2800, 0x5000, 0x4f724561u32.to_le_bytes()),
    };
    pmu.write(base + 4, &[0], now).unwrap();
    pmu.write(key, &bytes, now).unwrap();
    pmu.write(
        base + 4,
        &[match profile {
            FirmwareStartup::Maverick => 0x49,
            FirmwareStartup::Monaco => 0xc1,
        }],
        now,
    )
    .unwrap();
    pmu.write(base + 5, &[0], now).unwrap();
    pmu.write(base, &[0], now).unwrap();
    pmu.write(base + 1, &metadata.to_le_bytes(), now).unwrap();
}
fn seek(pmu: &mut Pmu, profile: FirmwareStartup, cursor: u16, now: u64) {
    let [low, high] = cursor.to_le_bytes();
    let ports = ports(profile);
    pmu.write(ports.address_low, &[low], now).unwrap();
    pmu.write(ports.address_high, &[high], now).unwrap();
}
fn upload(pmu: &mut Pmu, profile: FirmwareStartup, bytes: &[u8], now: u64) {
    seek(pmu, profile, 0, now);
    for window in bytes.chunks(16) {
        for (i, command) in window.chunks(8).enumerate() {
            pmu.write(ports(profile).data + 8 * i as u16, command, now)
                .unwrap();
        }
    }
}
fn image() -> Vec<u8> {
    let mut bytes = vec![0x5a; 0x278];
    bytes[HEADER..HEADER + HEADER_BYTES].fill(0);
    bytes[HEADER..HEADER + 4].copy_from_slice(b"uuid");
    for (offset, value) in [(8, 0x180u32), (12, 0x1a0), (0x30, 0x270)] {
        bytes[HEADER + offset..HEADER + offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[HEADER + 0x10..HEADER + 0x20].copy_from_slice(&[0x37; 16]);
    bytes
}
#[test]
fn native_loader_requires_explicit_resources_and_never_claims_reset_state() {
    assert!(
        Configuration::new(vec![], None, 0)
            .unwrap()
            .with_native_firmware_loader()
            .is_err()
    );
    for profile in [FirmwareStartup::Maverick, FirmwareStartup::Monaco] {
        let mut owner = pmu(profile);
        let mut output = [0x97];
        let base = owner.loader.as_ref().unwrap().control();
        assert!(owner.read(base + 4, &mut output, 100).is_err());
        assert_eq!(output, [0x97]);
        assert!(owner.write(ports(profile).address_low, &[0], 100).is_err());
        owner.read(maverick().upcount, &mut [0; 6], 0).unwrap();
        owner.write(base + 4, &[0], 0).unwrap();
        owner.read(base + 4, &mut output, 0).unwrap();
        assert_eq!(output, [0]);
        assert_eq!(owner.loader.as_ref().unwrap().phase, Phase::Stopped);
        let (key, bytes, _) = owner.loader.as_ref().unwrap().key();
        assert!(owner.write(key, &bytes[..3], 100).is_err());
        assert!(owner.write(key, &[0xff; 4], 100).is_err());
        assert!(owner.read(key, &mut output, 100).is_err());
        assert_eq!(output, [0]);
        assert!(owner.write(base + 7, &[2], 100).is_err());
        assert!(owner.read(base, &mut output, 100).is_err());
        assert!(owner.write(base + 4, &[0xff], 100).is_err());
        assert_eq!(owner.loader.as_ref().unwrap().phase, Phase::Stopped);
        owner.read(maverick().upcount, &mut [0; 6], 0).unwrap();
    }
}
#[test]
fn both_protection_sequences_own_staged_controls_and_sram() {
    for profile in [FirmwareStartup::Maverick, FirmwareStartup::Monaco] {
        let mut owner = pmu(profile);
        prefix(&mut owner, profile, 0x270, 0);
        let loader = owner.loader.as_ref().unwrap();
        assert_eq!(loader.phase, Phase::Uploading);
        assert!(!loader.written.iter().any(|written| *written));
        let base = loader.control();
        let mut metadata = [0; 2];
        owner.read(base + 1, &mut metadata, 0).unwrap();
        assert_eq!(metadata, 0x270u16.to_le_bytes());
        let bytes = image();
        upload(&mut owner, profile, &bytes, 0);
        assert_eq!(
            &owner.firmware.as_ref().unwrap().bytes()[..bytes.len()],
            &bytes
        );
        assert!(
            owner.firmware.as_ref().unwrap().bytes()[bytes.len()..]
                .iter()
                .all(|byte| *byte == 0xa5)
        );
        assert!(
            owner.loader.as_ref().unwrap().written[..bytes.len()]
                .iter()
                .all(|written| *written)
        );
        // Protection restoration is one byte at a different register;
        // there is no arbitrary key storage/readback or early unlock.
        let (key, value, lock) = owner.loader.as_ref().unwrap().key();
        for (address, data) in [
            (key, value.as_slice()),
            (lock, &[0][..]),
            (lock, &[0, 0, 0, 0][..]),
        ] {
            assert!(owner.write(address, data, 100).is_err());
        }
        owner.read(maverick().upcount, &mut [0; 6], 0).unwrap();
        if profile == FirmwareStartup::Maverick {
            owner.write(0xc828, &[4], 0).unwrap();
            let selected = owner.loader.as_ref().unwrap().image.as_ref().unwrap();
            assert_eq!(selected.bytes, bytes.len());
            assert_eq!(selected.uuid, [0x37; 16]);
            assert_eq!(selected.digest, <[u8; 32]>::from(Sha256::digest(&bytes)));
            owner.write(lock, &[0], 0).unwrap();
            // Address controls may position a readback stream, while
            // protected data writes still cannot alter the sealed image.
            seek(&mut owner, profile, 0, 0);
            let mut readback = [0; 16];
            owner
                .read(ports(profile).data, &mut readback[..8], 0)
                .unwrap();
            owner
                .read(ports(profile).data + 8, &mut readback[8..], 0)
                .unwrap();
            assert_eq!(&readback, &bytes[..16]);
            assert_eq!(
                owner
                    .loader
                    .as_ref()
                    .unwrap()
                    .image
                    .as_ref()
                    .unwrap()
                    .digest,
                <[u8; 32]>::from(Sha256::digest(&bytes))
            );
            assert!(matches!(
                owner.write(base + 6, &[1], 100),
                Err(SlaveError::Unsupported(_))
            ));
            assert_eq!(owner.loader.as_ref().unwrap().phase, Phase::Locked);
            let mut status = [0xff];
            owner.read(base + 0x13, &mut status, 0).unwrap();
            assert_eq!(status, [0]); // native loader remains stopped
            assert!(owner.write(ports(profile).data, &[0; 8], 100).is_err());
        } else {
            let mut mode = [0x97];
            assert!(matches!(
                owner.read(0x1404, &mut mode, 100),
                Err(SlaveError::Unsupported(_))
            ));
            assert_eq!(mode, [0x97]); // no guessed revision/mode/OTP
        }
        owner.read(maverick().upcount, &mut [0; 6], 0).unwrap();
        owner.write(base + 4, &[0], 0).unwrap();
        assert_eq!(owner.loader.as_ref().unwrap().phase, Phase::Stopped);
        assert!(owner.loader.as_ref().unwrap().image.is_none());
        assert!(
            !owner
                .loader
                .as_ref()
                .unwrap()
                .written
                .iter()
                .any(|written| *written)
        );
        assert_eq!(
            &owner.firmware.as_ref().unwrap().bytes()[..bytes.len()],
            &bytes
        );
        prefix(&mut owner, profile, 0x270, 0);
        assert!(owner.write(ports(profile).data, &[1], 0).is_err()); // old cursor revoked
    }
}
#[test]
fn malformed_or_holey_uploads_and_late_time_failure_have_no_partial_effects() {
    for profile in [FirmwareStartup::Maverick, FirmwareStartup::Monaco] {
        let mut owner = pmu(profile);
        prefix(&mut owner, profile, 0x270, 0);
        let before = owner.firmware.as_ref().unwrap().bytes().to_vec();
        seek(&mut owner, profile, 0, 10);
        assert!(owner.write(ports(profile).data, &[1; 8], 9).is_err());
        assert_eq!(owner.firmware.as_ref().unwrap().bytes(), &before);
        assert!(
            !owner
                .loader
                .as_ref()
                .unwrap()
                .written
                .iter()
                .any(|written| *written)
        );
        owner.write(ports(profile).data, &[1; 8], 10).unwrap();
        assert_eq!(&owner.firmware.as_ref().unwrap().bytes()[..8], &[1; 8]);
        assert!(owner.write(ports(profile).data, &[2; 8], 10).is_err());
        assert!(
            !owner.loader.as_ref().unwrap().written[8..]
                .iter()
                .any(|written| *written)
        );
    }
    let bytes = image();
    let written = vec![true; bytes.len()];
    let parsed = Image::parse(&bytes, &written, 0x270).unwrap();
    for i in [0, HEADER, bytes.len() - 1] {
        let mut holes = written.clone();
        holes[i] = false;
        if i + 1 < bytes.len() {
            assert!(Image::parse(&bytes, &holes, 0x270).is_err());
        } else {
            // AP has no image-length port. A shorter contiguous span is
            // only structurally staged, never authenticated or executable.
            assert_eq!(
                Image::parse(&bytes, &holes, 0x270).unwrap().bytes,
                bytes.len() - 1
            );
        }
    }
    assert!(Image::parse(&bytes, &written, 0x271).is_err());
    for offset in [0, 8, 12, 0x30] {
        let mut corrupt = bytes.clone();
        corrupt[HEADER + offset..HEADER + offset + 4].fill(0xff);
        assert!(Image::parse(&corrupt, &written, 0x270).is_err());
    }
    let mut owner = pmu(FirmwareStartup::Maverick);
    prefix(&mut owner, FirmwareStartup::Maverick, 0x270, 0);
    seek(&mut owner, FirmwareStartup::Maverick, 16, 0);
    for window in bytes[16..].chunks(16) {
        for (i, data) in window.chunks(8).enumerate() {
            owner
                .write(
                    ports(FirmwareStartup::Maverick).data + i as u16 * 8,
                    data,
                    0,
                )
                .unwrap();
        }
    }
    assert!(owner.write(0xc828, &[4], 100).is_err());
    assert_eq!(owner.loader.as_ref().unwrap().phase, Phase::Uploading);
    assert!(owner.loader.as_ref().unwrap().image.is_none());
    owner.read(maverick().upcount, &mut [0; 6], 0).unwrap();
    assert_eq!(parsed.configuration, 0x180);
    assert_eq!(parsed.version, 0x1a0);
}

#[test]
fn real_master_keeps_native_loader_ownership_and_failed_start_payload() {
    use crate::platform::apple::spmi::Spmi;
    use alloc::{boxed::Box, rc::Rc};
    use core::cell::RefCell;
    use stela_contracts::bus::Access;
    use stela_contracts::bus::Lifecycle;
    use stela_contracts::bus::LifecycleState;
    use stela_contracts::bus::MmioDevice;
    use stela_contracts::bus::MmioError;
    use stela_contracts::bus::Width;
    use stela_contracts::interrupt::AicInput;
    use stela_contracts::interrupt::InterruptLatch;
    struct Owned(Rc<RefCell<Pmu>>);
    impl SpmiSlave for Owned {
        fn read(&mut self, address: u16, bytes: &mut [u8], now: u64) -> Result<(), SlaveError> {
            self.0.borrow_mut().read(address, bytes, now)
        }
        fn write(&mut self, address: u16, bytes: &[u8], now: u64) -> Result<(), SlaveError> {
            self.0.borrow_mut().write(address, bytes, now)
        }
    }
    let mut pmic = pmu(FirmwareStartup::Maverick);
    prefix(&mut pmic, FirmwareStartup::Maverick, 0x270, 0);
    upload(&mut pmic, FirmwareStartup::Maverick, &image(), 0);
    pmic.write(0xc828, &[4], 0).unwrap();
    let owner = Rc::new(RefCell::new(pmic));
    let mut master = Spmi::with_configuration(
        AicInput::new(0, 228),
        stela_soc_data::spmi::Configuration::new(
            stela_soc_data::spmi::Profile::Gen1,
            192,
            [256, 256],
        )
        .unwrap(),
    );
    master.attach(15, Box::new(Owned(owner.clone()))).unwrap();
    let live = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    let paused = LifecycleState {
        clocked: false,
        quiesced: true,
        ..live
    };
    let mut irqs = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut irqs);
    master.check_lifecycle(paused).unwrap();
    master.set_lifecycle(paused, &mut access);
    assert_eq!(owner.borrow().loader.as_ref().unwrap().phase, Phase::Sealed);
    assert!(
        master
            .check_lifecycle(LifecycleState {
                reset: true,
                ..live
            })
            .is_err()
    );
    master.check_lifecycle(live).unwrap();
    master.set_lifecycle(live, &mut access);
    // Complete source one-byte protection restoration through the
    // command FIFO; its effect precedes the master's completion response.
    let command = |address: u16| u64::from(u32::from(address) << 16 | 15 << 8 | 0x30);
    master
        .write(4, Width::Word, command(0x7000), &mut access)
        .unwrap();
    master.write(4, Width::Word, 0, &mut access).unwrap();
    assert_eq!(owner.borrow().loader.as_ref().unwrap().phase, Phase::Locked);
    assert_ne!(
        master.read(8, Width::Word, &mut access).unwrap() & (1 << 15),
        0
    );
    master.write(0x78, Width::Word, 1, &mut access).unwrap();
    master
        .write(4, Width::Word, command(0xc806), &mut access)
        .unwrap();
    for _ in 0..2 {
        assert!(matches!(
            master.write(4, Width::Word, 1, &mut access),
            Err(MmioError::Unsupported { .. })
        ));
        assert_eq!(owner.borrow().loader.as_ref().unwrap().phase, Phase::Locked);
        assert!(master.read(8, Width::Word, &mut access).is_err());
        assert_eq!(master.read(0x78, Width::Word, &mut access), Ok(0));
    }
    assert!(owner.borrow().loader.as_ref().unwrap().image.is_some());
    assert!(
        owner.borrow().loader.as_ref().unwrap().written[..image().len()]
            .iter()
            .all(|written| *written)
    );
}

fn epoch_pmu(epoch: PmicEpoch, rtc: bool) -> Pmu {
    let profile = FirmwareStartup::Maverick;
    Pmu::configured(
        Configuration::new(vec![], rtc.then(maverick), u8::from(rtc))
            .unwrap()
            .with_firmware_sram(ports(profile), vec![0xa5; 0x3000])
            .unwrap()
            .with_unqualified_firmware_startup(profile)
            .unwrap()
            .with_native_firmware_loader()
            .unwrap()
            .with_native_pmic_epoch(epoch)
            .unwrap(),
        None,
    )
    .unwrap()
}
fn native_time(pmu: &Pmu) -> (u64, u64, u64) {
    pmu.loader.as_ref().unwrap().clock.as_ref().unwrap().state()
}
#[test]
fn native_epoch_belongs_to_pmic_and_checks_all_time_before_control_or_rtc_effects() {
    let epoch = PmicEpoch {
        counter: 0,
        cycles: 7,
        hz: 32768,
    };
    assert!(
        Configuration::new(vec![], None, 0)
            .unwrap()
            .with_native_pmic_epoch(epoch)
            .is_err()
    );
    let mut owner = epoch_pmu(epoch, false);
    owner.write(0xc804, &[0], 1).unwrap();
    assert_eq!(native_time(&owner), (1, 7, 32768));
    let before = native_time(&owner);
    assert!(owner.write(0xc804, &[0], 0).is_err());
    assert!(owner.write(0xc804, &[0xff], 1000).is_err());
    assert_eq!(native_time(&owner), before);
    assert_eq!(owner.loader.as_ref().unwrap().phase, Phase::Stopped);
    owner.check_time(1000).unwrap();
    owner.advance(1000);
    assert_eq!(native_time(&owner), (1000, 8, 8_768_000));
    let mut overflow = epoch_pmu(
        PmicEpoch {
            counter: 0,
            cycles: u64::MAX,
            hz: crate::platform::apple::counter::FREQUENCY_HZ,
        },
        true,
    );
    assert!(overflow.write(0xc804, &[0], 1).is_err());
    assert_eq!(overflow.loader.as_ref().unwrap().phase, Phase::Created);
    assert_eq!(native_time(&overflow), (0, u64::MAX, 0));
    let mut actual = [0xff; 6];
    overflow.read(maverick().upcount, &mut actual, 0).unwrap();
    assert_eq!(actual, [0; 6]); // failed native time did not publish RTC
}
#[test]
fn paused_master_still_advances_the_same_native_pmic_clock_without_firmware_completion() {
    use crate::platform::apple::spmi::Spmi;
    use alloc::{boxed::Box, rc::Rc};
    use core::cell::RefCell;
    use stela_contracts::bus::Access;
    use stela_contracts::bus::Lifecycle;
    use stela_contracts::bus::LifecycleState;
    use stela_contracts::bus::MmioDevice;
    use stela_contracts::interrupt::AicInput;
    use stela_contracts::interrupt::InterruptLatch;
    struct Owned(Rc<RefCell<Pmu>>);
    impl SpmiSlave for Owned {
        fn read(&mut self, at: u16, bytes: &mut [u8], now: u64) -> Result<(), SlaveError> {
            self.0.borrow_mut().read(at, bytes, now)
        }
        fn write(&mut self, at: u16, bytes: &[u8], now: u64) -> Result<(), SlaveError> {
            self.0.borrow_mut().write(at, bytes, now)
        }
        fn check_time(&self, now: u64) -> Result<(), SlaveError> {
            self.0.borrow().check_time(now)
        }
        fn advance(&mut self, now: u64) -> Option<u64> {
            self.0.borrow_mut().advance(now)
        }
    }
    let owner = Rc::new(RefCell::new(epoch_pmu(
        PmicEpoch {
            counter: 0,
            cycles: 0,
            hz: 1_000_000,
        },
        false,
    )));
    owner.borrow_mut().write(0xc804, &[0], 0).unwrap();
    let mut master = Spmi::with_configuration(
        AicInput::new(0, 228),
        stela_soc_data::spmi::Configuration::new(
            stela_soc_data::spmi::Profile::Gen1,
            192,
            [256, 256],
        )
        .unwrap(),
    );
    master.attach(15, Box::new(Owned(owner.clone()))).unwrap();
    let paused = LifecycleState {
        powered: true,
        clocked: false,
        quiesced: true,
        reset: false,
        retention: true,
    };
    let mut irqs = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut irqs);
    master.check_lifecycle(paused).unwrap();
    master.set_lifecycle(paused, &mut access);
    access.now = 25;
    assert_eq!(master.advance(&mut access), Ok(None));
    assert_eq!(native_time(&owner.borrow()), (25, 1, 1_000_000));
    access.now = 24;
    assert!(master.advance(&mut access).is_err());
    assert_eq!(native_time(&owner.borrow()), (25, 1, 1_000_000));
    assert_eq!(
        owner.borrow().loader.as_ref().unwrap().phase,
        Phase::Stopped
    );
    assert!(owner.borrow().loader.as_ref().unwrap().image.is_none());
}
#[test]
fn native_start_preflights_current_time_and_deadline_without_admitting_missing_services() {
    for (epoch, now) in [
        (
            PmicEpoch {
                counter: 0,
                cycles: u64::MAX - 100,
                hz: 1,
            },
            0,
        ),
        (
            PmicEpoch {
                counter: u64::MAX,
                cycles: 0,
                hz: 1,
            },
            u64::MAX,
        ),
    ] {
        let profile = FirmwareStartup::Maverick;
        let mut owner = epoch_pmu(epoch, false);
        prefix(&mut owner, profile, 0x270, now);
        upload(&mut owner, profile, &image(), now);
        owner.write(0xc828, &[4], now).unwrap();
        owner.write(0x7000, &[0], now).unwrap();
        let before = native_time(&owner);
        assert!(
            matches!(owner.write(0xc806, &[1], now), Err(SlaveError::Unsupported(reason)) if reason.contains("deadline"))
        );
        assert_eq!(native_time(&owner), before);
        assert_eq!(owner.loader.as_ref().unwrap().phase, Phase::Locked);
    }
    let profile = FirmwareStartup::Maverick;
    let mut owner = epoch_pmu(
        PmicEpoch {
            counter: 0,
            cycles: 0,
            hz: 1_000_000,
        },
        false,
    );
    prefix(&mut owner, profile, 0x1df4, 0);
    upload(&mut owner, profile, &integrity::test_image(), 0);
    owner.write(0xc828, &[4], 0).unwrap();
    owner.write(0x7000, &[0], 0).unwrap();
    assert!(
        matches!(owner.write(0xc806, &[1], 100), Err(SlaveError::Unsupported(reason)) if reason.contains("service resource owners"))
    );
    assert_eq!(native_time(&owner), (0, 0, 0));
    assert_eq!(owner.loader.as_ref().unwrap().phase, Phase::Locked);
}

#[test]
fn source_tag_failure_refuses_before_clock_control_or_image_effects() {
    let profile = FirmwareStartup::Maverick;
    let mut owner = epoch_pmu(
        PmicEpoch {
            counter: 0,
            cycles: 0,
            hz: 1_000_000,
        },
        true,
    );
    let mut bytes = integrity::test_image();
    bytes[0x2000] ^= 1;
    prefix(&mut owner, profile, 0x1df4, 0);
    upload(&mut owner, profile, &bytes, 0);
    owner.write(0xc828, &[4], 0).unwrap();
    owner.write(0x7000, &[0], 0).unwrap();
    let digest = owner
        .loader
        .as_ref()
        .unwrap()
        .image
        .as_ref()
        .unwrap()
        .digest;
    assert!(
        matches!(owner.write(0xc806, &[1], 100), Err(SlaveError::Unsupported(reason)) if reason.contains("integrity tag mismatch"))
    );
    assert_eq!(native_time(&owner), (0, 0, 0));
    assert_eq!(owner.loader.as_ref().unwrap().phase, Phase::Locked);
    assert_eq!(
        owner
            .loader
            .as_ref()
            .unwrap()
            .image
            .as_ref()
            .unwrap()
            .digest,
        digest
    );
    assert_eq!(
        &owner.firmware.as_ref().unwrap().bytes()[..bytes.len()],
        &bytes
    );
    let mut rtc = [0xff; 6];
    owner.read(maverick().upcount, &mut rtc, 0).unwrap();
    assert_eq!(rtc, [0; 6]);
}

#[test]
#[ignore = "oracle: STELA_TEST_CRAM_J314S_LLB"]
fn original_images_and_exact_protected_sequences_replay_without_completion_credit() {
    let source = std::fs::read(std::env::var("STELA_TEST_CRAM_J314S_LLB").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&source),
        "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
    );
    for (profile, start, len, metadata, configuration, version) in [
        (
            FirmwareStartup::Maverick,
            0x1f9b20,
            0x2270,
            0x1df4u16,
            0x1d88,
            0x1da8,
        ),
        (
            FirmwareStartup::Monaco,
            0x1fbd90,
            0x2c78,
            0x2c70,
            0x2a10,
            0x2a30,
        ),
    ] {
        let bytes = &source[start..start + len];
        let mut owner = pmu(profile);
        prefix(&mut owner, profile, metadata, 0);
        upload(&mut owner, profile, bytes, 0);
        let loader = owner.loader.as_ref().unwrap();
        let image = Image::parse(
            owner.firmware.as_ref().unwrap().bytes(),
            &loader.written,
            metadata,
        )
        .unwrap();
        assert_eq!(image.bytes, len);
        assert_eq!(image.configuration, configuration);
        assert_eq!(image.version, version);
        assert_eq!(image.digest, <[u8; 32]>::from(Sha256::digest(bytes)));
        assert!(bytes[version..].starts_with(b"ApplePMUFirmware-743.0.4~2753.release"));
        if profile == FirmwareStartup::Maverick {
            owner.write(0xc828, &[4], 0).unwrap();
            owner.write(0x7000, &[0], 0).unwrap();
            assert!(owner.write(0xc806, &[1], 100).is_err());
            assert_eq!(owner.loader.as_ref().unwrap().phase, Phase::Locked);
        }
    }
}
