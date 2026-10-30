// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn ax210_ucode_external_pnvm_source_dma_doorbell_and_notification() {
    use crate::wifi::intel::platform::{Observation, Stage};
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let root = std::path::Path::new(&root);
    let bytes = std::fs::read(root.join(Family::Ax210.firmware_name())).unwrap();
    let pnvm = std::fs::read(root.join("iwlwifi-ty-a0-gf-a0.pnvm")).unwrap();
    let digest: [u8; 32] = Sha256::digest(&pnvm).into();
    assert_eq!(
        digest,
        [
            0x96, 0x97, 0xe3, 0x27, 0xf8, 0x17, 0x14, 0x54, 0xb3, 0xc1, 0x9b, 0x1e, 0xc9, 0x44,
            0x97, 0x53, 0xd5, 0xb9, 0x34, 0xd4, 0xe9, 0x17, 0x22, 0xf4, 0x69, 0x61, 0x68, 0x18,
            0xa6, 0xd4, 0x77, 0xb0
        ]
    );
    let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
    let (observation, step_catalog) = step_fixture();
    let request = ax210_profile().pnvm_request().unwrap();
    let provider = resources::Catalog::from_handoff(vec![resources::Resource {
        name: request.name,
        target: request.requirement().target,
        provenance: resources::Provenance {
            source: "linux-firmware",
            revision: "59f9fc2ef8d1e312d2a613d4e1ffad2ff31a0a01",
            member: "intel/iwlwifi/iwlwifi-ty-a0-gf-a0.pnvm",
            license: "LicenseRef-LICENCE.iwlwifi_firmware",
        },
        expected_length: pnvm.len(),
        expected_sha256: digest,
        bytes: pnvm,
    }])
    .unwrap();
    let observations = Observations {
        oem_pnvm: Observation::NotCaptured,
        reduced_power: Observation::from_error(Stage::Probe, (1 << 63) | 14, None),
        step: observation,
        ..Observations::default()
    };
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = ax210_state();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start_ax210(
        &catalog,
        crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
        &source,
        &domain,
        &state,
        &drops,
    );
    event(&state, 1);
    boot.poll().unwrap();
    let mut packet = rx_packet(1, 0xcafe, 0);
    set_sku(&mut packet, [0x610d0, 0, 0]);
    complete(&boot, &domain, 0, 1, &packet);
    boot.poll().unwrap().unwrap();
    assert_eq!(domain.records.lock().unwrap().live.len(), 65);
    assert_eq!(
        // SAFETY: The PNVM bytes are hash-verified against this model profile requirement;
        // the original boot Domain keeps them with exclusive Source RAM through completion.
        unsafe { boot.begin_pnvm(&provider, observations, &source) }.unwrap(),
        PnvmProgress::Waiting
    );
    assert_eq!(domain.records.lock().unwrap().live.len(), 68);
    let receipts = boot.platform_receipts().unwrap();
    assert_eq!(receipts.pnvm_version, Some(0xe1c4fa8e));
    assert!(matches!(
        receipts.pnvm,
        calibration::Source::External {
            bios_fallback: None,
            ..
        }
    ));
    let memory = boot.ax210.as_ref().unwrap();
    let field = device_read(&domain, memory.scratch.region().address, 16, 16);
    assert_eq!(u32::from_le_bytes(field[8..12].try_into().unwrap()), 13652);
    complete(&boot, &domain, 1, 2, &pnvm_packet(0));
    assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Observed);
    assert_eq!(domain.records.lock().unwrap().live.len(), 68);
    boot.stop().unwrap();
    drop(boot);
    assert!(domain.records.lock().unwrap().live.is_empty());
    assert_eq!(
        source.calls.load(Ordering::Relaxed),
        source.released.load(Ordering::Relaxed)
    );
}

#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn ax210_image_iml_rom_rx_alive_preserves_pnvm_allocations() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax210.firmware_name())).unwrap();
    let sha: alloc::string::String = Sha256::digest(&bytes)
        .iter()
        .map(|b| alloc::format!("{b:02x}"))
        .collect();
    assert_eq!(
        sha,
        "792478ef7752595525379a5068e2d47e310a2c344636b7df866c54746ced1dc0"
    );
    let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
    let (observation, step_catalog) = step_fixture();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = ax210_state();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start_ax210(
        &catalog,
        crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
        &source,
        &domain,
        &state,
        &drops,
    );
    assert_eq!(domain.records.lock().unwrap().live.len(), 97);
    let expected = boot.firmware.iml().unwrap();
    let memory = boot.ax210.as_ref().unwrap();
    assert_eq!(
        device_read(&domain, memory.iml.region().address, 0, expected.len()),
        expected
    );
    event(&state, 1);
    boot.poll().unwrap();
    complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
    let report = boot.poll().unwrap().unwrap();
    assert_eq!(report.notification_version, 6);
    assert_eq!(domain.records.lock().unwrap().live.len(), 65); // 31 transient + IML
    let memory = boot.ax210.as_ref().unwrap();
    for address in [
        memory.info.region().address,
        memory.scratch.region().address,
        boot.context.region().address,
    ] {
        assert!(
            domain
                .records
                .lock()
                .unwrap()
                .live
                .contains_key(&id(address))
        );
    }
    boot.stop().unwrap();
    assert!(domain.records.lock().unwrap().live.is_empty());
    drop(boot);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(
        source.calls.load(Ordering::Relaxed),
        source.released.load(Ordering::Relaxed)
    );
}

#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn ax200_image_publishes_owned_context_and_consumes_completed_alive() {
    use sha2::{Digest, Sha256};
    let directory = std::env::var("STELA_IWLWIFI_IMAGES").expect("image directory");
    let bytes = std::fs::read(std::path::Path::new(&directory).join(Family::Ax200.firmware_name()))
        .unwrap();
    let sha: alloc::string::String = Sha256::digest(&bytes)
        .iter()
        .map(|b| alloc::format!("{b:02x}"))
        .collect();
    assert_eq!(
        sha,
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
    );
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start(&catalog, &source, &domain, &state, &drops);
    let live = domain.records.lock().unwrap().live.len();
    assert_eq!(live, 86);
    event(&state, 1);
    assert!(boot.poll().unwrap().is_none());
    complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
    assert_eq!(
        boot.poll().unwrap().unwrap().sku,
        [0x610d0, 0x1234, 0x55667788]
    );
    assert_eq!(domain.records.lock().unwrap().live.len(), live - 30);
    boot.stop().unwrap();
    assert!(domain.records.lock().unwrap().live.is_empty());
    drop(boot);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(
        source.calls.load(Ordering::Relaxed),
        source.released.load(Ordering::Relaxed)
    );
}
