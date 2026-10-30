// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn unified_real_commands_wait_for_init_notification_and_nvm_with_rfkill() {
    exercise_unified_nvm(false);
}

#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn unified_images_drive_real_command_and_notification_epoch() {
    exercise_unified_nvm(true);
}

#[test]
fn unified_wrong_response_and_bad_nvm_never_report_initialization() {
    use crate::wifi::intel::nvm::Request;
    for failure in 0..3 {
        let bytes = unified_bytes(false);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let boot = command_ready(boot, &empty, &source, &domain, &state);
        let mut init = boot.initialize_on_device_nvm();
        // SAFETY: The kept model epoch/domain own all DMA allocations, and Source
        // supplies exclusive RAM for the first initialization publication.
        unsafe { init.advance(&source) }.unwrap();
        let id = if failure == 0 {
            crate::wifi::intel::command::Id {
                group: 0,
                opcode: 2,
                version: 0,
            }
        } else {
            Request::ExtendedConfiguration.id()
        };
        complete(&init.boot, &domain, 1, 2, &command_packet(id, 0, &[]));
        if failure == 0 {
            assert!(matches!(
                // SAFETY: The wrong response is a synchronous model completion in that same
                // domain; Source and every pending mapping remain owned while refusing it.
                unsafe { init.advance(&source) },
                Err(Error::InitializationResponse {
                    command: 2,
                    group: 0
                })
            ));
        } else {
            // SAFETY: The extended-configuration ACK is complete in kept model RAM;
            // the original requester/domain and exclusive Source remain live.
            unsafe { init.advance(&source) }.unwrap();
            let mut packet = command_packet(Request::AccessComplete.id(), 1, &[]);
            let actual = crate::wifi::intel::command::Id {
                group: 0,
                opcode: 4,
                version: 0,
            };
            let notification = command_packet(actual, 0x8000, &[]);
            packet[64..128].copy_from_slice(&notification[..64]);
            packet[128..132].copy_from_slice(&0x55550000u32.to_le_bytes());
            complete(&init.boot, &domain, 2, 3, &packet);
            // SAFETY: The combined ACK/notification bytes were published synchronously;
            // the same initializer/domain keep their receive and command mappings.
            unsafe { init.advance(&source) }.unwrap();
            // SAFETY: The prior completion remains in that owned model epoch while the
            // initializer advances stages; Source has no competing device or worker.
            unsafe { init.advance(&source) }.unwrap();
            let bytes = if failure == 1 {
                vec![0; 467]
            } else {
                nvm_response()
            };
            complete(
                &init.boot,
                &domain,
                3,
                4,
                &command_packet(Request::GetInformation.id(), 2, &bytes),
            );
            assert!(matches!(
                // SAFETY: The malformed or rejected NVM response is synchronously completed
                // model data; the original owner/source keep its backing during refusal.
                unsafe { init.advance(&source) },
                Err(Error::Nvm(_))
            ));
        }
        assert_eq!(init.phase(), InitializationPhase::Failed);
        assert!(init.receipt().is_none());
        assert!(matches!(
            // SAFETY: The failed initializer still owns its source/domain and pending RAM;
            // this state-error reentry cannot acquire a new or unrelated DMA user.
            unsafe { init.advance(&source) },
            Err(Error::State)
        ));
        init.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
}

#[test]
fn unified_keeps_init_notification_across_alive_and_pnvm_buffers() {
    use crate::wifi::intel::nvm::Request;
    let bytes = unified_bytes(false);
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let sku = [1, 2, 3];
    let (observations, platform) = phase_catalog(&profile(), sku, true, true);
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start(&catalog, &source, &domain, &state, &drops);
    event(&state, 1);
    boot.poll().unwrap();
    let actual = crate::wifi::intel::command::Id {
        group: 0,
        opcode: 4,
        version: 0,
    };
    let mut alive = rx_packet(1, 0xcafe, 0);
    set_sku(&mut alive, sku);
    let early = command_packet(actual, 0x8000, &[0x11]);
    alive[192..256].copy_from_slice(&early[..64]);
    alive[256..260].copy_from_slice(&0x55550000u32.to_le_bytes());
    complete(&boot, &domain, 0, 1, &alive);
    boot.poll().unwrap().unwrap();
    // SAFETY: phase_catalog belongs to this model profile/SKU; Source
    // provides exclusive RAM within the same original requester/domain.
    unsafe { boot.begin_pnvm(&platform, observations, &source) }.unwrap();
    let mut pnvm = pnvm_packet(0x42);
    let side = command_packet(
        crate::wifi::intel::command::Id {
            group: 2,
            opcode: 0x55,
            version: 0,
        },
        0x8000,
        &[0x22],
    );
    pnvm[64..128].copy_from_slice(&side[..64]);
    pnvm[128..132].copy_from_slice(&0x55550000u32.to_le_bytes());
    complete(&boot, &domain, 1, 2, &pnvm);
    assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Observed);
    state
        .lock()
        .unwrap()
        .registers
        .extend([(0x388, 0x02123456), (0x38c, 0x789a)]);
    let mut init = boot.initialize_on_device_nvm();
    // SAFETY: PNVM observation kept this original model epoch and its mappings;
    // Source remains exclusive while the initializer stages its first command.
    unsafe { init.advance(&source) }.unwrap();
    complete(
        &init.boot,
        &domain,
        2,
        3,
        &command_packet(Request::ExtendedConfiguration.id(), 0, &[]),
    );
    // SAFETY: The extended-configuration ACK completed synchronously; its live
    // mapping and the original Source/domain remain owned through reclaim.
    unsafe { init.advance(&source) }.unwrap();
    complete(
        &init.boot,
        &domain,
        3,
        4,
        &command_packet(Request::AccessComplete.id(), 1, &[]),
    );
    // SAFETY: The access-complete ACK completed in that same model domain;
    // the initializer keeps the original source and receive mapping alive.
    unsafe { init.advance(&source) }.unwrap();
    assert_eq!(
        // SAFETY: The early init notification is held by this model owner;
        // Source and the pending DMA buffers have no concurrent device access.
        unsafe { init.advance(&source) }.unwrap(),
        InitializationProgress::Pending(InitializationPhase::NvmInformation)
    );
    complete(
        &init.boot,
        &domain,
        4,
        5,
        &command_packet(Request::GetInformation.id(), 2, &nvm_response()),
    );
    assert_eq!(
        // SAFETY: The NVM response was completed synchronously and its source/domain
        // remain held until observation and pending notifications are extracted.
        unsafe { init.advance(&source) }.unwrap(),
        InitializationProgress::Observed
    );
    assert_eq!(init.receipt().unwrap().init_complete.raw, [0x11]);
    let (mut boot, _) = match init.into_parts() {
        Ok(parts) => parts,
        Err(_) => panic!("missing observation"),
    };
    assert_eq!(boot.take_firmware_notification().unwrap().raw, [0x22]);
    assert!(boot.take_firmware_notification().is_none());
    boot.stop().unwrap();
    assert!(domain.records.lock().unwrap().live.is_empty());
}
