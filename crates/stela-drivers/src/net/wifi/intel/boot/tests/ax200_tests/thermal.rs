// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
use super::*;

#[test]
fn thermal_power_use_original_ax200_epoch_and_reclaimed_completions() {
    exercise_setup(false);
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn actual_ax200_thermal_power_versions_and_capability_branches() {
    exercise_setup(true);
}
fn exercise_setup(actual: bool) {
    let bytes = if actual {
        use sha2::{Digest, Sha256};
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        let bytes =
            std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
        );
        bytes
    } else {
        setup_bytes()
    };
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let bios_drops = Arc::new(AtomicUsize::new(0));
    let boot = start(&catalog, &source, &domain, &state, &drops);
    let boot = command_ready(boot, &empty, &source, &domain, &state);
    let init = drive_nvm(boot, &source, &domain, &state);
    let (lari, sequence, entry) = finish_lari(init, &source, &domain, &bios_drops, None);
    let before = state.lock().unwrap().ops.len();
    let lari = *unsafe {
        lari.begin_ax200_setup(Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 0,
        }))
    }
    .err()
    .unwrap();
    assert_eq!(state.lock().unwrap().ops.len(), before);
    assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
    let mut setup = unsafe {
        lari.begin_ax200_setup(Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        }))
    }
    .unwrap_or_else(|_| panic!("AX200 source continuation"));
    assert_eq!(
        unsafe { setup.advance(&source) }.unwrap(),
        Ax200SetupPhase::Waiting(Kind::TemperatureThresholds)
    );
    let decisions = setup.decisions().unwrap();
    assert_eq!(decisions.receive_queues, 1);
    assert!(decisions.firmware_auxiliary_station && decisions.firmware_ltr);
    assert!(!decisions.dqa_command);
    assert!(!setup.thermal_command_acknowledged());
    for (index, (id, payload)) in [
        (
            crate::net::wifi::intel::command::Id {
                group: 4,
                opcode: 4,
                version: 0,
            },
            vec![0; 20],
        ),
        (
            crate::net::wifi::intel::command::Id {
                group: 0,
                opcode: 0x77,
                version: 0,
            },
            vec![0, 0x10, 0, 0],
        ),
    ]
    .iter()
    .enumerate()
    {
        let sequence = sequence + index as u16;
        let descriptor = device_read(
            &domain,
            setup.lari.radio.initialized.boot.command.region().address,
            usize::from(sequence & 31) * 256,
            256,
        );
        let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
        let encoded =
            crate::net::wifi::intel::command::Command::encode(*id, 0, sequence, payload).unwrap();
        let mut emitted = device_read(&domain, first, 0, encoded.bytes().len().min(20));
        if encoded.bytes().len() > 20 {
            let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
            emitted.extend(device_read(&domain, rest, 0, encoded.bytes().len() - 20));
        }
        assert_eq!(emitted, encoded.bytes());
        let bell = state.lock().unwrap().registers[&0x460];
        unsafe { setup.advance(&source) }.unwrap();
        assert_eq!(state.lock().unwrap().registers[&0x460], bell);
        let mut response_id = *id;
        if response_id.group == 0 {
            response_id.group = 1;
        }
        complete(
            &setup.lari.radio.initialized.boot,
            &domain,
            entry + index as u16,
            entry + index as u16 + 1,
            &command_packet(response_id, sequence, &[]),
        );
        let mut r = domain.records.lock().unwrap();
        r.cpu_sync_fail = Some(r.cpu_syncs + 1);
        drop(r);
        assert!(matches!(
            unsafe { setup.advance(&source) },
            Err(Ax200SetupError::Boot(Error::CommandReclaim(_)))
        ));
        assert!(setup.first_error().is_none());
        assert_eq!(state.lock().unwrap().registers[&0x460], bell);
        domain.records.lock().unwrap().cpu_sync_fail = None;
        assert_eq!(
            unsafe { setup.advance(&source) }.unwrap(),
            if index == 0 {
                Ax200SetupPhase::Waiting(Kind::DevicePower)
            } else {
                Ax200SetupPhase::RegulatoryRequired
            }
        );
        assert!(setup.thermal_command_acknowledged());
    }
    assert_eq!(setup.responses().len(), 2);
    assert!(matches!(
        setup.platform_reads().last(),
        Some(crate::net::wifi::intel::radio::bios::service::Read::Uefi(
            crate::net::wifi::intel::platform::Variable::Eckv,
            Ok(_)
        ))
    ));
    // Completed setup must still surface a new real device failure.
    state.lock().unwrap().registers.insert(8, 1 << 29);
    assert!(matches!(
        unsafe { setup.advance(&source) },
        Err(Ax200SetupError::Boot(Error::DeviceError(_)))
    ));
    let first = setup.first_error().cloned();
    assert_eq!(unsafe { setup.advance(&source) }.err(), first);
    setup.stop().unwrap();
    drop(setup);
    assert!(domain.records.lock().unwrap().live.is_empty());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
}
