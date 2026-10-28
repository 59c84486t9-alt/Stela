// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Actual cold MLD MAC0+inactive link0, source command order and lifetime.
use super::*;
fn image(mac_version: u8, link_version: Option<u8>) -> Vec<u8> {
    let mut bytes = firmware_bytes(0);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            let mut versions = vec![8, 3, mac_version, 0];
            if let Some(version) = link_version {
                versions.extend([9, 3, version, 0]);
            }
            bytes.splice(at + 8 + len..at + 8 + len, versions.iter().copied());
            bytes[at + 4..at + 8].copy_from_slice(&((len + versions.len()) as u32).to_le_bytes());
            break;
        }
        at += 8 + len.next_multiple_of(4);
    }
    bytes.extend(30u32.to_le_bytes());
    bytes.extend(8u32.to_le_bytes());
    bytes.extend(3u32.to_le_bytes());
    bytes.extend((1u32 << 14).to_le_bytes());
    bytes
}
fn boot<'b, 'a>(mac: &'b Ax200Mac<'a, Model, ClockBios, Os>) -> &'b Ax200Boot<'a, Model> {
    &mac.country.board.scan.mcc.setup.lari.radio.initialized.boot
}
fn complete_mld(mac: &Ax200Mac<'_, Model, ClockBios, Os>, native: &Native, command: &MacCommand) {
    let boot = boot(mac);
    let slot = boot.read;
    assert!(boot.credits > 0);
    let raw = device_read(
        &native.domain,
        boot.free.region().address,
        usize::from(slot) * 8,
        8,
    );
    let vid = (u64::from_le_bytes(raw.try_into().unwrap()) & 0xfff) as u16;
    assert!(vid > 0 && boot.buffers[usize::from(vid - 1)].device_owned);
    complete_from_free_slot(
        boot,
        &native.domain,
        slot,
        vid,
        slot,
        &command_packet(command.id().wire(), mac.ticket().unwrap().sequence(), &[]),
    );
}
fn emitted(mac: &Ax200Mac<'_, Model, ClockBios, Os>, native: &Native, command: &MacCommand) {
    use crate::net::wifi::intel::command::Command;
    let sequence = mac.ticket().unwrap().sequence();
    let encoded = Command::encode(command.id(), 0, sequence, command.bytes()).unwrap();
    let descriptor = device_read(
        &native.domain,
        boot(mac).command.region().address,
        usize::from(sequence & 31) * 256,
        256,
    );
    assert_eq!(u16::from_le_bytes(descriptor[..2].try_into().unwrap()), 2);
    let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
    let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
    let mut raw = device_read(&native.domain, first, 0, encoded.first_tb().len());
    raw.extend(device_read(
        &native.domain,
        rest,
        0,
        encoded.remainder().len(),
    ));
    assert_eq!(raw, encoded.bytes());
}
#[test]
fn mld_mac_and_inactive_link_require_source_order_actual_ack_reclaim_and_control_remove() {
    for (mac, link) in [(1, None), (2, Some(1)), (3, Some(8))] {
        exercise(&image(mac, link));
    }
}
fn exercise(bytes: &[u8]) {
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let (country, _, _) = country_ready(
        &catalog,
        &empty,
        &source,
        &native,
        Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        }),
    );
    let address = country.initialized_nvm().address.bytes;
    let mut mac = country
        .begin_mld_mac_context()
        .unwrap_or_else(|_| panic!("MLD MAC"));
    assert!(mac.is_mld());
    assert!(mac.mac_id_and_color().is_none());
    assert!(mac.inactive_link_id().is_none());
    mac.replenish_completed_receive().unwrap();
    unsafe { mac.advance(&source) }.unwrap();
    let commands = mac.commands().to_vec();
    assert_eq!(
        commands.iter().map(MacCommand::kind).collect::<Vec<_>>(),
        [
            MacCommandKind::Add,
            MacCommandKind::DisableBeaconFilter,
            MacCommandKind::AddInactiveLink,
            MacCommandKind::Power
        ]
    );
    assert_eq!(
        commands[0].id(),
        crate::net::wifi::intel::command::Id {
            group: 3,
            opcode: 8,
            version: 0
        }
    );
    assert_eq!(commands[0].bytes().len(), 52);
    assert_eq!(&commands[0].bytes()[12..18], &address);
    assert_eq!(&commands[0].bytes()[20..24], &12u32.to_le_bytes());
    assert_eq!(&commands[0].bytes()[32..36], &1u32.to_le_bytes());
    assert_eq!(
        commands[2].id(),
        crate::net::wifi::intel::command::Id {
            group: 3,
            opcode: 9,
            version: 0
        }
    );
    assert_eq!(commands[2].bytes().len(), 208);
    assert_eq!(&commands[2].bytes()[12..16], &[255; 4]);
    assert_eq!(&commands[2].bytes()[16..22], &address);
    assert!(commands[2].bytes()[22..].iter().all(|byte| *byte == 0));
    for command in commands {
        emitted(&mac, &native, &command);
        complete_mld(&mac, &native, &command);
        let mut records = native.domain.records.lock().unwrap();
        records.cpu_sync_fail = Some(records.cpu_syncs + 1);
        drop(records);
        assert!(matches!(
            unsafe { mac.advance(&source) },
            Err(Ax200MacError::Boot(Error::CommandReclaim(_)))
        ));
        assert!(mac.first_error().is_none());
        native.domain.records.lock().unwrap().cpu_sync_fail = None;
        unsafe { mac.advance(&source) }.unwrap();
        mac.replenish_completed_receive().unwrap();
    }
    assert_eq!(mac.phase(), Ax200MacPhase::ScanRequired);
    assert_eq!(mac.mac_id_and_color(), Some(0));
    assert_eq!(mac.inactive_link_id(), Some(0));
    native.revoked.store(true, Ordering::SeqCst);
    mac.begin_remove().unwrap();
    unsafe { mac.advance(&source) }.unwrap();
    let commands = mac.commands()[4..].to_vec();
    assert_eq!(
        commands.iter().map(MacCommand::kind).collect::<Vec<_>>(),
        [
            MacCommandKind::Power,
            MacCommandKind::RemoveInactiveLink,
            MacCommandKind::Remove
        ]
    );
    for command in commands {
        emitted(&mac, &native, &command);
        complete_mld(&mac, &native, &command);
        unsafe { mac.advance(&source) }.unwrap();
        mac.replenish_completed_receive().unwrap();
    }
    assert_eq!(mac.phase(), Ax200MacPhase::Removed);
    assert!(mac.mac_id_and_color().is_none());
    assert!(mac.inactive_link_id().is_none());
    mac.stop().unwrap();
    drop(mac);
    assert!(native.domain.records.lock().unwrap().live.is_empty());
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn actual_ax200_mld_mac1_and_default_link1_drive_selected_original_owner() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
    );
    let fw = crate::net::wifi::intel::firmware::Firmware::parse(&bytes).unwrap();
    assert!(fw.supports_capability(110));
    assert_eq!(fw.command_version(3, 8).unwrap().command_version, 1);
    assert!(fw.command_version(3, 9).is_none());
    exercise(&bytes);
}
#[test]
fn mld_unknown_mac_or_link_and_partial_link_effects_preserve_original_owner() {
    for case in 0..3 {
        let bytes = image(
            if case == 0 { 4 } else { 1 },
            Some(if case == 1 { 9 } else { 1 }),
        );
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let (country, _, _) = country_ready(
            &catalog,
            &empty,
            &source,
            &native,
            Ax200SetupOptions::new(Clock {
                ticks_per_microsecond: 1_000_000,
            }),
        );
        let mut mac = country
            .begin_mld_mac_context()
            .unwrap_or_else(|_| panic!("MLD MAC"));
        let calls = source.calls.load(Ordering::Relaxed);
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        if case < 2 {
            assert!(matches!(
                unsafe { mac.advance(&source) },
                Err(Ax200MacError::Version { .. })
            ));
            assert_eq!(source.calls.load(Ordering::Relaxed), calls);
            assert_eq!(native.state.lock().unwrap().ops.len(), ops);
            assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        } else {
            mac.replenish_completed_receive().unwrap();
            unsafe { mac.advance(&source) }.unwrap();
            for index in 0..2 {
                let command = mac.commands()[index].clone();
                complete_mld(&mac, &native, &command);
                if index == 1 {
                    let mut r = native.domain.records.lock().unwrap();
                    r.sync_fail = Some(r.syncs + 2);
                }
                let result = unsafe { mac.advance(&source) };
                if index == 0 {
                    result.unwrap();
                } else {
                    assert!(result.is_err());
                }
            }
            assert_eq!(mac.mac_id_and_color(), Some(0));
            assert!(mac.inactive_link_id().is_none());
        }
        let error = mac.first_error().unwrap().clone();
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        assert_eq!(unsafe { mac.advance(&source) }, Err(error.clone()));
        assert_eq!(
            mac.replenish_completed_receive(),
            Err(match error {
                Ax200MacError::Boot(error) => error,
                _ => Error::State,
            })
        );
        assert_eq!(native.state.lock().unwrap().ops.len(), ops);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        if case == 2 {
            native.state.lock().unwrap().fail = Some(ops + 1);
            assert!(mac.stop().is_err());
            let live = native.domain.records.lock().unwrap().live.len();
            drop(mac);
            assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
        } else {
            mac.stop().unwrap();
        }
    }
}
#[test]
fn mld_receive_rearm_visibility_failure_latches_cause_and_quarantines_failed_stop() {
    let bytes = image(1, None);
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let (country, _, _) = country_ready(
        &catalog,
        &empty,
        &source,
        &native,
        Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        }),
    );
    let mut mac = country
        .begin_mld_mac_context()
        .unwrap_or_else(|_| panic!("MLD MAC"));
    let mut records = native.domain.records.lock().unwrap();
    records.sync_fail = Some(records.syncs + 1);
    drop(records);
    let error = mac.replenish_completed_receive().unwrap_err();
    assert_eq!(mac.first_error(), Some(&Ax200MacError::Boot(error.clone())));
    assert_eq!(mac.phase(), Ax200MacPhase::Failed);
    let operations = native.state.lock().unwrap().ops.len();
    let syncs = native.domain.records.lock().unwrap().syncs;
    assert_eq!(
        unsafe { mac.advance(&source) },
        Err(Ax200MacError::Boot(error.clone()))
    );
    assert_eq!(mac.replenish_completed_receive(), Err(error));
    assert_eq!(native.state.lock().unwrap().ops.len(), operations);
    assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
    native.state.lock().unwrap().fail = Some(operations + 1);
    assert!(mac.stop().is_err());
    let live = native.domain.records.lock().unwrap().live.len();
    drop(mac);
    assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
    assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
}
