// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Cold MLD MAC0+inactive link0, source command order and lifetime.
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
    // SAFETY: Source allocates exclusive model RAM for this same kept
    // requester/domain; Native keeps the policy owner and no real device runs.
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
            // SAFETY: this synchronous ACK keeps the command/receive maps;
            // injected CPU-sync failure cannot release or race those allocations.
            unsafe { mac.advance(&source) },
            Err(Ax200MacError::Boot(Error::CommandReclaim(_)))
        ));
        assert!(mac.first_error().is_none());
        native.domain.records.lock().unwrap().cpu_sync_fail = None;
        // SAFETY: failed reclamation kept the same source/domain mappings live;
        // clearing its injection adds no DMA user before this retry.
        unsafe { mac.advance(&source) }.unwrap();
        mac.replenish_completed_receive().unwrap();
    }
    assert_eq!(mac.phase(), Ax200MacPhase::ScanRequired);
    assert_eq!(mac.mac_id_and_color(), Some(0));
    assert_eq!(mac.inactive_link_id(), Some(0));
    native.revoked.store(true, Ordering::SeqCst);
    mac.begin_remove().unwrap();
    // SAFETY: revocation starts ordered removal while the same model MAC owner
    // keeps Source and every pending mapping, without asynchronous hardware.
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
        // SAFETY: this removal ACK completed synchronously; its original MAC
        // and domain keep the receive/command mappings until reclaim finishes.
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

#[path = "ax200_mld_mac_tests/cases.rs"]
mod cases;
