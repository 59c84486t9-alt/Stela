// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Actual selected MLD station config/config/TLC and no-queue flush/remove.
use super::*;
#[path = "ax200_mld_queue_tests.rs"]
mod queue_tests;

fn mld_image(version: u8) -> Vec<u8> {
    let mut bytes = feature(image(4, 1), 30, 110, true);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            bytes.splice(at + 8 + len..at + 8 + len, [0x0a, 3, version, 0]);
            bytes[at + 4..at + 8].copy_from_slice(&((len + 4) as u32).to_le_bytes());
            return bytes;
        }
        at += 8 + len.next_multiple_of(4);
    }
    panic!("command versions");
}
fn mld_bound<'a>(
    catalog: &'a resources::Catalog,
    empty: &'a resources::Catalog,
    source: &Source,
    native: &Native,
    policy: &Arc<PolicyState>,
    short: bool,
) -> Ax200Binding<'a, Model, ClockBios, ScanOs> {
    let (power, _, _) = powered(catalog, empty, source, native, policy, short);
    authorize(policy);
    // SAFETY: original finite response and actual provider/revocation model.
    let mut link = unsafe { power.begin_mld_link() }.unwrap_or_else(|_| panic!("MLD link"));
    unsafe { link.advance(source) }.unwrap();
    for command in link.commands().to_vec() {
        complete_mld_link(&link, native, &command);
        unsafe { link.advance(source) }.unwrap();
        link.replenish_completed_receive().unwrap();
    }
    assert_eq!(link.phase(), Ax200BindingPhase::AuthenticationRequired);
    link
}
fn complete_mld_link(
    link: &Ax200Binding<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    command: &BindingCommand,
) {
    let boot = boot(&link.power.phy.scan);
    let slot = boot.read;
    assert!(boot.credits > 0);
    let descriptor = device_read(
        &native.domain,
        boot.free.region().address,
        usize::from(slot) * 8,
        8,
    );
    let vid = (u64::from_le_bytes(descriptor.try_into().unwrap()) & 0xfff) as u16;
    assert!(vid > 0 && boot.buffers[usize::from(vid - 1)].device_owned);
    complete_from_free_slot(
        boot,
        &native.domain,
        slot,
        vid,
        slot,
        &command_packet(command.id().wire(), link.ticket().unwrap().sequence(), &[]),
    );
}
fn complete_mld_peer(
    peer: &Ax200LegacyPeer<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    command: &PeerCommand,
) {
    let slot = boot(&peer.binding.power.phy.scan).read;
    completion(
        peer,
        native,
        slot,
        command,
        if command.kind() == PeerCommandKind::Flush {
            &[0; 132]
        } else {
            &[]
        },
    );
}
fn exercise(bytes: &[u8]) {
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let link = mld_bound(&catalog, &empty, &source, &native, &policy, false);
    // SAFETY: actual same-device finite rates retained by genuine model leases.
    let mut peer =
        unsafe { link.begin_mld_peer(parameters()) }.unwrap_or_else(|_| panic!("MLD peer"));
    let sync_policy = policy.clone();
    native.domain.records.lock().unwrap().device_sync_hook = Some(Arc::new(move || {
        assert_eq!(sync_policy.held.load(Ordering::SeqCst), 1);
        assert_eq!(sync_policy.transmit_rates.load(Ordering::SeqCst), 0xfff);
    }));
    unsafe { peer.advance(&source) }.unwrap();
    native.domain.records.lock().unwrap().device_sync_hook = None;
    assert_eq!(
        peer.commands()
            .iter()
            .map(PeerCommand::kind)
            .collect::<Vec<_>>(),
        [
            PeerCommandKind::Add,
            PeerCommandKind::Configure,
            PeerCommandKind::Rates
        ]
    );
    assert_eq!(
        peer.commands()[0].id(),
        Id {
            group: 3,
            opcode: 0x0a,
            version: 0
        }
    );
    assert_eq!(peer.commands()[0].bytes(), peer.commands()[1].bytes());
    assert_eq!(peer.commands()[0].bytes().len(), 96);
    for (index, command) in peer.commands().to_vec().into_iter().enumerate() {
        assert_eq!(peer.station_id(), None);
        emitted(&peer, &native, &command);
        complete_mld_peer(&peer, &native, &command);
        if index == 1 {
            let mut records = native.domain.records.lock().unwrap();
            records.cpu_sync_fail = Some(records.cpu_syncs + 1);
            drop(records);
            assert!(matches!(
                unsafe { peer.advance(&source) },
                Err(Ax200LegacyPeerError::Boot(Error::CommandReclaim(_)))
            ));
            assert!(peer.first_error().is_none());
            assert_eq!(peer.station_id(), None);
            native.domain.records.lock().unwrap().cpu_sync_fail = None;
        }
        unsafe { peer.advance(&source) }.unwrap();
        peer.replenish_completed_receive().unwrap();
    }
    assert_eq!(peer.station_id(), Some(0));
    let acquired = policy.acquired.load(Ordering::SeqCst);
    native.revoked.store(true, Ordering::SeqCst);
    peer.begin_remove().unwrap();
    unsafe { peer.advance(&source) }.unwrap();
    let commands = peer.commands()[3..].to_vec();
    assert_eq!(
        commands.iter().map(PeerCommand::kind).collect::<Vec<_>>(),
        [PeerCommandKind::Flush, PeerCommandKind::Remove]
    );
    assert_eq!(
        commands[1].id(),
        Id {
            group: 3,
            opcode: 0x0c,
            version: 0
        }
    );
    for command in commands {
        peer = match peer.into_binding() {
            Err(owner) => *owner,
            Ok(_) => panic!("station escaped before remove"),
        };
        emitted(&peer, &native, &command);
        complete_mld_peer(&peer, &native, &command);
        unsafe { peer.advance(&source) }.unwrap();
        peer.replenish_completed_receive().unwrap();
    }
    assert_eq!(peer.phase(), Ax200LegacyPeerPhase::Removed);
    assert_eq!(policy.acquired.load(Ordering::SeqCst), acquired);
    let mut link = peer
        .into_binding()
        .unwrap_or_else(|_| panic!("same active link"));
    link.begin_remove().unwrap();
    unsafe { link.advance(&source) }.unwrap();
    for index in 3..link.commands().len() {
        let command = link.commands()[index].clone();
        complete_mld_link(&link, &native, &command);
        unsafe { link.advance(&source) }.unwrap();
        link.replenish_completed_receive().unwrap();
    }
    assert_eq!(link.phase(), Ax200BindingPhase::Unbound);
    link.stop().unwrap();
    drop(link);
    assert!(native.domain.records.lock().unwrap().live.is_empty());
}

mod cases;
