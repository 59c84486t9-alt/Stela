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
#[test]
fn mld_peer_requires_both_cfg_and_tlc_ack_reclaim_before_identity_and_flush_remove_before_parent() {
    exercise(&mld_image(1));
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
#[test]
fn unsupported_mld_station_body_and_missing_rate_refuse_before_first_station_effect() {
    for version in [1, 3] {
        let bytes = mld_image(version);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let link = mld_bound(&catalog, &empty, &source, &native, &policy, false);
        if version == 1 {
            policy
                .deny_rate
                .store(LegacyRate::Ofdm54 as usize + 1, Ordering::SeqCst);
        }
        // SAFETY: private same-provider model; missing envelope is denied.
        let mut peer =
            unsafe { link.begin_mld_peer(parameters()) }.unwrap_or_else(|_| panic!("MLD peer"));
        let calls = source.calls.load(Ordering::Relaxed);
        let ops = native.state.lock().unwrap().ops.len();
        let causes = native
            .state
            .lock()
            .unwrap()
            .registers
            .get(&8)
            .copied()
            .unwrap_or(0);
        let syncs = native.domain.records.lock().unwrap().syncs;
        let result = unsafe { peer.advance(&source) };
        if version == 3 {
            assert_eq!(
                result,
                Err(Ax200LegacyPeerError::Version {
                    group: 3,
                    command: 0x0a,
                    version: 3
                })
            );
        } else {
            assert_eq!(
                result,
                Err(Ax200LegacyPeerError::Binding(
                    Ax200BindingError::Regulatory(regulatory::Error::OsDenied)
                ))
            );
        }
        assert!(peer.ticket().is_none());
        assert_eq!(source.calls.load(Ordering::Relaxed), calls);
        let state = native.state.lock().unwrap();
        let expected_rx = [
            Op::Read(8),
            Op::Write(8, causes | !(1 | (1 << 31))),
            Op::Read(0x24),
        ];
        assert_eq!(
            &state.ops[ops..],
            if version == 3 {
                &[][..]
            } else {
                &expected_rx[..]
            }
        );
        drop(state);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        peer.stop().unwrap();
    }
}
#[test]
fn mld_partial_cfg_tlc_flush_or_remove_missing_ack_retains_original_link_and_failed_stop_dma() {
    for target in [1, 2, 3, 4] {
        let bytes = mld_image(2);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let link = mld_bound(&catalog, &empty, &source, &native, &policy, true);
        // SAFETY: retained genuine provider and explicit bounded-rate model.
        let mut peer =
            unsafe { link.begin_mld_peer(parameters()) }.unwrap_or_else(|_| panic!("MLD peer"));
        unsafe { peer.advance(&source) }.unwrap();
        for index in 0..target {
            let command = peer.commands()[index].clone();
            complete_mld_peer(&peer, &native, &command);
            unsafe { peer.advance(&source) }.unwrap();
            peer.replenish_completed_receive().unwrap();
            if index == 2 {
                peer.begin_remove().unwrap();
                unsafe { peer.advance(&source) }.unwrap();
            }
        }
        let kind = peer.commands()[target].kind();
        Clock {
            ticks_per_microsecond: 1,
        }
        .delay(20);
        let error = Ax200LegacyPeerError::Deadline(kind);
        assert_eq!(unsafe { peer.advance(&source) }, Err(error.clone()));
        assert_eq!(peer.first_error(), Some(&error));
        peer = match peer.into_binding() {
            Err(owner) => *owner,
            Ok(_) => panic!("partial station released link"),
        };
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        assert_eq!(unsafe { peer.advance(&source) }, Err(error.clone()));
        assert_eq!(peer.replenish_completed_receive(), Err(error));
        assert_eq!(native.state.lock().unwrap().ops.len(), ops);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        if target == 4 {
            native.state.lock().unwrap().fail = Some(ops + 1);
            assert!(peer.stop().is_err());
            let live = native.domain.records.lock().unwrap().live.len();
            drop(peer);
            assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
        } else {
            peer.stop().unwrap();
        }
    }
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn actual_ax200_mld_station_default_v1_and_tlc4_require_selected_owner_ack_lifetime() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
    );
    let firmware = crate::net::wifi::intel::firmware::Firmware::parse(&bytes).unwrap();
    assert!(firmware.supports_capability(110));
    assert!(firmware.command_version(3, 0x0a).is_none());
    assert_eq!(
        firmware.command_version(5, 0x0f).unwrap().command_version,
        4
    );
    exercise(&bytes);
}
