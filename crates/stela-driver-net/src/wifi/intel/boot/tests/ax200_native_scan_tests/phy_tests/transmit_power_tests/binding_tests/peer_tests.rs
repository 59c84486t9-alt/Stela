// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Original station0/TLC and no-queue drain/flush/remove lifetime.
use super::*;
use crate::Mac;
mod mld_tests;
fn image(tlc: u8, flush: u8) -> Vec<u8> {
    let mut bytes = binding_bytes(true);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            bytes.splice(
                at + 8 + len..at + 8 + len,
                [
                    0x18, 1, 12, 2, 0x19, 1, 2, 0, 0x1e, 1, 2, flush, 0x0f, 5, tlc, 0,
                ],
            );
            bytes[at + 4..at + 8].copy_from_slice(&((len + 16) as u32).to_le_bytes());
        }
        if kind == 30 && len == 8 && bytes[at + 8..at + 12] == 1u32.to_le_bytes() {
            let mut word = u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap());
            word |= 1 << 11; // source TLC_OFFLOAD43
            bytes[at + 12..at + 16].copy_from_slice(&word.to_le_bytes());
        }
        at += 8 + if kind == 48 { len + 16 } else { len }.next_multiple_of(4);
    }
    feature(bytes, 30, 68, true)
}
fn feature(mut bytes: Vec<u8>, kind: u32, bit: u32, enabled: bool) -> Vec<u8> {
    let mut at = 88;
    let mut found = false;
    while at < bytes.len() {
        let k = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if k == kind && len == 8 && bytes[at + 8..at + 12] == (bit / 32).to_le_bytes() {
            let mut word = u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap());
            word = (word & !(1 << (bit % 32))) | (u32::from(enabled) << (bit % 32));
            bytes[at + 12..at + 16].copy_from_slice(&word.to_le_bytes());
            found = true;
        }
        at += 8 + len.next_multiple_of(4);
    }
    if !found {
        bytes.extend(kind.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend((bit / 32).to_le_bytes());
        bytes.extend((u32::from(enabled) << (bit % 32)).to_le_bytes());
    }
    bytes
}
fn parameters() -> LegacyPeer {
    LegacyPeer {
        address: Mac([2, 3, 4, 5, 6, 7]),
        link: Mac([2, 3, 4, 5, 6, 7]),
        beacon_interval_tu: 100,
        rates: 0xfff,
    }
}
fn bound<'a>(
    catalog: &'a resources::Catalog,
    empty: &'a resources::Catalog,
    source: &Source,
    native: &Native,
    policy: &Arc<PolicyState>,
    short: bool,
) -> (Ax200Binding<'a, Model, ClockBios, ScanOs>, u16, u16) {
    let (power, mut sequence, mut entry) = powered(catalog, empty, source, native, policy, short);
    authorize(policy);
    // SAFETY: original authored exact-provider fixture and finite-rate service.
    let mut binding = unsafe { power.begin_binding() }.unwrap_or_else(|_| panic!("binding"));
    finish_add(&mut binding, source, native, &mut sequence, &mut entry);
    binding.replenish_completed_receive().unwrap();
    (binding, sequence, entry)
}
fn completion(
    peer: &Ax200LegacyPeer<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    entry: u16,
    command: &PeerCommand,
    payload: &[u8],
) {
    let boot = boot(&peer.binding.power.phy.scan);
    // Follow the emitted free descriptor, including recycled VIDs and
    // source ring wrap. Never invent credits or complete an unposted buffer.
    let slot = entry & (boot.entries - 1);
    assert_eq!(slot, boot.read);
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
        &command_packet(
            command.id().wire(),
            peer.ticket().unwrap().sequence(),
            payload,
        ),
    );
}
fn emitted(
    peer: &Ax200LegacyPeer<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    command: &PeerCommand,
) {
    let sequence = peer.ticket().unwrap().sequence();
    let encoded = Command::encode(command.id(), 0, sequence, command.bytes()).unwrap();
    let boot = boot(&peer.binding.power.phy.scan);
    let descriptor = device_read(
        &native.domain,
        boot.command.region().address,
        usize::from(sequence & 31) * 256,
        256,
    );
    let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
    let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
    let mut bytes = device_read(&native.domain, first, 0, encoded.first_tb().len());
    assert_eq!(
        u16::from_le_bytes(descriptor[..2].try_into().unwrap()),
        if encoded.remainder().is_empty() { 1 } else { 2 }
    );
    if encoded.remainder().is_empty() {
        // Short FLUSH/REMOVE fits entirely in TB0. The zero unused
        // descriptor is not a device address and must never be model-read.
        assert_eq!(&descriptor[12..22], &[0; 10]);
    } else {
        bytes.extend(device_read(
            &native.domain,
            rest,
            0,
            encoded.remainder().len(),
        ));
    }
    assert_eq!(bytes, encoded.bytes());
}
fn payload(kind: PeerCommandKind, flush: bool) -> Vec<u8> {
    match kind {
        PeerCommandKind::Add | PeerCommandKind::Drain | PeerCommandKind::Undrain => {
            vec![1, 0, 0, 0]
        }
        PeerCommandKind::Flush if flush => vec![0; 132],
        _ => vec![],
    }
}
#[test]
fn peer_commands_complete_on_ack() {
    if crate::test_process::isolate_model() {
        return;
    }
    for (tlc, flush) in [(1, 0), (3, 1), (4, 1)] {
        exercise(&image(tlc, flush), tlc, flush);
    }
    // The distinct original STA_TYPE API30 route also selects48 bytes.
    exercise(
        &feature(feature(image(4, 1), 30, 68, false), 29, 30, true),
        4,
        1,
    );
}
#[test]
fn mld_or_old_station_layout_and_missing_tlc_refuse_before_peer_dma() {
    if crate::test_process::isolate_model() {
        return;
    }
    for case in 0..4 {
        let bytes = match case {
            0 => feature(image(4, 1), 30, 110, true),
            1 => feature(feature(image(4, 1), 30, 68, false), 29, 30, false),
            2 => feature(image(4, 1), 30, 43, false),
            _ => feature(image(4, 1), 30, 40, true),
        };
        if case == 0 {
            ax200_mac_tests::assert_mld_mac_refusal(&bytes);
            continue;
        }
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (binding, _, _) = bound(&catalog, &empty, &source, &native, &policy, false);
        // SAFETY: same authored exclusive provider, rejecting unsupported
        // source station owners/layouts before any station HCMD is emitted.
        let mut peer =
            unsafe { binding.begin_legacy_peer(parameters()) }.unwrap_or_else(|_| panic!("peer"));
        let allocations = source.calls.load(Ordering::Relaxed);
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        assert_eq!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { peer.advance(&source) },
            Err(Ax200LegacyPeerError::MissingApi)
        );
        assert!(peer.commands().is_empty());
        assert!(peer.ticket().is_none());
        assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
        assert_eq!(native.state.lock().unwrap().ops.len(), ops);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        peer.stop().unwrap();
    }
}
fn exercise(bytes: &[u8], tlc: u8, flush: u8) {
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (binding, _, mut entry) = bound(&catalog, &empty, &source, &native, &policy, false);
    // SAFETY: isolated same-owner model keeps all twelve real legacy-rate
    // grants through peer removal and original binding stop.
    let mut peer =
        unsafe { binding.begin_legacy_peer(parameters()) }.unwrap_or_else(|_| panic!("peer"));
    let at_sync = policy.clone();
    native.domain.records.lock().unwrap().device_sync_hook = Some(Arc::new(move || {
        assert_eq!(at_sync.held.load(Ordering::SeqCst), 1);
        assert_eq!(at_sync.transmit_rates.load(Ordering::SeqCst), 0xfff);
    }));
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { peer.advance(&source) }.unwrap(),
        Ax200LegacyPeerPhase::Waiting(PeerCommandKind::Add)
    );
    native.domain.records.lock().unwrap().device_sync_hook = None;
    assert!(peer.station_id().is_none());
    assert_eq!(peer.commands().len(), 2);
    assert_eq!(peer.commands()[0].bytes().len(), 48);
    assert_eq!(&peer.commands()[0].bytes()[2..4], &[255; 2]);
    assert_eq!(&peer.commands()[0].bytes()[8..14], &parameters().address.0);
    assert_eq!(
        peer.commands()[1].bytes().len(),
        if tlc < 3 { 24 } else { 28 }
    );
    assert_eq!(&peer.commands()[1].bytes()[10..12], &0xfffu16.to_le_bytes());
    for command in peer.commands().to_vec() {
        emitted(&peer, &native, &command);
        completion(
            &peer,
            &native,
            entry,
            &command,
            &payload(command.kind(), flush != 0),
        );
        let mut records = native.domain.records.lock().unwrap();
        records.cpu_sync_fail = Some(records.cpu_syncs + 1);
        drop(records);
        assert!(matches!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { peer.advance(&source) },
            Err(Ax200LegacyPeerError::Boot(Error::CommandReclaim(_)))
        ));
        assert!(peer.first_error().is_none());
        native.domain.records.lock().unwrap().cpu_sync_fail = None;
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { peer.advance(&source) }.unwrap();
        peer.replenish_completed_receive().unwrap();
        entry += 1;
    }
    assert_eq!(peer.station_id(), Some(0));
    let acquired = policy.acquired.load(Ordering::SeqCst);
    native.revoked.store(true, Ordering::SeqCst);
    peer.begin_remove().unwrap();
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { peer.advance(&source) }.unwrap();
    let commands = peer.commands()[2..].to_vec();
    assert_eq!(
        commands.iter().map(PeerCommand::kind).collect::<Vec<_>>(),
        [
            PeerCommandKind::Drain,
            PeerCommandKind::Flush,
            PeerCommandKind::Undrain,
            PeerCommandKind::Remove
        ]
    );
    for command in commands {
        emitted(&peer, &native, &command);
        completion(
            &peer,
            &native,
            entry,
            &command,
            &payload(command.kind(), flush != 0),
        );
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { peer.advance(&source) }.unwrap();
        peer.replenish_completed_receive().unwrap();
        entry += 1;
    }
    assert_eq!(peer.phase(), Ax200LegacyPeerPhase::Removed);
    assert_eq!(policy.acquired.load(Ordering::SeqCst), acquired);
    let mut binding = peer.into_binding().unwrap_or_else(|_| panic!("binding"));
    binding.stop().unwrap();
    drop(binding);
    assert!(native.domain.records.lock().unwrap().live.is_empty());
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn ax200_mld_peer_schema_requires_distinct_mac_link_owner() {
    if crate::test_process::isolate_model() {
        return;
    }
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
    );
    let fw = crate::wifi::intel::firmware::Firmware::parse(&bytes).unwrap();
    assert!(fw.supports_capability(110));
    assert!(fw.supports_capability(68) || fw.supports_api(30));
    for (group, opcode, command, notification) in [
        (1, 0x18, 12, 2),
        (1, 0x19, 2, 0),
        (1, 0x1e, 2, 1),
        (5, 15, 4, 0),
    ] {
        let v = fw.command_version(group, opcode).unwrap();
        assert_eq!(
            (v.command_version, v.notification_version),
            (command, notification)
        );
    }
    ax200_mac_tests::assert_mld_mac_refusal(&bytes);
}
#[test]
fn peer_invalid_beacon_or_rates_denial_partial_tlc_and_untracked_flush_freeze_owner() {
    if crate::test_process::isolate_model() {
        return;
    }
    for case in 0..5 {
        let bytes = image(4, 1);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (binding, _, mut entry) = bound(&catalog, &empty, &source, &native, &policy, false);
        let mut params = parameters();
        if case == 0 {
            params.beacon_interval_tu = 15;
        }
        let mut peer =
            // SAFETY: the simulated device and its providers belong to this fixture alone; no other
            // worker touches them.
            unsafe { binding.begin_legacy_peer(params) }.unwrap_or_else(|_| panic!("peer"));
        let allocations = source.calls.load(Ordering::Relaxed);
        let bell = native.state.lock().unwrap().registers[&0x460];
        if case == 1 {
            policy
                .deny_rate
                .store(LegacyRate::Ofdm54 as usize + 1, Ordering::SeqCst);
        }
        if case < 2 {
            assert_eq!(
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { peer.advance(&source) },
                Err(if case == 0 {
                    Ax200LegacyPeerError::Peer
                } else {
                    Ax200LegacyPeerError::Binding(Ax200BindingError::Regulatory(
                        regulatory::Error::OsDenied,
                    ))
                })
            );
            assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
            assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
            if case == 1 {
                peer.stop().unwrap();
                continue;
            } // before-effects denial stays retryable
        } else {
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { peer.advance(&source) }.unwrap();
            for command in peer.commands().to_vec() {
                completion(
                    &peer,
                    &native,
                    entry,
                    &command,
                    &payload(command.kind(), true),
                );
                entry += 1;
                if case == 2 && command.kind() == PeerCommandKind::Add {
                    policy.unavailable.store(true, Ordering::SeqCst);
                    assert!(matches!(
                        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its
                        // sole simulated requester domain.
                        unsafe { peer.advance(&source) },
                        Err(Ax200LegacyPeerError::Binding(
                            Ax200BindingError::Regulatory(regulatory::Error::OsUnavailable)
                        ))
                    ));
                    break;
                }
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { peer.advance(&source) }.unwrap();
                peer.replenish_completed_receive().unwrap();
            }
            if case >= 3 {
                peer.begin_remove().unwrap();
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { peer.advance(&source) }.unwrap();
                let drain = peer.commands()[2].clone();
                completion(&peer, &native, entry, &drain, &[1, 0, 0, 0]);
                entry += 1;
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { peer.advance(&source) }.unwrap();
                peer.replenish_completed_receive().unwrap();
                let flush = peer.commands()[3].clone();
                let mut reply = vec![0; 132];
                if case == 3 {
                    reply[2] = 1;
                } else {
                    reply[0] = 1;
                }
                completion(&peer, &native, entry, &flush, &reply);
                assert_eq!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { peer.advance(&source) },
                    Err(if case == 3 {
                        Ax200LegacyPeerError::UnexpectedQueues(1)
                    } else {
                        Ax200LegacyPeerError::FlushStation(1)
                    })
                );
                assert!(peer.ticket().is_none());
            }
        }
        let error = peer.first_error().unwrap().clone();
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert_eq!(unsafe { peer.advance(&source) }, Err(error.clone()));
        assert_eq!(peer.replenish_completed_receive(), Err(error));
        assert_eq!(native.state.lock().unwrap().ops.len(), ops);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        if case == 2 {
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
fn peer_rejected_or_malformed_add_and_missing_ack_never_publish_tlc() {
    if crate::test_process::isolate_model() {
        return;
    }
    for case in 0..3 {
        let bytes = image(4, 1);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (binding, _, entry) = bound(&catalog, &empty, &source, &native, &policy, case == 2);
        // SAFETY: original synchronous finite-rate model; no queue exists.
        let mut peer =
            unsafe { binding.begin_legacy_peer(parameters()) }.unwrap_or_else(|_| panic!("peer"));
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { peer.advance(&source) }.unwrap();
        let add = peer.commands()[0].clone();
        if case == 2 {
            Clock {
                ticks_per_microsecond: 1,
            }
            .delay(20);
        } else {
            completion(
                &peer,
                &native,
                entry,
                &add,
                if case == 0 { &[2, 0, 0, 0] } else { &[1, 0] },
            );
        }
        assert_eq!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { peer.advance(&source) },
            Err(match case {
                0 => Ax200LegacyPeerError::Status(2),
                1 => Ax200LegacyPeerError::ResponseLength(2),
                _ => Ax200LegacyPeerError::Deadline(PeerCommandKind::Add),
            })
        );
        assert_eq!(peer.phase(), Ax200LegacyPeerPhase::Failed);
        assert!(peer.station_id().is_none());
        assert!(
            peer.responses()
                .iter()
                .all(|response| response.command != 15 || response.group != 5)
        );
        let error = peer.first_error().unwrap().clone();
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert_eq!(unsafe { peer.advance(&source) }, Err(error.clone()));
        assert_eq!(peer.replenish_completed_receive(), Err(error));
        assert_eq!(native.state.lock().unwrap().ops.len(), ops);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        peer.stop().unwrap();
    }
}
