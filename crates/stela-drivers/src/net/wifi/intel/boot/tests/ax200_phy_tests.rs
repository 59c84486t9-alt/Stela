// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Real command publication and RX reclaim through the original cold owner.
use super::*;

// Exact unchanged-Linux trace word: RX mask3, cold CAM diversity2/2.
// PHY_RX_CHAIN_VALID_POS=1, CNT_POS=10, MIMO_CNT_POS=12.
const LINUX_CAM_RX_CHAINS: u32 = 0x2806;
#[path = "ax200_transmit_power_tests.rs"]
mod transmit_power_tests;

fn phy_bytes(version: u8, rlc: Option<u8>) -> Vec<u8> {
    let mut bytes = bytes();
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            let mut versions = vec![8, 1, version, 0];
            if let Some(rlc) = rlc {
                versions.extend([8, 5, rlc, 0]);
            }
            bytes.splice(at + 8 + len..at + 8 + len, versions.iter().copied());
            bytes[at + 4..at + 8].copy_from_slice(&((len + versions.len()) as u32).to_le_bytes());
            return bytes;
        }
        at += 8 + len.next_multiple_of(4);
    }
    panic!("command versions");
}
fn complete_phy(
    phy: &Ax200Phy<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    entry: u16,
    sequence: u16,
    id: super::super::super::super::command::Id,
) {
    complete(
        boot(&phy.scan),
        &native.domain,
        entry,
        entry + 1,
        &command_packet(id.wire(), sequence, &[0x9b]),
    );
}
fn emitted(phy: &Ax200Phy<'_, Model, ClockBios, ScanOs>, native: &Native) -> Vec<u8> {
    let ticket = phy.ticket().unwrap();
    let descriptor = device_read(
        &native.domain,
        boot(&phy.scan).command.region().address,
        usize::from(ticket.sequence() & 31) * 256,
        256,
    );
    let command = phy
        .commands()
        .iter()
        .find(|c| {
            c.kind()
                == match phy.phase() {
                    Ax200PhyPhase::Waiting(kind) => kind,
                    _ => panic!("pending command"),
                }
        })
        .unwrap();
    let encoded = super::super::super::super::command::Command::encode(
        command.id(),
        0,
        ticket.sequence(),
        command.bytes(),
    )
    .unwrap();
    let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
    let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
    let mut bytes = device_read(&native.domain, first, 0, encoded.first_tb().len());
    bytes.extend(device_read(
        &native.domain,
        rest,
        0,
        encoded.remainder().len(),
    ));
    let mut expected = encoded.first_tb().to_vec();
    expected.extend_from_slice(encoded.remainder());
    assert_eq!(bytes, expected);
    bytes
}
#[test]
fn phy_add_rlc_and_remove_require_original_dma_ack_reclaim_and_held_policy() {
    for version in [3, 4] {
        for rlc in [None, Some(1), Some(2), Some(3)] {
            let bytes = phy_bytes(version, rlc);
            let firmware = crate::net::wifi::intel::firmware::Firmware::parse(&bytes).unwrap();
            assert_eq!(
                firmware.command_version(1, 8).unwrap().command_version,
                version
            );
            assert_eq!(
                firmware.command_version(5, 8).map(|v| v.command_version),
                rlc
            );
            assert_eq!((firmware.phy_sku().unwrap() >> 20) & 15, 3);
            assert!(!firmware.supports_capability(40));
            assert!(!firmware.supports_capability(48));
            let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let native = Native::default();
            let source = Source::default();
            let policy = Arc::new(PolicyState::default());
            let (scan, mut sequence, mut entry) =
                ready(&catalog, &empty, &source, &native, &policy, false);
            let mut phy = scan
                .begin_phy_context(channel(1))
                .unwrap_or_else(|_| panic!("PHY"));
            assert_eq!(phy.phy_id_and_color(), None);
            let handoffs = Arc::new(Mutex::new(Vec::new()));
            let captured_handoffs = handoffs.clone();
            let at_sync = policy.clone();
            let first_copy = native.domain.records.lock().unwrap().copied.len();
            native.domain.records.lock().unwrap().device_sync_hook = Some(Arc::new(move || {
                captured_handoffs
                    .lock()
                    .unwrap()
                    .push(at_sync.held.load(Ordering::SeqCst));
            }));
            assert_eq!(
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { phy.advance(&source) }.unwrap(),
                Ax200PhyPhase::Waiting(PhyCommandKind::Add)
            );
            assert_eq!(&phy.commands()[0].bytes()[4..12], &[1, 0, 0, 0, 1, 1, 0, 0]);
            let rx = u32::from_le_bytes(phy.commands()[0].bytes()[20..24].try_into().unwrap());
            if rlc.unwrap_or(0) < 2 {
                assert_eq!(rx, LINUX_CAM_RX_CHAINS);
            } else {
                assert_eq!(rx, 0);
            }
            let commands = phy.commands().to_vec();
            assert_eq!(commands.len(), if rlc == Some(2) { 2 } else { 1 });
            if rlc == Some(2) {
                assert_eq!(
                    &commands[1].bytes()[4..8],
                    &LINUX_CAM_RX_CHAINS.to_le_bytes()
                );
                assert_eq!(commands[1].id().version, 2);
                assert!(commands[1].bytes()[8..].iter().all(|b| *b == 0));
            }
            for command in commands {
                emitted(&phy, &native);
                let ticket = phy.ticket().unwrap().clone();
                assert_eq!(ticket.sequence(), sequence);
                assert_eq!(phy.phy_id_and_color(), None);
                complete_phy(&phy, &native, entry, sequence, command.id());
                let mut records = native.domain.records.lock().unwrap();
                records.cpu_sync_fail = Some(records.cpu_syncs + 1);
                drop(records);
                assert!(matches!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { phy.advance(&source) },
                    Err(Ax200PhyError::Boot(Error::CommandReclaim(_)))
                ));
                assert_eq!(phy.ticket(), Some(&ticket));
                assert_eq!(phy.phy_id_and_color(), None);
                assert!(phy.first_error().is_none());
                native.domain.records.lock().unwrap().cpu_sync_fail = None;
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { phy.advance(&source) }.unwrap();
                entry += 1;
                sequence += 1;
            }
            native.domain.records.lock().unwrap().device_sync_hook = None;
            assert_eq!(phy.phase(), Ax200PhyPhase::BindingRequired);
            assert_eq!(phy.phy_id_and_color(), Some(0));
            assert_eq!(
                policy.acquired.load(Ordering::SeqCst),
                2 * phy.commands().len()
            );
            assert_eq!(policy.held.load(Ordering::SeqCst), 0);
            let copies = native.domain.records.lock().unwrap().copied[first_copy..].to_vec();
            let handoffs = handoffs.lock().unwrap();
            assert_eq!(handoffs.len(), 4 * phy.commands().len());
            assert_eq!(copies.len(), handoffs.len());
            for (holds, copies) in handoffs
                .as_chunks::<4>()
                .0
                .iter()
                .zip(copies.as_chunks::<4>().0.iter())
            {
                // Remainder, TB0 and executable TFD are the exact additive
                // command's guarded DMA publication. ACK/reclaim then
                // restores an inert invalid TFD without acquiring RF permission.
                assert_eq!(holds, &[1, 1, 1, 0]);
                assert_eq!(copies[0].len(), 20);
                assert_eq!(copies[1].len(), 20);
                assert_eq!(copies[2].len(), 256);
                assert_eq!(&copies[2][..2], &[2, 0]);
                let invalid = &copies[3];
                assert_eq!(invalid.len(), 256);
                assert_eq!(&invalid[..4], &[1, 0, 8, 0]);
                let address = u64::from_le_bytes(invalid[4..12].try_into().unwrap());
                // The kept source invalid target is immutable and still
                // owned. No command payload can hide in an unguarded write.
                assert_eq!(
                    device_read(&native.domain, address, 0, 8),
                    [6, 15, 255, 255, 0, 0, 0, 0]
                );
            }
            drop(handoffs);
            let acquired = policy.acquired.load(Ordering::SeqCst);
            native.revoked.store(true, Ordering::SeqCst);
            phy.begin_remove().unwrap();
            assert_eq!(
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { phy.advance(&source) }.unwrap(),
                Ax200PhyPhase::Waiting(PhyCommandKind::Remove)
            );
            emitted(&phy, &native);
            let command = phy.commands().last().unwrap();
            assert_eq!(&command.bytes()[4..8], &3u32.to_le_bytes());
            complete_phy(&phy, &native, entry, sequence, command.id());
            assert_eq!(
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { phy.advance(&source) }.unwrap(),
                Ax200PhyPhase::Removed
            );
            assert_eq!(phy.phy_id_and_color(), None);
            assert_eq!(policy.acquired.load(Ordering::SeqCst), acquired);
            phy.stop().unwrap();
            drop(phy);
            assert!(native.domain.records.lock().unwrap().live.is_empty());
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 1);
        }
    }
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn actual_ax200_phy4_rlc2_schema_does_not_bypass_mld_mac_requirement() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
    assert_eq!(bytes.len(), 1_368_100);
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
    );
    let firmware = crate::net::wifi::intel::firmware::Firmware::parse(&bytes).unwrap();
    firmware.require_family(Family::Ax200).unwrap();
    assert_eq!(firmware.command_version(1, 8).unwrap().command_version, 4);
    assert_eq!(firmware.command_version(5, 8).unwrap().command_version, 2);
    assert_eq!(firmware.phy_sku(), Some(0x330018));
    assert!(!firmware.supports_capability(40));
    assert!(firmware.supports_capability(48));
    ax200_mac_tests::assert_mld_mac_refusal(&bytes);
}
#[test]
fn phy_prepublication_denial_and_unknown_schema_have_no_native_effects() {
    for case in 0..6 {
        let bytes = phy_bytes(if case == 5 { 5 } else { 3 }, Some(2));
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (scan, _, _) = ready(&catalog, &empty, &source, &native, &policy, false);
        let mut phy = scan
            .begin_phy_context(if case == 0 { channel(11) } else { channel(1) })
            .unwrap_or_else(|_| panic!("PHY"));
        match case {
            1 => policy.deny_channel.store(1, Ordering::SeqCst),
            2 => policy.unavailable.store(true, Ordering::SeqCst),
            3 => policy.revoke_at_acquire.store(2, Ordering::SeqCst),
            4 => native.revoked.store(true, Ordering::SeqCst),
            _ => (),
        }
        let bell = native.state.lock().unwrap().registers[&0x460];
        let allocations = source.calls.load(Ordering::Relaxed);
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        let result = unsafe { phy.advance(&source) };
        assert_eq!(
            result,
            Err(match case {
                0 => Ax200PhyError::Regulatory(regulatory::Error::HardwareDenied),
                1 => Ax200PhyError::Regulatory(regulatory::Error::OsDenied),
                2 | 3 => Ax200PhyError::Regulatory(regulatory::Error::OsUnavailable),
                4 => Ax200PhyError::Country(Ax200CountryError::Revoked),
                _ => Ax200PhyError::Version(5),
            })
        );
        assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
        assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
        assert!(phy.ticket().is_none());
        assert_eq!(policy.held.load(Ordering::SeqCst), 0);
        phy.stop().unwrap();
    }
}
#[test]
fn phy_cannot_consume_pending_or_completed_but_unretired_scan() {
    let bytes = phy_bytes(3, Some(2));
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
    scan = *scan
        .begin_phy_context(channel(1))
        .err()
        .expect("pending scan preserved");
    ack(&scan, &native, entry, sequence, false);
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { scan.advance(&source) }.unwrap();
    complete(
        boot(&scan),
        &native.domain,
        entry + 1,
        entry + 2,
        &completion(0, 1, 0),
    );
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.advance(&source) }.unwrap(),
        Ax200ScanPhase::DrainRequired
    );
    scan = *scan
        .begin_phy_context(channel(1))
        .err()
        .expect("retiring scan preserved");
    let history = scan.retire().unwrap();
    let mut phy = scan
        .begin_phy_context(channel(1))
        .unwrap_or_else(|_| panic!("retired original PHY"));
    assert_eq!(history.outcome(), scan::Outcome::Completed);
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { phy.advance(&source) }.unwrap(),
        Ax200PhyPhase::Waiting(PhyCommandKind::Add)
    );
    phy.stop().unwrap();
}
#[test]
fn phy_partial_rlc_failure_quarantines_original_owners_until_independent_stop() {
    for case in 0..5 {
        let bytes = phy_bytes(3, Some(2));
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, case == 2);
        let mut phy = scan
            .begin_phy_context(channel(1))
            .unwrap_or_else(|_| panic!("PHY"));
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { phy.advance(&source) }.unwrap();
        let add = phy.commands()[0].id();
        complete_phy(&phy, &native, entry, sequence, add);
        match case {
            0 => policy.unavailable.store(true, Ordering::SeqCst),
            1 => {
                let mut records = native.domain.records.lock().unwrap();
                records.sync_fail = Some(records.syncs + 2);
            }
            _ => (),
        }
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        let result = unsafe { phy.advance(&source) };
        match case {
            0 => assert_eq!(
                result,
                Err(Ax200PhyError::Regulatory(regulatory::Error::OsUnavailable))
            ),
            1 => assert!(matches!(result, Err(Ax200PhyError::Boot(Error::Dma(_))))),
            2 => {
                result.unwrap();
                Clock {
                    ticks_per_microsecond: 1,
                }
                .delay(20);
                assert_eq!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { phy.advance(&source) },
                    Err(Ax200PhyError::Deadline(PhyCommandKind::ReceiveChains))
                );
            }
            3 => {
                result.unwrap();
                let mut id = phy.commands()[1].id();
                id.opcode ^= 1;
                complete_phy(&phy, &native, entry + 1, sequence + 1, id);
                assert!(matches!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { phy.advance(&source) },
                    Err(Ax200PhyError::Boot(Error::InitializationResponse { .. }))
                ));
            }
            _ => {
                result.unwrap();
                let mut records = native.domain.records.lock().unwrap();
                records.cpu_sync_fail = Some(records.cpu_syncs + 1);
                drop(records);
                assert!(matches!(
                    phy.poll_receive(),
                    Err(Ax200PhyError::Scan(Ax200ScanError::Boot(_)))
                ));
                let operations = native.state.lock().unwrap().ops.len();
                let error = phy.first_error().unwrap().clone();
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                assert_eq!(unsafe { phy.advance(&source) }, Err(error));
                assert_eq!(native.state.lock().unwrap().ops.len(), operations);
            }
        }
        assert_eq!(phy.phase(), Ax200PhyPhase::Failed);
        assert_eq!(phy.phy_id_and_color(), None);
        let error = phy.first_error().unwrap().clone();
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert_eq!(unsafe { phy.advance(&source) }, Err(error));
        let operations = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        assert_eq!(
            phy.replenish_completed_receive(),
            Err(phy.first_error().unwrap().clone())
        );
        assert_eq!(native.state.lock().unwrap().ops.len(), operations);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        if case == 1 {
            let mut state = native.state.lock().unwrap();
            state.fail = Some(state.ops.len() + 1);
            drop(state);
            assert!(phy.stop().is_err());
            let live = native.domain.records.lock().unwrap().live.len();
            drop(phy);
            assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
            assert_eq!(native.drops.load(Ordering::Relaxed), 0);
            assert_eq!(native.bios_drops.load(Ordering::Relaxed), 0);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
        } else {
            phy.stop().unwrap();
            drop(phy);
            assert!(native.domain.records.lock().unwrap().live.is_empty());
        }
    }
}

#[test]
fn phy_rearm_visibility_and_producer_failures_preserve_first_error_and_original_owners() {
    for producer in [false, true] {
        let bytes = phy_bytes(4, Some(2));
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (scan, _, _) = ready(&catalog, &empty, &source, &native, &policy, false);
        let mut phy = scan
            .begin_phy_context(channel(1))
            .unwrap_or_else(|_| panic!("PHY"));
        let operations = native.state.lock().unwrap().ops.len();
        if producer {
            native.state.lock().unwrap().fail = Some(operations);
        } else {
            let mut records = native.domain.records.lock().unwrap();
            records.sync_fail = Some(records.syncs);
        }
        let error = phy.replenish_completed_receive().unwrap_err();
        assert!(matches!(error, Ax200PhyError::Boot(_)));
        assert_eq!(phy.phase(), Ax200PhyPhase::Failed);
        assert_eq!(phy.first_error(), Some(&error));
        assert_eq!(boot(&phy.scan).state, State::Poisoned);
        if producer {
            assert!(matches!(
                native.state.lock().unwrap().ops[operations],
                Op::Write(0x1c80, _)
            ));
        }
        let operations = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        assert_eq!(phy.replenish_completed_receive(), Err(error.clone()));
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert_eq!(unsafe { phy.advance(&source) }, Err(error.clone()));
        assert_eq!(native.state.lock().unwrap().ops.len(), operations);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        if producer {
            native.state.lock().unwrap().fail = Some(operations + 1);
            assert!(phy.stop().is_err());
            assert_eq!(phy.first_error(), Some(&error));
            let live = native.domain.records.lock().unwrap().live.len();
            drop(phy);
            assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
            assert_eq!(native.drops.load(Ordering::Relaxed), 0);
            assert_eq!(native.bios_drops.load(Ordering::Relaxed), 0);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
        } else {
            phy.stop().unwrap();
            drop(phy);
            assert!(native.domain.records.lock().unwrap().live.is_empty());
        }
    }
}
