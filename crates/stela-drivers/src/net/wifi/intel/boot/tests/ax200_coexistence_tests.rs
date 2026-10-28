// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Actual canonical profile, CI command DMA/ACK/reclaim and owner retention.
use super::*;
use crate::net::wifi::intel::boot::coexistence::CoexistenceError;
#[path = "ax200_link_tests.rs"]
mod link_tests;
const CI: Id = Id {
    group: 0,
    opcode: 0x5d,
    version: 0,
};
fn coex_image(version: u8) -> Vec<u8> {
    let mut bytes = image(3);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            bytes.splice(at + 8 + len..at + 8 + len, [0x5d, 1, version, 0]);
            bytes[at + 4..at + 8].copy_from_slice(&((len + 4) as u32).to_le_bytes());
            return bytes;
        }
        at += 8 + len.next_multiple_of(4);
    }
    panic!("command table");
}
fn queue_ready<'a>(
    catalog: &'a resources::Catalog,
    empty: &'a resources::Catalog,
    source: &Source,
    native: &Native,
    policy: &Arc<PolicyState>,
    short: bool,
) -> Ax200ManagementQueue<'a, Model, ClockBios, ScanOs> {
    let peer = peer_ready(catalog, empty, source, native, policy, short);
    let mut queue =
        unsafe { peer.begin_mld_management_queue() }.unwrap_or_else(|_| panic!("queue"));
    unsafe { queue.advance(source) }.unwrap();
    completion(&queue, native, SCHEDULER, &reply(511));
    unsafe { queue.advance(source) }.unwrap();
    queue.replenish_completed_receive().unwrap();
    queue
}
fn inject(
    owner: &Ax200Coexistence<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    id: Id,
    sequence: u16,
    bytes: &[u8],
) {
    let original = boot(&owner.queue.peer.as_ref().unwrap().binding.power.phy.scan);
    let slot = original.read;
    assert!(original.credits > 0);
    let raw = device_read(
        &native.domain,
        original.free.region().address,
        usize::from(slot) * 8,
        8,
    );
    let vid = (u64::from_le_bytes(raw.try_into().unwrap()) & 0xfff) as u16;
    assert!(vid > 0 && original.buffers[usize::from(vid - 1)].device_owned);
    complete_from_free_slot(
        original,
        &native.domain,
        slot,
        vid,
        slot,
        &command_packet(id, sequence, bytes),
    );
}
fn ci_emitted(
    owner: &Ax200Coexistence<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    bytes: &[u8],
) {
    let original = boot(&owner.queue.peer.as_ref().unwrap().binding.power.phy.scan);
    let sequence = owner.ticket().unwrap().sequence();
    let command = Command::encode(CI, 0, sequence, bytes).unwrap();
    let tfd = device_read(
        &native.domain,
        original.command.region().address,
        usize::from(sequence & 31) * 256,
        256,
    );
    assert_eq!(u16::from_le_bytes(tfd[..2].try_into().unwrap()), 2);
    let first = u64::from_le_bytes(tfd[4..12].try_into().unwrap());
    let rest = u64::from_le_bytes(tfd[14..22].try_into().unwrap());
    let mut actual = device_read(&native.domain, first, 0, command.first_tb().len());
    actual.extend(device_read(
        &native.domain,
        rest,
        0,
        command.remainder().len(),
    ));
    assert_eq!(actual, command.bytes());
}
#[test]
fn actual_bt_profile_survives_diagnostics_and_ci_cache_waits_for_ack_and_reclaim() {
    exercise(&coex_image(2));
}
fn exercise(bytes: &[u8]) {
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let queue = queue_ready(&catalog, &empty, &source, &native, &policy, false);
    let original = boot(&queue.peer.as_ref().unwrap().binding.power.phy.scan);
    assert_eq!(original.coexistence.check(), Ok(())); // real prefix BT_CONFIG ACK/reclaim.
    assert_eq!(original.coexistence.applied_ci, [0; 24]);
    let mut owner =
        unsafe { queue.begin_mld_coexistence() }.unwrap_or_else(|_| panic!("coexistence"));
    let mut profile = [0; 40];
    profile[32..36].copy_from_slice(&3u32.to_le_bytes());
    inject(
        &owner,
        &native,
        Id {
            group: 0,
            opcode: 0xce,
            version: 0,
        },
        0x8000,
        &profile,
    );
    let at_sync = policy.clone();
    native.domain.records.lock().unwrap().device_sync_hook = Some(Arc::new(move || {
        assert_eq!(at_sync.held.load(Ordering::SeqCst), 1);
        assert_eq!(at_sync.transmit_rates.load(Ordering::SeqCst), 0xfff);
    }));
    assert_eq!(
        unsafe { owner.advance(&source) }.unwrap(),
        Ax200CoexistencePhase::WaitingChannelInhibition
    );
    native.domain.records.lock().unwrap().device_sync_hook = None;
    let channel = owner.queue.peer.as_ref().unwrap().binding.power.channel();
    let expected = crate::net::wifi::intel::boot::coexistence::channel_inhibition(channel);
    let expected = expected.unwrap();
    ci_emitted(&owner, &native, &expected);
    assert_eq!(
        boot(&owner.queue.peer.as_ref().unwrap().binding.power.phy.scan)
            .coexistence
            .activity(),
        Ok(3)
    );
    let seq = owner.ticket().unwrap().sequence();
    inject(&owner, &native, CI.wire(), seq, &[]);
    let mut records = native.domain.records.lock().unwrap();
    records.cpu_sync_fail = Some(records.cpu_syncs + 1);
    drop(records);
    assert!(matches!(
        unsafe { owner.advance(&source) },
        Err(Ax200CoexistenceError::Boot(Error::CommandReclaim(_)))
    ));
    assert!(owner.first_error().is_none());
    assert_eq!(
        boot(&owner.queue.peer.as_ref().unwrap().binding.power.phy.scan)
            .coexistence
            .applied_ci,
        [0; 24]
    );
    native.domain.records.lock().unwrap().cpu_sync_fail = None;
    assert_eq!(
        unsafe { owner.advance(&source) }.unwrap(),
        Ax200CoexistencePhase::ManagementFramesRequired
    );
    owner.replenish_completed_receive().unwrap();
    assert_eq!(owner.management_antenna_mask(), Ok(2));
    let mut diagnostic = owner.take_other_notification().unwrap();
    assert_eq!(
        (diagnostic.command, diagnostic.group, diagnostic.raw.len()),
        (0xce, 0, 40)
    );
    diagnostic.raw.fill(0);
    assert_eq!(
        boot(&owner.queue.peer.as_ref().unwrap().binding.power.phy.scan)
            .coexistence
            .activity(),
        Ok(3)
    );
    assert_eq!(
        boot(&owner.queue.peer.as_ref().unwrap().binding.power.phy.scan)
            .coexistence
            .applied_ci,
        expected
    );
    assert_eq!(owner.responses().len(), 1);
    let syncs = native.domain.records.lock().unwrap().syncs;
    assert_eq!(
        unsafe { owner.advance(&source) }.unwrap(),
        Ax200CoexistencePhase::ManagementFramesRequired
    );
    assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
    let mut queue = owner
        .into_queue()
        .unwrap_or_else(|_| panic!("applied callback"));
    assert_eq!(queue.queue_id(), Some(511));
    queue.stop().unwrap();
    drop(queue);
    assert!(native.domain.records.lock().unwrap().live.is_empty());
}
#[test]
fn malformed_canonical_profile_and_future_ci_schema_refuse_before_publication() {
    for malformed in [false, true] {
        let bytes = coex_image(if malformed { 2 } else { 3 });
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let queue = queue_ready(&catalog, &empty, &source, &native, &policy, false);
        let mut owner =
            unsafe { queue.begin_mld_coexistence() }.unwrap_or_else(|_| panic!("coexistence"));
        if malformed {
            inject(
                &owner,
                &native,
                Id {
                    group: 0,
                    opcode: 0xce,
                    version: 0,
                },
                0x8000,
                &[0; 39],
            );
        }
        let live = native.domain.records.lock().unwrap().live.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        let error = Ax200CoexistenceError::Coexistence(if malformed {
            CoexistenceError::ProfileLength(39)
        } else {
            CoexistenceError::Version
        });
        assert_eq!(unsafe { owner.advance(&source) }, Err(error.clone()));
        assert!(owner.ticket().is_none());
        assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        let ops = native.state.lock().unwrap().ops.len();
        assert_eq!(unsafe { owner.advance(&source) }, Err(error.clone()));
        assert_eq!(owner.replenish_completed_receive(), Err(error));
        assert_eq!(native.state.lock().unwrap().ops.len(), ops);
        owner.stop().unwrap();
    }
}
#[test]
fn ci_publication_checks_every_original_rate_under_real_policy_before_dma_or_doorbell() {
    let bytes = coex_image(2);
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let queue = queue_ready(&catalog, &empty, &source, &native, &policy, false);
    policy
        .deny_rate
        .store(LegacyRate::Ofdm54 as usize + 1, Ordering::SeqCst);
    let mut owner =
        unsafe { queue.begin_mld_coexistence() }.unwrap_or_else(|_| panic!("coexistence"));
    let calls = source.calls.load(Ordering::Relaxed);
    let syncs = native.domain.records.lock().unwrap().syncs;
    let bell = native.state.lock().unwrap().registers[&0x460];
    assert_eq!(
        unsafe { owner.advance(&source) },
        Err(Ax200CoexistenceError::Binding(
            Ax200BindingError::Regulatory(regulatory::Error::OsDenied)
        ))
    );
    assert!(owner.first_error().is_none());
    assert!(owner.ticket().is_none());
    assert_eq!(owner.phase(), Ax200CoexistencePhase::NotStarted);
    assert_eq!(source.calls.load(Ordering::Relaxed), calls);
    assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
    assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
    policy.deny_rate.store(0, Ordering::SeqCst);
    assert_eq!(
        unsafe { owner.advance(&source) }.unwrap(),
        Ax200CoexistencePhase::WaitingChannelInhibition
    );
    owner.stop().unwrap();
}
#[test]
fn missing_ci_ack_does_not_apply_cache_or_release_original_queue_through_failed_stop() {
    let bytes = coex_image(2);
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let queue = queue_ready(&catalog, &empty, &source, &native, &policy, true);
    let mut owner =
        unsafe { queue.begin_mld_coexistence() }.unwrap_or_else(|_| panic!("coexistence"));
    unsafe { owner.advance(&source) }.unwrap();
    assert!(owner.ticket().is_some());
    Clock {
        ticks_per_microsecond: 1,
    }
    .delay(20);
    assert_eq!(
        unsafe { owner.advance(&source) },
        Err(Ax200CoexistenceError::Deadline)
    );
    assert_eq!(
        boot(&owner.queue.peer.as_ref().unwrap().binding.power.phy.scan)
            .coexistence
            .applied_ci,
        [0; 24]
    );
    owner = match owner.into_queue() {
        Err(owner) => *owner,
        Ok(_) => panic!("unacknowledged CI escaped"),
    };
    let ops = native.state.lock().unwrap().ops.len();
    native.state.lock().unwrap().fail = Some(ops + 1);
    assert!(owner.stop().is_err());
    let live = native.domain.records.lock().unwrap().live.len();
    drop(owner);
    assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
    assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
}
#[test]
#[ignore = "requires unchanged pinned AX200 firmware"]
fn actual_ax200_bt_config6_ci2_and_fixed_old_profile_source_owner() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
    );
    let firmware = crate::net::wifi::intel::firmware::Firmware::parse(&bytes).unwrap();
    for (id, expected) in [(0x9b, 6), (0x5d, 2)] {
        let version = firmware.command_version(1, id).unwrap();
        assert_eq!(
            (version.command_version, version.notification_version),
            (expected, 0)
        );
    }
    assert!(firmware.supports_capability(67));
    assert!(firmware.command_version(1, 0xce).is_none());
    exercise(&bytes);
}
