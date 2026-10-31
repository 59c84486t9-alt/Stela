// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! MLD scheduler/DMA ownership, reserved HCMD queue and empty teardown.
use super::*;
mod coexistence_tests;
const SCHEDULER: Id = Id {
    group: 5,
    opcode: 0x17,
    version: 0,
};
const FLUSH: Id = Id {
    group: 0,
    opcode: 0x1e,
    version: 0,
};
fn image(version: u8) -> Vec<u8> {
    let mut bytes = mld_image(1);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            bytes.splice(at + 8 + len..at + 8 + len, [0x17, 5, version, 2]);
            bytes[at + 4..at + 8].copy_from_slice(&((len + 4) as u32).to_le_bytes());
            return bytes;
        }
        at += 8 + len.next_multiple_of(4);
    }
    panic!("command versions");
}
fn peer_ready<'a>(
    catalog: &'a resources::Catalog,
    empty: &'a resources::Catalog,
    source: &Source,
    native: &Native,
    policy: &Arc<PolicyState>,
    short: bool,
) -> Ax200LegacyPeer<'a, Model, ClockBios, ScanOs> {
    let link = mld_bound(catalog, empty, source, native, policy, short);
    // SAFETY: original finite-rate provider and native owner model.
    let mut peer =
        unsafe { link.begin_mld_peer(parameters()) }.unwrap_or_else(|_| panic!("MLD peer"));
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { peer.advance(source) }.unwrap();
    for command in peer.commands().to_vec() {
        complete_mld_peer(&peer, native, &command);
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { peer.advance(source) }.unwrap();
        peer.replenish_completed_receive().unwrap();
    }
    assert_eq!(peer.station_id(), Some(0));
    peer
}
fn completion(
    queue: &Ax200ManagementQueue<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    id: Id,
    payload: &[u8],
) {
    let boot = boot(&queue.peer.as_ref().unwrap().binding.power.phy.scan);
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
        &command_packet(id.wire(), queue.ticket().unwrap().sequence(), payload),
    );
}
fn emitted(
    queue: &Ax200ManagementQueue<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    id: Id,
    payload: &[u8],
) {
    let boot = boot(&queue.peer.as_ref().unwrap().binding.power.phy.scan);
    let sequence = queue.ticket().unwrap().sequence();
    let command = Command::encode(id, 0, sequence, payload).unwrap();
    let descriptor = device_read(
        &native.domain,
        boot.command.region().address,
        usize::from(sequence & 31) * 256,
        256,
    );
    assert_eq!(
        u16::from_le_bytes(descriptor[..2].try_into().unwrap()),
        if command.remainder().is_empty() { 1 } else { 2 }
    );
    let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
    let mut bytes = device_read(&native.domain, first, 0, command.first_tb().len());
    if command.remainder().is_empty() {
        assert_eq!(&descriptor[12..22], &[0; 10]);
    } else {
        let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
        bytes.extend(device_read(
            &native.domain,
            rest,
            0,
            command.remainder().len(),
        ));
    }
    assert_eq!(bytes, command.bytes());
}
fn reply(queue: u16) -> [u8; 8] {
    let mut bytes = [0; 8];
    bytes[..2].copy_from_slice(&queue.to_le_bytes());
    bytes[4..6].fill(255);
    bytes
}
fn flush(queue: u16) -> [u8; 132] {
    let mut bytes = [0; 132];
    bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&15u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&queue.to_le_bytes());
    bytes[8..12].fill(255);
    bytes
}
#[test]
fn mld_scheduler_add_owns_real_dma_and_full_queue_identity_until_flush_remove_ack_reclaim() {
    exercise(&image(3));
}
fn exercise(bytes: &[u8]) {
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let peer = peer_ready(&catalog, &empty, &source, &native, &policy, false);
    let baseline = native.domain.records.lock().unwrap().live.len();
    // SAFETY: original exclusive requester and policy lifetime.
    let mut queue =
        unsafe { peer.begin_mld_management_queue() }.unwrap_or_else(|_| panic!("queue owner"));
    let at_sync = policy.clone();
    native.domain.records.lock().unwrap().device_sync_hook = Some(Arc::new(move || {
        assert_eq!(at_sync.held.load(Ordering::SeqCst), 1);
        assert_eq!(at_sync.transmit_rates.load(Ordering::SeqCst), 0xfff);
    }));
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { queue.advance(&source) }.unwrap(),
        Ax200ManagementQueuePhase::WaitingAdd
    );
    native.domain.records.lock().unwrap().device_sync_hook = None;
    assert_eq!(queue.queue_id(), None);
    let configuration = queue.configuration.as_ref().unwrap();
    let payload = configuration.payload().to_vec();
    emitted(&queue, &native, SCHEDULER, &payload);
    let memory = queue.memory.as_ref().unwrap();
    let layout = memory.layout();
    assert_eq!(memory.slots(), 16);
    assert_eq!(
        &payload[..20],
        &[0, 0, 0, 0, 1, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]
    );
    assert_eq!(
        u64::from_le_bytes(payload[20..28].try_into().unwrap()),
        layout.byte_counts.address
    );
    assert_eq!(
        u64::from_le_bytes(payload[28..36].try_into().unwrap()),
        layout.descriptors.address
    );
    assert_eq!(
        device_read(&native.domain, layout.invalid.address, 0, 8),
        [6, 15, 255, 255, 0, 0, 0, 0]
    );
    for slot in 0..16 {
        let descriptor = device_read(&native.domain, layout.descriptors.address, slot * 256, 256);
        assert_eq!(u16::from_le_bytes(descriptor[..2].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_le_bytes(descriptor[4..12].try_into().unwrap()),
            layout.invalid.address
        );
    }
    completion(&queue, &native, SCHEDULER, &reply(511));
    let mut records = native.domain.records.lock().unwrap();
    records.cpu_sync_fail = Some(records.cpu_syncs + 1);
    drop(records);
    assert!(matches!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { queue.advance(&source) },
        Err(Ax200ManagementQueueError::Boot(Error::CommandReclaim(_)))
    ));
    assert!(queue.first_error().is_none());
    assert_eq!(queue.queue_id(), None);
    native.domain.records.lock().unwrap().cpu_sync_fail = None;
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { queue.advance(&source) }.unwrap(),
        Ax200ManagementQueuePhase::ManagementFramesRequired
    );
    queue.replenish_completed_receive().unwrap();
    assert_eq!(queue.queue_id(), Some(511));
    assert_eq!(queue.write_pointer(), Some(255));
    assert_eq!(
        native.domain.records.lock().unwrap().live.len(),
        baseline + 4
    );
    let acquired = policy.acquired.load(Ordering::SeqCst);
    native.revoked.store(true, Ordering::SeqCst);
    queue.begin_remove_station().unwrap();
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { queue.advance(&source) }.unwrap();
    emitted(&queue, &native, FLUSH, &[0, 0, 0, 0, 255, 255, 0, 0]);
    completion(&queue, &native, FLUSH, &flush(511));
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { queue.advance(&source) }.unwrap();
    queue.replenish_completed_receive().unwrap();
    assert_eq!(queue.phase(), Ax200ManagementQueuePhase::WaitingRemove);
    assert!(queue.rings[0].1.uncertain());
    queue = match queue.into_binding() {
        Err(owner) => *owner,
        Ok(_) => panic!("queue escaped before remove"),
    };
    let mut remove = [0; 36];
    remove[..4].copy_from_slice(&1u32.to_le_bytes());
    remove[4..8].copy_from_slice(&1u32.to_le_bytes());
    remove[8..12].copy_from_slice(&15u32.to_le_bytes());
    emitted(&queue, &native, SCHEDULER, &remove);
    completion(&queue, &native, SCHEDULER, &[]);
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { queue.advance(&source) }.unwrap(),
        Ax200ManagementQueuePhase::WaitingStationRemove
    );
    assert!(queue.rings.is_empty());
    assert_eq!(native.domain.records.lock().unwrap().live.len(), baseline);
    queue = match queue.into_binding() {
        Err(owner) => *owner,
        Ok(_) => panic!("station escaped before real remove"),
    };
    let station_remove = Id {
        group: 3,
        opcode: 0x0c,
        version: 0,
    };
    emitted(&queue, &native, station_remove, &[0; 4]);
    completion(&queue, &native, station_remove, &[]);
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { queue.advance(&source) }.unwrap(),
        Ax200ManagementQueuePhase::Removed
    );
    assert_eq!(policy.acquired.load(Ordering::SeqCst), acquired);
    let mut binding = queue
        .into_binding()
        .unwrap_or_else(|_| panic!("same active link after station removal"));
    binding.replenish_completed_receive().unwrap();
    assert_eq!(binding.phase(), Ax200BindingPhase::AuthenticationRequired);
    binding.begin_remove().unwrap();
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { binding.advance(&source) }.unwrap();
    for index in 3..binding.commands().len() {
        let command = binding.commands()[index].clone();
        complete_mld_link(&binding, &native, &command);
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { binding.advance(&source) }.unwrap();
        binding.replenish_completed_receive().unwrap();
    }
    assert_eq!(binding.phase(), Ax200BindingPhase::Unbound);
    binding.stop().unwrap();
    drop(binding);
    assert!(native.domain.records.lock().unwrap().live.is_empty());
}
#[test]
fn unknown_scheduler_schema_and_denied_rate_never_allocate_or_publish_queue_dma() {
    for version in [3, 4] {
        let bytes = image(version);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let peer = peer_ready(&catalog, &empty, &source, &native, &policy, false);
        if version == 3 {
            policy
                .deny_rate
                .store(LegacyRate::Ofdm54 as usize + 1, Ordering::SeqCst);
        }
        // SAFETY: authored missing-permission service is denied before effects.
        let mut queue =
            unsafe { peer.begin_mld_management_queue() }.unwrap_or_else(|_| panic!("queue"));
        let calls = source.calls.load(Ordering::Relaxed);
        let syncs = native.domain.records.lock().unwrap().syncs;
        let bell = native.state.lock().unwrap().registers[&0x460];
        assert_eq!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { queue.advance(&source) },
            Err(if version == 3 {
                Ax200ManagementQueueError::Binding(Ax200BindingError::Regulatory(
                    regulatory::Error::OsDenied,
                ))
            } else {
                Ax200ManagementQueueError::Queue(
                    crate::wifi::intel::transmit::queue::Error::Version,
                )
            })
        );
        assert_eq!(source.calls.load(Ordering::Relaxed), calls);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
        assert!(queue.memory.is_none());
        assert!(queue.ticket().is_none());
        queue.stop().unwrap();
    }
}
#[test]
fn reserved_hcmd_queue_and_failed_scheduler_reply_never_grant_queue_ownership() {
    for reserved in [false, true] {
        let bytes = image(3);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let peer = peer_ready(&catalog, &empty, &source, &native, &policy, false);
        // SAFETY: same original native/provider model.
        let mut queue =
            unsafe { peer.begin_mld_management_queue() }.unwrap_or_else(|_| panic!("queue"));
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { queue.advance(&source) }.unwrap();
        let mut bytes = reply(if reserved { 0 } else { 1 });
        if !reserved {
            bytes[2] = 1;
        }
        completion(&queue, &native, SCHEDULER, &bytes);
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert!(unsafe { queue.advance(&source) }.is_err());
        assert_eq!(queue.queue_id(), None);
        assert_eq!(queue.phase(), Ax200ManagementQueuePhase::Failed);
        queue = match queue.into_binding() {
            Err(owner) => *owner,
            Ok(_) => panic!("unqualified scheduler reply escaped"),
        };
        let error = queue.first_error().unwrap().clone();
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert_eq!(unsafe { queue.advance(&source) }, Err(error.clone()));
        assert_eq!(queue.replenish_completed_receive(), Err(error));
        assert_eq!(native.state.lock().unwrap().ops.len(), ops);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        queue.stop().unwrap();
    }
}
#[test]
fn scheduler_map_invalidation_failure_after_successful_stop_keeps_original_peer_policy_owner() {
    let bytes = image(3);
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let peer = peer_ready(&catalog, &empty, &source, &native, &policy, false);
    let baseline = native.domain.records.lock().unwrap().live.len();
    // SAFETY: same exclusive native/policy epoch.
    let mut queue =
        unsafe { peer.begin_mld_management_queue() }.unwrap_or_else(|_| panic!("queue"));
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { queue.advance(&source) }.unwrap();
    completion(&queue, &native, SCHEDULER, &reply(1));
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { queue.advance(&source) }.unwrap();
    queue.replenish_completed_receive().unwrap();
    let mut records = native.domain.records.lock().unwrap();
    records.unmap_fail = Some(records.unmaps + baseline);
    drop(records);
    assert!(queue.stop().is_err());
    assert_eq!(
        boot(&queue.peer.as_ref().unwrap().binding.power.phy.scan).state,
        State::Stopped
    );
    assert!(queue.rings[0].1.uncertain());
    let live = native.domain.records.lock().unwrap().live.len();
    assert_eq!(live, 4);
    drop(queue);
    assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
    assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
}
#[test]
fn missing_scheduler_add_or_remove_ack_freezes_extra_dma_and_parent_through_failed_stop() {
    for remove in [false, true] {
        let bytes = image(3);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let peer = peer_ready(&catalog, &empty, &source, &native, &policy, true);
        // SAFETY: original exclusive requester and finite policy model.
        let mut queue =
            unsafe { peer.begin_mld_management_queue() }.unwrap_or_else(|_| panic!("queue"));
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { queue.advance(&source) }.unwrap();
        if remove {
            completion(&queue, &native, SCHEDULER, &reply(1));
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { queue.advance(&source) }.unwrap();
            queue.replenish_completed_receive().unwrap();
            queue.begin_remove_station().unwrap();
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { queue.advance(&source) }.unwrap();
            completion(&queue, &native, FLUSH, &flush(1));
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { queue.advance(&source) }.unwrap();
            queue.replenish_completed_receive().unwrap();
        }
        let phase = queue.phase();
        assert_eq!(
            phase,
            if remove {
                Ax200ManagementQueuePhase::WaitingRemove
            } else {
                Ax200ManagementQueuePhase::WaitingAdd
            }
        );
        Clock {
            ticks_per_microsecond: 1,
        }
        .delay(20);
        let error = Ax200ManagementQueueError::Deadline(phase);
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert_eq!(unsafe { queue.advance(&source) }, Err(error.clone()));
        assert!(
            queue
                .memory
                .as_ref()
                .is_some_and(|memory| memory.uncertain())
                || queue.rings[0].1.uncertain()
        );
        queue = match queue.into_binding() {
            Err(owner) => *owner,
            Ok(_) => panic!("missing scheduler ack released peer"),
        };
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert_eq!(unsafe { queue.advance(&source) }, Err(error.clone()));
        assert_eq!(queue.replenish_completed_receive(), Err(error));
        assert_eq!(native.state.lock().unwrap().ops.len(), ops);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        if remove {
            native.state.lock().unwrap().fail = Some(ops + 1);
            assert!(queue.stop().is_err());
            let live = native.domain.records.lock().unwrap().live.len();
            drop(queue);
            assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
        } else {
            queue.stop().unwrap();
            drop(queue);
            assert!(native.domain.records.lock().unwrap().live.is_empty());
        }
    }
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn ax200_mld_scheduler3_reply2_allocates_and_removes_original_queue_dma() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
    );
    let firmware = crate::wifi::intel::firmware::Firmware::parse(&bytes).unwrap();
    let version = firmware.command_version(5, 0x17).unwrap();
    assert_eq!(
        (version.command_version, version.notification_version),
        (3, 2)
    );
    exercise(&bytes);
}
