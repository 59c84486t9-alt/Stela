// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Stateful peer controls for original command/RX/OS owners, not caller proofs.
use super::*;

fn complete_scan(
    scan: &mut Ax200Scan<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    source: &Source,
    sequence: u16,
    entry: u16,
) {
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { scan.start(request(false), 30_000_000, source) }.unwrap();
    ack(scan, native, entry, sequence, false);
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.advance(source) }.unwrap(),
        Ax200ScanPhase::Scanning
    );
    complete(
        boot(scan),
        &native.domain,
        entry + 1,
        entry + 2,
        &completion(0, 1, 0),
    );
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.advance(source) }.unwrap(),
        Ax200ScanPhase::DrainRequired
    );
}
fn notification(command: u8) -> Vec<u8> {
    command_packet(
        super::super::super::super::command::Id {
            group: 0,
            opcode: command,
            version: 0,
        },
        0x8000,
        &[],
    )
}
fn replenish_prefix_for_receive(
    scan: &mut Ax200Scan<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    needed: u16,
) {
    // The real cold-boot command prefix has already consumed RX buffers. A
    // device may not complete the longer scenarios below against unposted
    // descriptors, even though their RAM was allocated at initialization.
    let credits = boot(scan).credits;
    let read = boot(scan).read;
    let producer = native.state.lock().unwrap().registers[&0x1c80];
    let command = native.state.lock().unwrap().registers[&0x460];
    let allocations = native.domain.records.lock().unwrap().live.len();
    assert_eq!(u32::from(credits + read), producer);
    assert!(credits < needed);
    assert!(read + needed < boot(scan).entries);
    assert_eq!(boot(scan).hcmd.notification_count(), 0);
    // Use the production handoff, free-descriptor writes and grouped
    // producer doorbell. Never mutate credits or device ownership in a peer.
    let replenished = scan.replenish_completed_receive().unwrap();
    assert_eq!(replenished.returned, read);
    assert_ne!(replenished.published, 0);
    assert!(replenished.published.is_multiple_of(8));
    assert_eq!(replenished.device_credits, credits + replenished.published);
    assert_eq!(boot(scan).credits, replenished.device_credits);
    assert!(replenished.device_credits >= needed);
    assert!(!replenished.waiting_for_completed_slot);
    let published = native.state.lock().unwrap().registers[&0x1c80];
    assert_eq!(
        published,
        (producer + u32::from(replenished.published)) & u32::from(boot(scan).entries - 1)
    );
    assert_ne!(published, producer);
    assert_eq!(native.state.lock().unwrap().registers[&0x460], command);
    assert_eq!(
        native.domain.records.lock().unwrap().live.len(),
        allocations
    );
    // These scenarios do not wrap. Verify that each forthcoming peer event
    // uses the original VID/address posted in its free descriptor,
    // including the initially staged descriptors beyond the old producer.
    for slot in read..read + needed {
        let descriptor = device_read(
            &native.domain,
            boot(scan).free.region().address,
            usize::from(slot) * 8,
            8,
        );
        let descriptor = u64::from_le_bytes(descriptor.try_into().unwrap());
        let buffer = &boot(scan).buffers[usize::from(slot)];
        assert!(buffer.device_owned);
        assert_eq!(descriptor & 0xfff, u64::from(slot + 1));
        assert_eq!(descriptor & !0xfff, buffer.allocation.region().address);
    }
}
#[test]
fn completed_scan_retires_and_second_scan_uses_new_ticket_real_dma_and_completion() {
    let bytes = bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (mut scan, mut sequence, mut entry) =
        ready(&catalog, &empty, &source, &native, &policy, false);
    replenish_prefix_for_receive(&mut scan, &native, 6);
    let mut previous_ticket = None;
    let mut histories = Vec::new();
    for turn in 0..2 {
        let maps = native.domain.records.lock().unwrap().live.len();
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
        let command = scan.command_ticket().unwrap().clone();
        assert_eq!(command.sequence(), sequence);
        ack(&scan, &native, entry, sequence, false);
        assert_eq!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { scan.advance(&source) }.unwrap(),
            Ax200ScanPhase::Scanning
        );
        complete(
            boot(&scan),
            &native.domain,
            entry + 1,
            entry + 2,
            &beacon_packet(),
        );
        let result = match scan.poll_result().unwrap() {
            ScanResultProgress::Observed(result) => result,
            _ => panic!("peer beacon"),
        };
        let ticket = result.result().unwrap().ticket;
        if let Some(previous) = previous_ticket {
            assert_ne!(ticket, previous);
        }
        previous_ticket = Some(ticket);
        complete(
            boot(&scan),
            &native.domain,
            entry + 2,
            entry + 3,
            &completion(0, 1, 0),
        );
        assert_eq!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { scan.advance(&source) }.unwrap(),
            Ax200ScanPhase::DrainRequired
        );
        let bell = native.state.lock().unwrap().registers[&0x460];
        let producer = native.state.lock().unwrap().registers[&0x1c80];
        assert!(matches!(
            scan.retire(),
            Err(Ax200ScanError::DeferredUsers(1))
        ));
        assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
        assert_eq!(scan.protocol_phase(), scan::Phase::Retiring);
        assert!(scan.request().is_some());
        drop(result);
        let retired = scan.retire().unwrap();
        assert_eq!(native.state.lock().unwrap().registers[&0x1c80], producer);
        assert_eq!(retired.outcome(), scan::Outcome::Completed);
        assert_eq!(retired.start_response().ticket, command);
        assert_eq!(retired.completion().raw_packet()[4..8], [0x0f, 0, 0, 0x80]);
        assert!(retired.abort_response().is_none());
        assert_eq!(retired.command_bytes().len(), 1940);
        assert_eq!(scan.protocol_phase(), scan::Phase::Idle);
        assert_eq!(scan.phase(), Ax200ScanPhase::NotStarted);
        assert!(scan.request().is_none());
        assert!(scan.command_ticket().is_none());
        assert!(scan.completion().is_none());
        assert_eq!(native.domain.records.lock().unwrap().live.len(), maps);
        histories.push(retired);
        assert_eq!(policy.acquired.load(Ordering::SeqCst), 3 * (turn + 1));
        // poll_result obtains a real policy pair too. No retirement radio/OS
        // grant and no invented channel-restore command is issued.
        sequence += 1;
        entry += 3;
    }
    assert_ne!(
        histories[0].start_response().ticket,
        histories[1].start_response().ticket
    );
    scan.stop().unwrap();
    drop(scan);
    assert!(native.domain.records.lock().unwrap().live.is_empty());
    assert_eq!(histories[0].command_bytes(), histories[1].command_bytes());
    assert_eq!(native.drops.load(Ordering::Relaxed), 1);
}
#[test]
fn every_scan_result_variant_pins_retirement_until_real_consumer_drop() {
    for case in 0..4 {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
        ack(&scan, &native, entry, sequence, false);
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.advance(&source) }.unwrap();
        let mut packet = beacon_packet();
        match case {
            1 => packet[20] = 0, // CRC/overrun rejected at normalization
            2 => native.revoked.store(true, Ordering::SeqCst),
            3 => packet[8..10].copy_from_slice(&u16::MAX.to_le_bytes()),
            _ => (),
        }
        complete(boot(&scan), &native.domain, entry + 1, entry + 2, &packet);
        let result = scan.poll_result().unwrap();
        match &result {
            ScanResultProgress::Observed(result) => assert_eq!(result.result().is_ok(), case == 0),
            ScanResultProgress::Rejected(rejected) => {
                assert_eq!(case, 3);
                assert!(!rejected.raw_packet().is_empty());
            }
            _ => panic!("actual result missing"),
        }
        complete(
            boot(&scan),
            &native.domain,
            entry + 2,
            entry + 3,
            &completion(0, 1, 0),
        );
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.advance(&source) }.unwrap();
        assert!(matches!(
            scan.retire(),
            Err(Ax200ScanError::DeferredUsers(1))
        ));
        assert!(scan.request().is_some());
        drop(result);
        assert_eq!(scan.retire().unwrap().outcome(), scan::Outcome::Completed);
        if case == 2 {
            let allocations = source.calls.load(Ordering::Relaxed);
            assert!(matches!(
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { scan.start(request(false), 30_000_000, &source) },
                Err(Ax200ScanError::Country(Ax200CountryError::Revoked))
            ));
            assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
        }
        scan.stop().unwrap();
    }
}
#[test]
fn late_completed_rb_is_raw_only_and_its_observer_must_finish_before_uid_reuse() {
    for rejected in [false, true] {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
        complete_scan(&mut scan, &native, &source, sequence, entry);
        let mut late = beacon_packet();
        if rejected {
            late[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
        }
        let length = (u32::from_le_bytes(late[..4].try_into().unwrap()) & 0x3fff) as usize + 4;
        complete(boot(&scan), &native.domain, entry + 2, entry + 3, &late);
        assert!(matches!(
            scan.retire(),
            Err(Ax200ScanError::PostScanReceiveRequired)
        ));
        assert!(matches!(scan.poll_result(), Err(Ax200ScanError::State)));
        let raw = scan.poll_retiring_receive().unwrap().unwrap();
        let actual = match raw.progress() {
            MpduProgress::Observed(value) => {
                assert!(!rejected);
                value.raw_packet()
            }
            MpduProgress::Rejected(value) => {
                assert!(rejected);
                value.raw_packet()
            }
            _ => panic!("late packet lost"),
        };
        assert_eq!(actual, &late[..length]);
        assert!(scan.poll_retiring_receive().unwrap().is_none());
        assert!(matches!(
            scan.retire(),
            Err(Ax200ScanError::DeferredUsers(1))
        ));
        scan.replenish_completed_receive().unwrap();
        assert!(matches!(
            scan.retire(),
            Err(Ax200ScanError::DeferredUsers(1))
        ));
        drop(raw);
        scan.retire().unwrap();
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
        ack(&scan, &native, entry + 3, sequence + 1, false);
        assert_eq!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { scan.advance(&source) }.unwrap(),
            Ax200ScanPhase::Scanning
        );
        complete(
            boot(&scan),
            &native.domain,
            entry + 4,
            entry + 5,
            &completion(0, 1, 0),
        );
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.advance(&source) }.unwrap();
        scan.retire().unwrap();
        scan.stop().unwrap();
    }
}
#[test]
fn duplicate_completion_mcc_and_unrelated_notifications_are_never_dropped_for_retirement() {
    for case in 0..3 {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
        complete_scan(&mut scan, &native, &source, sequence, entry);
        let packet = if case == 0 {
            completion(0, 1, 0)
        } else {
            notification(if case == 1 { 0xc9 } else { 0x99 })
        };
        complete(boot(&scan), &native.domain, entry + 2, entry + 3, &packet);
        if case == 2 {
            assert!(matches!(
                scan.retire(),
                Err(Ax200ScanError::NotificationsRequired(1))
            ));
            assert_eq!(scan.take_other_notification().unwrap().command, 0x99);
            scan.retire().unwrap();
        } else {
            assert!(matches!(
                scan.retire(),
                Err(Ax200ScanError::StaleNotification)
            ));
            assert_eq!(scan.phase(), Ax200ScanPhase::Failed);
            assert!(scan.take_other_notification().is_none());
            assert_eq!(boot(&scan).hcmd.notification_count(), 1);
            assert!(scan.request().is_some());
            assert!(scan.completion().is_some());
        }
        scan.stop().unwrap();
    }
}
#[test]
fn stale_first_request_completion_after_retirement_cannot_complete_second_request() {
    let bytes = bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
    complete_scan(&mut scan, &native, &source, sequence, entry);
    let first = scan.retire().unwrap();
    assert_eq!(first.completion().outcome(), scan::Outcome::Completed);
    complete(
        boot(&scan),
        &native.domain,
        entry + 2,
        entry + 3,
        &completion(0, 1, 0),
    );
    let allocations = source.calls.load(Ordering::Relaxed);
    let acquired = policy.acquired.load(Ordering::SeqCst);
    let bell = native.state.lock().unwrap().registers[&0x460];
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.start(request(false), 30_000_000, &source) },
        Err(Ax200ScanError::StaleNotification)
    );
    assert_eq!(scan.protocol_phase(), scan::Phase::Idle);
    assert!(scan.command_ticket().is_none());
    assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
    assert_eq!(policy.acquired.load(Ordering::SeqCst), acquired);
    assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
    assert!(scan.take_other_notification().is_none());
    scan.stop().unwrap();
}
#[test]
fn retirement_native_read_fault_is_sticky_and_keeps_original_owners() {
    let bytes = bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
    complete_scan(&mut scan, &native, &source, sequence, entry);
    {
        let mut state = native.state.lock().unwrap();
        state.fail = Some(state.ops.len() + 1);
    }
    let error = match scan.retire() {
        Err(error @ Ax200ScanError::Boot(_)) => error,
        _ => panic!("read failure missing"),
    };
    native.state.lock().unwrap().fail = None;
    assert!(matches!(scan.retire(), Err(next) if next == error));
    assert_eq!(scan.first_error(), Some(&error));
    assert_eq!(scan.protocol_phase(), scan::Phase::Retiring);
    assert!(scan.request().is_some());
    drop(scan);
    assert!(!native.domain.records.lock().unwrap().live.is_empty());
    assert_eq!(native.drops.load(Ordering::Relaxed), 0);
    assert_eq!(native.bios_drops.load(Ordering::Relaxed), 0);
    assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
}
#[test]
fn abort_ack_and_aborted_completion_retire_without_repairing_revoked_country() {
    for revoked in [false, true] {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
        ack(&scan, &native, entry, sequence, false);
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.advance(&source) }.unwrap();
        if revoked {
            native.revoked.store(true, Ordering::SeqCst);
        } else {
            scan.cancel().unwrap();
        }
        assert_eq!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { scan.advance(&source) }.unwrap(),
            Ax200ScanPhase::WaitingAbort
        );
        assert!(matches!(scan.retire(), Err(Ax200ScanError::State)));
        ack(&scan, &native, entry + 1, sequence + 1, true);
        assert_eq!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { scan.advance(&source) }.unwrap(),
            Ax200ScanPhase::Cancelling
        );
        assert!(matches!(scan.retire(), Err(Ax200ScanError::State)));
        complete(
            boot(&scan),
            &native.domain,
            entry + 2,
            entry + 3,
            &completion(0, 2, 0),
        );
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.advance(&source) }.unwrap();
        let retired = scan.retire().unwrap();
        assert_eq!(retired.outcome(), scan::Outcome::Aborted);
        assert!(retired.abort_response().is_some());
        assert_eq!(scan.protocol_phase(), scan::Phase::Idle);
        if revoked {
            let error = scan.first_error().unwrap().clone();
            assert_eq!(
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { scan.start(request(false), 30_000_000, &source) },
                Err(error)
            );
        } else {
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
        }
        scan.stop().unwrap();
    }
}

#[test]
fn retirement_backpressure_preserves_hidden_rb_and_requires_real_notification_consumption() {
    let bytes = bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
    replenish_prefix_for_receive(&mut scan, &native, 5);
    complete_scan(&mut scan, &native, &source, sequence, entry);
    let mut unrelated = notification(0x99);
    let header = unrelated[..8].to_vec();
    unrelated.fill(0);
    for at in (0..4096).step_by(64) {
        unrelated[at..at + 8].copy_from_slice(&header);
    }
    complete(
        boot(&scan),
        &native.domain,
        entry + 2,
        entry + 3,
        &unrelated,
    );
    complete(
        boot(&scan),
        &native.domain,
        entry + 3,
        entry + 4,
        &unrelated,
    );
    complete(
        boot(&scan),
        &native.domain,
        entry + 4,
        entry + 5,
        &beacon_packet(),
    );
    let before = boot(&scan).read;
    let producer = native.state.lock().unwrap().registers[&0x1c80];
    assert!(matches!(
        scan.retire(),
        Err(Ax200ScanError::ReceiveBackpressure { notifications: 128 })
    ));
    assert_eq!(boot(&scan).read, before + 2);
    assert_eq!(native.state.lock().unwrap().registers[&0x1c80], producer);
    assert!(scan.request().is_some());
    let mut count = 0;
    while let Some(notification) = scan.take_other_notification() {
        assert_eq!(notification.command, 0x99);
        count += 1;
    }
    assert_eq!(count, 128);
    assert!(matches!(
        scan.retire(),
        Err(Ax200ScanError::PostScanReceiveRequired)
    ));
    assert_eq!(boot(&scan).read, before + 3);
    let raw = scan.poll_retiring_receive().unwrap().unwrap();
    assert!(matches!(raw.progress(), MpduProgress::Observed(_)));
    assert!(matches!(
        scan.retire(),
        Err(Ax200ScanError::DeferredUsers(1))
    ));
    drop(raw);
    scan.retire().unwrap();
    scan.stop().unwrap();
}
#[test]
fn command_reclaim_failure_cannot_retire_even_with_terminal_packet_already_in_same_rb() {
    let bytes = bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
    let mut packet = command_packet(
        super::super::super::super::command::Id {
            group: 1,
            opcode: 0x0d,
            version: 0,
        },
        sequence,
        &[],
    );
    let terminal = completion(0, 1, 0);
    packet[64..88].copy_from_slice(&terminal[..24]);
    packet[128..132].copy_from_slice(&0x55550000u32.to_le_bytes());
    complete(boot(&scan), &native.domain, entry, entry + 1, &packet);
    {
        let mut records = native.domain.records.lock().unwrap();
        records.cpu_sync_fail = Some(records.cpu_syncs + 1);
    }
    assert!(matches!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.advance(&source) },
        Err(Ax200ScanError::Boot(Error::CommandReclaim(_)))
    ));
    assert!(boot(&scan).hcmd.pending_is_present());
    assert!(matches!(scan.retire(), Err(Ax200ScanError::State)));
    assert_eq!(scan.protocol_phase(), scan::Phase::Submitted);
    assert!(scan.start_response().is_none());
    native.domain.records.lock().unwrap().cpu_sync_fail = None;
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.advance(&source) }.unwrap(),
        Ax200ScanPhase::DrainRequired
    );
    assert!(!boot(&scan).hcmd.pending_is_present());
    scan.retire().unwrap();
    scan.stop().unwrap();
}
