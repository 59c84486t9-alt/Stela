// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn hcmd_real_tfd_writeback_and_rx_completion_own_payload_lifetime() {
    use crate::net::wifi::intel::command::{Command, Tfd};
    let bytes = ax210_bytes();
    let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let (observation, step_catalog) = step_fixture();
    let step = crate::net::wifi::intel::platform::load_step(observation, &step_catalog).unwrap();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = ax210_state();
    let drops = Arc::new(AtomicUsize::new(0));
    let boot = start_ax210(&catalog, step, &source, &domain, &state, &drops);
    let mut boot = command_ready(boot, &empty, &source, &domain, &state);
    let ring = boot.command.region().address;
    let sentinel = device_read(&domain, ring, 0, 256);
    assert_eq!(u16::from_le_bytes(sentinel[..2].try_into().unwrap()), 1);
    let invalid = u64::from_le_bytes(sentinel[4..12].try_into().unwrap());
    assert_eq!(
        device_read(&domain, invalid, 0, 8),
        [6, 15, 255, 255, 0, 0, 0, 0]
    );
    for slot in 0..128 {
        assert_eq!(device_read(&domain, ring, slot * 256, 256), sentinel);
    }
    let payload: Vec<_> = (0..100u8).collect();
    // SAFETY: The AX210 model keeps its exact domain and fresh exclusive Source RAM;
    // this serialized direct-payload command carries no indirect firmware objects.
    let ticket = unsafe { boot.submit_command(command_id(), &payload, &source) }.unwrap();
    let pending_live = domain.records.lock().unwrap().live.len();
    assert!(matches!(
        // SAFETY: The first command's backing remains held by this same polling owner;
        // Source/domain stay exclusive while the second direct payload is refused.
        unsafe { boot.submit_command(command_id(), &payload, &source) },
        Err(Error::CommandPending)
    ));
    assert_eq!(domain.records.lock().unwrap().live.len(), pending_live);
    let wire = device_read(&domain, ring, 0, 256);
    assert_eq!(u16::from_le_bytes(wire[..2].try_into().unwrap()), 2);
    let first = u64::from_le_bytes(wire[4..12].try_into().unwrap());
    let rest = u64::from_le_bytes(wire[14..22].try_into().unwrap());
    let cmd = Command::encode(command_id(), 0, 0, &payload).unwrap();
    assert_eq!(
        wire,
        Tfd::encode(&[
            crate::net::wifi::intel::context::Region {
                address: first,
                bytes: 20
            },
            crate::net::wifi::intel::context::Region {
                address: rest,
                bytes: 88
            },
        ])
        .unwrap()
        .bytes()
    );
    assert_eq!(device_read(&domain, first, 0, 20), cmd.first_tb());
    assert_eq!(device_read(&domain, rest, 0, 88), cmd.remainder());
    assert_eq!(state.lock().unwrap().registers.get(&0x460), Some(&1));
    device_write(&domain, first, 12, &[0xa5; 8], false);
    assert_eq!(
        boot.poll_command(&ticket).unwrap(),
        CommandProgress::Pending
    );
    assert_eq!(domain.records.lock().unwrap().live.len(), pending_live);
    complete(
        &boot,
        &domain,
        1,
        2,
        &command_packet(command_id(), ticket.sequence(), &[0xde, 0xad, 0, 0]),
    );
    let response = match boot.poll_command(&ticket).unwrap() {
        CommandProgress::Completed(r) => r,
        _ => panic!("not complete"),
    };
    assert_eq!(response.ticket, ticket);
    assert_eq!(response.raw, [0xde, 0xad, 0, 0]);
    assert_eq!(response.request, command_id());
    assert_eq!(device_read(&domain, ring, 0, 256), sentinel);
    assert_eq!(domain.records.lock().unwrap().live.len(), pending_live - 1);
    assert!(matches!(
        boot.poll_command(&ticket),
        Err(Error::CommandTicket)
    ));
    boot.stop().unwrap();
    assert!(domain.records.lock().unwrap().live.is_empty());
}

#[test]
fn hcmd_source_no_reclaim_and_all_notifications_in_completed_rb_are_preserved() {
    let bytes = firmware_bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let boot = start(&catalog, &source, &domain, &state, &drops);
    let mut boot = command_ready(boot, &empty, &source, &domain, &state);
    let raw = command_packet(command_id(), 0x1234, &[]);
    let mut forged = Packets::new(Family::Ax200, 0, &raw)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    forged.command = 0x1c;
    forged.group = 0;
    forged.sequence = 0x8000;
    let before = state.lock().unwrap().ops.len();
    assert_eq!(
        boot.hcmd.retain_notification(&forged),
        Err(Error::CommandSequence(0x1234))
    );
    assert!(boot.take_firmware_notification().is_none());
    assert_eq!(state.lock().unwrap().ops.len(), before);
    // SAFETY: The sole model polling owner keeps the original domain and exclusive
    // Source; the selected fixture API has no indirect allocations or device users.
    let ticket = unsafe { boot.submit_command(command_id(), &[0; 40], &source) }.unwrap();
    for (index, id, sequence) in [
        (1, command_id(), 0x8000),
        (
            2,
            crate::net::wifi::intel::command::Id {
                group: 0,
                opcode: 0x1c,
                version: 0,
            },
            0,
        ),
    ] {
        complete(
            &boot,
            &domain,
            index,
            index + 1,
            &command_packet(id, sequence, &[1, 2]),
        );
        assert_eq!(
            boot.poll_command(&ticket).unwrap(),
            CommandProgress::Pending
        );
        let notification = boot.take_firmware_notification().unwrap();
        assert_eq!(notification.command, id.opcode);
    }
    let mut packet = command_packet(command_id(), ticket.sequence(), &[0xff]);
    let notification_id = crate::net::wifi::intel::command::Id {
        group: 0,
        opcode: 4,
        version: 0,
    };
    let second = command_packet(notification_id, 0x8000, &[0x42]);
    packet[64..128].copy_from_slice(&second[..64]);
    packet[128..132].copy_from_slice(&0x55550000u32.to_le_bytes());
    complete(&boot, &domain, 3, 4, &packet);
    assert!(matches!(
        boot.poll_command(&ticket).unwrap(),
        CommandProgress::Completed(_)
    ));
    assert_eq!(boot.take_firmware_notification().unwrap().raw, [0x42]);
    assert!(boot.take_firmware_notification().is_none());
    boot.stop().unwrap();
}

#[test]
fn hcmd_completion_reclaim_retries_without_releasing_or_resubmitting() {
    for failure in 0..4 {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        // SAFETY: This failure-matrix epoch owns fresh Source RAM in its original Domain;
        // the direct command has no indirect resources and model completion is serialized.
        let ticket = unsafe { boot.submit_command(command_id(), &[0xa5; 40], &source) }.unwrap();
        let live = domain.records.lock().unwrap().live.len();
        complete(
            &boot,
            &domain,
            1,
            2,
            &command_packet(command_id(), ticket.sequence(), &[0x7f]),
        );
        {
            let mut r = domain.records.lock().unwrap();
            if failure == 0 {
                r.sync_fail = Some(r.syncs);
            } else if failure == 1 {
                r.unmap_fail = Some(r.unmaps);
            } else {
                r.cpu_sync_fail = Some(r.cpu_syncs + failure - 1);
            }
        }
        assert!(matches!(
            boot.poll_command(&ticket),
            Err(Error::CommandReclaim(_))
        ));
        assert_eq!(domain.records.lock().unwrap().live.len(), live);
        assert!(matches!(
            // SAFETY: Reclaim failure left this same epoch/source and all pending DMA kept;
            // there is no concurrent submit/reset owner or indirect resource to release.
            unsafe { boot.submit_command(command_id(), &[], &source) },
            Err(Error::CommandPending)
        ));
        {
            let mut r = domain.records.lock().unwrap();
            r.sync_fail = None;
            r.unmap_fail = None;
            r.cpu_sync_fail = None;
        }
        assert!(
            matches!(boot.poll_command(&ticket).unwrap(),CommandProgress::Completed(CommandResponse{raw,..}) if raw==[0x7f])
        );
        assert_eq!(domain.records.lock().unwrap().live.len(), live - 1);
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
}
