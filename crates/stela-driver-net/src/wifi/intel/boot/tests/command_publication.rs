// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn hcmd_wrong_duplicate_and_foreign_completions_do_not_grant_reclaim() {
    for sequence in [0x100, 1, 0x4000, 0] {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        // SAFETY: Source supplies fresh exclusive RAM in this boot owner's model domain;
        // command_id selects the fixture transport API and has no indirect DMA objects.
        let ticket = unsafe { boot.submit_command(command_id(), &[0; 40], &source) }.unwrap();
        let live = domain.records.lock().unwrap().live.len();
        let mut packet = command_packet(command_id(), sequence, &[1]);
        if sequence == 0 {
            let dup = packet.clone();
            packet[64..128].copy_from_slice(&dup[..64]);
            packet[128..132].copy_from_slice(&0x55550000u32.to_le_bytes());
        }
        complete(&boot, &domain, 1, 2, &packet);
        assert!(matches!(
            boot.poll_command(&ticket),
            Err(Error::CommandSequence(_))
        ));
        assert_eq!(domain.records.lock().unwrap().live.len(), live);
        assert!(matches!(
            boot.poll_command(&ticket),
            Err(Error::CommandTicket)
        ));
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
    let bytes = firmware_bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let boot = start(&catalog, &source, &domain, &state, &drops);
    let mut first = command_ready(boot, &empty, &source, &domain, &state);
    // SAFETY: The first polling owner keeps its own source/domain and fresh RAM;
    // this fixture command has no external firmware objects or indirect allocations.
    let ticket = unsafe { first.submit_command(command_id(), &[], &source) }.unwrap();
    let other_source = Source::default();
    let other_domain = Arc::new(Domain::default());
    let other_state = Arc::new(Mutex::new(ModelState::default()));
    let other_drops = Arc::new(AtomicUsize::new(0));
    let boot = start(
        &catalog,
        &other_source,
        &other_domain,
        &other_state,
        &other_drops,
    );
    let mut other = command_ready(boot, &empty, &other_source, &other_domain, &other_state);
    // SAFETY: This second epoch uses other_source and other_domain, never the first
    // owner's backing; the serialized model command has no indirect DMA resources.
    let other_ticket = unsafe { other.submit_command(command_id(), &[], &other_source) }.unwrap();
    assert_eq!(ticket.sequence(), other_ticket.sequence());
    assert_ne!(ticket, other_ticket);
    let before = other_state.lock().unwrap().ops.len();
    assert!(matches!(
        other.poll_command(&ticket),
        Err(Error::CommandTicket)
    ));
    assert_eq!(other_state.lock().unwrap().ops.len(), before);
    first.stop().unwrap();
    other.stop().unwrap();
}

#[test]
fn hcmd_publication_faults_keep_real_owner_and_all_exposed_dma() {
    // Alloc/map/initial visibility/TB0 visibility precede descriptor
    // publication; descriptor visibility or producer failure is uncertain.
    for failure in 0..6 {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let mut source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        let live = domain.records.lock().unwrap().live.len();
        if failure == 0 {
            source.fail_at = Some(source.calls.load(Ordering::Relaxed));
        }
        if failure == 1 {
            let mut r = domain.records.lock().unwrap();
            r.map_fail = Some(r.maps);
        }
        if (2..=4).contains(&failure) {
            let mut r = domain.records.lock().unwrap();
            r.sync_fail = Some(r.syncs + failure - 2);
        }
        if failure == 5 {
            let mut s = state.lock().unwrap();
            s.fail = Some(s.ops.len() + 1);
        }
        // SAFETY: The same model owner/source keep all mappings through injected failures;
        // only serialized allocation/visibility/producer operations can fail here.
        assert!(unsafe { boot.submit_command(command_id(), &[0; 40], &source) }.is_err());
        assert_eq!(
            domain.records.lock().unwrap().live.len(),
            live + usize::from(failure >= 4)
        );
        if failure >= 4 {
            assert_eq!(boot.state, State::Poisoned);
            state.lock().unwrap().stop_ack = false;
            assert!(boot.stop().is_err());
            drop(boot);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(domain.records.lock().unwrap().live.len(), live + 1);
        } else {
            assert_eq!(boot.state, State::PnvmObserved);
            state.lock().unwrap().fail = None;
            boot.stop().unwrap();
            assert!(domain.records.lock().unwrap().live.is_empty());
        }
    }
}

#[test]
fn hcmd_ring_and_sequence_wrap_match_each_family_without_reusing_live_slots() {
    for ax210 in [false, true] {
        let p = if ax210 { ax210_profile() } else { profile() };
        let bytes = if ax210 {
            ax210_bytes()
        } else {
            firmware_bytes()
        };
        let catalog = catalog_for(&p, p.family().firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let (observation, step_catalog) = step_fixture();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = if ax210 {
            ax210_state()
        } else {
            Arc::new(Mutex::new(ModelState::default()))
        };
        let drops = Arc::new(AtomicUsize::new(0));
        let staged = crate::wifi::intel::identity::stage(&p, &catalog).unwrap();
        let awake = awake_profile(state.clone(), drops.clone(), p);
        let boot = if ax210 {
            // SAFETY: The AX210 model has exclusive Source/domain RAM and synchronous register
            // observations; NoIwlmei keeps this sole reset owner with no SAP or IRQ user.
            unsafe {
                RomBoot::start_ax210(
                    awake,
                    staged,
                    crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
                    &source,
                    Some(domain.clone()),
                    256,
                    ProductResetPolicy::NoIwlmei,
                )
            }
        } else {
            // SAFETY: The AX200 model uses fresh exclusive Source RAM attached to this Domain;
            // Model serializes register/completion effects and has no competing reset worker.
            unsafe { RomBoot::start(awake, staged, &source, Some(domain.clone()), 512) }
        }
        .unwrap();
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        let ring = boot.command.region().address;
        let sentinel = device_read(&domain, ring, 0, 256);
        let count = if ax210 { 132u16 } else { 260u16 };
        let slots = if ax210 { 128u16 } else { 32u16 };
        for n in 0..count {
            // SAFETY: Each prior command completed and reclaimed before this iteration; the
            // same model owner/source publish this direct payload without indirect resources.
            let ticket = unsafe { boot.submit_command(command_id(), &[n as u8], &source) }.unwrap();
            assert_eq!(ticket.sequence(), n & 255);
            let wire = device_read(&domain, ring, usize::from(n & (slots - 1)) * 256, 256);
            let first = u64::from_le_bytes(wire[4..12].try_into().unwrap());
            let hdr = device_read(&domain, first, 0, 9);
            assert_eq!(u16::from_le_bytes(hdr[2..4].try_into().unwrap()), n & 255);
            assert_eq!(hdr[8], n as u8);
            assert_eq!(
                state.lock().unwrap().registers.get(&0x460),
                Some(&u32::from(if ax210 { n + 1 } else { (n + 1) & 255 }))
            );
            complete(
                &boot,
                &domain,
                n + 1,
                n + 2,
                &command_packet(command_id(), ticket.sequence(), &[]),
            );
            assert!(matches!(
                boot.poll_command(&ticket).unwrap(),
                CommandProgress::Completed(_)
            ));
            assert_eq!(
                device_read(&domain, ring, usize::from(n & (slots - 1)) * 256, 256),
                sentinel
            );
        }
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
}

#[test]
fn hcmd_exhausted_boot_rx_credit_refuses_publication() {
    let bytes = firmware_bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let boot = start(&catalog, &source, &domain, &state, &drops);
    let mut boot = command_ready(boot, &empty, &source, &domain, &state);
    // All posted credits are consumed by real completed RX notifications,
    // not by an invented successful repost in this boot-only receiver.
    // SAFETY: The polling owner keeps its original model source/domain and RAM;
    // this fixture command has no indirect resources, and completions are serialized.
    let ticket = unsafe { boot.submit_command(command_id(), &[], &source) }.unwrap();
    for index in 1..24 {
        let seq = if index == 23 {
            ticket.sequence()
        } else {
            0x8000
        };
        complete(
            &boot,
            &domain,
            index,
            index + 1,
            &command_packet(command_id(), seq, &[]),
        );
        let result = boot.poll_command(&ticket).unwrap();
        assert_eq!(matches!(result, CommandProgress::Completed(_)), index == 23);
    }
    let ops = state.lock().unwrap().ops.len();
    let maps = domain.records.lock().unwrap().maps;
    assert!(matches!(
        // SAFETY: The original model epoch/source remain exclusive even with no RX credit;
        // the direct fixture payload has no indirect resources before publication refusal.
        unsafe { boot.submit_command(command_id(), &[0; 40], &source) },
        Err(Error::CompletionCredit)
    ));
    assert_eq!(state.lock().unwrap().ops.len(), ops);
    assert_eq!(domain.records.lock().unwrap().maps, maps);
    boot.stop().unwrap();
}
