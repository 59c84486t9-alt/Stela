// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
use super::*;

#[test]
fn mcc_query_bios_selection_and_response_never_echo_requested_country() {
    exercise_mcc(false);
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn mcc_ax200_v5_response_is_kept_with_original_dma_epoch() {
    exercise_mcc(true);
}
fn exercise_mcc(actual: bool) {
    let bytes = if actual {
        use sha2::{Digest, Sha256};
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        let bytes =
            std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
        );
        bytes
    } else {
        setup_bytes()
    };
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let bios_drops = Arc::new(AtomicUsize::new(0));
    let boot = start(&catalog, &source, &domain, &state, &drops);
    let boot = command_ready(boot, &empty, &source, &domain, &state);
    let init = drive_nvm(boot, &source, &domain, &state);
    let (lari, sequence, entry) = finish_lari(init, &source, &domain, &bios_drops, None);
    let (setup, sequence, entry) = finish_setup(lari, sequence, entry, &source, &domain);
    let mut mcc = setup.begin_mcc().unwrap_or_else(|_| panic!("actual setup"));
    // The source explicitly sends MCC in RF-kill. It is not an RF grant.
    *state.lock().unwrap().registers.get_mut(&0x24).unwrap() &= !0x08000000;
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { mcc.advance(&source) }.unwrap(),
        Ax200MccPhase::WaitingCurrent
    );
    for (i, (request, reply, source_id)) in [(*b"ZZ", *b"US", 0x10), (*b"CN", *b"JP", 2)]
        .iter()
        .enumerate()
    {
        let sequence = sequence + i as u16;
        let descriptor = device_read(
            &domain,
            mcc.setup
                .lari
                .radio
                .initialized
                .boot
                .command
                .region()
                .address,
            usize::from(sequence & 31) * 256,
            256,
        );
        let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
        let id = crate::net::wifi::intel::mcc::Request::id();
        let payload = crate::net::wifi::intel::mcc::Request {
            country: *request,
            source: *source_id,
        }
        .bytes()
        .unwrap();
        let encoded =
            crate::net::wifi::intel::command::Command::encode(id, 0, sequence, &payload).unwrap();
        let mut emitted = device_read(&domain, first, 0, 20);
        let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
        emitted.extend(device_read(&domain, rest, 0, encoded.bytes().len() - 20));
        assert_eq!(emitted, encoded.bytes());
        let bell = state.lock().unwrap().registers[&0x460];
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { mcc.advance(&source) }.unwrap();
        assert_eq!(state.lock().unwrap().registers[&0x460], bell);
        complete(
            &mcc.setup.lari.radio.initialized.boot,
            &domain,
            entry + i as u16,
            entry + i as u16 + 1,
            &command_packet(
                crate::net::wifi::intel::command::Id {
                    group: 1,
                    opcode: 0xc8,
                    version: 0,
                },
                sequence,
                &mcc_payload(*reply, *source_id, 51),
            ),
        );
        let mut r = domain.records.lock().unwrap();
        r.cpu_sync_fail = Some(r.cpu_syncs + 1);
        drop(r);
        assert!(matches!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { mcc.advance(&source) },
            Err(Ax200MccError::Boot(Error::CommandReclaim(_)))
        ));
        assert_eq!(mcc.profiles().len(), i);
        assert!(mcc.first_error().is_none());
        domain.records.lock().unwrap().cpu_sync_fail = None;
        assert_eq!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { mcc.advance(&source) }.unwrap(),
            if i == 0 {
                Ax200MccPhase::WaitingBios
            } else {
                Ax200MccPhase::PolicyRequired
            }
        );
        assert_eq!(mcc.profiles().last().unwrap().country, *reply);
        assert_ne!(mcc.profiles().last().unwrap().country, *request);
    }
    assert_eq!(mcc.channels().len(), 51);
    assert_eq!(mcc.channels().iter().filter(|c| c.valid).count(), 1);
    assert_eq!(
        mcc.bios_country().unwrap(),
        crate::net::wifi::intel::radio::lari::Observation::Observed(
            crate::net::wifi::intel::radio::lari::Value {
                value: 0x434e,
                source: crate::net::wifi::intel::radio::lari::Source::Uefi,
                revision: 0
            }
        )
    );
    assert_eq!(mcc.responses().len(), 2);
    assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
    mcc.stop().unwrap();
    drop(mcc);
    assert!(domain.records.lock().unwrap().live.is_empty());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
}
