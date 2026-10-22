// SPDX-License-Identifier: GPL-2.0-only
//! Public receive-only GTK continuation, independent of a vendor or supplicant.

use stela_drivers::net::{
    Mac,
    wifi::{
        Band, RadioStatus, RawRate,
        frame::Mpdu,
        security::{
            Cipher, Error, InstallOutcome, InstallTicket, Integrity, KeyIdentity, KeyScope,
            KeySlot, PacketNumber, ReplaySeed, SecurityStatus, TransmitSeed,
        },
    },
};

const AP: Mac = Mac([2, 0, 0, 0, 0, 1]);
const MATERIAL: [u8; 16] = [0x21; 16];

fn slot() -> KeySlot {
    // SAFETY: pure model has no physical table, DMA or old deferred users.
    unsafe { KeySlot::new(7) }.unwrap()
}
fn pn(value: u64) -> PacketNumber {
    PacketNumber::new(value).unwrap()
}
fn fresh(slot: &mut KeySlot, material: &[u8], receive: ReplaySeed) -> InstallTicket {
    slot.begin_install(
        2,
        Cipher::Ccmp128,
        material,
        receive,
        KeyScope::Group(AP),
        TransmitSeed::RECEIVE_ONLY,
    )
    .unwrap()
}
fn retire(slot: &mut KeySlot) {
    slot.invalidate();
    // SAFETY: model acknowledgement/removal/drain has no physical users.
    unsafe { slot.retire_after_drain() };
}
fn resume(slot: &mut KeySlot, receive: ReplaySeed) -> Result<InstallTicket, Error> {
    // SAFETY: synthetic authenticated-command fixture specifies exact material,
    // group/BSSID/index/cipher and RSC; no real OS handshake is claimed here.
    unsafe {
        slot.begin_receive_only_resume(2, Cipher::Ccmp128, &MATERIAL, receive, KeyScope::Group(AP))
    }
}
fn frame(key: KeyIdentity, value: u64, queue: usize) -> Mpdu {
    let qos = queue < 16;
    let header = if qos { 26 } else { 24 };
    let mut bytes = vec![0; header + 3];
    bytes[..2].copy_from_slice(&(if qos { 0x4288_u16 } else { 0x4208_u16 }).to_le_bytes());
    bytes[4..10].fill(0xff);
    bytes[10..16].copy_from_slice(&AP.0);
    bytes[16..22].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    if qos {
        bytes[24] = queue as u8;
    }
    bytes[header..].copy_from_slice(&[1, 2, 3]);
    Mpdu::new(
        bytes,
        RadioStatus {
            band: Band::Ghz5,
            channel: 36,
            frequency_mhz: 5180,
            signal_dbm: Some(-40),
            chain_signal_dbm: [None; 4],
            rate: RawRate {
                layout: 1,
                words: [0; 4],
            },
            tsf: None,
        },
        SecurityStatus {
            key: Some(key),
            pn: Some(pn(value)),
            decrypted: true,
            integrity: Integrity::Verified,
            iv_stripped: true,
            mic_stripped: true,
            ..SecurityStatus::default()
        },
    )
    .unwrap()
}

#[test]
fn all_tid_and_non_qos_floors_survive_same_ap_reconnect_and_intervening_other_gtk() {
    let mut slot = slot();
    let initial = fresh(&mut slot, &MATERIAL, ReplaySeed::ZERO);
    slot.complete_install(initial, InstallOutcome::Accepted)
        .unwrap();
    let original = initial.identity();
    for queue in 0..17 {
        slot.authorize(&frame(original, 100 + queue as u64, queue))
            .unwrap();
    }
    retire(&mut slot);
    assert_eq!(
        slot.begin_install(
            2,
            Cipher::Ccmp128,
            &MATERIAL,
            ReplaySeed::ZERO,
            KeyScope::Group(AP),
            TransmitSeed::RECEIVE_ONLY
        ),
        Err(Error::Reinstallation)
    );
    let rsc = core::array::from_fn(|q| {
        pn(if q % 2 == 0 {
            50 + q as u64
        } else {
            150 + q as u64
        })
    });
    let ticket = resume(&mut slot, ReplaySeed::per_queue(rsc)).unwrap();
    let merged = core::array::from_fn::<_, 17, _>(|q| (100 + q as u64).max(rsc[q].value()));
    assert_eq!(ticket.receive_seed().counters(), merged);
    assert_eq!(ticket.transmit_seed(), TransmitSeed::RECEIVE_ONLY);
    assert_eq!(slot.installed(), None);
    assert_eq!(
        slot.authorize(&frame(original, 1000, 0)).unwrap_err(),
        Error::NoInstalledKey
    );
    slot.complete_install(ticket, InstallOutcome::Accepted)
        .unwrap();
    let current = ticket.identity();
    assert_ne!(current, original);
    assert_eq!(
        slot.authorize(&frame(original, 1000, 0)).unwrap_err(),
        Error::WrongKey
    );
    assert_eq!(
        slot.reserve_host_tx_nonce(current).unwrap_err(),
        Error::WrongNonceOwner
    );
    for (queue, floor) in merged.into_iter().enumerate() {
        assert_eq!(
            slot.authorize(&frame(current, floor, queue)).unwrap_err(),
            Error::Replay
        );
        slot.authorize(&frame(current, floor + 1, queue)).unwrap();
    }
    retire(&mut slot);
    let other = fresh(&mut slot, &[0x42; 16], ReplaySeed::ZERO);
    slot.complete_install(other, InstallOutcome::Accepted)
        .unwrap();
    retire(&mut slot);
    let next = resume(&mut slot, ReplaySeed::ZERO).unwrap();
    assert_eq!(next.receive_seed().counters(), merged.map(|v| v + 1));
    slot.complete_install(next, InstallOutcome::Accepted)
        .unwrap();
    for (queue, floor) in merged.into_iter().enumerate() {
        assert_eq!(
            slot.authorize(&frame(next.identity(), floor + 1, queue))
                .unwrap_err(),
            Error::Replay
        );
        slot.authorize(&frame(next.identity(), floor + 2, queue))
            .unwrap();
    }
}

#[test]
fn exact_group_material_bssid_cipher_and_index_are_required() {
    let mut slot = slot();
    let initial = fresh(&mut slot, &MATERIAL, ReplaySeed::uniform(pn(10)));
    slot.complete_install(initial, InstallOutcome::Accepted)
        .unwrap();
    retire(&mut slot);
    for (index, cipher, material, scope) in [
        (1, Cipher::Ccmp128, MATERIAL, KeyScope::Group(AP)),
        (2, Cipher::Gcmp128, MATERIAL, KeyScope::Group(AP)),
        (2, Cipher::Ccmp128, [0x22; 16], KeyScope::Group(AP)),
        (
            2,
            Cipher::Ccmp128,
            MATERIAL,
            KeyScope::Group(Mac([2, 0, 0, 0, 0, 2])),
        ),
    ] {
        // SAFETY: pure authenticated-input fixture; malformed exact scope must refuse.
        assert_eq!(
            unsafe {
                slot.begin_receive_only_resume(index, cipher, &material, ReplaySeed::ZERO, scope)
            },
            Err(Error::Reinstallation)
        );
    }
    assert_eq!(
        unsafe {
            slot.begin_receive_only_resume(
                0,
                Cipher::Ccmp128,
                &MATERIAL,
                ReplaySeed::ZERO,
                KeyScope::Pairwise(AP),
            )
        },
        Err(Error::WrongNonceOwner)
    );
    assert!(resume(&mut slot, ReplaySeed::uniform(pn(20))).is_ok());
}

#[test]
fn transmitting_or_pairwise_history_can_never_be_resumed_as_receive_only_gtk() {
    for transmit in [
        TransmitSeed::FIRMWARE_FRESH,
        TransmitSeed::host(pn(77)),
        TransmitSeed::RECEIVE_ONLY,
    ] {
        let mut slot = slot();
        let ticket = slot
            .begin_install(
                0,
                Cipher::Ccmp128,
                &MATERIAL,
                ReplaySeed::ZERO,
                KeyScope::Pairwise(AP),
                transmit,
            )
            .unwrap();
        slot.complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        retire(&mut slot);
        assert_eq!(
            resume(&mut slot, ReplaySeed::uniform(pn(1000))),
            Err(Error::Reinstallation)
        );
        assert_eq!(
            slot.begin_install(
                0,
                Cipher::Ccmp128,
                &MATERIAL,
                ReplaySeed::ZERO,
                KeyScope::Pairwise(AP),
                transmit
            ),
            Err(Error::Reinstallation)
        );
    }
}

#[test]
fn uncertain_resume_and_pending_drain_quarantine_until_real_retirement_keep_rsc() {
    for report_uncertain in [false, true] {
        let mut slot = slot();
        let first = fresh(&mut slot, &MATERIAL, ReplaySeed::uniform(pn(10)));
        slot.complete_install(first, InstallOutcome::Accepted)
            .unwrap();
        retire(&mut slot);
        let pending = resume(&mut slot, ReplaySeed::uniform(pn(200))).unwrap();
        if report_uncertain {
            slot.complete_install(pending, InstallOutcome::Uncertain)
                .unwrap();
        } else {
            slot.invalidate();
        }
        assert_eq!(resume(&mut slot, ReplaySeed::ZERO), Err(Error::Quarantined));
        assert_eq!(slot.installed(), None);
        retire(&mut slot);
        assert_eq!(
            slot.complete_install(pending, InstallOutcome::Accepted),
            Err(Error::StaleAcknowledgement)
        );
        let current = resume(&mut slot, ReplaySeed::ZERO).unwrap();
        assert_eq!(current.receive_seed().counters(), [200; 17]);
        slot.complete_install(current, InstallOutcome::Accepted)
            .unwrap();
        assert_eq!(
            slot.authorize(&frame(current.identity(), 200, 16))
                .unwrap_err(),
            Error::Replay
        );
    }
}

#[test]
fn authenticated_rsc_learned_during_rejected_resume_is_never_rolled_back() {
    let mut slot = slot();
    let first = fresh(&mut slot, &MATERIAL, ReplaySeed::ZERO);
    slot.complete_install(first, InstallOutcome::Accepted)
        .unwrap();
    retire(&mut slot);
    let rejected = resume(&mut slot, ReplaySeed::uniform(pn(300))).unwrap();
    slot.complete_install(rejected, InstallOutcome::RejectedAndEmpty)
        .unwrap();
    let next = resume(&mut slot, ReplaySeed::ZERO).unwrap();
    assert_eq!(next.receive_seed().counters(), [300; 17]);
    slot.complete_install(next, InstallOutcome::Accepted)
        .unwrap();
    assert_eq!(
        slot.authorize(&frame(next.identity(), 300, 0)).unwrap_err(),
        Error::Replay
    );
    slot.authorize(&frame(next.identity(), 301, 0)).unwrap();
}

#[test]
fn first_uncertain_group_install_is_receive_only_history_not_tx_nonce_permission() {
    let mut slot = slot();
    let first = fresh(&mut slot, &MATERIAL, ReplaySeed::uniform(pn(20)));
    slot.complete_install(first, InstallOutcome::Uncertain)
        .unwrap();
    assert_eq!(
        resume(&mut slot, ReplaySeed::uniform(pn(30))),
        Err(Error::Quarantined)
    );
    retire(&mut slot);
    let next = resume(&mut slot, ReplaySeed::uniform(pn(30))).unwrap();
    assert_eq!(next.receive_seed().counters(), [30; 17]);
    slot.complete_install(next, InstallOutcome::Accepted)
        .unwrap();
    assert_eq!(
        slot.reserve_host_tx_nonce(next.identity()).unwrap_err(),
        Error::WrongNonceOwner
    );
    assert_eq!(
        slot.begin_install(
            0,
            Cipher::Ccmp128,
            &MATERIAL,
            ReplaySeed::ZERO,
            KeyScope::Pairwise(AP),
            TransmitSeed::FIRMWARE_FRESH
        ),
        Err(Error::Reinstallation)
    );
}
