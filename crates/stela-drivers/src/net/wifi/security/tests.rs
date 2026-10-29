use super::*;
use crate::net::wifi::{Band, RadioStatus, RawRate};
use alloc::vec;

fn slot(number: u16) -> KeySlot {
    // Independent pure model: no physical slot, DMA or deferred users exist.
    // SAFETY: this test owns the key slot number alone.
    unsafe { KeySlot::new(number).unwrap() }
}

fn install(slot: &mut KeySlot) -> KeyIdentity {
    let ticket = slot
        .begin_install(
            2,
            Cipher::Ccmp128,
            &[0x42; 16],
            ReplaySeed::ZERO,
            KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
            TransmitSeed::RECEIVE_ONLY,
        )
        .unwrap();
    assert_eq!(slot.installed(), None);
    slot.complete_install(ticket, InstallOutcome::Accepted)
        .unwrap();
    slot.installed().unwrap()
}

fn packet(key: KeyIdentity, pn: u64, tid: Option<u8>) -> Mpdu {
    let len = if tid.is_some() { 26 } else { 24 };
    let mut bytes = vec![0; len + 3];
    bytes[..2].copy_from_slice(
        &(if tid.is_some() {
            0x4088_u16
        } else {
            0x4008_u16
        })
        .to_le_bytes(),
    );
    if let Some(tid) = tid {
        bytes[24] = tid;
    }
    bytes[len..].copy_from_slice(&[1, 2, 3]);
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
            rx_rate: None,
            tsf: None,
        },
        SecurityStatus {
            key: Some(key),
            pn: PacketNumber::new(pn),
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
fn mixed_qos_and_nonqos_replay_matches_full_source_counter_effects() {
    let mut slot = slot(7);
    let key = install(&mut slot);
    let maximum = (1_u64 << 48) - 1;
    let values = [0, 1, 2, 17, 18, maximum - 1, maximum];
    let mut hash = Sha256::new();
    let mut count = 0;
    // Complete mt76 helper trace: both arrival orders, all TIDs,
    // non-QoS aliasing, authenticated floors, exhaustion and all 17 counters.
    // Pure canonical replay model; no physical integrity/ACK is inferred.
    for first in 0..17 {
        for second in 0..17 {
            for seed in [0, 1, 17, maximum] {
                for a in values {
                    for b in values {
                        slot.rx_pn = [seed; 17];
                        for (kind, pn) in [(first, a), (second, b)] {
                            let mpdu = packet(key, pn, (kind != 16).then_some(kind));
                            let result = slot.authorize(&mpdu);
                            assert!(result.is_ok() || matches!(result, Err(Error::Replay)));
                            let accepted = u8::from(result.is_ok());
                            hash.update([accepted, accepted]);
                        }
                        for pn in slot.rx_pn {
                            hash.update(&pn.to_be_bytes()[2..]);
                        }
                        count += 1;
                    }
                }
            }
        }
    }
    assert_eq!(count, 56_644);
    assert_eq!(
        alloc::format!("{:x}", hash.finalize()),
        "b5505742f235fb8a9c1af36ce9e9f9ae40590f1bc336719f7d39e35bc9b4f7a5"
    );
}

#[test]
fn key_acknowledgement_rekey_and_stale_rx() {
    let mut slot = slot(7);
    let old = install(&mut slot);
    assert_eq!(
        slot.authorize(&packet(old, 8, None)).unwrap().payload(),
        &[1, 2, 3]
    );
    assert_eq!(
        slot.begin_install(
            2,
            Cipher::Ccmp128,
            &[0x43; 16],
            ReplaySeed::ZERO,
            KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
            TransmitSeed::RECEIVE_ONLY
        ),
        Err(Error::KeyStillInstalled)
    );
    slot.invalidate();
    // Fixture has no physical key, RX or deferred users.
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    unsafe {
        slot.retire_after_drain();
    }
    let ticket = slot
        .begin_install(
            2,
            Cipher::Ccmp128,
            &[0x43; 16],
            ReplaySeed::ZERO,
            KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
            TransmitSeed::RECEIVE_ONLY,
        )
        .unwrap();
    assert!(matches!(
        slot.authorize(&packet(old, 9, None)),
        Err(Error::NoInstalledKey)
    ));
    assert_eq!(
        slot.begin_install(
            2,
            Cipher::Ccmp128,
            &[0x43; 16],
            ReplaySeed::ZERO,
            KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
            TransmitSeed::RECEIVE_ONLY
        ),
        Err(Error::Busy)
    );
    slot.complete_install(ticket, InstallOutcome::Accepted)
        .unwrap();
    let new = slot.installed().unwrap();
    assert_ne!(old.generation(), new.generation());
    assert!(matches!(
        slot.authorize(&packet(old, 9, None)),
        Err(Error::WrongKey)
    ));
    assert!(slot.authorize(&packet(new, 1, None)).is_ok());
    assert_eq!(
        slot.complete_install(ticket, InstallOutcome::Accepted),
        Err(Error::StaleAcknowledgement)
    );
}

#[test]
fn uncertain_install_requires_real_retirement() {
    let mut slot = slot(3);
    let ticket = slot
        .begin_install(
            0,
            Cipher::Gcmp128,
            &[0x43; 16],
            ReplaySeed::ZERO,
            KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
            TransmitSeed::RECEIVE_ONLY,
        )
        .unwrap();
    slot.complete_install(ticket, InstallOutcome::Uncertain)
        .unwrap();
    assert_eq!(
        slot.begin_install(
            0,
            Cipher::Ccmp128,
            &[0x44; 16],
            ReplaySeed::ZERO,
            KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
            TransmitSeed::RECEIVE_ONLY
        ),
        Err(Error::Quarantined)
    );
    // Fixture has no hardware or queued RX users.
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    unsafe {
        slot.retire_after_drain();
    }
    assert!(
        slot.begin_install(
            0,
            Cipher::Ccmp128,
            &[0x44; 16],
            ReplaySeed::ZERO,
            KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
            TransmitSeed::RECEIVE_ONLY
        )
        .unwrap()
        .identity()
        .generation()
            > ticket.identity().generation()
    );
}

fn begin_firmware_key(slot: &mut KeySlot, byte: u8) -> Result<InstallTicket, Error> {
    slot.begin_install(
        0,
        Cipher::Ccmp128,
        &[byte; 16],
        ReplaySeed::ZERO,
        KeyScope::Pairwise(Mac([2, 0, 0, 0, 0, 1])),
        TransmitSeed::FIRMWARE_FRESH,
    )
}

fn drain_model(slot: &mut KeySlot) {
    // Pure slot fixture has no physical key, DMA or old deferred users.
    // A real caller must prove the documented independent remove/drain.
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    unsafe {
        slot.retire_after_drain();
    }
}

#[test]
fn only_the_installed_key_is_compared_for_reinstallation() {
    let mut slot = slot(7);
    let first = begin_firmware_key(&mut slot, 0xa0).unwrap();
    slot.complete_install(first, InstallOutcome::Accepted)
        .unwrap();
    // An identical install changes nothing; another key needs removal first.
    assert_eq!(
        begin_firmware_key(&mut slot, 0xa0),
        Err(Error::AlreadyInstalled(first.identity()))
    );
    assert_eq!(
        begin_firmware_key(&mut slot, 0xb1),
        Err(Error::KeyStillInstalled)
    );
    slot.invalidate();
    drain_model(&mut slot);
    // After removal, as in Linux, any key installs with fresh counters.
    let again = begin_firmware_key(&mut slot, 0xa0).unwrap();
    assert!(again.identity().generation() > first.identity().generation());
    slot.complete_install(again, InstallOutcome::Uncertain)
        .unwrap();
    assert_eq!(begin_firmware_key(&mut slot, 0xc2), Err(Error::Quarantined));
    drain_model(&mut slot);
    let rejected = begin_firmware_key(&mut slot, 0xc2).unwrap();
    slot.complete_install(rejected, InstallOutcome::RejectedAndEmpty)
        .unwrap();
    let fresh = begin_firmware_key(&mut slot, 0xc2).unwrap();
    slot.complete_install(fresh, InstallOutcome::Accepted)
        .unwrap();
    assert_eq!(slot.installed(), Some(fresh.identity()));
}

#[test]
fn invalidating_a_pending_install_refuses_its_late_acknowledgement() {
    for invalidate_first in [false, true] {
        let mut slot = slot(7);
        let pending = begin_firmware_key(&mut slot, 0xb1).unwrap();
        if invalidate_first {
            slot.invalidate();
        }
        drain_model(&mut slot);
        assert_eq!(
            slot.complete_install(pending, InstallOutcome::Accepted),
            Err(Error::StaleAcknowledgement)
        );
        assert!(begin_firmware_key(&mut slot, 0xb1).is_ok());
    }
}

#[test]
fn replay_is_per_tid_with_non_qos_aliasing_tid_zero() {
    let mut slot = slot(1);
    let key = install(&mut slot);
    for tid in (0..16).map(Some) {
        assert!(matches!(
            slot.authorize(&packet(key, 0, tid)),
            Err(Error::Replay)
        ));
        assert!(slot.authorize(&packet(key, 5, tid)).is_ok());
        for pn in [1, 4, 5] {
            assert!(matches!(
                slot.authorize(&packet(key, pn, tid)),
                Err(Error::Replay)
            ));
        }
        assert!(slot.authorize(&packet(key, 6, tid)).is_ok());
    }
    assert!(matches!(
        slot.authorize(&packet(key, 6, None)),
        Err(Error::Replay)
    ));
    assert!(slot.authorize(&packet(key, 7, None)).is_ok());
    assert!(matches!(
        slot.authorize(&packet(key, 7, Some(0))),
        Err(Error::Replay)
    ));
    assert_eq!(slot.rx_pn[16], 0);
}

#[test]
fn decryption_and_hardware_replay_claim_do_not_authorize() {
    let mut slot = slot(1);
    let key = install(&mut slot);
    let mut frame = packet(key, 10, Some(0));
    frame.security.integrity = Integrity::Unknown;
    assert!(matches!(slot.authorize(&frame), Err(Error::Integrity)));
    frame.security.integrity = Integrity::Verified;
    frame.security.pn = None;
    frame.security.hardware_replay = HardwareReplay::Validated { layout: 1 };
    assert!(matches!(
        slot.authorize(&frame),
        Err(Error::MissingPacketNumber)
    ));
    frame.security.pn = PacketNumber::new(10);
    assert!(slot.authorize(&frame).is_ok());
}

#[test]
fn failed_packet_does_not_advance_replay_state() {
    let mut slot = slot(1);
    let key = install(&mut slot);
    let mut frame = packet(key, 99, None);
    frame.fcs_error = true;
    assert!(matches!(slot.authorize(&frame), Err(Error::Integrity)));
    assert!(slot.authorize(&packet(key, 3, None)).is_ok());
    frame.fcs_error = false;
    frame.security.mic_stripped = false;
    assert!(matches!(slot.authorize(&frame), Err(Error::Truncated)));
    assert!(slot.authorize(&packet(key, 4, None)).is_ok());
}

#[test]
fn aggregates_fragments_and_non_data_are_explicit() {
    let mut slot = slot(1);
    let key = install(&mut slot);
    let mut frame = packet(key, 1, None);
    frame.aggregation.ampdu = Some(2);
    assert!(matches!(slot.authorize(&frame), Err(Error::Unsupported(_))));
    for control in [0x4408_u16, 0x4000, 0x4048] {
        let mut bytes = vec![0; 24];
        bytes[..2].copy_from_slice(&control.to_le_bytes());
        let bad = Mpdu::new(bytes, frame.radio.clone(), frame.security).unwrap();
        assert!(matches!(slot.authorize(&bad), Err(Error::Unsupported(_))));
    }
    assert!(slot.authorize(&packet(key, 1, None)).is_ok());
}

#[test]
fn identical_key_retry_does_not_reset_nonce_or_replay_state() {
    let mut slot = slot(1);
    let key = install(&mut slot);
    assert!(slot.authorize(&packet(key, 10, None)).is_ok());
    assert_eq!(
        slot.begin_install(
            2,
            Cipher::Ccmp128,
            &[0x42; 16],
            ReplaySeed::ZERO,
            KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
            TransmitSeed::RECEIVE_ONLY
        ),
        Err(Error::AlreadyInstalled(key))
    );
    assert!(matches!(
        slot.authorize(&packet(key, 10, None)),
        Err(Error::Replay)
    ));
}

#[test]
fn kept_crypto_header_and_mic_match_all_declared_ciphers() {
    for cipher in [
        Cipher::Ccmp128,
        Cipher::Ccmp256,
        Cipher::Gcmp128,
        Cipher::Gcmp256,
    ] {
        for index in 0..4 {
            let mut slot = slot(5);
            let length = if matches!(cipher, Cipher::Ccmp128 | Cipher::Gcmp128) {
                16
            } else {
                32
            };
            let material = [0x42; 32];
            let ticket = slot
                .begin_install(
                    index,
                    cipher,
                    &material[..length],
                    ReplaySeed::ZERO,
                    KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
                    TransmitSeed::RECEIVE_ONLY,
                )
                .unwrap();
            slot.complete_install(ticket, InstallOutcome::Accepted)
                .unwrap();
            let key = slot.installed().unwrap();
            let base = packet(key, 0x112233445566, Some(15));
            let mut bytes = base.bytes()[..26].to_vec();
            bytes.extend_from_slice(&[0x66, 0x55, 0, 0x20 | index << 6, 0x44, 0x33, 0x22, 0x11]);
            bytes.extend_from_slice(&[1, 2, 3]);
            bytes.resize(bytes.len() + cipher.mic_length(), 0xcc);
            let mut status = base.security;
            status.iv_stripped = false;
            status.mic_stripped = false;
            let mut frame = Mpdu::new(bytes, base.radio.clone(), status).unwrap();
            frame.security.pn = PacketNumber::new(0x112233445567);
            assert!(matches!(
                slot.authorize(&frame),
                Err(Error::InconsistentPacketNumber)
            ));
            frame.security.pn = None;
            let authorized = slot.authorize(&frame).unwrap();
            assert_eq!(authorized.payload(), &[1, 2, 3]);
            assert_eq!(authorized.packet_number().value(), 0x112233445566);
        }
    }
}

#[test]
fn every_bad_security_observation_preserves_replay_floor() {
    let mut slot = slot(1);
    let key = install(&mut slot);
    for case in 0..7 {
        let mut frame = packet(key, 99, None);
        match case {
            0 => frame.security.icv_error = true,
            1 => frame.security.tkip_mic_error = true,
            2 => frame.security.decrypted = false,
            3 => frame.security.integrity = Integrity::Failed,
            4 => frame.security.hardware_replay = HardwareReplay::Failed { layout: 2 },
            5 => frame.monitor_only = true,
            _ => frame.fcs_error = true,
        }
        assert!(matches!(slot.authorize(&frame), Err(Error::Integrity)));
    }
    assert!(slot.authorize(&packet(key, 1, None)).is_ok());
}

#[test]
fn authenticated_initial_rsc_is_committed_only_with_key_ack() {
    let mut slot = slot(7);
    let seed = ReplaySeed::uniform(PacketNumber::new(100).unwrap());
    let ticket = slot
        .begin_install(
            2,
            Cipher::Ccmp128,
            &[0x42; 16],
            seed,
            KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
            TransmitSeed::RECEIVE_ONLY,
        )
        .unwrap();
    assert_eq!(ticket.receive_seed().counters(), [100; 17]);
    assert_eq!(slot.installed(), None);
    slot.complete_install(ticket, InstallOutcome::Accepted)
        .unwrap();
    let key = slot.installed().unwrap();
    for tid in (0..16).map(Some) {
        assert!(matches!(
            slot.authorize(&packet(key, 100, tid)),
            Err(Error::Replay)
        ));
        assert!(slot.authorize(&packet(key, 101, tid)).is_ok());
    }
    for pn in [100, 101] {
        assert!(matches!(
            slot.authorize(&packet(key, pn, None)),
            Err(Error::Replay)
        ));
    }
    assert!(slot.authorize(&packet(key, 102, None)).is_ok());
    assert!(matches!(
        slot.authorize(&packet(key, 102, Some(0))),
        Err(Error::Replay)
    ));
    assert_eq!(slot.rx_pn[16], 100);
}

#[test]
fn key_purpose_has_a_real_peer_and_legal_on_air_index() {
    let mut key = slot(7);
    let peer = Mac([2, 0, 0, 0, 0, 1]);
    assert_eq!(
        key.begin_install(
            2,
            Cipher::Ccmp128,
            &[1; 16],
            ReplaySeed::ZERO,
            KeyScope::Pairwise(peer),
            TransmitSeed::RECEIVE_ONLY
        ),
        Err(Error::InvalidKeyIndex)
    );
    for peer in [Mac([0; 6]), Mac::BROADCAST] {
        assert_eq!(
            key.begin_install(
                0,
                Cipher::Ccmp128,
                &[1; 16],
                ReplaySeed::ZERO,
                KeyScope::Pairwise(peer),
                TransmitSeed::RECEIVE_ONLY
            ),
            Err(Error::InvalidPeer)
        );
        assert_eq!(
            key.begin_install(
                2,
                Cipher::Ccmp128,
                &[1; 16],
                ReplaySeed::ZERO,
                KeyScope::Group(peer),
                TransmitSeed::RECEIVE_ONLY
            ),
            Err(Error::InvalidPeer)
        );
    }
    assert!(key.installed().is_none());
}

#[test]
fn recreated_hardware_slot_cannot_accept_old_native_epoch() {
    let old = {
        let mut previous = slot(7);
        let old = install(&mut previous);
        assert!(previous.authorize(&packet(old, 10, None)).is_ok());
        previous.invalidate();
        // Pure model has no hardware, queued RX, or outstanding key users.
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        unsafe {
            previous.retire_after_drain();
        }
        old
    };
    let mut current = slot(7);
    let ticket = current
        .begin_install(
            2,
            Cipher::Ccmp128,
            &[0x43; 16],
            ReplaySeed::ZERO,
            KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
            TransmitSeed::RECEIVE_ONLY,
        )
        .unwrap();
    current
        .complete_install(ticket, InstallOutcome::Accepted)
        .unwrap();
    let new = current.installed().unwrap();
    assert_eq!(old.slot(), new.slot());
    assert_eq!(old.generation(), new.generation());
    assert_ne!(old.native_epoch(), new.native_epoch());
    assert!(matches!(
        current.authorize(&packet(old, 10, None)),
        Err(Error::WrongKey)
    ));
    assert!(current.authorize(&packet(new, 1, None)).is_ok());
}

#[test]
fn ccmp_header_layout_and_bounds() {
    assert_eq!(
        PacketNumber::from_header(&[0x66, 0x55, 0, 0xa0, 0x44, 0x33, 0x22, 0x11]),
        Ok((PacketNumber(0x112233445566), 2))
    );
    assert_eq!(PacketNumber::new(1 << 48), None);
    for n in 0..8 {
        assert_eq!(
            PacketNumber::from_header(&[0; 8][..n]),
            Err(Error::Truncated)
        );
    }
    // Linux reads only the PN bytes and key ID; reserved bits are ignored.
    assert_eq!(
        PacketNumber::from_header(&[1, 0, 0xff, 0x5f, 0, 0, 0, 0]),
        Ok((PacketNumber(1), 1))
    );
}
