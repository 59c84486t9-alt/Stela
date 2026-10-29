// SPDX-License-Identifier: GPL-2.0-only
// CCMP receive replay follows Linux net/mac80211/{rx,wpa}.c and mt76/mac80211.c.
// Copyright 2002-2004 Instant802 Networks, Inc.; 2008 Jouni Malinen;
// Copyright (C) 2016-2017 Intel Deutschland GmbH;
// Copyright (C) 2020-2023 Intel Corporation. See THIRD_PARTY.md.
//! Hardware-verified unicast robust-management CCMP/GCMP receive authentication.
//! This is a selected-key crypto boundary, not PMF negotiation, software CCMP
//! decryption or current-station delivery. Vendor status must come from
//! completed RX under its peer/key owner, exactly as for data.

use super::{Error, KeyIdentity, KeyScope, KeySlot, PacketNumber, management};
use crate::net::{
    Mac,
    wifi::{
        Aggregation,
        frame::{self, Mpdu},
    },
};

const MANAGEMENT_REPLAY_QUEUE: usize = 16;
const MANAGEMENT_HEADER: usize = 24;

/// One original integrity-checked frame and consumed PTK management PN. No
/// public constructor or Clone. A delayed station consumer must consume this
/// and separately recheck its association and still-installed PTK.
#[derive(Debug)]
pub struct Authenticated<'a> {
    mpdu: &'a Mpdu,
    key: KeyIdentity,
    pn: PacketNumber,
    start: usize,
    end: usize,
}
impl<'a> Authenticated<'a> {
    pub const fn frame(&self) -> &'a Mpdu {
        self.mpdu
    }
    pub const fn key(&self) -> KeyIdentity {
        self.key
    }
    pub const fn packet_number(&self) -> PacketNumber {
        self.pn
    }
    pub fn body(&self) -> &'a [u8] {
        &self.mpdu.bytes()[self.start..self.end]
    }
}

impl KeySlot {
    /// Authenticate one ordinary unicast robust-management frame for `local`.
    /// Peer transmitter and BSSID must match this exact acknowledged PTK. Data
    /// counters 0..15 are independent; copied hardware replay flags never skip
    /// counter16. This grants no permission to change a station's association.
    pub fn authorize_unicast_management<'a>(
        &mut self,
        mpdu: &'a Mpdu,
        local: Mac,
    ) -> Result<Authenticated<'a>, Error> {
        let key = self.installed().ok_or(Error::NoInstalledKey)?;
        if !matches!(key.scope(), KeyScope::Pairwise(_)) {
            return Err(Error::Unsupported("unicast management requires a PTK"));
        }
        let h = mpdu.header();
        if !h.protected() {
            return Err(Error::NotProtected);
        }
        if h.length != MANAGEMENT_HEADER
            || !management::robust(mpdu)
            || h.fragmented()
            || h.control & (frame::TO_DS | frame::FROM_DS) != 0
            || mpdu.aggregation != Aggregation::default()
        {
            return Err(Error::Unsupported("management framing/fragment/aggregate"));
        }
        let peer = key.scope().peer();
        if local.is_multicast()
            || local.0 == [0; 6]
            || h.receiver != local
            || h.transmitter != Some(peer)
            || mpdu.bytes()[16..22] != peer.0
        {
            return Err(Error::InvalidPeer);
        }
        let (start, end, pn) = self.checked_payload(mpdu, key, None)?;
        let minimum = if h.control & frame::TYPE_SUBTYPE == frame::ACTION {
            1
        } else {
            2
        };
        if end - start < minimum {
            return Err(Error::Truncated);
        }
        self.commit_receive(MANAGEMENT_REPLAY_QUEUE, pn)?;
        Ok(Authenticated {
            mpdu,
            key,
            pn,
            start,
            end,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wifi::{
        Band, RadioStatus, RawRate,
        security::{Cipher, InstallOutcome, Integrity, ReplaySeed, SecurityStatus, TransmitSeed},
    };
    use alloc::{format, vec};
    use sha2::{Digest, Sha256};

    const LOCAL: Mac = Mac([2, 1, 2, 3, 4, 5]);
    const PEER: Mac = Mac([2, 6, 7, 8, 9, 10]);
    fn slot() -> KeySlot {
        // SAFETY: independent software slot model has no hardware or old users.
        let mut slot = unsafe { KeySlot::new(7) }.unwrap();
        let ticket = slot
            .begin_install(
                0,
                Cipher::Ccmp128,
                &[0x42; 16],
                ReplaySeed::ZERO,
                KeyScope::Pairwise(PEER),
                TransmitSeed::FIRMWARE_FRESH,
            )
            .unwrap();
        slot.complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        slot
    }
    fn packet(key: KeyIdentity, kind: u8, pn: u64) -> Mpdu {
        let fc = match kind {
            0..=15 => 0x4288_u16,
            16 => 0x4208,
            17 => 0x40c0,
            18 => 0x40a0,
            _ => 0x40d0,
        };
        let mut bytes = vec![0; if kind < 16 { 26 } else { 24 }];
        bytes[..2].copy_from_slice(&fc.to_le_bytes());
        bytes[4..10].copy_from_slice(&LOCAL.0);
        bytes[10..16].copy_from_slice(&PEER.0);
        bytes[16..22].copy_from_slice(&PEER.0);
        if kind < 16 {
            bytes[24] = kind;
        }
        bytes.extend_from_slice(&[3, 2, 7, 0]);
        Mpdu::new(
            bytes,
            RadioStatus {
                band: Band::Ghz5,
                channel: 36,
                frequency_mhz: 5180,
                signal_dbm: Some(-40),
                chain_signal_dbm: [None; 4],
                rate: RawRate {
                    layout: 0x7925,
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
    fn changed(mpdu: &Mpdu, edit: impl FnOnce(&mut alloc::vec::Vec<u8>)) -> Mpdu {
        let mut bytes = mpdu.bytes().to_vec();
        edit(&mut bytes);
        Mpdu::new(bytes, mpdu.radio.clone(), mpdu.security).unwrap()
    }

    #[test]
    fn management_and_all_data_queues_match_complete_mt76_replay_effects() {
        let mut slot = slot();
        let key = slot.installed().unwrap();
        let maximum = (1_u64 << 48) - 1;
        let values = [0, 1, 2, 17, 18, maximum - 1, maximum];
        let mut hash = Sha256::new();
        let mut count = 0;
        // --management mode of wifi_mixed_replay_oracle.py executes the complete
        // pinned mt76 helper, including all17 resulting counters in every pair.
        for first in 0..20 {
            for second in 0..20 {
                for seed in [0, 1, 17, maximum] {
                    for a in values {
                        for b in values {
                            slot.rx_pn = [seed; 17];
                            for (kind, pn) in [(first, a), (second, b)] {
                                let frame = packet(key, kind, pn);
                                let accepted = if kind < 17 {
                                    slot.authorize(&frame).is_ok()
                                } else {
                                    slot.authorize_unicast_management(&frame, LOCAL).is_ok()
                                };
                                hash.update([u8::from(accepted); 2]);
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
        assert_eq!(count, 78_400);
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "5b6e722645d08a36e790e0ba510b88388f623aa5d5a04730eaba598f48f3a567"
        );
    }

    #[test]
    fn management_checks_do_not_consume_rejected_frames_or_data_counters() {
        let mut slot = slot();
        let key = slot.installed().unwrap();
        let good = packet(key, 17, 7);
        for case in 0..26 {
            let mut bad = good.clone();
            let mut local = LOCAL;
            match case {
                0 => bad.security.integrity = Integrity::Unknown,
                1 => bad.security.integrity = Integrity::Failed,
                2 => bad.security.decrypted = false,
                3 => bad.security.icv_error = true,
                4 => bad.security.tkip_mic_error = true,
                5 => {
                    bad.security.hardware_replay =
                        super::super::HardwareReplay::Failed { layout: 0x7925 }
                }
                6 => bad.security.key = None,
                7 => {
                    bad.security.key = Some({
                        let mut stale = key;
                        stale.generation += 1;
                        stale
                    })
                }
                8 => bad.security.pn = None,
                9 => bad.fcs_error = true,
                10 => bad.monitor_only = true,
                11 => bad = changed(&good, |b| b[4] |= 1),
                12 => bad = changed(&good, |b| b[10] ^= 2),
                13 => bad = changed(&good, |b| b[16] ^= 2),
                14 => bad = changed(&good, |b| b[1] |= 1),
                15 => bad = changed(&good, |b| b[1] |= 2),
                16 => bad = changed(&good, |b| b[1] |= 4),
                17 => bad = changed(&good, |b| b[22] = 1),
                18 => {
                    bad = changed(&good, |b| {
                        b[1] |= 0x80;
                        b.extend_from_slice(&[0; 4]);
                    })
                }
                19 => bad = changed(&good, |b| b[0] = 0x80),
                20 => bad = changed(&good, |b| b.truncate(25)),
                21 => bad.aggregation.ampdu = Some(1),
                22 => local.0[5] ^= 1,
                23 => local = Mac([0; 6]),
                24 => bad.security.mic_stripped = false,
                _ => bad.security.iv_stripped = false,
            }
            assert!(
                slot.authorize_unicast_management(&bad, local).is_err(),
                "case {case}"
            );
            assert_eq!(slot.rx_pn, [0; 17], "case {case}");
        }
        let proof = slot.authorize_unicast_management(&good, LOCAL).unwrap();
        assert_eq!(proof.key(), key);
        assert_eq!(proof.packet_number().value(), 7);
        assert!(core::ptr::eq(proof.frame(), &good));
        assert_eq!(proof.body(), &[3, 2, 7, 0]);
        assert_eq!(slot.rx_pn[..16], [0; 16]);
        assert_eq!(slot.rx_pn[16], 7);
        assert!(matches!(
            slot.authorize_unicast_management(&good, LOCAL),
            Err(Error::Replay)
        ));
        slot.authorize(&packet(key, 0, 7)).unwrap();
        assert_eq!(slot.rx_pn[0], 7);
        let next = packet(key, 18, 8);
        slot.authorize_unicast_management(&next, LOCAL).unwrap();
        assert_eq!(slot.rx_pn[16], 8);
    }

    #[test]
    fn retained_iv_and_mic_are_removed_only_from_the_authenticated_body_view() {
        let mut slot = slot();
        let key = slot.installed().unwrap();
        let base = packet(key, 19, 0x112233445566);
        let mut frame = changed(&base, |b| {
            b.splice(24..24, [0x66, 0x55, 0, 0x20, 0x44, 0x33, 0x22, 0x11]);
            b.extend_from_slice(&[0x77; 8]);
        });
        frame.security.iv_stripped = false;
        frame.security.mic_stripped = false;
        let mut wrong = frame.clone();
        wrong.security.pn = PacketNumber::new(1);
        assert!(matches!(
            slot.authorize_unicast_management(&wrong, LOCAL),
            Err(Error::InconsistentPacketNumber)
        ));
        let wrong_index = changed(&frame, |b| b[27] |= 0x40);
        assert!(matches!(
            slot.authorize_unicast_management(&wrong_index, LOCAL),
            Err(Error::WrongKey)
        ));
        let proof = slot.authorize_unicast_management(&frame, LOCAL).unwrap();
        assert_eq!(proof.body(), base.bytes().get(24..).unwrap());
        assert_eq!(proof.frame().bytes().len(), 44);
        assert_eq!(slot.rx_pn[16], 0x112233445566);
        slot.invalidate();
        assert!(matches!(
            slot.authorize_unicast_management(&frame, LOCAL),
            Err(Error::NoInstalledKey)
        ));
    }

    #[test]
    fn management_plaintext_and_all_counters_match_complete_source_ccmp_helper() {
        let mut slot = slot();
        let key = slot.installed().unwrap();
        let maximum = (1_u64 << 48) - 1;
        let floors = [0, 1, 17, maximum - 1, maximum];
        let pns = [0, 1, 2, 18, maximum - 1, maximum];
        let mut hash = Sha256::new();
        let mut cases = 0;
        // wifi_management_ccmp_oracle.py runs complete source parse_qos,
        // PN header conversion and hardware-decrypted CCMP receive/strip helpers.
        for kind in 0..3 {
            for floor in floors {
                for pn in pns {
                    for stripped in [false, true] {
                        for body in 2..66 {
                            slot.rx_pn = [0; 17];
                            slot.rx_pn[16] = floor;
                            let base = packet(key, 17 + kind, pn);
                            let frame = changed(&base, |b| {
                                b.truncate(24);
                                let n = pn.to_le_bytes();
                                b.extend_from_slice(&[n[0], n[1], 0, 0x20, n[2], n[3], n[4], n[5]]);
                                for q in 0..body {
                                    b.push(q * 3 + kind);
                                }
                                if !stripped {
                                    b.extend_from_slice(&[0; 8]);
                                }
                            });
                            let mut frame = frame;
                            frame.security.iv_stripped = false;
                            frame.security.mic_stripped = stripped;
                            let result = slot.authorize_unicast_management(&frame, LOCAL);
                            let length = if result.is_ok() { 24 + body as u16 } else { 0 };
                            hash.update([
                                u8::from(result.is_ok()),
                                16,
                                length as u8,
                                (length >> 8) as u8,
                            ]);
                            for value in slot.rx_pn {
                                hash.update(&value.to_be_bytes()[2..]);
                            }
                            match result {
                                Ok(proof) => {
                                    hash.update(&proof.frame().bytes()[..24]);
                                    hash.update(proof.body());
                                }
                                Err(Error::Replay) => {}
                                other => panic!("unexpected source-profile result {other:?}"),
                            }
                            cases += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 11_520);
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "f57b7e8695809f6446ab2bc1d57046314aed5128546c344422cc12a5f9e17dc8"
        );
    }

    #[test]
    fn management_takes_every_ptk_suite_and_never_promotes_a_group_key() {
        for (cipher, scope) in [
            (Cipher::Ccmp128, KeyScope::Group(PEER)),
            (Cipher::Ccmp256, KeyScope::Pairwise(PEER)),
            (Cipher::Gcmp128, KeyScope::Pairwise(PEER)),
            (Cipher::Gcmp256, KeyScope::Pairwise(PEER)),
        ] {
            // SAFETY: isolated pure key-slot model with no physical/deferred users.
            let mut slot = unsafe { KeySlot::new(7) }.unwrap();
            let length = if matches!(cipher, Cipher::Ccmp128 | Cipher::Gcmp128) {
                16
            } else {
                32
            };
            let ticket = slot
                .begin_install(
                    0,
                    cipher,
                    &vec![0x42; length],
                    ReplaySeed::ZERO,
                    scope,
                    if matches!(scope, KeyScope::Group(_)) {
                        TransmitSeed::RECEIVE_ONLY
                    } else {
                        TransmitSeed::FIRMWARE_FRESH
                    },
                )
                .unwrap();
            slot.complete_install(ticket, InstallOutcome::Accepted)
                .unwrap();
            let frame = packet(slot.installed().unwrap(), 17, 9);
            let result = slot.authorize_unicast_management(&frame, LOCAL);
            if matches!(scope, KeyScope::Group(_)) {
                assert!(matches!(result, Err(Error::Unsupported(_))));
                assert_eq!(slot.rx_pn, [0; 17]);
            } else {
                assert_eq!(result.unwrap().packet_number().value(), 9);
                assert_eq!(slot.rx_pn[MANAGEMENT_REPLAY_QUEUE], 9);
            }
        }
    }
}
