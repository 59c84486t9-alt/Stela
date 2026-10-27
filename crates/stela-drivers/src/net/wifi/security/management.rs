// SPDX-License-Identifier: GPL-2.0-only
// BIP AAD, MMIE/IPN and CMAC handling adapt Linux net/mac80211/{wpa,aes_cmac}.c:
// Copyright 2008 Jouni Malinen <j@w1.fi>; Copyright (C) 2020 Intel Corporation.
// Robust classification and MMIE layout adapt Linux include/linux/ieee80211.h:
// Copyright 2001-2003 SSH Communications Security Corp and Jouni Malinen;
// 2005 Devicescape Software, Inc.; 2006 Michael Wu;
// 2013-2014 Intel Mobile Communications GmbH; 2016-2017 Intel Deutschland GmbH;
// 2018-2026 Intel Corporation.
// CMAC subkeys/stream/finalization adapt Linux lib/crypto/aes.c:
// Copyright 2026 Google LLC. Original notices and source pin in THIRD_PARTY.md.
//! Group robust-management authentication under an actually retained IGTK.
//! Authentication is not PMF negotiation, current-association/port authority,
//! physical key completion or permission to act on a delayed management frame.

use super::{Cipher, KeyIdentity, KeyScope, PacketNumber, valid_receive_observations};
use crate::net::wifi::{Aggregation, frame};
use aes::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MMIE_ID: u8 = 76;
const MMIE_BYTES: usize = 18;
const MIC_BYTES: usize = 8;
const MANAGEMENT_HEADER: usize = 24;
const AAD_MASK: u16 = 0x3800; // source Retry | PwrMgt | MoreData

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidKey,
    InvalidFrame,
    WrongPeer,
    WrongKey,
    BadMmie,
    Replay,
    Integrity,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BIP management authentication: {self:?}")
    }
}
impl core::error::Error for Error {}

/// Source robust-management classification. This does not authenticate frames;
/// a protected Action's body may still be encrypted, as in the source helper.
pub fn robust(mpdu: &frame::Mpdu) -> bool {
    if mpdu.bytes().len() < MANAGEMENT_HEADER + 1 {
        return false;
    }
    match mpdu.header().control & frame::TYPE_SUBTYPE {
        frame::DISASSOCIATION | frame::DEAUTHENTICATION => true,
        frame::ACTION => {
            mpdu.header().protected()
                || !matches!(
                    mpdu.bytes()[MANAGEMENT_HEADER],
                    4 | 7 | 11 | 15 | 20 | 21 | 22 | 127
                )
        }
        _ => false,
    }
}

/// Source CMAC replay/MIC counters, wrapping at their original u32 boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    pub replays: u32,
    pub mic_failures: u32,
}

/// One authenticated original frame. No public constructor or Clone: deferred
/// station delivery must consume it and separately recheck the exact association
/// and still-current parent GTK/IGTK. Hardware replay flags never create this.
pub struct Authenticated<'a> {
    mpdu: &'a frame::Mpdu,
    gtk: KeyIdentity,
    index: u8,
    pn: PacketNumber,
    end: usize,
}
impl<'a> Authenticated<'a> {
    pub const fn frame(&self) -> &'a frame::Mpdu {
        self.mpdu
    }
    pub const fn gtk(&self) -> KeyIdentity {
        self.gtk
    }
    pub const fn index(&self) -> u8 {
        self.index
    }
    pub const fn packet_number(&self) -> PacketNumber {
        self.pn
    }
    pub fn body(&self) -> &'a [u8] {
        &self.mpdu.bytes()[MANAGEMENT_HEADER..self.end]
    }
}

// Kept only by an actual vendor key owner; pending/uncertain keys cannot call
// authenticate. AES expanded keys and CMAC subkeys are zeroized on real drain.
// The native owner still controls ACK, namespace, generation and retirement.
pub(crate) struct BipKey {
    gtk: KeyIdentity,
    index: u8,
    receive: PacketNumber,
    cmac: Cmac,
    statistics: Statistics,
}
impl BipKey {
    pub(crate) fn new(
        gtk: KeyIdentity,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Self, Error> {
        if gtk.cipher() != Cipher::Ccmp128
            || !matches!(gtk.scope(), KeyScope::Group(_))
            || !matches!(index, 4 | 5)
            || material.len() != 16
        {
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            gtk,
            index,
            receive,
            cmac: Cmac::new(material)?,
            statistics: Statistics::default(),
        })
    }
    pub(crate) const fn statistics(&self) -> Statistics {
        self.statistics
    }
    pub(crate) const fn receive_floor(&self) -> PacketNumber {
        self.receive
    }
    pub(crate) fn authenticate<'a>(
        &mut self,
        mpdu: &'a frame::Mpdu,
    ) -> Result<Authenticated<'a>, Error> {
        let header = mpdu.header();
        if header.length != MANAGEMENT_HEADER
            || header.protected()
            || header.fragmented()
            || header.control & (frame::TO_DS | frame::FROM_DS) != 0
            || mpdu.aggregation != Aggregation::default()
            || !robust(mpdu)
        {
            return Err(Error::InvalidFrame);
        }
        if !valid_receive_observations(mpdu) {
            return Err(Error::Integrity);
        }
        let peer = self.gtk.scope().peer();
        if !header.receiver.is_multicast()
            || header.transmitter != Some(peer)
            || mpdu.bytes()[16..22] != peer.0
        {
            return Err(Error::WrongPeer);
        }
        let mmie = mpdu
            .bytes()
            .get(mpdu.bytes().len().saturating_sub(MMIE_BYTES)..)
            .filter(|b| {
                b.len() == MMIE_BYTES && mpdu.bytes().len() >= MANAGEMENT_HEADER + MMIE_BYTES
            })
            .ok_or(Error::BadMmie)?;
        if mmie[0] != MMIE_ID || usize::from(mmie[1]) != MMIE_BYTES - 2 {
            return Err(Error::BadMmie);
        }
        if u16::from_le_bytes(mmie[2..4].try_into().unwrap()) != u16::from(self.index) {
            return Err(Error::WrongKey);
        }
        let pn = PacketNumber::new(u64::from_le_bytes([
            mmie[4], mmie[5], mmie[6], mmie[7], mmie[8], mmie[9], 0, 0,
        ]))
        .unwrap();
        if pn.value() <= self.receive.value() {
            self.statistics.replays = self.statistics.replays.wrapping_add(1);
            return Err(Error::Replay);
        }
        let mut aad = [0; 20];
        aad[..2].copy_from_slice(&(header.control & !AAD_MASK).to_le_bytes());
        aad[2..].copy_from_slice(&mpdu.bytes()[4..22]);
        let mut cmac = self.cmac.start();
        cmac.update(&aad);
        cmac.update(&mpdu.bytes()[MANAGEMENT_HEADER..mpdu.bytes().len() - MIC_BYTES]);
        cmac.update(&[0; MIC_BYTES]);
        let mic = cmac.finish();
        if !bool::from(mic[..MIC_BYTES].ct_eq(&mmie[10..])) {
            self.statistics.mic_failures = self.statistics.mic_failures.wrapping_add(1);
            return Err(Error::Integrity);
        }
        self.receive = pn;
        Ok(Authenticated {
            mpdu,
            gtk: self.gtk,
            index: self.index,
            pn,
            end: mpdu.bytes().len() - MMIE_BYTES,
        })
    }
}

struct Cmac {
    cipher: Aes128,
    subkeys: Zeroizing<[[u8; 16]; 2]>,
}
fn double(mut value: [u8; 16]) -> [u8; 16] {
    let carry = value[0] >> 7;
    for i in 0..15 {
        value[i] = (value[i] << 1) | (value[i + 1] >> 7);
    }
    value[15] = (value[15] << 1) ^ (0x87 * carry);
    value
}
impl Cmac {
    fn new(key: &[u8]) -> Result<Self, Error> {
        let cipher = Aes128::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
        let mut l = Zeroizing::new([0; 16]);
        cipher.encrypt_block(aes::Block::from_mut_slice(l.as_mut()));
        let first = double(*l);
        Ok(Self {
            cipher,
            subkeys: Zeroizing::new([first, double(first)]),
        })
    }
    fn start(&self) -> Stream<'_> {
        Stream {
            key: self,
            state: Zeroizing::new([0; 16]),
            used: 0,
        }
    }
}
struct Stream<'a> {
    key: &'a Cmac,
    state: Zeroizing<[u8; 16]>,
    used: usize,
}
impl Stream<'_> {
    fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.used == 16 {
                self.key
                    .cipher
                    .encrypt_block(aes::Block::from_mut_slice(self.state.as_mut()));
                self.used = 0;
            }
            self.state[self.used] ^= b;
            self.used += 1;
        }
    }
    fn finish(mut self) -> [u8; 16] {
        let final_key = usize::from(self.used != 16);
        if self.used != 16 {
            self.state[self.used] ^= 0x80;
        }
        for i in 0..16 {
            self.state[i] ^= self.key.subkeys[final_key][i];
        }
        self.key
            .cipher
            .encrypt_block(aes::Block::from_mut_slice(self.state.as_mut()));
        *self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{
        Mac,
        wifi::{
            Band, RadioStatus, RawRate,
            security::{InstallOutcome, KeySlot, ReplaySeed, SecurityStatus, TransmitSeed},
        },
    };
    use alloc::{vec, vec::Vec};
    use sha2::{Digest, Sha256};

    fn gtk() -> KeyIdentity {
        // SAFETY: independent pure protocol oracle, no actual hardware namespace/users.
        let mut slot = unsafe { KeySlot::new(7) }.unwrap();
        let ticket = slot
            .begin_install(
                2,
                Cipher::Ccmp128,
                &[0x44; 16],
                ReplaySeed::ZERO,
                KeyScope::Group(Mac([2, 6, 7, 8, 9, 10])),
                TransmitSeed::RECEIVE_ONLY,
            )
            .unwrap();
        slot.complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        slot.installed().unwrap()
    }
    fn packet(bytes: Vec<u8>) -> frame::Mpdu {
        frame::Mpdu::new(
            bytes,
            RadioStatus {
                band: Band::Ghz5,
                channel: 36,
                frequency_mhz: 5180,
                signal_dbm: Some(-40),
                chain_signal_dbm: [None; 4],
                rate: RawRate {
                    layout: 0,
                    words: [0; 4],
                },
                rx_rate: None,
                tsf: None,
            },
            SecurityStatus::default(),
        )
        .unwrap()
    }
    fn mic(key: &Cmac, bytes: &[u8]) -> [u8; 16] {
        let mut aad = [0; 20];
        let fc = u16::from_le_bytes(bytes[..2].try_into().unwrap());
        aad[..2].copy_from_slice(&(fc & !AAD_MASK).to_le_bytes());
        aad[2..].copy_from_slice(&bytes[4..22]);
        let mut s = key.start();
        s.update(&aad);
        s.update(&bytes[24..bytes.len() - 8]);
        s.update(&[0; 8]);
        s.finish()
    }
    fn source_frame(i: usize, pn: u64) -> Vec<u8> {
        let body = if i % 3 == 2 { 6 + i % 61 } else { 2 + i % 65 };
        let mut bytes = vec![0; 24 + body + 18];
        let fc = (match i % 3 {
            0 => 0x00c0,
            1 => 0x00a0,
            _ => 0x00d0,
        }) | (((i / 3) % 8) as u16) << 11;
        bytes[..2].copy_from_slice(&fc.to_le_bytes());
        bytes[4..10].fill(0xff);
        bytes[10..16].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
        bytes[16..22].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
        bytes[22..24].copy_from_slice(&((i as u16) << 4).to_le_bytes());
        for j in 0..body {
            bytes[24 + j] = (i * 31 + j) as u8;
        }
        bytes[24] = if i % 3 == 2 { 3 } else { 7 };
        bytes[25] = if i % 3 == 2 { 2 } else { 0 };
        let mmie = &mut bytes[24 + body..];
        mmie[0] = 76;
        mmie[1] = 16;
        mmie[2] = 4 + (i % 2) as u8;
        mmie[4..10].copy_from_slice(&pn.to_le_bytes()[..6]);
        let end = bytes.len();
        let digest = mic(&Cmac::new(&[0x55; 16]).unwrap(), &bytes);
        bytes[end - 8..].copy_from_slice(&digest[..8]);
        bytes
    }

    #[test]
    fn cmac_and_full_bip_mac_trace_match_complete_unchanged_source_helpers() {
        let key = Cmac::new(&[
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ])
        .unwrap();
        assert_eq!(
            key.start().finish(),
            [
                0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
                0x67, 0x46
            ]
        );
        let mut hash = Sha256::new();
        // 384 exact unchanged source CMAC/AAD/IPN helper cases; no hardware claim.
        for i in 0usize..384 {
            let body = i % 131;
            let len = 24 + body + 18;
            let mut bytes = vec![0; len];
            let raw: [u8; 16] = core::array::from_fn(|j| (i * 17 + j) as u8);
            let fc = (match i % 3 {
                0 => 0xc0,
                1 => 0xa0,
                _ => 0xd0,
            }) | ((((i / 3) % 8) as u16) * 0x800);
            bytes[..2].copy_from_slice(&fc.to_le_bytes());
            for (j, b) in bytes.iter_mut().enumerate().take(24).skip(4) {
                *b = (i * 7 + j) as u8;
            }
            for j in 0..body {
                bytes[24 + j] = (i * 31 + j) as u8;
            }
            let pn = (i as u64) * 1_000_003 + 1;
            let mmie = &mut bytes[24 + body..];
            mmie[0] = 76;
            mmie[1] = 16;
            mmie[2] = 4 + (i % 2) as u8;
            mmie[4..10].copy_from_slice(&pn.to_le_bytes()[..6]);
            let digest = mic(&Cmac::new(&raw).unwrap(), &bytes);
            bytes[len - 8..].copy_from_slice(&digest[..8]);
            let mut aad = [0; 20];
            aad[..2].copy_from_slice(&(fc & !AAD_MASK).to_le_bytes());
            aad[2..].copy_from_slice(&bytes[4..22]);
            hash.update([i as u8, (i >> 8) as u8, len as u8, (len >> 8) as u8]);
            hash.update(&bytes);
            hash.update(aad);
            hash.update(&pn.to_be_bytes()[2..]);
        }
        assert_eq!(
            alloc::format!("{:x}", hash.finalize()),
            "cdae6f4d1a3567411307def1dd1fe55222d8d7d43f6adfa98165614e8487aa64"
        );
    }

    #[test]
    fn all_source_robust_categories_and_protected_action_rules_match() {
        let mut hash = Sha256::new();
        for kind in [0x00c0u16, 0x00a0, 0x00d0, 0x0080, 0x00b0, 0x0008] {
            for protected in [false, true] {
                for category in 0..=255u8 {
                    let mut bytes = vec![0; 25];
                    let fc = kind | if protected { 0x4000 } else { 0 };
                    bytes[..2].copy_from_slice(&fc.to_le_bytes());
                    bytes[24] = category;
                    hash.update([u8::from(robust(&packet(bytes)))]);
                }
            }
        }
        assert_eq!(
            alloc::format!("{:x}", hash.finalize()),
            "838da38c54f8be0a3fed285b0890f1d04b9196a966c1f47f4407e92f9cab94de"
        );
    }

    #[test]
    fn complete_source_key_selection_decrypt_replay_mic_and_counter_effects_match() {
        let parent = gtk();
        let mut hash = Sha256::new();
        let mut count = 0;
        for i in 0usize..128 {
            for (f, seed) in [0u64, 1, 100, 0xffff_ffff_fffe, 0xffff_ffff_ffff]
                .into_iter()
                .enumerate()
            {
                for (p, pn) in [0u64, 1, 2, 101, 0xffff_ffff_fffe, 0xffff_ffff_ffff]
                    .into_iter()
                    .enumerate()
                {
                    for mode in 0..7 {
                        let mut bytes = source_frame(i, pn);
                        let end = bytes.len();
                        match mode {
                            1 => bytes[end - 1] ^= 1,
                            2 => bytes[end - 18] ^= 1,
                            3 => bytes[end - 17] ^= 1,
                            4 => bytes[end - 16] ^= 1,
                            5 => bytes[24] ^= 1,
                            _ => {}
                        }
                        let mut frame = packet(bytes);
                        if mode == 6 {
                            frame.security.decrypted = true;
                            frame.security.integrity = super::super::Integrity::Verified;
                        }
                        let mut key = BipKey::new(
                            parent,
                            4 + (i % 2) as u8,
                            &[0x55; 16],
                            PacketNumber::new(seed).unwrap(),
                        )
                        .unwrap();
                        key.statistics = Statistics {
                            replays: if i % 7 == 0 { u32::MAX } else { 0 },
                            mic_failures: if i % 11 == 0 { u32::MAX } else { 0 },
                        };
                        let result = key.authenticate(&frame);
                        let accepted = result.is_ok();
                        let after_len = result.as_ref().map_or(end, |a| a.end);
                        hash.update([i as u8, f as u8, p as u8, mode, u8::from(accepted)]);
                        hash.update(&key.receive_floor().value().to_be_bytes()[2..]);
                        hash.update(key.statistics().replays.to_le_bytes());
                        hash.update(key.statistics().mic_failures.to_le_bytes());
                        hash.update((after_len as u16).to_le_bytes());
                        hash.update(&frame.bytes()[..after_len]);
                        count += 1;
                    }
                }
            }
        }
        assert_eq!(count, 26_880);
        assert_eq!(
            alloc::format!("{:x}", hash.finalize()),
            "30699480f6d259480befb7b1d73ade37cbc2df73d11df92eac0a485bb19c4c31"
        );
    }

    #[test]
    fn bad_peer_mmie_fragment_aggregate_or_receive_evidence_never_consumes_ipn() {
        let gtk = gtk();
        for fault in 0..16 {
            let mut bytes = source_frame(0, 101);
            let expected = match fault {
                0 => {
                    bytes[4] &= !1;
                    Error::WrongPeer
                }
                1 => {
                    bytes[10] ^= 2;
                    Error::WrongPeer
                }
                2 => {
                    bytes[16] ^= 2;
                    Error::WrongPeer
                }
                3 => {
                    bytes[28] ^= 1;
                    Error::WrongKey
                }
                4 => {
                    bytes[26] ^= 1;
                    Error::BadMmie
                }
                5 => {
                    bytes[27] ^= 1;
                    Error::BadMmie
                }
                6 => {
                    bytes[1] |= 0x40;
                    Error::InvalidFrame
                }
                7 => {
                    bytes[22] |= 1;
                    Error::InvalidFrame
                }
                8 => {
                    bytes[1] |= 1;
                    Error::InvalidFrame
                }
                9 => {
                    bytes[1] |= 0x80;
                    Error::InvalidFrame
                }
                10 => {
                    bytes.truncate(41);
                    Error::BadMmie
                }
                15 => Error::InvalidFrame,
                _ => Error::Integrity,
            };
            let mut frame = packet(bytes);
            match fault {
                11 => frame.fcs_error = true,
                12 => frame.monitor_only = true,
                13 => frame.security.icv_error = true,
                14 => {
                    frame.security.hardware_replay =
                        super::super::HardwareReplay::Failed { layout: 0x7925 }
                }
                15 => frame.aggregation.ampdu = Some(7),
                _ => {}
            }
            let mut key =
                BipKey::new(gtk, 4, &[0x55; 16], PacketNumber::new(100).unwrap()).unwrap();
            assert!(
                matches!(key.authenticate(&frame),Err(e) if e==expected),
                "fault {fault}"
            );
            assert_eq!(key.receive_floor().value(), 100);
            assert_eq!(key.statistics(), Statistics::default());
            let original = packet(source_frame(0, 101));
            let accepted = key.authenticate(&original).unwrap();
            assert_eq!(accepted.packet_number().value(), 101);
            assert_eq!(accepted.body(), &[7, 0]);
        }
    }
}
