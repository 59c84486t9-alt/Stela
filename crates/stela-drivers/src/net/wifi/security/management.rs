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
mod tests;
