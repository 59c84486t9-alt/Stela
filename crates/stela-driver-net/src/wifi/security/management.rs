// SPDX-License-Identifier: GPL-2.0-only
// BIP AAD, MMIE/IPN and CMAC handling adapt Linux net/mac80211/{wpa,aes_cmac}.c:
// Copyright 2008 Jouni Malinen <j@w1.fi>; Copyright (C) 2020 Intel Corporation.
// Robust classification and MMIE layout adapt Linux include/linux/ieee80211.h:
// Copyright 2001-2003 SSH Communications Security Corp and Jouni Malinen;
// 2005 Devicescape Software, Inc.; 2006 Michael Wu;
// 2013-2014 Intel Mobile Communications GmbH; 2016-2017 Intel Deutschland GmbH;
// 2018-2026 Intel Corporation.
// CMAC subkeys/stream/finalization adapt Linux lib/crypto/aes.c:
// Copyright 2026 Google LLC. BIP-GMAC nonce and AAD follow Linux
// net/mac80211/aes_gmac.c: Copyright 2015, Qualcomm Atheros, Inc.
// Original notices and source pin in THIRD_PARTY.md.
//! Group robust-management authentication under an IGTK.
//! Authentication is not PMF negotiation, current-association/port permission,
//! physical key completion or permission to act on a delayed management frame.

use super::{KeyIdentity, KeyScope, PacketNumber, valid_receive_observations};
use crate::wifi::{Aggregation, frame};
use alloc::boxed::Box;
use stela_crypto::{
    Aes128, Aes256,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MMIE_ID: u8 = 76;
const MANAGEMENT_HEADER: usize = 24;
/// GHASH's reduction constant, R = 11100001 || 0^120 (NIST SP 800-38D 6.3).
const GHASH_R: u128 = 0xe1 << 120;

/// The RSNE group management cipher suite, BIP-CMAC-128 when it is omitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementCipher {
    Cmac128,
    Cmac256,
    Gmac128,
    Gmac256,
}
impl ManagementCipher {
    /// The 00-0F-AC suite type (`WLAN_CIPHER_SUITE_AES_CMAC`,
    /// `_BIP_CMAC_256`, `_BIP_GMAC_128`, `_BIP_GMAC_256`).
    pub const fn from_suite(suite: u8) -> Option<Self> {
        match suite {
            6 => Some(Self::Cmac128),
            13 => Some(Self::Cmac256),
            11 => Some(Self::Gmac128),
            12 => Some(Self::Gmac256),
            _ => None,
        }
    }
    pub const fn suite(self) -> u8 {
        match self {
            Self::Cmac128 => 6,
            Self::Cmac256 => 13,
            Self::Gmac128 => 11,
            Self::Gmac256 => 12,
        }
    }
    pub const fn key_length(self) -> usize {
        match self {
            Self::Cmac128 | Self::Gmac128 => 16,
            Self::Cmac256 | Self::Gmac256 => 32,
        }
    }
    /// BIP-CMAC-128 truncates its MIC to 8 bytes; the others keep 16.
    pub const fn mic_length(self) -> usize {
        match self {
            Self::Cmac128 => 8,
            _ => 16,
        }
    }
    /// The whole MMIE: element header, key ID, IPN and MIC.
    pub const fn mmie_length(self) -> usize {
        10 + self.mic_length()
    }
}
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

// Kept only by a vendor key owner; pending/uncertain keys cannot call
// authenticate. AES expanded keys and CMAC subkeys are zeroized on real drain.
// The native owner still controls ACK, namespace, generation and retirement.
pub(crate) struct BipKey {
    gtk: KeyIdentity,
    cipher: ManagementCipher,
    index: u8,
    receive: PacketNumber,
    mac: Mac,
    statistics: Statistics,
}
enum Mac {
    Cmac(Cmac),
    Gmac(Gmac),
}
impl BipKey {
    pub(crate) fn new(
        gtk: KeyIdentity,
        cipher: ManagementCipher,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Self, Error> {
        if !matches!(gtk.scope(), KeyScope::Group(_))
            || !matches!(index, 4 | 5)
            || material.len() != cipher.key_length()
        {
            return Err(Error::InvalidKey);
        }
        let mac = match cipher {
            ManagementCipher::Cmac128 | ManagementCipher::Cmac256 => {
                Mac::Cmac(Cmac::new(material)?)
            }
            ManagementCipher::Gmac128 | ManagementCipher::Gmac256 => {
                Mac::Gmac(Gmac::new(material)?)
            }
        };
        Ok(Self {
            gtk,
            cipher,
            index,
            receive,
            mac,
            statistics: Statistics::default(),
        })
    }
    pub(crate) const fn cipher(&self) -> ManagementCipher {
        self.cipher
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
        let (mmie_bytes, mic_bytes) = (self.cipher.mmie_length(), self.cipher.mic_length());
        let bytes = mpdu.bytes();
        let mmie = bytes
            .get(bytes.len().saturating_sub(mmie_bytes)..)
            .filter(|b| b.len() == mmie_bytes && bytes.len() >= MANAGEMENT_HEADER + mmie_bytes)
            .ok_or(Error::BadMmie)?;
        if mmie[0] != MMIE_ID || usize::from(mmie[1]) != mmie_bytes - 2 {
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
        aad[2..].copy_from_slice(&bytes[4..22]);
        let body = &bytes[MANAGEMENT_HEADER..bytes.len() - mic_bytes];
        let zero = &[0; 16][..mic_bytes];
        let mic = match &self.mac {
            Mac::Cmac(cmac) => {
                let mut stream = cmac.start();
                stream.update(&aad);
                stream.update(body);
                stream.update(zero);
                stream.finish()
            }
            // ieee80211_aes_gmac: A2 || IPN, most significant byte first.
            Mac::Gmac(gmac) => {
                let mut nonce = [0; 12];
                nonce[..6].copy_from_slice(&bytes[10..16]);
                for (to, from) in nonce[6..].iter_mut().zip(mmie[4..10].iter().rev()) {
                    *to = *from;
                }
                gmac.tag(&nonce, &[&aad, body, zero])
            }
        };
        if !bool::from(mic[..mic_bytes].ct_eq(&mmie[10..])) {
            self.statistics.mic_failures = self.statistics.mic_failures.wrapping_add(1);
            return Err(Error::Integrity);
        }
        self.receive = pn;
        Ok(Authenticated {
            mpdu,
            gtk: self.gtk,
            index: self.index,
            pn,
            end: bytes.len() - mmie_bytes,
        })
    }
}

/// AES with a 128- or 256-bit key; both zeroize their schedules on drop.
enum Aes {
    Aes128(Box<Aes128>),
    Aes256(Box<Aes256>),
}
impl Aes {
    fn new(key: &[u8]) -> Result<Self, Error> {
        match key.len() {
            16 => Aes128::new_from_slice(key).map(|aes| Self::Aes128(Box::new(aes))),
            32 => Aes256::new_from_slice(key).map(|aes| Self::Aes256(Box::new(aes))),
            _ => return Err(Error::InvalidKey),
        }
        .map_err(|_| Error::InvalidKey)
    }
    fn encrypt(&self, block: &mut [u8; 16]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block(block),
            Self::Aes256(cipher) => cipher.encrypt_block(block),
        }
    }
}

struct Cmac {
    cipher: Aes,
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
        let cipher = Aes::new(key)?;
        let mut l = Zeroizing::new([0; 16]);
        cipher.encrypt(&mut l);
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
                self.key.cipher.encrypt(&mut self.state);
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
        self.key.cipher.encrypt(&mut self.state);
        *self.state
    }
}

/// GMAC: GCM's tag over additional data alone (NIST SP 800-38D), as the
/// kernel's gcm(aes) computes it for `ieee80211_aes_gmac`.
struct Gmac {
    cipher: Aes,
    hash: Zeroizing<[u8; 16]>,
}
impl Gmac {
    fn new(key: &[u8]) -> Result<Self, Error> {
        let cipher = Aes::new(key)?;
        let mut hash = Zeroizing::new([0; 16]);
        cipher.encrypt(&mut hash);
        Ok(Self { cipher, hash })
    }
    fn tag(&self, nonce: &[u8; 12], data: &[&[u8]]) -> [u8; 16] {
        let hash = Zeroizing::new(u128::from_be_bytes(*self.hash));
        let mut state = Zeroizing::new(0u128);
        let mut block = Zeroizing::new([0; 16]);
        let mut used = 0;
        let mut length = 0u64;
        for &b in data.iter().flat_map(|part| part.iter()) {
            block[used] = b;
            used += 1;
            if used == 16 {
                *state = multiply(*state ^ u128::from_be_bytes(*block), *hash);
                used = 0;
            }
            length += 8;
        }
        if used != 0 {
            block[used..].fill(0);
            *state = multiply(*state ^ u128::from_be_bytes(*block), *hash);
        }
        // len(A) || len(C), in bits; there is no ciphertext.
        *state = multiply(*state ^ u128::from(length) << 64, *hash);
        let mut counter = [0; 16];
        counter[..12].copy_from_slice(nonce);
        counter[15] = 1;
        self.cipher.encrypt(&mut counter);
        (u128::from_be_bytes(counter) ^ *state).to_be_bytes()
    }
}

/// Multiplication in GF(2^128) with GCM's bit order, without secret-dependent
/// branches or table lookups.
fn multiply(x: u128, y: u128) -> u128 {
    let mut product = 0;
    let mut v = y;
    for bit in (0..128).rev() {
        product ^= v & 0u128.wrapping_sub(x >> bit & 1);
        v = v >> 1 ^ GHASH_R & 0u128.wrapping_sub(v & 1);
    }
    product
}

#[cfg(test)]
mod tests;
