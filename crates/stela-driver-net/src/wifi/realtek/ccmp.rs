// SPDX-License-Identifier: GPL-2.0-only
// CCMP nonce and AAD follow Linux net/mac80211/wpa.c: Copyright 2002-2004
// Instant802 Networks, Inc.; 2008 Jouni Malinen; 2016-2017 Intel Deutschland
// GmbH; 2020-2023 Intel Corporation. See THIRD_PARTY.md.
//! CCMP-128 sealing of a robust management frame, which rtw88 leaves to
//! mac80211 with `IEEE80211_KEY_FLAG_SW_MGMT_TX`, and opening one hardware
//! left sealed.
use crate::wifi::security::PacketNumber;
use alloc::vec::Vec;
use stela_crypto::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};

/// `IEEE80211_CCMP_MIC_LEN`.
const MIC: usize = 8;
const BLOCK: usize = 16;

fn encrypt(cipher: &Aes128, block: &mut [u8; BLOCK]) {
    cipher.encrypt_block(GenericArray::from_mut_slice(block));
}

/// `ccmp_special_blocks` of a management frame's 24-byte `header`: the nonce
/// and the additional authenticated data with its length prefix.
fn special_blocks(header: &[u8], pn: PacketNumber) -> ([u8; 13], Vec<u8>) {
    let mut nonce = [0; 13];
    // The priority is zero, and the management flag sets bit 4.
    nonce[0] = 0x10;
    nonce[1..7].copy_from_slice(&header[10..16]);
    let [p0, p1, p2, p3, p4, p5, ..] = pn.value().to_le_bytes();
    nonce[7..].copy_from_slice(&[p5, p4, p3, p2, p1, p0]);
    let mut aad = Vec::with_capacity(24);
    aad.extend_from_slice(&22u16.to_be_bytes());
    // Subtype and flags as mac80211 masks them: retry, power and more data go.
    aad.push(header[0]);
    aad.push(header[1] & 0xc7 | 0x40);
    aad.extend_from_slice(&header[4..22]);
    aad.push(header[22] & 0x0f);
    aad.push(0);
    (nonce, aad)
}

/// The frame `header`, `iv` and `body` make once `body` is sealed under `key`,
/// for the packet number `iv` carries.
pub fn seal(key: &[u8; 16], header: &[u8], iv: &[u8; 8], pn: PacketNumber, body: &[u8]) -> Vec<u8> {
    let (nonce, aad) = special_blocks(header, pn);
    let mut out = Vec::with_capacity(header.len() + 8 + body.len() + MIC);
    out.extend_from_slice(header);
    out.extend_from_slice(iv);
    out.extend(ccm(key, &nonce, &aad, body));
    out
}

/// `frame`, sealed for the packet number its IV carries, with its body in the
/// clear and its MIC cleared, if that MIC holds.
pub fn open(key: &[u8; 16], frame: &[u8], pn: PacketNumber) -> Option<Vec<u8>> {
    let header = frame.get(..24)?;
    let sealed = frame.get(32..)?;
    let body = sealed.get(..sealed.len().checked_sub(MIC)?)?;
    let (nonce, aad) = special_blocks(header, pn);
    // Counter mode undoes itself; only the MIC of that pass means nothing.
    let mut clear = ccm(key, &nonce, &aad, body);
    clear.truncate(body.len());
    if ccm(key, &nonce, &aad, &clear) != sealed {
        return None;
    }
    let mut out = frame.to_vec();
    out[32..32 + clear.len()].copy_from_slice(&clear);
    out[32 + clear.len()..].fill(0);
    Some(out)
}

/// `body` encrypted under `key`, then its MIC.
fn ccm(key: &[u8; 16], nonce: &[u8; 13], aad: &[u8], body: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    // CBC-MAC over B0, the AAD and the body. L is two, M is eight.
    let mut mac = [0; BLOCK];
    mac[0] = 0x40 | (((MIC as u8 - 2) / 2) << 3) | 1;
    mac[1..14].copy_from_slice(nonce);
    mac[14..].copy_from_slice(&(body.len() as u16).to_be_bytes());
    encrypt(&cipher, &mut mac);
    for chunk in aad.chunks(BLOCK).chain(body.chunks(BLOCK)) {
        for (byte, input) in mac.iter_mut().zip(chunk) {
            *byte ^= input;
        }
        encrypt(&cipher, &mut mac);
    }
    let counter = |number: u16| {
        let mut block = [0; BLOCK];
        block[0] = 1;
        block[1..14].copy_from_slice(nonce);
        block[14..].copy_from_slice(&number.to_be_bytes());
        encrypt(&cipher, &mut block);
        block
    };
    let mut out = Vec::with_capacity(body.len() + MIC);
    for (index, chunk) in body.chunks(BLOCK).enumerate() {
        let stream = counter(index as u16 + 1);
        out.extend(chunk.iter().zip(stream).map(|(byte, key)| byte ^ key));
    }
    let tag = counter(0);
    out.extend(mac.iter().zip(tag).take(MIC).map(|(byte, key)| byte ^ key));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_sealed_opens_and_a_changed_byte_does_not() {
        let key = [7; 16];
        let mut header = [0; 24];
        header[..2].copy_from_slice(&[0xd0, 0x40]);
        header[4..10].fill(2);
        header[10..22].fill(3);
        let pn = PacketNumber::new(9).unwrap();
        let iv = [9, 0, 0, 0x20, 0, 0, 0, 0];
        let mut frame = seal(&key, &header, &iv, pn, &[8, 0, 1, 2]);
        assert_ne!(frame[32..36], [8, 0, 1, 2]);
        let opened = open(&key, &frame, pn).unwrap();
        assert_eq!(opened[32..36], [8, 0, 1, 2]);
        assert_eq!(opened[36..], [0; 8]);
        frame[33] ^= 1;
        assert_eq!(open(&key, &frame, pn), None);
    }

    /// IEEE 802.11i's CCMP vector, a data frame, whose nonce and masked header
    /// `ccmp_special_blocks` would give.
    #[test]
    fn the_standards_frame_seals_to_its_ciphertext_and_mic() {
        let key = [
            0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85, 0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd,
            0xd5, 0x2f,
        ];
        let nonce = [
            0, 0x50, 0x30, 0xf1, 0x84, 0x44, 0x08, 0xb5, 0x03, 0x97, 0x76, 0xe7, 0x0c,
        ];
        let aad = [
            0, 22, 0x08, 0x40, 0x0f, 0xd2, 0xe1, 0x28, 0xa5, 0x7c, 0x50, 0x30, 0xf1, 0x84, 0x44,
            0x08, 0xab, 0xae, 0xa5, 0xb8, 0xfc, 0xba, 0, 0,
        ];
        let body = [
            0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85, 0xae, 0x96, 0x7b, 0xb6, 0x2f, 0xb6, 0xcd,
            0xa8, 0xeb, 0x7e, 0x78, 0xa0, 0x50,
        ];
        let sealed = [
            0xf3, 0xd0, 0xa2, 0xfe, 0x9a, 0x3d, 0xbf, 0x23, 0x42, 0xa6, 0x43, 0xe4, 0x32, 0x46,
            0xe8, 0x0c, 0x3c, 0x04, 0xd0, 0x19, 0x78, 0x45, 0xce, 0x0b, 0x16, 0xf9, 0x76, 0x23,
        ];
        assert_eq!(ccm(&key, &nonce, &aad, &body), sealed);
    }

    #[test]
    fn a_management_frame_keeps_its_subtype_and_sets_its_management_nonce_flag() {
        let mut header = [0; 24];
        header[0] = 0xd0;
        // Retry, power management and more data, which authentication skips.
        header[1] = 0x38;
        header[10..16].copy_from_slice(&[4; 6]);
        header[22] = 0x37;
        let pn = PacketNumber::new(0x0102_0304_0506).unwrap();
        let (nonce, aad) = special_blocks(&header, pn);
        assert_eq!(nonce[0], 0x10);
        assert_eq!(nonce[1..7], [4; 6]);
        assert_eq!(nonce[7..], [1, 2, 3, 4, 5, 6]);
        assert_eq!(aad[..4], [0, 22, 0xd0, 0x40]);
        assert_eq!(aad[22..], [7, 0]);
    }
}
