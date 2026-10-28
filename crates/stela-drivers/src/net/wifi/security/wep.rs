// SPDX-License-Identifier: GPL-2.0-only
// WEP framing adapted from Linux net/mac80211/wep.c; source notices in
// THIRD_PARTY.md.
//! Software WEP for the shared-key authentication challenge response, which
//! mac80211 encrypts itself before any key reaches the hardware.

use super::Cipher;
use zeroize::Zeroize;

/// `~crc32_le(~0, bytes)`, the WEP ICV and the 6 GHz short SSID.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb8_8320 } else { 0 };
        }
    }
    !crc
}

/// One static WEP key with its on-air index.
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    material: [u8; 13],
    cipher: Cipher,
    index: u8,
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Key")
            .field("cipher", &self.cipher)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

impl Key {
    /// WLAN_KEY_LEN_WEP40 or WLAN_KEY_LEN_WEP104 material at a default key
    /// index, as `cfg80211_validate_key_settings` takes it.
    pub fn new(material: &[u8], index: u8) -> Option<Self> {
        let cipher = match material.len() {
            5 => Cipher::Wep40,
            13 => Cipher::Wep104,
            _ => return None,
        };
        if index > 3 {
            return None;
        }
        let mut key = Self {
            material: [0; 13],
            cipher,
            index,
        };
        key.material[..material.len()].copy_from_slice(material);
        Some(key)
    }
    pub const fn cipher(&self) -> Cipher {
        self.cipher
    }
    pub const fn index(&self) -> u8 {
        self.index
    }
    pub fn material(&self) -> &[u8] {
        &self.material[..self.cipher.key_length()]
    }
}

/// `ieee80211_wep_get_iv`: advance the IV, skipping the Fluhrer-Mantin-Shamir
/// weak (KeyByte + 3, 0xff, N) form, and return its three bytes.
pub fn next_iv(iv: &mut u32, key_length: usize) -> [u8; 3] {
    *iv = iv.wrapping_add(1);
    if *iv & 0xff00 == 0xff00 {
        let b = usize::from((*iv >> 16) as u8);
        if (3..3 + key_length).contains(&b) {
            *iv = iv.wrapping_add(0x0100);
        }
    }
    [(*iv >> 16) as u8, (*iv >> 8) as u8, *iv as u8]
}

/// `ieee80211_wep_encrypt`: insert the IV and key index after the 24-byte
/// header, then RC4(IV | key) over the body and its CRC-32 ICV.
pub fn encrypt(frame: &mut alloc::vec::Vec<u8>, key: &Key, iv: [u8; 3]) {
    let body = frame.split_off(24);
    frame.extend_from_slice(&iv);
    frame.push(key.index << 6);
    let start = frame.len();
    frame.extend_from_slice(&body);
    frame.extend_from_slice(&crc32(&body).to_le_bytes());
    let mut seed = [0u8; 16];
    seed[..3].copy_from_slice(&iv);
    seed[3..3 + key.material().len()].copy_from_slice(key.material());
    rc4(&seed[..3 + key.material().len()], &mut frame[start..]);
    seed.zeroize();
}

fn rc4(key: &[u8], data: &mut [u8]) {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, usize::from(j));
    }
    let (mut i, mut j) = (0u8, 0u8);
    for byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[usize::from(i)]);
        s.swap(usize::from(i), usize::from(j));
        *byte ^= s[usize::from(s[usize::from(i)].wrapping_add(s[usize::from(j)]))];
    }
    s.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_matches_the_rfc_6229_keystream() {
        let mut data = [0u8; 8];
        rc4(&[1, 2, 3, 4, 5], &mut data);
        assert_eq!(data, [0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27]);
    }

    #[test]
    fn weak_ivs_are_skipped_like_ieee80211_wep_get_iv() {
        // 0x03ff00 has B = 3 within the key bytes, so it moves to 0x040000.
        let mut iv = 0x03_fe_ff;
        assert_eq!(next_iv(&mut iv, 5), [4, 0, 0]);
        let mut iv = 0x02_fe_ff;
        assert_eq!(next_iv(&mut iv, 5), [2, 0xff, 0]);
        let mut iv = 0x08_fe_ff;
        assert_eq!(
            (next_iv(&mut iv, 5), next_iv(&mut 0x08_fe_ff, 13)),
            ([8, 0xff, 0], [9, 0, 0])
        );
    }

    #[test]
    fn encryption_round_trips_with_its_icv() {
        let key = Key::new(&[1, 2, 3, 4, 5], 2).unwrap();
        let mut frame = alloc::vec![0xb0; 24];
        frame.extend_from_slice(b"challenge");
        encrypt(&mut frame, &key, [7, 8, 9]);
        assert_eq!(&frame[24..28], &[7, 8, 9, 2 << 6]);
        let mut body = frame[28..].to_vec();
        rc4(&[7, 8, 9, 1, 2, 3, 4, 5], &mut body);
        assert_eq!(&body[..9], b"challenge");
        assert_eq!(&body[9..], &crc32(b"challenge").to_le_bytes());
        assert!(Key::new(&[0; 6], 0).is_none() && Key::new(&[0; 13], 4).is_none());
    }
}
