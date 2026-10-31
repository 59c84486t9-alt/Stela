// SPDX-License-Identifier: GPL-2.0-only
// Michael adapted from Linux net/wireless/michael-mic.c; source notices in
// THIRD_PARTY.md.
//! Michael, TKIP's message check, for a device that decrypts TKIP and leaves
//! the check to the host.

/// `MICHAEL_MIC_LEN`.
pub const MIC_BYTES: usize = 8;

/// `michael_block`.
fn block(left: &mut u32, right: &mut u32, word: u32) {
    *left ^= word;
    *right ^= left.rotate_left(17);
    *left = left.wrapping_add(*right);
    let swapped = ((*left & 0xff00_ff00) >> 8) | ((*left & 0x00ff_00ff) << 8);
    *right ^= swapped;
    *left = left.wrapping_add(*right);
    *right ^= left.rotate_left(3);
    *left = left.wrapping_add(*right);
    *right ^= left.rotate_right(2);
    *left = left.wrapping_add(*right);
}

/// Michael of `message`, ended by 0x5a and the zeros that fill its last word
/// and one word more.
fn digest(key: &[u8; MIC_BYTES], message: impl Iterator<Item = u8>) -> [u8; MIC_BYTES] {
    let [a, b, c, d, e, f, g, h] = *key;
    let mut left = u32::from_le_bytes([a, b, c, d]);
    let mut right = u32::from_le_bytes([e, f, g, h]);
    let (mut word, mut filled) = (0, 0);
    for byte in message.chain([0x5a]) {
        word |= u32::from(byte) << (8 * filled);
        filled += 1;
        if filled == 4 {
            block(&mut left, &mut right, word);
            (word, filled) = (0, 0);
        }
    }
    if filled != 0 {
        block(&mut left, &mut right, word);
    }
    block(&mut left, &mut right, 0);
    let mut mic = [0; MIC_BYTES];
    mic[..4].copy_from_slice(&left.to_le_bytes());
    mic[4..].copy_from_slice(&right.to_le_bytes());
    mic
}

/// `michael_mic` of `data`, an MSDU from `source` to `destination` at
/// `priority`, with no IV or trailer about it.
pub fn michael(
    key: &[u8; MIC_BYTES],
    destination: &[u8; 6],
    source: &[u8; 6],
    priority: u8,
    data: &[u8],
) -> [u8; MIC_BYTES] {
    let priority = [priority, 0, 0, 0];
    let message = destination
        .iter()
        .chain(source)
        .chain(&priority)
        .chain(data);
    digest(key, message.copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IEEE 802.11-2020's Michael test vectors, each key the MIC before it.
    #[test]
    fn the_standards_vectors_chain() {
        let vectors: [(&[u8], [u8; 8]); 6] = [
            (b"", [0x82, 0x92, 0x5c, 0x1c, 0xa1, 0xd1, 0x30, 0xb8]),
            (b"M", [0x43, 0x47, 0x21, 0xca, 0x40, 0x63, 0x9b, 0x3f]),
            (b"Mi", [0xe8, 0xf9, 0xbe, 0xca, 0xe9, 0x7e, 0x5d, 0x29]),
            (b"Mic", [0x90, 0x03, 0x8f, 0xc6, 0xcf, 0x13, 0xc1, 0xdb]),
            (b"Mich", [0xd5, 0x5e, 0x10, 0x05, 0x10, 0x12, 0x89, 0x86]),
            (b"Michael", [0x0a, 0x94, 0x2b, 0x12, 0x4e, 0xca, 0xa5, 0x46]),
        ];
        let mut key = [0; 8];
        for (message, mic) in vectors {
            assert_eq!(digest(&key, message.iter().copied()), mic);
            key = mic;
        }
    }

    #[test]
    fn the_header_is_part_of_the_check() {
        let key = [7; 8];
        let mic = michael(&key, &[1; 6], &[2; 6], 0, b"data");
        assert_ne!(mic, michael(&key, &[3; 6], &[2; 6], 0, b"data"));
        assert_ne!(mic, michael(&key, &[1; 6], &[3; 6], 0, b"data"));
        assert_ne!(mic, michael(&key, &[1; 6], &[2; 6], 5, b"data"));
    }
}
