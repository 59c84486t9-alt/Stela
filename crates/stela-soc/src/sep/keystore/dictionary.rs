//! The DER dictionaries AppleKeyStore exchanges: a SET of SEQUENCEs, each a
//! UTF8String key and its value, in key order (libaks `encode_list_dict`).
use alloc::{vec, vec::Vec};

pub(super) fn number(value: u8) -> Vec<u8> {
    if value < 128 {
        tagged(2, &[value])
    } else {
        tagged(2, &[0, value])
    }
}

/// Only fixed-size, internally authored fields reach this encoder.
pub(super) fn tagged(tag: u8, bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() < 256);
    let mut result = vec![tag];
    if bytes.len() >= 128 {
        result.push(0x81);
    }
    result.push(bytes.len() as u8);
    result.extend_from_slice(bytes);
    result
}

pub(super) fn dictionary(fields: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    debug_assert!(fields.windows(2).all(|f| f[0].0 < f[1].0));
    let mut bytes = Vec::new();
    for (key, value) in fields {
        let mut pair = tagged(12, key);
        pair.extend_from_slice(value);
        bytes.extend(tagged(0x30, &pair));
    }
    tagged(0x31, &bytes)
}
