//! The DER dictionaries AppleKeyStore exchanges: a SET of SEQUENCEs, each a
//! UTF8String key and its value, in key order (libaks `encode_list_dict`).
use crate::Result;
use alloc::{vec, vec::Vec};
use stela_contracts::refuse;

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

/// The keys and octet-string values of a dictionary whose values are all
/// octet strings. Empty bytes are an empty dictionary.
pub(super) fn octet_strings(bytes: &[u8]) -> Result<Vec<(&[u8], &[u8])>> {
    let mut entries = Vec::new();
    if bytes.is_empty() {
        return Ok(entries);
    }
    let (mut pairs, rest) = element(bytes, 0x31)?;
    if !rest.is_empty() {
        return Err(refuse!("SEP keystore dictionary has bytes after its set"));
    }
    while !pairs.is_empty() {
        let (pair, rest) = element(pairs, 0x30)?;
        pairs = rest;
        let (key, value) = element(pair, 12)?;
        let (value, rest) = element(value, 4)?;
        if !rest.is_empty() {
            return Err(refuse!("SEP keystore dictionary entry has extra fields"));
        }
        entries.push((key, value));
    }
    Ok(entries)
}

/// The content of the DER element with `tag` at the start of `bytes`, and
/// the bytes after it.
fn element(bytes: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    let malformed = || refuse!("SEP keystore dictionary is not the DER it expects");
    let (&found, rest) = bytes.split_first().ok_or_else(malformed)?;
    let (&first, rest) = rest.split_first().ok_or_else(malformed)?;
    if found != tag {
        return Err(malformed());
    }
    // Short form below 0x80; long form in one or two bytes, minimal.
    let (length, rest) = match (first, rest) {
        (0..=0x7f, rest) => (first as usize, rest),
        (0x81, [length, rest @ ..]) if *length >= 0x80 => (*length as usize, rest),
        (0x82, [high, low, rest @ ..]) if *high != 0 => {
            (usize::from(*high) << 8 | usize::from(*low), rest)
        }
        _ => return Err(malformed()),
    };
    if rest.len() < length {
        return Err(malformed());
    }
    Ok(rest.split_at(length))
}
