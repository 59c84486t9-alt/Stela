//! Synthetic Image4 fixtures shared by downstream tests.
use super::*;
use alloc::vec::Vec;

pub fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![tag];
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else {
        let length = (value.len() as u32).to_be_bytes();
        let skip = length.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend(&length[skip..]);
    }
    out.extend(value);
    out
}

pub fn im4p(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    der(
        SEQUENCE,
        &[
            der(IA5_STRING, b"IM4P"),
            der(IA5_STRING, kind),
            der(IA5_STRING, b"synthetic"),
            der(0x04, payload),
        ]
        .concat(),
    )
}

pub fn img4(payload: &[u8], manifest: &[u8]) -> Vec<u8> {
    der(
        SEQUENCE,
        &[
            der(IA5_STRING, b"IMG4"),
            payload.to_vec(),
            der(CONTEXT_0, manifest),
        ]
        .concat(),
    )
}
