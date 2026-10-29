// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

pub(super) fn firmware_bytes() -> Vec<u8> {
    let mut bytes = vec![0; 88];
    bytes[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
    bytes[72..76].copy_from_slice(&(77u32 << 8).to_le_bytes());
    let mut tlv = |kind: u32, data: &[u8]| {
        bytes.extend(kind.to_le_bytes());
        bytes.extend((data.len() as u32).to_le_bytes());
        bytes.extend(data);
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
    };
    tlv(27, &2u32.to_le_bytes());
    tlv(32, &4096u32.to_le_bytes());
    tlv(48, &[1, 0, 99, 6, 0xfe, 0xc, 99, 1]);
    tlv(23, &0x2du32.to_le_bytes());
    for (offset, n, seed) in [
        (0u32, 16, 1u8),
        (0xffffcccc, 0, 0),
        (0x1000, 16, 2),
        (0xaaaabbbb, 0, 0),
        (0, 16, 3),
        (0x2000, 4096, 4),
    ] {
        let mut data = offset.to_le_bytes().to_vec();
        data.extend((0..n).map(|n| seed.wrapping_add(n as u8)));
        tlv(19, &data);
    }
    bytes
}

pub(super) fn radio_bytes(ax210: bool) -> Vec<u8> {
    let mut bytes = unified_bytes(ax210);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 23 {
            let word = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) | (3 << 16);
            bytes[at + 8..at + 12].copy_from_slice(&word.to_le_bytes());
        }
        at += 8 + len.next_multiple_of(4);
    }
    let versions = [
        0xd1,
        1,
        3,
        0,
        0x98,
        1,
        1,
        0,
        0x9b,
        1,
        6,
        0,
        1,
        2,
        2,
        0,
        0xc1,
        0,
        99,
        if ax210 { 5 } else { 4 },
        0x1c,
        1,
        if ax210 { 10 } else { 9 },
        7,
        0xf7,
        5,
        99,
        3,
    ];
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            bytes.splice(at + 8 + len..at + 8 + len, versions);
            bytes[at + 4..at + 8].copy_from_slice(&((len + versions.len()) as u32).to_le_bytes());
            break;
        }
        at += 8 + len.next_multiple_of(4);
    }
    bytes.extend(30u32.to_le_bytes());
    bytes.extend(8u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    bytes.extend((1u32 << 5).to_le_bytes());
    if ax210 {
        bytes.extend(29u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(2u32.to_le_bytes());
        bytes.extend((1u32 << 4).to_le_bytes());
    }
    bytes
}

pub(super) fn unified_bytes(ax210: bool) -> Vec<u8> {
    let mut b = if ax210 {
        ax210_bytes()
    } else {
        firmware_bytes()
    };
    let mut at = 88;
    loop {
        let kind = u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(b[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            b.splice(at + 8 + len..at + 8 + len, [2, 12, 1, 4]);
            b[at + 4..at + 8].copy_from_slice(&((len + 4) as u32).to_le_bytes());
            break;
        }
        at += 8 + len.next_multiple_of(4);
    }
    b.extend(29u32.to_le_bytes());
    b.extend(8u32.to_le_bytes());
    b.extend(1u32.to_le_bytes());
    b.extend((1u32 << 16).to_le_bytes());
    b
}

pub(super) fn nvm_response() -> Vec<u8> {
    let mut b = vec![0; 468];
    for (at, word) in [
        (0, 1u32),
        (8, 0x8000001f),
        (12, 3),
        (16, 3),
        (20, 1),
        (24, 2),
        (28, 0x12345678),
        (32, 0xabcdef),
    ] {
        b[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    b[4..8].copy_from_slice(&[0x34, 0x12, 0xa5, 4]);
    b
}

pub(super) fn pnvm_packet(status: u32) -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    bytes[..4].copy_from_slice(&12u32.to_le_bytes());
    bytes[4] = 0xfe;
    bytes[5] = 0xc;
    bytes[7] = 0x80;
    bytes[8..12].copy_from_slice(&status.to_le_bytes());
    bytes[12..16].copy_from_slice(&0x12345678u32.to_le_bytes());
    bytes[64..68].copy_from_slice(&0x55550000u32.to_le_bytes());
    bytes
}

pub(super) fn set_sku(bytes: &mut [u8], sku: [u32; 3]) {
    for (n, word) in sku.into_iter().enumerate() {
        bytes[124 + n * 4..128 + n * 4].copy_from_slice(&word.to_le_bytes());
    }
}

pub(super) fn ax210_bytes() -> Vec<u8> {
    let mut bytes = firmware_bytes();
    bytes[72..76].copy_from_slice(&(89u32 << 8).to_le_bytes());
    bytes.extend(52u32.to_le_bytes());
    bytes.extend(64u32.to_le_bytes());
    bytes.extend([0xa5; 64]);
    bytes
}

pub(super) fn lari_bytes(ax210: bool, schema: u8) -> Vec<u8> {
    let mut bytes = radio_bytes(ax210);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            bytes.splice(at + 8 + len..at + 8 + len, [1, 12, schema, 0, 8, 12, 1, 0]);
            bytes[at + 4..at + 8].copy_from_slice(&((len + 8) as u32).to_le_bytes());
            break;
        }
        at += 8 + len.next_multiple_of(4);
    }
    bytes
}
