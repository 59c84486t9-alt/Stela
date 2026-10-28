// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 Intel Corporation
//! HCI packet types and their framing on the Intel PCIe Bluetooth rings.
use super::{Error, Result};
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Kind {
    Command = 1,
    Acl = 2,
    Sco = 3,
    Event = 4,
    Iso = 5,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub kind: Kind,
    pub bytes: Vec<u8>,
    pub padding: Vec<u8>,
    pub receive_header: [u8; 8],
    pub completion: u32,
    pub diagnostic: bool,
}
pub(super) fn length(kind: Kind, bytes: &[u8]) -> Result<usize> {
    let (header, data) = match kind {
        Kind::Command | Kind::Sco if bytes.len() >= 3 => (3, usize::from(bytes[2])),
        Kind::Acl if bytes.len() >= 4 => (4, usize::from(u16::from_le_bytes([bytes[2], bytes[3]]))),
        Kind::Event if bytes.len() >= 2 => (2, usize::from(bytes[1])),
        Kind::Iso if bytes.len() >= 4 => (
            4,
            usize::from(u16::from_le_bytes([bytes[2], bytes[3]]) & 0x3fff),
        ),
        _ => {
            return Err(Error::Packet {
                requirement: "complete HCI packet header",
                raw: bytes.to_vec(),
            });
        }
    };
    Ok(header + data)
}
pub(super) fn receive(bytes: &[u8], completion: u32) -> Result<Packet> {
    if bytes.len() < 8 {
        return Err(Error::Packet {
            requirement: "complete RFH",
            raw: bytes.to_vec(),
        });
    }
    let n = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
    if !(4..=4088).contains(&n) {
        return Err(Error::Packet {
            requirement: "bounded RFH packet length",
            raw: bytes.to_vec(),
        });
    }
    let raw = bytes.get(8..8 + n).ok_or_else(|| Error::Packet {
        requirement: "complete RFH data",
        raw: bytes.to_vec(),
    })?;
    let kind = match u32::from_le_bytes(raw[..4].try_into().unwrap()) {
        2 => Kind::Acl,
        3 => Kind::Sco,
        4 => Kind::Event,
        5 => Kind::Iso,
        _ => {
            return Err(Error::Packet {
                requirement: "supported RX PCIe HCI type",
                raw: raw.to_vec(),
            });
        }
    };
    let data = &raw[4..];
    let length = length(kind, data)?;
    if length > data.len() {
        return Err(Error::Packet {
            requirement: "complete HCI RX payload",
            raw: raw.to_vec(),
        });
    }
    Ok(Packet {
        kind,
        bytes: data[..length].to_vec(),
        padding: data[length..].to_vec(),
        receive_header: bytes[..8].try_into().unwrap(),
        completion,
        diagnostic: kind == Kind::Event
            && data.len() >= 3
            && data[0] == 0xff
            && data[2] == 0x97
            && data[1] != 0,
    })
}
