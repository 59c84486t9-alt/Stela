// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
//! DROM images: `tb_drom_parse` and its entry walks. Parsed identifiers and
//! lane hints grant nothing: a router's adapters are what it reports.
use alloc::vec::Vec;

pub const DATA_START: usize = 13;
pub const MAX_LEN: usize = 4095 + DATA_START;
const PORT_ENTRY: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedRevision(u8),
    HeaderSize,
    Size,
    Entry { offset: u16 },
    ProductLength { offset: u16 },
    LaneLength { port: u8 },
    DualPort { port: u8, dual: u8 },
    UidCrc { expected: u8, actual: u8 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Crc32 {
    pub expected: u32,
    pub actual: u32,
}
impl Crc32 {
    pub fn matches(self) -> bool {
        self.expected == self.actual
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UidSource {
    Router,
    V1DromFallback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lane {
    pub link_number: u8,
    pub dual_port: Option<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Generic,
    Port {
        disabled: bool,
        extra: bool,
        lane: Option<Lane>,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Port {
    pub disabled: bool,
    pub lane: Option<Lane>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub offset: u16,
    pub length: u8,
    pub index: u8,
    pub kind: Kind,
}
/// Acquired bytes and source interpretations, not a native resource grant.
/// CRC32 mismatch is explicit while entries remain observable, as Linux warns
/// and continues. Version1 UID CRC failure is fatal; version3 uses CS7 UID.
pub struct Image {
    pub uid: u64,
    pub uid_source: UidSource,
    pub revision: u8,
    pub crc32: Crc32,
    pub product: (u16, u16),
    pub bytes: Vec<u8>,
    pub entries: Vec<Entry>,
    vendor_name: Option<usize>,
    device_name: Option<usize>,
}
impl Image {
    /// Parse `bytes` of a router with `max_port` adapters, of which `lanes`
    /// says which are lane adapters. `uid` is the router's CS7 identifier, or
    /// 0 to take it from a version 1 image.
    pub fn parse(
        bytes: Vec<u8>,
        uid: u64,
        max_port: u8,
        lanes: impl Fn(u8) -> bool,
    ) -> Result<Self, Error> {
        let mut image = Self {
            uid,
            uid_source: UidSource::Router,
            revision: 0,
            crc32: Crc32 {
                expected: 0,
                actual: 0,
            },
            product: (0, 0),
            bytes,
            entries: Vec::new(),
            vendor_name: None,
            device_name: None,
        };
        parse(&mut image, max_port, lanes)?;
        Ok(image)
    }
    /// Effective source DROM software metadata. Missing entries remain None;
    /// neither this observation nor a dual-port hint grants a routed lifetime.
    pub fn port(&self, port: u8) -> Option<Port> {
        let mut observed: Option<Port> = None;
        for e in &self.entries {
            if e.index != port {
                continue;
            }
            if let Kind::Port {
                disabled,
                extra: false,
                lane,
            } = e.kind
            {
                let value = observed.get_or_insert(Port {
                    disabled: false,
                    lane: None,
                });
                value.disabled = disabled;
                if let Some(mut lane) = lane {
                    if lane.dual_port.is_none() {
                        lane.dual_port = value.lane.and_then(|p| p.dual_port);
                    }
                    value.lane = Some(lane);
                }
            }
        }
        observed
    }
    pub fn entry_data(&self, index: usize) -> Option<&[u8]> {
        let e = self.entries.get(index)?;
        let start = usize::from(e.offset);
        self.bytes.get(start + 2..start + usize::from(e.length))
    }
    fn name(&self, index: Option<usize>) -> Option<&[u8]> {
        let data = self.entry_data(index?)?;
        Some(&data[..data.iter().position(|b| *b == 0).unwrap_or(data.len())])
    }
    pub fn vendor_name(&self) -> Option<&[u8]> {
        self.name(self.vendor_name)
    }
    pub fn device_name(&self) -> Option<&[u8]> {
        self.name(self.device_name)
    }
}
fn crc8(data: &[u8]) -> u8 {
    let mut crc = 0xff;
    for b in data {
        crc ^= *b;
        for _ in 0..8 {
            crc = (crc << 1) ^ if crc & 0x80 != 0 { 7 } else { 0 };
        }
    }
    crc
}
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0x82f63b78 } else { 0 };
        }
    }
    !crc
}
fn le16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}
fn parse(image: &mut Image, max_port: u8, lanes: impl Fn(u8) -> bool) -> Result<(), Error> {
    if image.bytes.len() < 16 {
        return Err(Error::HeaderSize);
    }
    let bytes = &image.bytes;
    let declared = usize::from(le16(bytes, 14) & 4095) + DATA_START;
    if declared != bytes.len() {
        return Err(Error::Size);
    }
    image.revision = bytes[13];
    let header = match image.revision {
        1 => {
            if bytes.len() < 22 {
                return Err(Error::HeaderSize);
            }
            let actual = crc8(&bytes[1..9]);
            if actual != bytes[0] {
                return Err(Error::UidCrc {
                    expected: bytes[0],
                    actual,
                });
            }
            if image.uid == 0 {
                image.uid = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
                image.uid_source = UidSource::V1DromFallback;
            }
            image.product = (le16(bytes, 16), le16(bytes, 18));
            22
        }
        3 => 16,
        other => return Err(Error::UnsupportedRevision(other)),
    };
    image.crc32 = Crc32 {
        expected: u32::from_le_bytes(bytes[9..13].try_into().unwrap()),
        actual: crc32(&bytes[DATA_START..]),
    };
    let mut at = header;
    while at < bytes.len() {
        if at + 2 > bytes.len() {
            return Err(Error::Entry { offset: at as u16 });
        }
        let length = usize::from(bytes[at]);
        if length < 2 || at + length > bytes.len() {
            return Err(Error::Entry { offset: at as u16 });
        }
        let flags = bytes[at + 1];
        let index = flags & 63;
        let port = flags & 128 != 0;
        let i = image.entries.len();
        if !port {
            match index {
                1 => image.vendor_name = Some(i),
                2 => image.device_name = Some(i),
                9 => {
                    if length < 8 {
                        return Err(Error::ProductLength { offset: at as u16 });
                    }
                    if image.product == (0, 0) {
                        image.product = (le16(bytes, at + 4), le16(bytes, at + 6));
                    }
                }
                _ => {}
            }
        }
        image.entries.push(Entry {
            offset: at as u16,
            length: length as u8,
            index,
            kind: if port {
                let disabled = flags & 64 != 0;
                let extra = index > max_port;
                let lane = if !disabled && !extra && lanes(index) {
                    if length != PORT_ENTRY {
                        return Err(Error::LaneLength { port: index });
                    }
                    let (flags, dual) = (bytes[at + 2], bytes[at + 3] & 63);
                    if flags & 0x80 != 0 && (dual == 0 || dual > max_port) {
                        return Err(Error::DualPort { port: index, dual });
                    }
                    Some(Lane {
                        link_number: (flags >> 4) & 1,
                        dual_port: (flags & 0x80 != 0).then_some(dual),
                    })
                } else {
                    None
                };
                Kind::Port {
                    disabled,
                    extra,
                    lane,
                }
            } else {
                Kind::Generic
            },
        });
        at += length;
    }
    Ok(())
}
/// Finish a hand-made image: its length and checksums.
#[cfg(test)]
pub(crate) fn seal(bytes: &mut [u8]) {
    let len = (bytes.len() - DATA_START) as u16;
    bytes[14..16].copy_from_slice(&len.to_le_bytes());
    bytes[0] = crc8(&bytes[1..9]);
    let crc = crc32(&bytes[13..]);
    bytes[9..13].copy_from_slice(&crc.to_le_bytes());
}

#[cfg(test)]
mod tests;
