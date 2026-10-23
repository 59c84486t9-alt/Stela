// SPDX-License-Identifier: GPL-2.0-only
// Layouts and entry encodings from Linux drivers/iommu/amd/init.c,
// commit cc9de5d4b5ab6459f5774946aa3195ad51236fa8.
// Copyright (C) 2007-2010 Advanced Micro Devices, Inc.
// Original authors: Joerg Roedel <jroedel@suse.de>, Leo Duran <leo.duran@amd.com>.
//! Allocation-free IVRS decoding. Firmware descriptions grant no ownership,
//! requester isolation, MMIO access or permission to change a remapping unit.
//! Framing, checksums, known entry encodings, range grammar and version identity
//! are checked for every block, including superseded IVHD versions. Raw policy
//! flags, UID formats and extension bytes remain firmware descriptions: MMIO
//! alignment, reserved bits and policy semantics require separate live admission
//! and explicit refusal of unresolved requirements. Range starts must be followed
//! immediately by their end; interleaved entries, including padding, are refused.

const TABLE_HEADER: usize = 48;
const BLOCK_HEADER: usize = 4;
const IVHD_SHORT: usize = 24;
const IVHD_LONG: usize = 40;
const IVMD_HEADER: usize = 32;
const HID_PREFIX: usize = 22;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseError {
    pub offset: usize,
    pub kind: ErrorKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Truncated,
    Signature,
    TableLength,
    Checksum,
    BlockLength,
    UnsupportedBlock(u8),
    UnsupportedEntry(u8),
    HidVersion,
    DeviceRange,
    DuplicateVersion,
    UnitIdentity,
    AddressOverflow,
}

fn error(offset: usize, kind: ErrorKind) -> ParseError {
    ParseError { offset, kind }
}

fn read16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("checked field"))
}

fn read64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("checked field"))
}

/// An entire, checksum-validated IVRS table. Input must have its exact declared
/// length; callers with a larger firmware mapping must first bound that view.
#[derive(Clone, Copy, Debug)]
pub struct Ivrs<'a> {
    raw: &'a [u8],
}

impl<'a> Ivrs<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, ParseError> {
        if raw.len() < TABLE_HEADER {
            return Err(error(raw.len(), ErrorKind::Truncated));
        }
        if &raw[..4] != b"IVRS" {
            return Err(error(0, ErrorKind::Signature));
        }
        if u64::from(read32(raw, 4)) != raw.len() as u64 {
            return Err(error(4, ErrorKind::TableLength));
        }
        if raw.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 {
            return Err(error(9, ErrorKind::Checksum));
        }
        let mut offset = TABLE_HEADER;
        while offset < raw.len() {
            let remaining = &raw[offset..];
            if remaining.len() < BLOCK_HEADER {
                return Err(error(offset, ErrorKind::Truncated));
            }
            let length = usize::from(read16(remaining, 2));
            if length < BLOCK_HEADER {
                return Err(error(offset + 2, ErrorKind::BlockLength));
            }
            let block = remaining
                .get(..length)
                .ok_or_else(|| error(offset, ErrorKind::Truncated))?;
            match block[0] {
                0x10 | 0x11 | 0x40 => {
                    let header = if block[0] == 0x10 {
                        IVHD_SHORT
                    } else {
                        IVHD_LONG
                    };
                    if length < header {
                        return Err(error(offset + 2, ErrorKind::BlockLength));
                    }
                    validate_entries(&block[header..], block[0], offset + header)?;
                }
                0x20..=0x22 => {
                    if length < IVMD_HEADER {
                        return Err(error(offset + 2, ErrorKind::BlockLength));
                    }
                    if block[0] == 0x22 && read16(block, 4) > read16(block, 6) {
                        return Err(error(offset + 4, ErrorKind::DeviceRange));
                    }
                    read64(block, 16)
                        .checked_add(read64(block, 24))
                        .ok_or_else(|| error(offset + 16, ErrorKind::AddressOverflow))?;
                }
                other => return Err(error(offset, ErrorKind::UnsupportedBlock(other))),
            }
            offset += length;
        }
        let table = Self { raw };
        // No allocation or assumed block ordering: compare every version pair
        // only after all block/entry bounds have been established.
        for first in table.hardware_blocks() {
            for second in table
                .hardware_blocks()
                .filter(|unit| unit.offset > first.offset)
            {
                if first.id() != second.id() {
                    continue;
                }
                if first.version() == second.version() {
                    return Err(error(second.offset, ErrorKind::DuplicateVersion));
                }
                if !first.same_identity(second) {
                    return Err(error(second.offset, ErrorKind::UnitIdentity));
                }
            }
        }
        Ok(table)
    }

    pub fn raw(self) -> &'a [u8] {
        self.raw
    }

    pub fn info(self) -> u32 {
        read32(self.raw, 36)
    }

    pub fn revision(self) -> u8 {
        self.raw[8]
    }

    pub fn blocks(self) -> Blocks<'a> {
        Blocks {
            remaining: &self.raw[TABLE_HEADER..],
            offset: TABLE_HEADER,
        }
    }

    pub fn hardware_blocks(self) -> impl Iterator<Item = Ivhd<'a>> {
        self.blocks().filter_map(|block| match block {
            Block::Hardware(unit) => Some(unit),
            Block::Memory(_) => None,
        })
    }

    /// One highest-version description per (segment, IOMMU device ID), in
    /// table order. All lower versions were still validated by `parse`.
    pub fn units(self) -> impl Iterator<Item = Ivhd<'a>> {
        self.hardware_blocks().filter(move |unit| {
            !self
                .hardware_blocks()
                .any(|other| other.id() == unit.id() && other.version() > unit.version())
        })
    }

    pub fn memory_definitions(self) -> impl Iterator<Item = Ivmd<'a>> {
        self.blocks().filter_map(|block| match block {
            Block::Memory(memory) => Some(memory),
            Block::Hardware(_) => None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequesterId {
    pub segment: u16,
    pub device_id: u16,
}

/// Version order is explicit, independently of firmware block ordering.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HardwareVersion {
    Type10,
    Type11,
    Type40,
}

#[derive(Clone, Copy, Debug)]
pub struct Ivhd<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> Ivhd<'a> {
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }

    pub fn offset(self) -> usize {
        self.offset
    }

    pub fn version(self) -> HardwareVersion {
        match self.raw[0] {
            0x10 => HardwareVersion::Type10,
            0x11 => HardwareVersion::Type11,
            0x40 => HardwareVersion::Type40,
            _ => unreachable!("validated IVHD type"),
        }
    }

    pub fn flags(self) -> u8 {
        self.raw[1]
    }

    pub fn id(self) -> RequesterId {
        RequesterId {
            segment: read16(self.raw, 16),
            device_id: read16(self.raw, 4),
        }
    }

    pub fn capability_offset(self) -> u16 {
        read16(self.raw, 6)
    }

    pub fn mmio_address(self) -> u64 {
        read64(self.raw, 8)
    }

    pub fn info(self) -> u16 {
        read16(self.raw, 18)
    }

    /// Type 10 feature reporting; type 11/40 EFR attributes. These different
    /// encodings are preserved rather than compared as common identity.
    pub fn feature_or_attributes(self) -> u32 {
        read32(self.raw, 20)
    }

    /// Exact firmware EFR/EFR2 images in the pinned driver's long header.
    pub fn extended_features(self) -> Option<(u64, u64)> {
        (self.version() != HardwareVersion::Type10)
            .then(|| (read64(self.raw, 24), read64(self.raw, 32)))
    }

    pub fn entries(self) -> DeviceEntries<'a> {
        let header = if self.version() == HardwareVersion::Type10 {
            IVHD_SHORT
        } else {
            IVHD_LONG
        };
        DeviceEntries {
            remaining: &self.raw[header..],
            segment: self.id().segment,
        }
    }

    fn same_identity(self, other: Self) -> bool {
        // Flags, info, feature reporting and EFR attributes may describe
        // different capabilities in different versions; they are not identity.
        self.capability_offset() == other.capability_offset()
            && self.mmio_address() == other.mmio_address()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Block<'a> {
    Hardware(Ivhd<'a>),
    Memory(Ivmd<'a>),
}

pub struct Blocks<'a> {
    remaining: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Blocks<'a> {
    type Item = Block<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let length = usize::from(read16(self.remaining, 2));
        let (raw, rest) = self.remaining.split_at(length);
        let offset = self.offset;
        self.offset += length;
        self.remaining = rest;
        Some(match raw[0] {
            0x10 | 0x11 | 0x40 => Block::Hardware(Ivhd { raw, offset }),
            0x20..=0x22 => Block::Memory(Ivmd { raw, offset }),
            _ => unreachable!("validated IVRS block"),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangePolicy {
    Plain,
    Alias(RequesterId),
    Extended(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceKind<'a> {
    Padding,
    NotUsed,
    All,
    Select(RequesterId),
    RangeStart {
        first: RequesterId,
        policy: RangePolicy,
    },
    RangeEnd(RequesterId),
    Alias {
        requester: RequesterId,
        target: RequesterId,
    },
    Extended {
        requester: RequesterId,
        data: u32,
    },
    Special {
        header_id: u16,
        requester: RequesterId,
        handle: u8,
        variety: u8,
    },
    Hid {
        requester: RequesterId,
        hid: &'a [u8; 8],
        cid: &'a [u8; 8],
        uid_format: u8,
        uid: &'a [u8],
    },
}

/// Original bytes and data-setting flags are retained even for padding, range
/// ends and special entries. HID UID formats are raw firmware metadata, not an
/// assertion that an ACPI namespace or UID conversion service is implemented.
#[derive(Clone, Copy, Debug)]
pub struct DeviceEntry<'a> {
    raw: &'a [u8],
    pub kind: DeviceKind<'a>,
}

impl<'a> DeviceEntry<'a> {
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }

    pub fn flags(self) -> u8 {
        self.raw[3]
    }
}

pub struct DeviceEntries<'a> {
    remaining: &'a [u8],
    segment: u16,
}

fn entry_length(raw: &[u8], version: u8, offset: usize) -> Result<usize, ParseError> {
    let Some(&kind) = raw.first() else {
        return Err(error(offset, ErrorKind::Truncated));
    };
    let length = if kind < 0x80 {
        4usize << (kind >> 6)
    } else if kind == 0xf0 {
        if version != 0x40 {
            return Err(error(offset, ErrorKind::HidVersion));
        }
        let prefix = raw
            .get(..HID_PREFIX)
            .ok_or_else(|| error(offset, ErrorKind::Truncated))?;
        HID_PREFIX + usize::from(prefix[21])
    } else {
        return Err(error(offset, ErrorKind::UnsupportedEntry(kind)));
    };
    if length > raw.len() {
        return Err(error(offset, ErrorKind::Truncated));
    }
    match kind {
        0x00..=0x04 | 0x40..=0x43 | 0x46..=0x48 | 0xf0 => Ok(length),
        other => Err(error(offset, ErrorKind::UnsupportedEntry(other))),
    }
}

fn validate_entries(mut raw: &[u8], version: u8, mut offset: usize) -> Result<(), ParseError> {
    let mut range: Option<(u16, usize)> = None;
    while !raw.is_empty() {
        let length = entry_length(raw, version, offset)?;
        match (range, raw[0]) {
            (None, 0x03 | 0x43 | 0x47) => range = Some((read16(raw, 1), offset)),
            (Some((start, _)), 0x04) if read16(raw, 1) >= start => range = None,
            (Some(_), _) | (None, 0x04) => return Err(error(offset, ErrorKind::DeviceRange)),
            _ => (),
        }
        raw = &raw[length..];
        offset += length;
    }
    if let Some((_, start)) = range {
        return Err(error(start, ErrorKind::DeviceRange));
    }
    Ok(())
}

impl<'a> Iterator for DeviceEntries<'a> {
    type Item = DeviceEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        // A HID can only be present in the already-validated type 40 header.
        let length = entry_length(self.remaining, 0x40, 0).expect("validated IVHD entry");
        let (raw, rest) = self.remaining.split_at(length);
        self.remaining = rest;
        let requester = RequesterId {
            segment: self.segment,
            device_id: read16(raw, 1),
        };
        let target = || RequesterId {
            segment: self.segment,
            device_id: read16(raw, 5),
        };
        let kind = match raw[0] {
            0x00 | 0x40 => DeviceKind::Padding,
            0x41 => DeviceKind::NotUsed,
            0x01 => DeviceKind::All,
            0x02 => DeviceKind::Select(requester),
            0x03 | 0x43 | 0x47 => DeviceKind::RangeStart {
                first: requester,
                policy: match raw[0] {
                    0x43 => RangePolicy::Alias(target()),
                    0x47 => RangePolicy::Extended(read32(raw, 4)),
                    _ => RangePolicy::Plain,
                },
            },
            0x04 => DeviceKind::RangeEnd(requester),
            0x42 => DeviceKind::Alias {
                requester,
                target: target(),
            },
            0x46 => DeviceKind::Extended {
                requester,
                data: read32(raw, 4),
            },
            0x48 => DeviceKind::Special {
                header_id: requester.device_id,
                requester: target(),
                handle: raw[4],
                variety: raw[7],
            },
            0xf0 => DeviceKind::Hid {
                requester,
                hid: raw[4..12].try_into().expect("validated HID"),
                cid: raw[12..20].try_into().expect("validated CID"),
                uid_format: raw[20],
                uid: &raw[HID_PREFIX..],
            },
            _ => unreachable!("validated device entry"),
        };
        Some(DeviceEntry { raw, kind })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryScope {
    All {
        segment: u16,
    },
    Device(RequesterId),
    Range {
        first: RequesterId,
        last: RequesterId,
    },
}

/// Exact, unrounded firmware policy. Flags, scope and bytes are not a grant to
/// reserve or unity-map those addresses. Extension bytes remain in `raw`.
#[derive(Clone, Copy, Debug)]
pub struct Ivmd<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> Ivmd<'a> {
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }

    pub fn offset(self) -> usize {
        self.offset
    }

    pub fn flags(self) -> u8 {
        self.raw[1]
    }

    pub fn segment(self) -> u16 {
        // Pinned AMD driver's private header, not older ACPICA's reserved u64.
        read16(self.raw, 8)
    }

    pub fn device_id(self) -> u16 {
        read16(self.raw, 4)
    }

    pub fn auxiliary(self) -> u16 {
        read16(self.raw, 6)
    }

    pub fn scope(self) -> MemoryScope {
        let first = RequesterId {
            segment: self.segment(),
            device_id: self.device_id(),
        };
        match self.raw[0] {
            0x20 => MemoryScope::All {
                segment: self.segment(),
            },
            0x21 => MemoryScope::Device(first),
            0x22 => MemoryScope::Range {
                first,
                last: RequesterId {
                    segment: self.segment(),
                    device_id: self.auxiliary(),
                },
            },
            _ => unreachable!("validated IVMD type"),
        }
    }

    pub fn start(self) -> u64 {
        read64(self.raw, 16)
    }

    pub fn length(self) -> u64 {
        read64(self.raw, 24)
    }

    pub fn end(self) -> u64 {
        self.start() + self.length()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    fn put16(raw: &mut [u8], offset: usize, value: u16) {
        raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(raw: &mut [u8], offset: usize, value: u64) {
        raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn checksum(raw: &mut [u8]) {
        raw[9] = 0;
        raw[9] = 0u8.wrapping_sub(raw.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
    }
    fn table(blocks: &[&[u8]]) -> Vec<u8> {
        let mut raw = vec![0; TABLE_HEADER];
        raw[..4].copy_from_slice(b"IVRS");
        raw[8] = 2;
        for block in blocks {
            raw.extend_from_slice(block);
        }
        let length = u32::try_from(raw.len()).unwrap();
        raw[4..8].copy_from_slice(&length.to_le_bytes());
        checksum(&mut raw);
        raw
    }
    fn hardware(kind: u8, segment: u16, device_id: u16, entries: &[u8]) -> Vec<u8> {
        let mut raw = vec![0; if kind == 0x10 { IVHD_SHORT } else { IVHD_LONG }];
        raw[0] = kind;
        raw[1] = 0x15;
        put16(&mut raw, 4, device_id);
        put16(&mut raw, 6, 0x40);
        put64(&mut raw, 8, 0xfed90000);
        put16(&mut raw, 16, segment);
        put16(&mut raw, 18, 0x1203);
        raw.extend_from_slice(entries);
        let length = u16::try_from(raw.len()).unwrap();
        put16(&mut raw, 2, length);
        raw
    }
    fn entry(kind: u8, device_id: u16, flags: u8, extra: Option<u32>) -> Vec<u8> {
        let mut raw = vec![kind, 0, 0, flags];
        put16(&mut raw, 1, device_id);
        if let Some(extra) = extra {
            raw.extend_from_slice(&extra.to_le_bytes());
        }
        raw
    }
    fn fail(raw: &[u8], kind: ErrorKind) {
        assert_eq!(Ivrs::parse(raw).unwrap_err().kind, kind);
    }

    #[test]
    fn complete_table_and_every_block_are_checked_before_success() {
        let good = table(&[&hardware(0x10, 0, 8, &[])]);
        for end in 0..TABLE_HEADER {
            fail(&good[..end], ErrorKind::Truncated);
        }
        fail(&good[..good.len() - 1], ErrorKind::TableLength);
        let mut extra = good.clone();
        extra.push(0);
        fail(&extra, ErrorKind::TableLength);
        for version in [0x10, 0x11, 0x40] {
            let entries = [
                entry(2, 0x1234, 0, None),
                entry(0x42, 0x5678, 0, Some(0xabcd00)),
            ]
            .concat();
            let complete = table(&[&hardware(version, 0, 8, &entries)]);
            // Rebind the outer length/checksum so every incomplete block and
            // entry prefix reaches the inner bounds checks.
            for end in TABLE_HEADER + 1..complete.len() {
                let mut prefix = complete[..end].to_vec();
                prefix[4..8].copy_from_slice(&(end as u32).to_le_bytes());
                checksum(&mut prefix);
                fail(&prefix, ErrorKind::Truncated);
            }
        }
        let mut raw = good.clone();
        raw[0] = b'X';
        fail(&raw, ErrorKind::Signature);
        let mut raw = good.clone();
        raw[36] ^= 1;
        fail(&raw, ErrorKind::Checksum);
        for (version, header) in [(0x10, IVHD_SHORT), (0x11, IVHD_LONG), (0x40, IVHD_LONG)] {
            for length in 0..header {
                let mut block = hardware(version, 0, 8, &[]);
                put16(&mut block, 2, length as u16);
                fail(&table(&[&block]), ErrorKind::BlockLength);
            }
        }
        let mut oversized = hardware(0x11, 0, 8, &[]);
        put16(&mut oversized, 2, 41);
        fail(&table(&[&oversized]), ErrorKind::Truncated);
        let mut short = hardware(0x40, 0, 8, &[]);
        short.truncate(IVHD_LONG - 1);
        put16(&mut short, 2, (IVHD_LONG - 1) as u16);
        fail(&table(&[&short]), ErrorKind::BlockLength);
        fail(
            &table(&[&[0x23, 0, 4, 0]]),
            ErrorKind::UnsupportedBlock(0x23),
        );
        fail(&table(&[&[0, 0, 0]]), ErrorKind::Truncated);
        // A valid first unit does not hide malformed bytes in a later block.
        fail(
            &table(&[&hardware(0x10, 0, 8, &[]), &[0x23, 0, 4, 0]]),
            ErrorKind::UnsupportedBlock(0x23),
        );
    }

    #[test]
    fn unit_versions_are_grouped_by_full_identity_without_order_assumptions() {
        let first = hardware(0x10, 0x1234, 0xabcd, &[]);
        let mut middle = hardware(0x11, 0x1234, 0xabcd, &[]);
        middle[1] = 0x36;
        put16(&mut middle, 18, 0x2345);
        put64(&mut middle, 24, 0x1122334455667788);
        let mut high = hardware(0x40, 0x1234, 0xabcd, &[]);
        put64(&mut high, 24, 0x8877665544332211);
        put64(&mut high, 32, 0xaabbccddeeff0011);
        high[20..24].copy_from_slice(&0x56781234u32.to_le_bytes());
        let other_segment = hardware(0x10, 0x1235, 0xabcd, &[]);
        let other_device = hardware(0x11, 0x1234, 0xabce, &[]);
        let mut raw = table(&[&high, &other_segment, &middle, &other_device, &first]);
        raw[36..40].copy_from_slice(&0x12345678u32.to_le_bytes());
        checksum(&mut raw);
        let parsed = Ivrs::parse(&raw).unwrap();
        assert_eq!(parsed.raw().as_ptr(), raw.as_ptr());
        assert_eq!((parsed.info(), parsed.revision()), (0x12345678, 2));
        assert_eq!(parsed.hardware_blocks().count(), 5);
        let units: Vec<_> = parsed.units().collect();
        assert_eq!(units.len(), 3);
        assert_eq!(
            units[0].id(),
            RequesterId {
                segment: 0x1234,
                device_id: 0xabcd
            }
        );
        assert_eq!(units[0].version(), HardwareVersion::Type40);
        assert_eq!(
            units[0].extended_features(),
            Some((0x8877665544332211, 0xaabbccddeeff0011))
        );
        assert_eq!(units[0].feature_or_attributes(), 0x56781234);
        assert_eq!(units[1].version(), HardwareVersion::Type10);
        assert_eq!(units[1].extended_features(), None);
        let preserved = parsed
            .hardware_blocks()
            .find(|unit| unit.version() == HardwareVersion::Type11 && unit.id().device_id == 0xabcd)
            .unwrap();
        assert_eq!((preserved.flags(), preserved.info()), (0x36, 0x2345));
        fail(&table(&[&first, &first]), ErrorKind::DuplicateVersion);
        for offset in [6, 8] {
            let mut inconsistent = middle.clone();
            inconsistent[offset] ^= 1;
            fail(&table(&[&first, &inconsistent]), ErrorKind::UnitIdentity);
        }
        // Even a lower, unselected version must have valid entry grammar.
        let broken_low = hardware(0x10, 0x1234, 0xabcd, &[0x80]);
        fail(
            &table(&[&high, &broken_low]),
            ErrorKind::UnsupportedEntry(0x80),
        );
    }

    #[test]
    fn entries_preserve_alias_extended_special_and_range_data() {
        let mut entries = Vec::new();
        entries.extend(entry(0, 0, 0, None));
        entries.extend(entry(0x40, 0, 0, Some(0)));
        entries.extend(entry(0x41, 0, 0, Some(0)));
        entries.extend(entry(1, 0, 0xa5, None));
        entries.extend(entry(2, 0xf123, 0x12, None));
        entries.extend(entry(0x42, 0xe123, 0x34, Some(0x00abcd00)));
        entries.extend(entry(0x46, 0xd123, 0x56, Some(0x80001234)));
        for (kind, extra) in [
            (3, None),
            (0x43, Some(0x00bcde00)),
            (0x47, Some(0x87654321)),
        ] {
            entries.extend(entry(kind, 0xc000, 0x78, extra));
            entries.extend(entry(4, 0xcfff, 0x99, None));
        }
        entries.extend(entry(0x48, 0, 0x9a, Some(0x01fabc07)));
        let raw = table(&[&hardware(0x11, 0x4567, 8, &entries)]);
        let unit = Ivrs::parse(&raw).unwrap().units().next().unwrap();
        let decoded: Vec<_> = unit.entries().collect();
        let rid = |device_id| RequesterId {
            segment: 0x4567,
            device_id,
        };
        assert_eq!(decoded.len(), 14);
        assert_eq!(decoded[0].kind, DeviceKind::Padding);
        assert_eq!(decoded[0].raw().len(), 4);
        assert_eq!(decoded[1].kind, DeviceKind::Padding);
        assert_eq!(decoded[1].raw().len(), 8);
        assert_eq!(decoded[2].kind, DeviceKind::NotUsed);
        assert_eq!(decoded[3].kind, DeviceKind::All);
        assert_eq!(decoded[3].flags(), 0xa5);
        assert_eq!(decoded[4].kind, DeviceKind::Select(rid(0xf123)));
        assert_eq!(
            decoded[5].kind,
            DeviceKind::Alias {
                requester: rid(0xe123),
                target: rid(0xabcd)
            }
        );
        assert_eq!(
            decoded[6].kind,
            DeviceKind::Extended {
                requester: rid(0xd123),
                data: 0x80001234
            }
        );
        assert_eq!(
            decoded[9].kind,
            DeviceKind::RangeStart {
                first: rid(0xc000),
                policy: RangePolicy::Alias(rid(0xbcde))
            }
        );
        assert_eq!(decoded[9].flags(), 0x78);
        assert_eq!(
            decoded[11].kind,
            DeviceKind::RangeStart {
                first: rid(0xc000),
                policy: RangePolicy::Extended(0x87654321)
            }
        );
        assert_eq!(decoded[12].kind, DeviceKind::RangeEnd(rid(0xcfff)));
        assert_eq!(decoded[12].flags(), 0x99);
        assert_eq!(
            decoded[13].kind,
            DeviceKind::Special {
                header_id: 0,
                requester: rid(0xfabc),
                handle: 7,
                variety: 1
            }
        );
        assert_eq!(decoded[13].flags(), 0x9a);
        assert_eq!(decoded[5].raw(), &entries[28..36]);
    }

    #[test]
    fn malformed_ranges_and_unsupported_or_truncated_entries_are_rejected() {
        let start = entry(3, 0x8000, 0, None);
        let end = entry(4, 0x8fff, 0, None);
        for entries in [
            end.clone(),
            start.clone(),
            [start.clone(), start.clone(), end.clone()].concat(),
            [start.clone(), entry(2, 0x8001, 0, None), end.clone()].concat(),
            [start.clone(), entry(4, 0x7fff, 0, None)].concat(),
        ] {
            fail(
                &table(&[&hardware(0x10, 0, 8, &entries)]),
                ErrorKind::DeviceRange,
            );
        }
        for kind in [0x03, 0x43, 0x47] {
            let first = entry(kind, 0x8000, 0, (kind != 0x03).then_some(0x12345678));
            fail(
                &table(&[&hardware(0x11, 0, 8, &first)]),
                ErrorKind::DeviceRange,
            );
            let interleaved = [first, entry(0, 0, 0, None), end.clone()].concat();
            fail(
                &table(&[&hardware(0x11, 0, 8, &interleaved)]),
                ErrorKind::DeviceRange,
            );
        }
        for kind in [0x05, 0x44, 0x80, 0xff] {
            let bytes = vec![kind; if kind < 0x40 { 4 } else { 8 }];
            fail(
                &table(&[&hardware(0x40, 0, 8, &bytes)]),
                ErrorKind::UnsupportedEntry(kind),
            );
        }
        for entry in [
            entry(2, 0x1234, 0, None),
            entry(0x42, 0x1234, 0, Some(0x567800)),
        ] {
            for length in 1..entry.len() {
                fail(
                    &table(&[&hardware(0x10, 0, 8, &entry[..length])]),
                    ErrorKind::Truncated,
                );
            }
        }
    }

    #[test]
    fn hid_has_version_and_exact_variable_length_bounds_without_uid_conversion() {
        let mut hid = entry(0xf0, 0xabcd, 0x96, None);
        hid.extend_from_slice(b"AMDI0040");
        hid.extend_from_slice(b"COMPAT00");
        hid.extend_from_slice(&[2, 3, b'a', 0, b'b']);
        let raw = table(&[&hardware(0x40, 0x1234, 8, &hid)]);
        let entry = Ivrs::parse(&raw)
            .unwrap()
            .units()
            .next()
            .unwrap()
            .entries()
            .next()
            .unwrap();
        assert_eq!(
            entry.kind,
            DeviceKind::Hid {
                requester: RequesterId {
                    segment: 0x1234,
                    device_id: 0xabcd
                },
                hid: b"AMDI0040",
                cid: b"COMPAT00",
                uid_format: 2,
                uid: b"a\0b",
            }
        );
        assert_eq!(entry.flags(), 0x96);
        assert_eq!(entry.raw(), hid);
        for version in [0x10, 0x11] {
            fail(
                &table(&[&hardware(version, 0, 8, &hid)]),
                ErrorKind::HidVersion,
            );
        }
        for length in 1..hid.len() {
            fail(
                &table(&[&hardware(0x40, 0, 8, &hid[..length])]),
                ErrorKind::Truncated,
            );
        }
        hid[21] = 0;
        hid.truncate(HID_PREFIX);
        assert!(Ivrs::parse(&table(&[&hardware(0x40, 0, 8, &hid)])).is_ok());
    }

    #[test]
    fn memory_policy_keeps_private_segment_flags_and_unrounded_addresses() {
        let mut blocks = Vec::new();
        for kind in [0x20, 0x21, 0x22] {
            let mut block = vec![0; IVMD_HEADER];
            block[0] = kind;
            block[1] = 0x0f;
            put16(&mut block, 2, IVMD_HEADER as u16);
            put16(&mut block, 4, 0x8123);
            put16(&mut block, 6, 0xaffe);
            put16(&mut block, 8, 0xfedc);
            put64(&mut block, 16, 0x12345);
            put64(&mut block, 24, 0x23456);
            blocks.push(block);
        }
        let raw = table(&blocks.iter().map(Vec::as_slice).collect::<Vec<_>>());
        let memory: Vec<_> = Ivrs::parse(&raw).unwrap().memory_definitions().collect();
        assert_eq!(memory.len(), 3);
        for item in &memory {
            assert_eq!(
                (
                    item.flags(),
                    item.segment(),
                    item.start(),
                    item.length(),
                    item.end()
                ),
                (0x0f, 0xfedc, 0x12345, 0x23456, 0x3579b)
            );
        }
        assert_eq!(memory[0].scope(), MemoryScope::All { segment: 0xfedc });
        assert_eq!(
            memory[1].scope(),
            MemoryScope::Device(RequesterId {
                segment: 0xfedc,
                device_id: 0x8123
            })
        );
        let mut extended = blocks[0].clone();
        extended.extend_from_slice(&[0x91, 0x82]);
        put16(&mut extended, 2, (IVMD_HEADER + 2) as u16);
        let extension_table = table(&[&extended]);
        assert_eq!(
            Ivrs::parse(&extension_table)
                .unwrap()
                .memory_definitions()
                .next()
                .unwrap()
                .raw(),
            extended
        );
        let complete = table(&[&blocks[0]]);
        for end in TABLE_HEADER + 1..complete.len() {
            let mut prefix = complete[..end].to_vec();
            prefix[4..8].copy_from_slice(&(end as u32).to_le_bytes());
            checksum(&mut prefix);
            fail(&prefix, ErrorKind::Truncated);
        }
        assert_eq!(
            memory[2].scope(),
            MemoryScope::Range {
                first: RequesterId {
                    segment: 0xfedc,
                    device_id: 0x8123
                },
                last: RequesterId {
                    segment: 0xfedc,
                    device_id: 0xaffe
                },
            }
        );
        let mut bad = blocks[2].clone();
        put16(&mut bad, 6, 0x8122);
        fail(&table(&[&bad]), ErrorKind::DeviceRange);
        let mut bad = blocks[1].clone();
        put64(&mut bad, 16, u64::MAX);
        fail(&table(&[&bad]), ErrorKind::AddressOverflow);
        for length in BLOCK_HEADER..IVMD_HEADER {
            let mut bad = blocks[0][..length].to_vec();
            put16(&mut bad, 2, length as u16);
            fail(&table(&[&bad]), ErrorKind::BlockLength);
        }
    }
}
