// SPDX-License-Identifier: GPL-2.0-only
// Layouts and entry encodings from Linux drivers/iommu/amd/init.c,
// commit cc9de5d4b5ab6459f5774946aa3195ad51236fa8.
// Copyright (C) 2007-2010 Advanced Micro Devices, Inc.
// Original authors: Joerg Roedel <jroedel@suse.de>, Leo Duran <leo.duran@amd.com>.
//! Resource-bounded IVRS decoding. Firmware descriptions grant no ownership,
//! requester isolation, MMIO access or permission to change a remapping unit.
//! Framing, checksums, known entry encodings, range grammar and version identity
//! are checked for every block, including superseded IVHD versions. Raw policy
//! flags, UID formats and extension bytes remain firmware descriptions: MMIO
//! alignment, reserved bits and policy semantics require separate live admission
//! and explicit refusal of unresolved requirements. Range starts must be followed
//! immediately by their end; interleaved entries, including padding, are refused.
use alloc::vec::Vec;
use core::cmp::Reverse;

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
    ResourceLimit,
    OutOfMemory,
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
#[derive(Debug)]
pub struct Ivrs<'a> {
    raw: &'a [u8],
    units: Vec<Ivhd<'a>>,
}

impl<'a> Ivrs<'a> {
    /// `maximum_hardware_blocks` is the caller's admission budget,
    /// including superseded versions. No implicit platform-sized limit applies.
    /// All framing/entry checks precede index allocation. A budget failure may
    /// reject an input before examining its remaining bytes, never admit it.
    pub fn parse(raw: &'a [u8], maximum_hardware_blocks: usize) -> Result<Self, ParseError> {
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
        let mut hardware_blocks = 0usize;
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
                    if hardware_blocks == maximum_hardware_blocks {
                        return Err(error(offset, ErrorKind::ResourceLimit));
                    }
                    hardware_blocks += 1;
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
        let mut units = Vec::new();
        units
            .try_reserve_exact(hardware_blocks)
            .map_err(|_| error(TABLE_HEADER, ErrorKind::OutOfMemory))?;
        units.extend(
            Blocks {
                remaining: &raw[TABLE_HEADER..],
                offset: TABLE_HEADER,
            }
            .filter_map(|block| match block {
                Block::Hardware(unit) => Some(unit),
                Block::Memory(_) => None,
            }),
        );
        // The complete table is validated. Sorting needs no further allocation;
        // adjacent checks cover every version of each capability instance.
        units.sort_unstable_by_key(|unit| (unit.instance(), Reverse(unit.version()), unit.offset));
        for pair in units.windows(2) {
            let [first, second] = [pair[0], pair[1]];
            if first.instance() == second.instance() {
                let offending = first.offset.max(second.offset);
                if first.version() == second.version() {
                    return Err(error(offending, ErrorKind::DuplicateVersion));
                }
                if first.mmio_address() != second.mmio_address() {
                    return Err(error(offending, ErrorKind::UnitIdentity));
                }
            }
        }
        let mut previous = None;
        units.retain(|unit| {
            let id = unit.instance();
            let selected = previous != Some(id);
            previous = Some(id);
            selected
        });
        units.sort_unstable_by_key(|unit| unit.offset);
        Ok(Self { raw, units })
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub fn info(&self) -> u32 {
        read32(self.raw, 36)
    }

    pub fn revision(&self) -> u8 {
        self.raw[8]
    }

    pub fn blocks(&self) -> Blocks<'a> {
        Blocks {
            remaining: &self.raw[TABLE_HEADER..],
            offset: TABLE_HEADER,
        }
    }

    pub fn hardware_blocks(&self) -> impl Iterator<Item = Ivhd<'a>> {
        self.blocks().filter_map(|block| match block {
            Block::Hardware(unit) => Some(unit),
            Block::Memory(_) => None,
        })
    }

    /// One highest-version description per (segment, IOMMU device ID,
    /// capability offset), in table order. All lower versions were validated.
    /// Descriptions do not grant independent ownership of their PCI function
    /// or MMIO aperture; live admission must exclude resource overlap.
    pub fn units(&self) -> impl ExactSizeIterator<Item = Ivhd<'a>> + '_ {
        self.units.iter().copied()
    }

    pub fn memory_definitions(&self) -> impl Iterator<Item = Ivmd<'a>> {
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

    /// PCI function containing the IOMMU capability. Multiple instances may
    /// share this function; the capability offset distinguishes them.
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

    fn instance(self) -> (u16, u16, u16) {
        // AMD 48882 rev 3.11 section 5.2.2.1: a function may contain multiple
        // capabilities. HT UnitID may be shared and is not an instance key.
        let id = self.id();
        (id.segment, id.device_id, self.capability_offset())
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

/// Original bytes and data-setting flags are held even for padding, range
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
    AllDevices,
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

    /// Defined only for per-device/range records. AMD 48882 rev 3.11 Table 112
    /// reserves this field for type 20; its scope is all devices in the system.
    pub fn segment(self) -> Option<u16> {
        match self.raw[0] {
            0x20 => None,
            0x21 | 0x22 => Some(read16(self.raw, 8)),
            _ => unreachable!("validated IVMD type"),
        }
    }

    /// Raw field: reserved for type 20, requester ID for type 21, range start
    /// for type 22. Reserved bytes do not narrow the reported scope.
    pub fn device_id(self) -> u16 {
        read16(self.raw, 4)
    }

    /// Raw field: reserved for types 20/21, inclusive range end for type 22.
    pub fn auxiliary(self) -> u16 {
        read16(self.raw, 6)
    }

    pub fn scope(self) -> MemoryScope {
        match self.raw[0] {
            0x20 => MemoryScope::AllDevices,
            0x21 => MemoryScope::Device(RequesterId {
                segment: read16(self.raw, 8),
                device_id: self.device_id(),
            }),
            0x22 => MemoryScope::Range {
                first: RequesterId {
                    segment: read16(self.raw, 8),
                    device_id: self.device_id(),
                },
                last: RequesterId {
                    segment: read16(self.raw, 8),
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
        assert_eq!(Ivrs::parse(raw, usize::MAX).unwrap_err().kind, kind);
    }

    #[test]
    fn admission_budget_counts_every_version_and_keeps_zero_unit_tables_valid() {
        let empty = table(&[]);
        assert_eq!(Ivrs::parse(&empty, 0).unwrap().units().len(), 0);
        let mut memory = vec![0; IVMD_HEADER];
        memory[0] = 0x20;
        put16(&mut memory, 2, IVMD_HEADER as u16);
        let memory_only = table(&[&memory]);
        let parsed = Ivrs::parse(&memory_only, 0).unwrap();
        assert_eq!(parsed.units().len(), 0);
        assert_eq!(parsed.memory_definitions().count(), 1);

        let low = hardware(0x10, 7, 0x8123, &[]);
        let high = hardware(0x40, 7, 0x8123, &[]);
        let raw = table(&[&low, &memory, &high]);
        let unchanged = raw.clone();
        for (budget, offset) in [
            (0, TABLE_HEADER),
            (1, TABLE_HEADER + low.len() + memory.len()),
        ] {
            assert_eq!(
                Ivrs::parse(&raw, budget).unwrap_err(),
                error(offset, ErrorKind::ResourceLimit)
            );
        }
        let parsed = Ivrs::parse(&raw, 2).unwrap();
        assert_eq!(parsed.units().len(), 1);
        assert_eq!(
            parsed.units().next().unwrap().version(),
            HardwareVersion::Type40
        );
        assert_eq!(parsed.hardware_blocks().count(), 2);
        assert_eq!(raw, unchanged);
    }

    #[test]
    fn every_version_permutation_selects_the_same_unit_and_checks_hidden_versions() {
        let versions = [
            hardware(0x10, 0xffff, 0xffff, &[]),
            hardware(0x11, 0xffff, 0xffff, &[]),
            hardware(0x40, 0xffff, 0xffff, &[]),
        ];
        for permutation in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let blocks = permutation.map(|index| versions[index].as_slice());
            let raw = table(&blocks);
            let parsed = Ivrs::parse(&raw, 3).unwrap();
            let selected = parsed.units().next().unwrap();
            assert_eq!(selected.version(), HardwareVersion::Type40);
            assert_eq!(selected.raw(), versions[2]);
            // Full original block order remains independent of cached selection.
            for (block, expected) in parsed.hardware_blocks().zip(blocks) {
                assert_eq!(block.raw(), expected);
            }
            for version in 0..3 {
                let mut duplicate = blocks.to_vec();
                duplicate.push(&versions[version]);
                fail(&table(&duplicate), ErrorKind::DuplicateVersion);
                let mut changed = versions[version].clone();
                changed[8] ^= 0x10;
                let mut inconsistent = blocks.to_vec();
                inconsistent[permutation
                    .iter()
                    .position(|&index| index == version)
                    .unwrap()] = &changed;
                fail(&table(&inconsistent), ErrorKind::UnitIdentity);
            }
        }
    }

    #[test]
    fn large_interleaved_index_preserves_selected_table_order_and_original_bytes() {
        const UNITS: u16 = 2048;
        let mut blocks = Vec::new();
        // Firmware order disagrees with both identity and version
        // sort order; the final cache must follow the selected record's offset.
        for id in (0..UNITS).rev() {
            blocks.push(hardware(0x11, id % 7, id, &[]));
        }
        for id in 0..UNITS {
            blocks.push(hardware(0x40, id % 7, id, &[]));
        }
        for id in (0..UNITS).rev() {
            blocks.push(hardware(0x10, id % 7, id, &[]));
        }
        let raw = table(&blocks.iter().map(Vec::as_slice).collect::<Vec<_>>());
        let original = raw.clone();
        let parsed = Ivrs::parse(&raw, usize::from(UNITS) * 3).unwrap();
        assert_eq!(parsed.hardware_blocks().count(), usize::from(UNITS) * 3);
        for _ in 0..3 {
            assert_eq!(parsed.units().len(), usize::from(UNITS));
            for (id, unit) in parsed.units().enumerate() {
                assert_eq!(unit.id().device_id, id as u16);
                assert_eq!(unit.id().segment, id as u16 % 7);
                assert_eq!(unit.version(), HardwareVersion::Type40);
                assert_eq!(unit.raw().as_ptr(), raw[unit.offset()..].as_ptr());
            }
        }
        assert_eq!(raw, original);
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
        let parsed = Ivrs::parse(&raw, usize::MAX).unwrap();
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
        let mut inconsistent = middle.clone();
        inconsistent[8] ^= 1;
        fail(&table(&[&first, &inconsistent]), ErrorKind::UnitIdentity);
        // Even a lower, unselected version must have valid entry grammar.
        let broken_low = hardware(0x10, 0x1234, 0xabcd, &[0x80]);
        fail(
            &table(&[&high, &broken_low]),
            ErrorKind::UnsupportedEntry(0x80),
        );
    }

    #[test]
    fn multiple_capabilities_on_one_function_select_versions_independently() {
        let mut blocks = Vec::new();
        for (capability, base, versions) in [
            (0x40, 0xfed80000, &[0x10, 0x11, 0x40][..]),
            (0x80, 0xfedc0000, &[0x10, 0x11][..]),
        ] {
            for &version in versions {
                let mut block = hardware(version, 7, 0x8123, &[]);
                put16(&mut block, 6, capability);
                put64(&mut block, 8, base);
                // Both units may have the same deprecated HT UnitID (zero).
                put16(&mut block, 18, 0);
                blocks.push(block);
            }
        }
        // Every permutation of the five descriptions, with different maximum
        // versions per capability. Expected selection follows original bytes.
        for mut permutation in 0..120 {
            let mut remaining = vec![0, 1, 2, 3, 4];
            let mut order = Vec::new();
            while !remaining.is_empty() {
                let index = permutation % remaining.len();
                permutation /= remaining.len();
                order.push(remaining.remove(index));
            }
            let ordered: Vec<_> = order
                .iter()
                .map(|&index| blocks[index].as_slice())
                .collect();
            let raw = table(&ordered);
            let original = raw.clone();
            let parsed = Ivrs::parse(&raw, 5).unwrap();
            let selected: Vec<_> = parsed.units().collect();
            assert_eq!(selected.len(), 2);
            let expected: Vec<_> = order
                .iter()
                .copied()
                .filter(|&index| index == 2 || index == 4)
                .collect();
            for (unit, index) in selected.iter().zip(expected) {
                assert_eq!(unit.raw(), blocks[index]);
                assert_eq!(unit.raw().as_ptr(), raw[unit.offset()..].as_ptr());
            }
            assert_eq!(selected[0].id(), selected[1].id());
            assert_ne!(
                selected[0].capability_offset(),
                selected[1].capability_offset()
            );
            for (unit, block) in parsed.hardware_blocks().zip(&ordered) {
                assert_eq!(unit.raw(), *block);
            }
            assert_eq!(raw, original);
            // The instance key does not hide duplicate or inconsistent lower
            // descriptions behind a different capability's higher version.
            for block in &blocks {
                let mut duplicate = ordered.clone();
                duplicate.push(block);
                fail(&table(&duplicate), ErrorKind::DuplicateVersion);
            }
            for index in 0..blocks.len() {
                let mut changed = blocks[index].clone();
                changed[8] ^= 0x10;
                let inconsistent: Vec<_> = order
                    .iter()
                    .map(|&current| {
                        if current == index {
                            changed.as_slice()
                        } else {
                            blocks[current].as_slice()
                        }
                    })
                    .collect();
                fail(&table(&inconsistent), ErrorKind::UnitIdentity);
            }
        }
        // Shared nonzero HT UnitID is also metadata, not an instance key.
        for block in &mut blocks {
            put16(block, 18, 0x1f00);
        }
        let raw = table(&blocks.iter().map(Vec::as_slice).collect::<Vec<_>>());
        assert_eq!(Ivrs::parse(&raw, 5).unwrap().units().len(), 2);
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
        let unit = Ivrs::parse(&raw, usize::MAX)
            .unwrap()
            .units()
            .next()
            .unwrap();
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
        let entry = Ivrs::parse(&raw, usize::MAX)
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
        assert!(Ivrs::parse(&table(&[&hardware(0x40, 0, 8, &hid)]), usize::MAX).is_ok());
    }

    #[test]
    fn global_memory_scope_ignores_reserved_ids_and_neighboring_segments() {
        for segment in [0, 0xffff] {
            let before = hardware(0x10, segment, 8, &[]);
            let after = hardware(0x10, segment ^ 0xffff, 8, &[]);
            for (device, auxiliary, reserved_segment) in
                [(0, 0, 0), (0xffff, 0, 0x1234), (0xaffe, 0x8123, 0xfedc)]
            {
                for flags in [0, 0x0f] {
                    let mut global = vec![0; IVMD_HEADER];
                    global[0] = 0x20;
                    global[1] = flags;
                    put16(&mut global, 2, IVMD_HEADER as u16);
                    put16(&mut global, 4, device);
                    put16(&mut global, 6, auxiliary);
                    put16(&mut global, 8, reserved_segment);
                    global[10..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
                    put64(&mut global, 16, 0x12345);
                    put64(&mut global, 24, 0x1000);
                    for descriptions in [
                        [global.as_slice(), before.as_slice(), after.as_slice()],
                        [before.as_slice(), global.as_slice(), after.as_slice()],
                        [before.as_slice(), after.as_slice(), global.as_slice()],
                    ] {
                        let raw = table(&descriptions);
                        let original = raw.clone();
                        let parsed = Ivrs::parse(&raw, 2).unwrap();
                        assert_eq!(parsed.units().len(), 2);
                        let mut definitions = parsed.memory_definitions();
                        let memory = definitions.next().unwrap();
                        assert!(definitions.next().is_none());
                        assert_eq!(memory.segment(), None);
                        assert_eq!(memory.scope(), MemoryScope::AllDevices);
                        assert_eq!(
                            (memory.device_id(), memory.auxiliary()),
                            (device, auxiliary)
                        );
                        assert_eq!(memory.raw(), global);
                        assert_eq!(memory.raw().as_ptr(), raw[memory.offset()..].as_ptr());
                        // Preserve context for later live-policy admission;
                        // neither neighboring segment narrows raw type-20 scope.
                        let mut offset = TABLE_HEADER;
                        for (block, expected) in parsed.blocks().zip(descriptions) {
                            let (bytes, actual_offset) = match block {
                                Block::Hardware(unit) => (unit.raw(), unit.offset()),
                                Block::Memory(item) => (item.raw(), item.offset()),
                            };
                            assert_eq!((bytes, actual_offset), (expected, offset));
                            offset += expected.len();
                        }
                        assert_eq!(raw, original);
                    }
                }
            }
        }
    }

    #[test]
    fn memory_policy_keeps_type_specific_scope_flags_and_unrounded_addresses() {
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
        let memory: Vec<_> = Ivrs::parse(&raw, usize::MAX)
            .unwrap()
            .memory_definitions()
            .collect();
        assert_eq!(memory.len(), 3);
        for (index, item) in memory.iter().enumerate() {
            assert_eq!(
                (
                    item.flags(),
                    item.segment(),
                    item.start(),
                    item.length(),
                    item.end()
                ),
                (
                    0x0f,
                    (index != 0).then_some(0xfedc),
                    0x12345,
                    0x23456,
                    0x3579b
                )
            );
        }
        assert_eq!(memory[0].scope(), MemoryScope::AllDevices);
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
            Ivrs::parse(&extension_table, usize::MAX)
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
