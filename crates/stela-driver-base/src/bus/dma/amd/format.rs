// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2007-2010 Advanced Micro Devices, Inc.
// Author: Joerg Roedel <jroedel@suse.de>
//         Leo Duran <leo.duran@amd.com>
// Copyright (c) 2024-2025, NVIDIA CORPORATION & AFFILIATES
// Command encodings adapted from Linux drivers/iommu/amd/{iommu.c,
// amd_iommu_types.h}; page entries from generic_pt/fmt/amdv1.h, commit
// cc9de5d4b5ab6459f5774946aa3195ad51236fa8. See platform/THIRD_PARTY.md.
//! Checked AMDv1 page and command encodings. No operation here touches a
//! remapper or establishes page ownership, visibility or completion.
use super::super::mapping::Direction;
use core::{num::NonZeroU16, ops::Range};

const PAGE_SHIFT: u32 = 12;
const PAGE: u64 = 1 << PAGE_SHIFT;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const NEXT_LEVEL_SHIFT: u32 = 9;
const FORCE_COHERENT: u64 = 1 << 60;
const READ: u64 = 1 << 61;
const WRITE: u64 = 1 << 62;
const TYPE_SHIFT: u32 = 28;
const COMPLETION_WAIT: u32 = 1;
const INVALIDATE_DEVICE: u32 = 2;
const INVALIDATE_PAGES: u32 = 3;
const INVALIDATE_INTERRUPTS: u32 = 5;
const INVALIDATE_ALL: u32 = 8;
const COMPLETION_STORE: u32 = 1;
const COMPLETION_INTERRUPT: u32 = 2;
const INVALIDATE_SIZE: u64 = 1;
const INVALIDATE_TABLES: u32 = 2;
const ALL_PAGES: u64 = 0x7fff_ffff_ffff_f000 | INVALIDATE_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    PhysicalWidth,
    PhysicalAddress,
    Alignment,
    TableLevel,
    EmptyRange,
}

/// An unencrypted physical address inside the unit's measured address width.
/// Encryption/coherency and resource permission require separate admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalAddress(u64);

impl PhysicalAddress {
    pub fn new(address: u64, physical_bits: u8) -> Result<Self, FormatError> {
        if !(32..=52).contains(&physical_bits) {
            return Err(FormatError::PhysicalWidth);
        }
        if address >= 1u64 << physical_bits {
            return Err(FormatError::PhysicalAddress);
        }
        Ok(Self(address))
    }

    pub fn value(self) -> u64 {
        self.0
    }

    fn aligned(self, alignment: u64) -> Result<u64, FormatError> {
        if !self.0.is_multiple_of(alignment) {
            return Err(FormatError::Alignment);
        }
        Ok(self.0)
    }
}

/// Domain zero is reserved and cannot be assigned to a translated device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainId(NonZeroU16);

impl DomainId {
    pub fn new(id: u16) -> Option<Self> {
        NonZeroU16::new(id).map(Self)
    }

    pub fn value(self) -> u16 {
        self.0.get()
    }
}

/// AMD host page-table mode: one through six 4 KiB levels. Mode zero would
/// bypass translation and is not represented. The sixth level uses 128 slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableLevel(u8);

impl TableLevel {
    pub fn new(mode: u8) -> Result<Self, FormatError> {
        if !(1..=6).contains(&mode) {
            return Err(FormatError::TableLevel);
        }
        Ok(Self(mode))
    }

    pub fn mode(self) -> u8 {
        self.0
    }

    pub fn child(self) -> Option<Self> {
        (self.0 > 1).then(|| Self(self.0 - 1))
    }

    pub fn address_bits(self) -> u32 {
        (PAGE_SHIFT + 9 * u32::from(self.0)).min(64)
    }

    pub fn index(self, address: u64) -> usize {
        let shift = PAGE_SHIFT + 9 * u32::from(self.0 - 1);
        let mask = if self.0 == 6 { 127 } else { 511 };
        ((address >> shift) & mask) as usize
    }
}

/// A little-endian 64-bit entry. Only ordinary 4 KiB leaves and adjacent
/// table levels are exposed here; large/contiguous leaves need their own codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageEntry(u64);

impl PageEntry {
    pub const EMPTY: Self = Self(0);

    pub fn table(address: PhysicalAddress, parent: TableLevel) -> Result<Self, FormatError> {
        let child = parent.child().ok_or(FormatError::TableLevel)?;
        Ok(Self(
            address.aligned(PAGE)?
                | PRESENT
                | (u64::from(child.mode()) << NEXT_LEVEL_SHIFT)
                | READ
                | WRITE,
        ))
    }

    /// `force_coherent` requests the FC bit only. The live owner must check
    /// the platform's payload coherency before selecting it.
    pub fn page(
        address: PhysicalAddress,
        direction: Direction,
        force_coherent: bool,
    ) -> Result<Self, FormatError> {
        let rights = match direction {
            Direction::ToDevice => READ,
            Direction::FromDevice => WRITE,
            Direction::Bidirectional => READ | WRITE,
        };
        Ok(Self(
            address.aligned(PAGE)?
                | PRESENT
                | rights
                | if force_coherent { FORCE_COHERENT } else { 0 },
        ))
    }

    pub fn bits(self) -> u64 {
        self.0
    }

    pub fn address(self) -> u64 {
        self.0 & ADDRESS
    }

    pub fn bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

/// One 16-byte ring entry. Serialize through `bytes` or write each returned
/// word little-endian; Rust layout is never used as a device wire format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Command([u32; 4]);

impl Command {
    fn simple(kind: u32, requester: u16) -> Self {
        Self([u32::from(requester), kind << TYPE_SHIFT, 0, 0])
    }

    pub fn invalidate_device(requester: u16) -> Self {
        Self::simple(INVALIDATE_DEVICE, requester)
    }

    pub fn invalidate_interrupts(requester: u16) -> Self {
        Self::simple(INVALIDATE_INTERRUPTS, requester)
    }

    /// The live unit must have the invalidate-all (IA) capability.
    pub fn invalidate_all() -> Self {
        Self::simple(INVALIDATE_ALL, 0)
    }

    /// Flush every address in the domain, optionally including cached PDEs.
    pub fn invalidate_domain(domain: DomainId, tables: bool) -> Self {
        Self::pages(domain, ALL_PAGES, tables)
    }

    /// Cover the complete nonempty byte range, including partial end pages.
    /// Large intervals fall back to a full domain flush, never a truncated one.
    pub fn invalidate_pages(
        domain: DomainId,
        range: Range<u64>,
        tables: bool,
    ) -> Result<Self, FormatError> {
        if range.start >= range.end {
            return Err(FormatError::EmptyRange);
        }
        let address = range.start & !(PAGE - 1);
        let significant = 64 - (address ^ (range.end - 1)).leading_zeros();
        let encoded = match significant {
            0..=12 => address,
            13 => address | INVALIDATE_SIZE,
            14..=52 => address | (((1u64 << (significant - 1)) - 1) & ADDRESS) | INVALIDATE_SIZE,
            _ => ALL_PAGES,
        };
        Ok(Self::pages(domain, encoded, tables))
    }

    fn pages(domain: DomainId, address: u64, tables: bool) -> Self {
        Self([
            0,
            (INVALIDATE_PAGES << TYPE_SHIFT) | u32::from(domain.value()),
            address as u32 | if tables { INVALIDATE_TABLES } else { 0 },
            (address >> 32) as u32,
        ])
    }

    /// Store the exact sequence into an owned, visible 8-byte semaphore once
    /// preceding commands complete, optionally raising the completion IRQ.
    /// A numeric address does not keep that semaphore or register its IRQ.
    pub fn completion(
        semaphore: PhysicalAddress,
        sequence: u64,
        interrupt: bool,
    ) -> Result<Self, FormatError> {
        let address = semaphore.aligned(8)?;
        Ok(Self([
            address as u32 | COMPLETION_STORE | if interrupt { COMPLETION_INTERRUPT } else { 0 },
            (address >> 32) as u32 | (COMPLETION_WAIT << TYPE_SHIFT),
            sequence as u32,
            (sequence >> 32) as u32,
        ]))
    }

    pub fn words(self) -> [u32; 4] {
        self.0
    }

    pub fn bytes(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(self.0) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

/// Compare a semaphore observation with a submitted sequence across
/// wrap. The live owner must keep the sequence distance strictly below 2^63;
/// neither a queue-head observation nor an elapsed timeout is a semaphore.
pub fn sequence_completed(observed: u64, target: u64) -> bool {
    observed.wrapping_sub(target) as i64 >= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pa(value: u64) -> PhysicalAddress {
        PhysicalAddress::new(value, 52).unwrap()
    }

    #[test]
    fn physical_width_alignment_and_levels_are_checked_without_truncation() {
        for bits in [0, 31, 53, 64, 255] {
            assert_eq!(
                PhysicalAddress::new(0, bits),
                Err(FormatError::PhysicalWidth)
            );
        }
        assert_eq!(
            PhysicalAddress::new(1 << 48, 48),
            Err(FormatError::PhysicalAddress)
        );
        assert_eq!(
            PhysicalAddress::new(u64::MAX, 52),
            Err(FormatError::PhysicalAddress)
        );
        assert_eq!(
            PageEntry::page(pa(1), Direction::ToDevice, false),
            Err(FormatError::Alignment)
        );
        for mode in [0, 7, 255] {
            assert_eq!(TableLevel::new(mode), Err(FormatError::TableLevel));
        }
        let leaf = TableLevel::new(1).unwrap();
        assert_eq!(
            PageEntry::table(pa(0x1000), leaf),
            Err(FormatError::TableLevel)
        );
        assert_eq!(leaf.index(0x1ff000), 511);
        let top = TableLevel::new(6).unwrap();
        assert_eq!((top.address_bits(), top.index(u64::MAX)), (64, 127));
        assert_eq!(TableLevel::new(4).unwrap().address_bits(), 48);
    }

    #[test]
    fn entry_words_encode_direction_and_address_bits() {
        let physical = 0x000a_bcde_1234_5000;
        // These literal wire words are independent of the codec's bit names.
        for (direction, expected) in [
            (Direction::ToDevice, 0x200a_bcde_1234_5001),
            (Direction::FromDevice, 0x400a_bcde_1234_5001),
            (Direction::Bidirectional, 0x600a_bcde_1234_5001),
        ] {
            assert_eq!(
                PageEntry::page(pa(physical), direction, false)
                    .unwrap()
                    .bits(),
                expected
            );
        }
        assert_eq!(
            PageEntry::page(pa(physical), Direction::Bidirectional, true)
                .unwrap()
                .bits(),
            0x700a_bcde_1234_5001
        );
        assert_eq!(
            PageEntry::table(pa(physical), TableLevel::new(4).unwrap())
                .unwrap()
                .bits(),
            0x600a_bcde_1234_5601
        );
        assert_eq!(
            PageEntry::page(pa(0x000f_ffff_ffff_f000), Direction::ToDevice, false)
                .unwrap()
                .bits(),
            0x200f_ffff_ffff_f001
        );
        assert_eq!(
            PhysicalAddress::new(0x000f_ffff_ffff_ffff, 52)
                .unwrap()
                .value(),
            0x000f_ffff_ffff_ffff
        );
        for (direction, rights) in [
            (Direction::ToDevice, READ),
            (Direction::FromDevice, WRITE),
            (Direction::Bidirectional, READ | WRITE),
        ] {
            let entry = PageEntry::page(pa(physical), direction, false).unwrap();
            assert_eq!(entry.bits(), physical | rights | PRESENT);
            assert_eq!(entry.address(), physical);
            assert_eq!(u64::from_le_bytes(entry.bytes()), entry.bits());
            let coherent = PageEntry::page(pa(physical), direction, true).unwrap();
            assert_eq!(coherent.bits() ^ entry.bits(), FORCE_COHERENT);
        }
        for mode in 2..=6 {
            let entry = PageEntry::table(pa(physical), TableLevel::new(mode).unwrap()).unwrap();
            assert_eq!(
                entry.bits(),
                physical | READ | WRITE | PRESENT | (u64::from(mode - 1) << 9)
            );
        }
        assert_eq!(PageEntry::EMPTY.bits(), 0);
    }

    #[test]
    fn command_words_match_pinned_linux_wire_records() {
        let domain = DomainId::new(0xffff).unwrap();
        assert!(DomainId::new(0).is_none());
        assert_eq!(
            Command::invalidate_device(0xfedc).words(),
            [0xfedc, 0x2000_0000, 0, 0]
        );
        assert_eq!(
            Command::invalidate_interrupts(0xfedc).words(),
            [0xfedc, 0x5000_0000, 0, 0]
        );
        assert_eq!(Command::invalidate_all().words(), [0, 0x8000_0000, 0, 0]);
        assert_eq!(
            Command::invalidate_domain(domain, true).words(),
            [0, 0x3000_ffff, 0xffff_f003, 0x7fff_ffff]
        );
        let completion =
            Command::completion(pa(0x000a_bcde_1234_5008), 0xfedc_ba98_7654_3210, true).unwrap();
        assert_eq!(
            completion.words(),
            [0x1234_500b, 0x100a_bcde, 0x7654_3210, 0xfedc_ba98]
        );
        assert_eq!(
            completion.bytes(),
            [
                0x0b, 0x50, 0x34, 0x12, 0xde, 0xbc, 0x0a, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
                0xdc, 0xfe
            ]
        );
        assert_eq!(
            Command::completion(pa(4), 0, false),
            Err(FormatError::Alignment)
        );
        assert_eq!(
            Command::completion(pa(8), 0, false).unwrap().words(),
            [9, 0x1000_0000, 0, 0]
        );
    }

    #[test]
    fn interval_invalidation_covers_unaligned_crossing_and_full_width_ranges() {
        let domain = DomainId::new(7).unwrap();
        for (range, low, high) in [
            (0x1234..0x1fff, 0x1000, 0),
            (0x4000..0x6000, 0x4001, 0),
            (0x2fff..0x6001, 0x3001, 0),
            (0xffff_ffff..0x1_0000_0001, 0xffff_f001, 0),
            (0..1 << 52, 0xffff_f001, 0x0007_ffff),
            (0..(1 << 52) + 1, 0xffff_f001, 0x7fff_ffff),
            (0..u64::MAX, 0xffff_f001, 0x7fff_ffff),
        ] {
            assert_eq!(
                Command::invalidate_pages(domain, range, false)
                    .unwrap()
                    .words(),
                [0, 0x3000_0007, low, high]
            );
        }
        for range in [0..0, Range { start: 3, end: 2 }] {
            assert_eq!(
                Command::invalidate_pages(domain, range, true),
                Err(FormatError::EmptyRange)
            );
        }
    }

    #[test]
    fn completion_uses_signed_modular_distance_not_plain_integer_order() {
        assert!(sequence_completed(19, 19));
        assert!(sequence_completed(20, 19));
        assert!(!sequence_completed(18, 19));
        assert!(sequence_completed(1, u64::MAX));
        assert!(!sequence_completed(u64::MAX, 1));
        assert!(!sequence_completed(1 << 63, 0));
    }
}
