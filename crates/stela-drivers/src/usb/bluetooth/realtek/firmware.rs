// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Endless Mobile, Inc.
//! Bounded EPATCH v1 selection and download ordering, adapted from Linux
//! a804c5742bff224d4cb4d25dd383554d598be32b `rtlbt_parse_firmware` and
//! `rtl_download_firmware`. The selected patch's last four bytes are replaced
//! by the container version; configuration follows the patch byte for byte.
use super::FormatError;
use crate::bytes::{le16, le32};
use alloc::vec::Vec;

const HEADER: usize = 14;
const MAX_IMAGE: usize = 4 * 1024 * 1024;
const MAX_CONFIG: usize = 64 * 1024;
const FRAGMENT: usize = 252;
const EXTENSION_SIGNATURE: [u8; 4] = [0x51, 0x04, 0xfd, 0x77];

/// Exact firmware project, selected only after independent controller identity.
/// V1 and V2 parsing remain separate: RTL8852BU uses RTBTCore through V2Patch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Project {
    Rtl8761Bu,
    Rtl8822B,
    Rtl8852Bu,
}
impl Project {
    pub fn id(self) -> u8 {
        match self {
            Self::Rtl8761Bu => 14,
            Self::Rtl8822B => 8,
            Self::Rtl8852Bu => 20,
        }
    }
}

/// Complete validated selected ROM patch. The source image remains borrowed;
/// staging copies only the selected payload and exact supplied configuration.
#[derive(Debug)]
pub struct Patch<'a> {
    pub project: Project,
    pub rom_version: u8,
    pub firmware_version: u32,
    payload: &'a [u8],
}
impl<'a> Patch<'a> {
    pub fn parse(bytes: &'a [u8], project: Project, rom_version: u8) -> Result<Self, FormatError> {
        if !(HEADER + 8..=MAX_IMAGE).contains(&bytes.len()) {
            return Err(FormatError::Size);
        }
        if &bytes[..8] != b"Realtech" {
            return Err(FormatError::Signature);
        }
        if project == Project::Rtl8852Bu {
            return Err(FormatError::Project);
        }
        // The supported real v1 inputs have exactly the donor's terminal
        // project instruction preceded by EOF. Unknown extension programs are
        // refused explicitly, rather than guessing their backwards traversal.
        let trailer = &bytes[bytes.len() - 8..];
        if trailer[0] != 0xff || trailer[2..4] != [1, 0] || trailer[4..] != EXTENSION_SIGNATURE {
            return Err(FormatError::Extension);
        }
        if trailer[1] != project.id() {
            return Err(FormatError::Project);
        }
        let count = usize::from(le16(bytes, 12));
        let table_end = HEADER + count * 8;
        let payload_end = bytes.len() - 8;
        if count == 0 || table_end > payload_end {
            return Err(FormatError::PatchTable);
        }
        let mut entries = Vec::with_capacity(count);
        let wanted = u16::from(rom_version) + 1;
        let mut selected = None;
        for i in 0..count {
            let chip = le16(bytes, HEADER + i * 2);
            let len = usize::from(le16(bytes, HEADER + count * 2 + i * 2));
            let start = usize::try_from(le32(bytes, HEADER + count * 4 + i * 4))
                .map_err(|_| FormatError::PatchBounds)?;
            let end = start.checked_add(len).ok_or(FormatError::PatchBounds)?;
            if chip == 0 || len < 4 || start < table_end || end > payload_end {
                return Err(FormatError::PatchBounds);
            }
            for &(other_chip, other_start, other_end) in &entries {
                if chip == other_chip {
                    return Err(FormatError::DuplicateChip);
                }
                if start < other_end && other_start < end {
                    return Err(FormatError::OverlappingPatches);
                }
            }
            entries.push((chip, start, end));
            if chip == wanted {
                selected = Some(&bytes[start..end]);
            }
        }
        Ok(Self {
            project,
            rom_version,
            firmware_version: le32(bytes, 8),
            payload: selected.ok_or(FormatError::MissingRom)?,
        })
    }
    /// Preserve the exact validated configuration. None means the caller has
    /// independently established that this exact profile permits no config;
    /// it is never an inference from a malformed/missing supplied resource.
    pub fn stage(&self, configuration: Option<&Configuration<'_>>) -> Staged {
        let config = configuration.map_or(&[][..], |c| c.bytes);
        let mut bytes = Vec::with_capacity(self.payload.len() + config.len());
        bytes.extend_from_slice(&self.payload[..self.payload.len() - 4]);
        bytes.extend_from_slice(&self.firmware_version.to_le_bytes());
        bytes.extend_from_slice(config);
        Staged { bytes }
    }
}

/// Exact vendor config magic, declared size and complete bounded register
/// entries. Empty entry inventory is legal (the actual RTL8761BU config).
#[derive(Debug)]
pub struct Configuration<'a> {
    bytes: &'a [u8],
    pub entries: usize,
}
impl<'a> Configuration<'a> {
    pub(super) fn bytes(&self) -> &[u8] {
        self.bytes
    }
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FormatError> {
        if !(6..=MAX_CONFIG).contains(&bytes.len())
            || bytes[..4] != [0x55, 0xab, 0x23, 0x87]
            || usize::from(le16(bytes, 4)) != bytes.len() - 6
        {
            return Err(FormatError::ConfigHeader);
        }
        let mut entries = Vec::new();
        let mut at = 6;
        while at < bytes.len() {
            let header = bytes.get(at..at + 3).ok_or(FormatError::ConfigEntry)?;
            let start = u32::from(u16::from_le_bytes([header[0], header[1]]));
            let len = usize::from(header[2]);
            let end = start + len as u32;
            if len == 0 || end > 0x10000 || at + 3 + len > bytes.len() {
                return Err(FormatError::ConfigEntry);
            }
            if entries.iter().any(|&(a, b)| start < b && a < end) {
                return Err(FormatError::OverlappingConfig);
            }
            entries.push((start, end));
            at += 3 + len;
        }
        Ok(Self {
            bytes,
            entries: entries.len(),
        })
    }
}

/// Owned upload bytes, not evidence of controller acceptance or initialization.
#[derive(Debug)]
pub struct Staged {
    bytes: Vec<u8>,
}
impl Staged {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// 0xfc20 parameters consist of index followed by data. The final command
    /// is always present, even for an exact multiple of 252 with no final data.
    /// Indices are 0..127, then 1..127 repeatedly; the last index sets bit 7.
    pub fn fragments(&self) -> impl Iterator<Item = Fragment<'_>> {
        let last = self.bytes.len() / FRAGMENT;
        (0..=last).map(move |i| {
            let index = if i == 0 { 0 } else { ((i - 1) % 127 + 1) as u8 };
            let start = i * FRAGMENT;
            let end = core::cmp::min(start + FRAGMENT, self.bytes.len());
            Fragment {
                index: index | if i == last { 0x80 } else { 0 },
                data: &self.bytes[start..end],
            }
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub index: u8,
    pub data: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image() -> Vec<u8> {
        let mut b = vec![0; 48];
        b[..8].copy_from_slice(b"Realtech");
        b[8..12].copy_from_slice(&0x12345678u32.to_le_bytes());
        b[12..14].copy_from_slice(&2u16.to_le_bytes());
        for (i, chip, start) in [(0, 1u16, 32u32), (1, 2, 36)] {
            b[14 + i * 2..16 + i * 2].copy_from_slice(&chip.to_le_bytes());
            b[18 + i * 2..20 + i * 2].copy_from_slice(&4u16.to_le_bytes());
            b[22 + i * 4..26 + i * 4].copy_from_slice(&start.to_le_bytes());
        }
        b[40..].copy_from_slice(&[0xff, 14, 1, 0, 0x51, 4, 0xfd, 0x77]);
        b
    }
    #[test]
    fn selects_observed_rom_and_rewrites_version_before_exact_configuration() {
        let b = image();
        let config = [0x55, 0xab, 0x23, 0x87, 4, 0, 0xd9, 0, 1, 15];
        let config = Configuration::parse(&config).unwrap();
        let p = Patch::parse(&b, Project::Rtl8761Bu, 1).unwrap();
        assert_eq!(p.rom_version, 1);
        assert_eq!(
            p.stage(Some(&config)).bytes(),
            [
                0x78, 0x56, 0x34, 0x12, 0x55, 0xab, 0x23, 0x87, 4, 0, 0xd9, 0, 1, 15
            ]
        );
        assert_eq!(config.entries, 1);
        assert_eq!(
            Patch::parse(&b, Project::Rtl8761Bu, 2).unwrap_err(),
            FormatError::MissingRom
        );
        assert_eq!(
            Patch::parse(&b, Project::Rtl8822B, 0).unwrap_err(),
            FormatError::Project
        );
    }
    #[test]
    fn validates_entire_container_before_emitting_any_selected_patch() {
        let base = image();
        for (at, value, expected) in [
            (0, b'X', FormatError::Signature),
            (40, 0, FormatError::Extension),
            (41, 8, FormatError::Project),
            (12, 255, FormatError::PatchTable),
            (16, 1, FormatError::DuplicateChip),
            (24, 1, FormatError::PatchBounds),
            (26, 33, FormatError::OverlappingPatches),
            (20, 3, FormatError::PatchBounds),
        ] {
            let mut b = base.clone();
            b[at] = value;
            assert_eq!(
                Patch::parse(&b, Project::Rtl8761Bu, 0).unwrap_err(),
                expected,
                "at {at}"
            );
        }
        for len in 0..base.len() {
            assert!(Patch::parse(&base[..len], Project::Rtl8761Bu, 0).is_err());
        }
    }
    #[test]
    fn config_requires_magic_complete_size_entries_and_nonoverlap() {
        assert_eq!(
            Configuration::parse(&[0x55, 0xab, 0x23, 0x87, 0, 0])
                .unwrap()
                .entries,
            0
        );
        for b in [&[][..], &[0x55, 0xab, 0x23, 0x87, 1, 0][..]] {
            assert_eq!(
                Configuration::parse(b).unwrap_err(),
                FormatError::ConfigHeader
            );
        }
        for tail in [
            &[0xd9, 0][..],
            &[0xd9, 0, 0][..],
            &[0xff, 0xff, 2, 1, 2][..],
            &[0xd9, 0, 2, 1][..],
        ] {
            let mut b = vec![0x55, 0xab, 0x23, 0x87, tail.len() as u8, 0];
            b.extend_from_slice(tail);
            assert_eq!(
                Configuration::parse(&b).unwrap_err(),
                FormatError::ConfigEntry
            );
        }
        let mut b = vec![0x55, 0xab, 0x23, 0x87, 8, 0];
        b.extend_from_slice(&[1, 0, 1, 3, 1, 0, 1, 4]);
        assert_eq!(
            Configuration::parse(&b).unwrap_err(),
            FormatError::OverlappingConfig
        );
    }
    #[test]
    fn download_indices_roll_over_and_exact_multiple_has_real_empty_final_fragment() {
        let stage = Staged {
            bytes: vec![7; 252 * 256],
        };
        let packets: Vec<_> = stage.fragments().collect();
        assert_eq!(packets.len(), 257);
        for (i, expected) in [
            (0, 0),
            (127, 127),
            (128, 1),
            (254, 127),
            (255, 1),
            (256, 0x82),
        ] {
            assert_eq!(packets[i].index, expected);
        }
        assert!(packets[256].data.is_empty());
        assert!(packets[..256].iter().all(|f| f.data.len() == 252));
        let partial = Staged {
            bytes: vec![1; 253],
        };
        assert_eq!(
            partial.fragments().last().unwrap(),
            Fragment {
                index: 0x81,
                data: &[1]
            }
        );
    }
}
