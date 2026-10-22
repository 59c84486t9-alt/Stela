// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! Complete bounded MT79xx maps and exact WMT framing, adapted from Linux
//! a804c5742bff224d4cb4d25dd383554d598be32b btmtk_setup_firmware_79xx.
use super::FormatError;
use crate::bytes::le32;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
const HEADER: usize = 32;
const GLOBAL: usize = 64;
const MAP: usize = 64;
const SPECIFICATION: usize = 52;
const FRAGMENT: usize = 250;
const MAX_IMAGE: usize = 4 * 1024 * 1024;
const MAX_SECTIONS: usize = 256;

/// Raw complete map includes all security/key/CRC, mode, alignment and reserved
/// fields. These bytes are transmitted unchanged, never treated as host-side
/// vendor authentication. Hashes retain both the complete region (including
/// nonuploaded metadata) and its independently bounded download extent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionMetadata {
    pub map: [u8; MAP],
    pub region_sha256: [u8; 32],
    pub download_sha256: [u8; 32],
}
impl SectionMetadata {
    pub fn section_type(&self) -> u32 {
        le32(&self.map, 0)
    }
    pub fn offset(&self) -> u32 {
        le32(&self.map, 4)
    }
    pub fn size(&self) -> u32 {
        le32(&self.map, 8)
    }
    pub fn download_address(&self) -> u32 {
        le32(&self.map, 12)
    }
    pub fn download_size(&self) -> u32 {
        le32(&self.map, 16)
    }
    pub fn security_key(&self) -> u32 {
        le32(&self.map, 20)
    }
    pub fn mode_crc_type(&self) -> u32 {
        le32(&self.map, 32)
    }
    pub fn specification(&self) -> &[u8] {
        &self.map[MAP - SPECIFICATION..]
    }
    /// Actual donor download-selection request; byte0 selects legacy download.
    pub fn request(&self) -> [u8; SPECIFICATION + 1] {
        let mut bytes = [0; SPECIFICATION + 1];
        bytes[1..].copy_from_slice(self.specification());
        bytes
    }
}
/// Owned immutable source observations; no firmware or Provider borrow survives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmwareMetadata {
    pub header: [u8; HEADER],
    pub global_descriptor: [u8; GLOBAL],
    pub sections: Vec<SectionMetadata>,
    pub length: usize,
    pub sha256: [u8; 32],
}
/// Complete validated input. Chip/ROM/flavor selection and exact resource
/// requirements are independent live controller responsibilities.
#[derive(Debug)]
pub struct Patch<'a> {
    header: [u8; HEADER],
    global_descriptor: [u8; GLOBAL],
    pub sections: Vec<Section<'a>>,
    length: usize,
    sha256: [u8; 32],
}
#[derive(Debug)]
pub struct Section<'a> {
    pub metadata: SectionMetadata,
    payload: &'a [u8],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub flag: u8,
    pub data: &'a [u8],
}
impl<'a> Patch<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FormatError> {
        if !(HEADER + GLOBAL + MAP..=MAX_IMAGE).contains(&bytes.len()) {
            return Err(FormatError::Size);
        }
        // Exact source-backed ALPS header family of the current 7961/7922/7925
        // inputs. Other encodings remain unsupported, not inferred compatible.
        // The C struct is 28 bytes; the format reserves a 32-byte header area.
        // Retain the remaining four bytes raw rather than misplacing magic.
        if &bytes[16..20] != b"ALPS" || bytes[24..28] != [0xff; 4] {
            return Err(FormatError::Header);
        }
        let count = le32(bytes, HEADER + 12) as usize;
        if count == 0 || count > MAX_SECTIONS || count > (bytes.len() - HEADER - GLOBAL) / MAP {
            return Err(FormatError::SectionTable);
        }
        let table_end = HEADER + GLOBAL + count * MAP;
        let mut sections: Vec<Section<'a>> = Vec::with_capacity(count);
        let mut total = 0usize;
        for i in 0..count {
            let at = HEADER + GLOBAL + i * MAP;
            let map: [u8; MAP] = bytes[at..at + MAP].try_into().unwrap();
            let start = le32(&map, 4) as usize;
            let size = le32(&map, 8) as usize;
            let end = start
                .checked_add(size)
                .filter(|end| *end <= bytes.len())
                .ok_or(FormatError::SectionBounds)?;
            if start < table_end {
                return Err(FormatError::SectionBounds);
            }
            let size_download = le32(&map, 16) as usize;
            if size_download > size || le32(&map, 12).checked_add(size_download as u32).is_none() {
                return Err(FormatError::DownloadBounds);
            }
            if size != 0
                && sections.iter().any(|s| {
                    let a = s.metadata.offset() as usize;
                    let b = a + s.metadata.size() as usize;
                    a != b && start < b && a < end
                })
            {
                return Err(FormatError::OverlappingSections);
            }
            let payload = &bytes[start..start + size_download];
            sections.push(Section {
                metadata: SectionMetadata {
                    map,
                    region_sha256: Sha256::digest(&bytes[start..end]).into(),
                    download_sha256: Sha256::digest(payload).into(),
                },
                payload,
            });
            total += size_download;
        }
        if total == 0 {
            return Err(FormatError::NoDownload);
        }
        Ok(Self {
            header: bytes[..HEADER].try_into().unwrap(),
            global_descriptor: bytes[HEADER..HEADER + GLOBAL].try_into().unwrap(),
            sections,
            length: bytes.len(),
            sha256: Sha256::digest(bytes).into(),
        })
    }
    pub fn metadata(&self) -> FirmwareMetadata {
        FirmwareMetadata {
            header: self.header,
            global_descriptor: self.global_descriptor,
            sections: self.sections.iter().map(|s| s.metadata.clone()).collect(),
            length: self.length,
            sha256: self.sha256,
        }
    }
}
impl Section<'_> {
    /// Exact donor flags: first=1 even for a single short block, middle=2,
    /// last=3 only after the first. Empty sections emit no query or fragments.
    pub fn fragments(&self) -> impl Iterator<Item = Fragment<'_>> {
        self.payload
            .chunks(FRAGMENT)
            .enumerate()
            .map(|(i, data)| Fragment {
                flag: if i == 0 {
                    1
                } else if (i + 1) * FRAGMENT >= self.payload.len() {
                    3
                } else {
                    2
                },
                data,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image() -> Vec<u8> {
        let mut b = vec![0; HEADER + GLOBAL + 3 * MAP + 251 + 3];
        b[16..20].copy_from_slice(b"ALPS");
        b[24..28].fill(0xff);
        b[HEADER + 12..HEADER + 16].copy_from_slice(&3u32.to_le_bytes());
        for (i, size, download, offset) in
            [(0, 251u32, 251u32, 288u32), (1, 0, 0, 539), (2, 3, 0, 539)]
        {
            let a = HEADER + GLOBAL + i * MAP;
            for (n, value) in [
                (0, 1u32),
                (4, offset),
                (8, size),
                (12, 0x900000),
                (16, download),
                (20, 0x01000000),
                (32, 0x0101),
            ] {
                b[a + n..a + n + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        b[288..539].fill(0xab);
        b[539..].copy_from_slice(b"MTA");
        b
    }
    #[test]
    fn preserves_security_controls_nonuploaded_metadata_and_exact_donor_flags() {
        let b = image();
        let p = Patch::parse(&b).unwrap();
        let meta = p.metadata();
        assert_eq!(meta.length, b.len());
        assert_eq!(meta.sha256, <[u8; 32]>::from(Sha256::digest(&b)));
        let section = &p.sections[0];
        assert_eq!(section.metadata.security_key(), 0x01000000);
        assert_eq!(&section.metadata.request()[1..], &b[108..160]);
        let f: Vec<_> = section.fragments().collect();
        assert_eq!(f.len(), 2);
        assert_eq!(
            (f[0].flag, f[0].data.len(), f[1].flag, f[1].data.len()),
            (1, 250, 3, 1)
        );
        assert_eq!(p.sections[1].fragments().count(), 0);
        assert_eq!(p.sections[2].fragments().count(), 0);
        assert_eq!(
            meta.sections[2].region_sha256,
            <[u8; 32]>::from(Sha256::digest(b"MTA"))
        );
        let mut short = b;
        short[104..108].copy_from_slice(&1u32.to_le_bytes());
        short[112..116].copy_from_slice(&1u32.to_le_bytes());
        let p = Patch::parse(&short).unwrap();
        let f: Vec<_> = p.sections[0].fragments().collect();
        assert_eq!(f[0].flag, 1);
        assert_eq!(f.len(), 1);
    }
    #[test]
    fn rejects_the_complete_invalid_map_before_any_payload_can_be_emitted() {
        let b = image();
        for len in 0..b.len() {
            assert!(Patch::parse(&b[..len]).is_err());
        }
        for (at, value, expected) in [
            (16, 0, FormatError::Header),
            (44, 255, FormatError::SectionTable),
            (100, 0, FormatError::SectionBounds),
            (112, 255, FormatError::DownloadBounds),
            // The nonuploaded metadata region must still be in bounds.
            (232, 255, FormatError::SectionBounds),
            (228, 0, FormatError::OverlappingSections),
        ] {
            let mut x = b.clone();
            x[at] = value;
            assert_eq!(Patch::parse(&x).unwrap_err(), expected, "at {at}");
        }
    }
}
