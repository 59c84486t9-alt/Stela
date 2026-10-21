// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
// Copyright(c) 2019-2020 Realtek Corporation
//! Borrowed firmware layouts from pinned rtw88/mac.c and rtw89/fw.c.
//! This parses bytes, not vendor authentication, calibration or radio readiness.
use alloc::vec::Vec;
use core::ops::Range;

const MAX_IMAGE: usize = 16 * 1024 * 1024;
const LEGACY_HEADER: usize = 64;
const CHECKSUM: usize = 8;
const MFW_HEADER: usize = 16;
const MFW_ENTRY: usize = 16;
const AX_HEADER: usize = 32;
const AX_SECTION: usize = 16;
const MAX_SECTIONS: usize = 10;
const SECURITY_SECTION: u8 = 9;
const SECURITY_SIGNATURE: usize = 512;
const NORMAL: u8 = 1;
const NORMAL_CE: u8 = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    Truncated { offset: usize, bytes: usize },
    ResourceLimit,
    Length,
    AddressOverflow,
    Signature,
    UnsupportedHeader(u8),
    UnsupportedFormattedSecurity(u32),
    NoCompatibleFirmware { cut: u8 },
    EmptyContainer,
    TooManySections(u8),
    DynamicHeader,
}

#[derive(Debug)]
pub enum Layout<'a> {
    Rtw88(Rtw88<'a>),
    Rtw89(Rtw89<'a>),
}

fn bytes(data: &[u8], offset: usize, len: usize) -> Result<&[u8], ParseError> {
    let end = offset.checked_add(len).ok_or(ParseError::ResourceLimit)?;
    data.get(offset..end)
        .ok_or(ParseError::Truncated { offset, bytes: len })
}
fn le16(data: &[u8], offset: usize) -> Result<u16, ParseError> {
    Ok(u16::from_le_bytes(
        bytes(data, offset, 2)?.try_into().unwrap(),
    ))
}
fn le32(data: &[u8], offset: usize) -> Result<u32, ParseError> {
    Ok(u32::from_le_bytes(
        bytes(data, offset, 4)?.try_into().unwrap(),
    ))
}
fn image_limit(data: &[u8]) -> Result<(), ParseError> {
    if data.len() > MAX_IMAGE {
        Err(ParseError::ResourceLimit)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyMemory {
    Dmem,
    Imem,
    Emem,
}

#[derive(Debug)]
pub struct LegacySection<'a> {
    pub memory: LegacyMemory,
    pub raw_address: u32,
    pub download_address: u32,
    /// Includes the eight checksum bytes which the real device must verify.
    pub data: &'a [u8],
    pub payload_bytes: usize,
    pub range: Range<usize>,
}

#[derive(Debug)]
pub struct Rtw88<'a> {
    pub header: &'a [u8; LEGACY_HEADER],
    pub version: u16,
    pub subversion: u8,
    pub subindex: u8,
    pub h2c_format: u16,
    pub sections: Vec<LegacySection<'a>>,
}
impl<'a> Rtw88<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        image_limit(data)?;
        let header: &[u8; LEGACY_HEADER] = bytes(data, 0, LEGACY_HEADER)?.try_into().unwrap();
        if le16(data, 0)? != 0x8822 {
            return Err(ParseError::Signature);
        }
        let mut sections = Vec::with_capacity(3);
        let mut offset = LEGACY_HEADER;
        for (memory, address, payload) in [
            (LegacyMemory::Dmem, 0x20, 0x24),
            (LegacyMemory::Imem, 0x3c, 0x30),
            (LegacyMemory::Emem, 0x38, 0x34),
        ] {
            let payload_bytes = le32(data, payload)? as usize;
            if memory == LegacyMemory::Emem && (header[0x18] & 0x10 == 0 || payload_bytes == 0) {
                continue;
            }
            let length = payload_bytes
                .checked_add(CHECKSUM)
                .ok_or(ParseError::ResourceLimit)?;
            let section = bytes(data, offset, length)?;
            let raw_address = le32(data, address)?;
            let download_address = raw_address & !(1 << 31);
            download_address
                .checked_add(length as u32)
                .ok_or(ParseError::AddressOverflow)?;
            sections.push(LegacySection {
                memory,
                raw_address,
                download_address,
                data: section,
                payload_bytes,
                range: offset..offset + length,
            });
            offset += length;
        }
        if offset != data.len() {
            return Err(ParseError::Length);
        }
        Ok(Self {
            header,
            version: le16(data, 4)?,
            subversion: header[6],
            subindex: header[7],
            h2c_format: le16(data, 0x1c)?,
            sections,
        })
    }
}

#[derive(Debug)]
pub struct Entry<'a> {
    pub descriptor: &'a [u8],
    pub cut: u8,
    pub kind: u8,
    pub mp: u8,
    pub range: Range<usize>,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub struct Section<'a> {
    pub descriptor: &'a [u8],
    pub raw_address: u32,
    pub download_address: u32,
    pub kind: u8,
    pub redownload: bool,
    pub checksum: bool,
    /// Includes the checksum, if present; excludes any appended MSS signatures.
    pub data: &'a [u8],
    pub range: Range<usize>,
    pub mssc: u32,
    /// Opaque signatures retained without claiming authentication or a key choice.
    pub signatures: &'a [u8],
}

#[derive(Debug)]
pub struct AxImage<'a> {
    pub header: &'a [u8],
    pub dynamic_header: &'a [u8],
    pub version: [u8; 4],
    pub commit_id: u32,
    pub idmem_share_mode: u8,
    /// The AX donor uses 2020, independent of the stored part-size field.
    pub part_bytes: usize,
    pub sections: Vec<Section<'a>>,
}
impl<'a> AxImage<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let fixed = bytes(data, 0, AX_HEADER)?;
        let header_version = (le32(data, 12)? >> 24) as u8;
        if header_version != 0 {
            return Err(ParseError::UnsupportedHeader(header_version));
        }
        let count = ((le32(data, 24)? >> 8) & 255) as u8;
        if usize::from(count) > MAX_SECTIONS {
            return Err(ParseError::TooManySections(count));
        }
        let base = AX_HEADER + usize::from(count) * AX_SECTION;
        bytes(data, 0, base)?;
        let w7 = le32(data, 28)?;
        let header_bytes = if w7 & (1 << 16) != 0 {
            ((le32(data, 12)? >> 16) & 255) as usize
        } else {
            base
        };
        if header_bytes < base {
            return Err(ParseError::DynamicHeader);
        }
        let dynamic_header = bytes(data, base, header_bytes - base)?;
        if w7 & (1 << 16) != 0
            && (dynamic_header.len() < 4
                || le32(dynamic_header, 0)? as usize != dynamic_header.len())
        {
            return Err(ParseError::DynamicHeader);
        }
        let mut offset = header_bytes;
        let mut sections = Vec::with_capacity(usize::from(count));
        for index in 0..usize::from(count) {
            let at = AX_HEADER + index * AX_SECTION;
            let descriptor = bytes(data, at, AX_SECTION)?;
            let raw_address = le32(descriptor, 0)?;
            let download_address = raw_address & 0x1fff_ffff;
            let flags = le32(descriptor, 4)?;
            let kind = ((flags >> 24) & 15) as u8;
            let checksum = flags & (1 << 28) != 0;
            let length = (flags & 0xff_ffff) as usize + if checksum { CHECKSUM } else { 0 };
            let mssc = if kind == SECURITY_SECTION {
                le32(descriptor, 8)?
            } else {
                0
            };
            if kind == SECURITY_SECTION && mssc & 255 == 255 {
                return Err(ParseError::UnsupportedFormattedSecurity(mssc));
            }
            let signature_bytes = (mssc as usize)
                .checked_mul(SECURITY_SIGNATURE)
                .ok_or(ParseError::ResourceLimit)?;
            let section = bytes(data, offset, length)?;
            let signatures = bytes(data, offset + length, signature_bytes)?;
            download_address
                .checked_add(length as u32)
                .ok_or(ParseError::AddressOverflow)?;
            sections.push(Section {
                descriptor,
                raw_address,
                download_address,
                kind,
                redownload: flags & (1 << 29) != 0,
                checksum,
                data: section,
                range: offset..offset + length,
                mssc,
                signatures,
            });
            offset += length + signature_bytes;
        }
        if offset != data.len() {
            return Err(ParseError::Length);
        }
        Ok(Self {
            header: fixed,
            dynamic_header,
            version: fixed[4..8].try_into().unwrap(),
            commit_id: le32(data, 8)?,
            idmem_share_mode: ((w7 >> 18) & 15) as u8,
            part_bytes: 2020,
            sections,
        })
    }
}

#[derive(Debug)]
pub struct Rtw89<'a> {
    pub container_header: Option<&'a [u8]>,
    /// Includes unselected WOW/log/test records; unknown kinds are retained.
    pub entries: Vec<Entry<'a>>,
    pub selected: usize,
    pub image: AxImage<'a>,
    /// Complete trailing firmware elements, including tables not yet consumed.
    pub trailing_elements: &'a [u8],
}
impl<'a> Rtw89<'a> {
    pub fn parse(data: &'a [u8], observed_cut: u8) -> Result<Self, ParseError> {
        image_limit(data)?;
        let mut entries = Vec::new();
        let (container_header, end) = if data.first() == Some(&0xff) {
            let container_header = Some(bytes(data, 0, MFW_HEADER)?);
            let count = usize::from(data[1]);
            if count == 0 {
                return Err(ParseError::EmptyContainer);
            }
            let table_end = MFW_HEADER + count * MFW_ENTRY;
            bytes(data, 0, table_end)?;
            let mut max_end = table_end;
            for index in 0..count {
                let descriptor = bytes(data, MFW_HEADER + index * MFW_ENTRY, MFW_ENTRY)?;
                let offset = le32(descriptor, 4)? as usize;
                let length = le32(descriptor, 8)? as usize;
                if offset < table_end {
                    return Err(ParseError::Length);
                }
                let content = bytes(data, offset, length)?;
                max_end = max_end.max(offset + length);
                entries.push(Entry {
                    descriptor,
                    cut: descriptor[0],
                    kind: descriptor[1],
                    mp: descriptor[2],
                    range: offset..offset + length,
                    data: content,
                });
            }
            (container_header, max_end)
        } else {
            // The donor permits a legacy single image for normal type only.
            entries.push(Entry {
                descriptor: &[],
                cut: 0,
                kind: NORMAL,
                mp: 0,
                range: 0..data.len(),
                data,
            });
            (None, data.len())
        };
        let best = |kind| {
            let mut selected = None;
            for (index, entry) in entries.iter().enumerate() {
                if entry.kind == kind
                    && entry.mp == 0
                    && entry.cut <= observed_cut
                    && selected.is_none_or(|old: usize| entries[old].cut < entry.cut)
                {
                    selected = Some(index);
                }
            }
            selected
        };
        // RTL8852B sets try_ce_fw: prefer CE, then ordinary normal firmware.
        let selected = best(NORMAL_CE)
            .or_else(|| best(NORMAL))
            .ok_or(ParseError::NoCompatibleFirmware { cut: observed_cut })?;
        let image = AxImage::parse(entries[selected].data)?;
        Ok(Self {
            container_header,
            entries,
            selected,
            image,
            trailing_elements: &data[end..],
        })
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(crate) fn legacy_fixture() -> Vec<u8> {
        let mut b = vec![0u8; 64 + 12 + 16 + 10];
        b[..2].copy_from_slice(&0x8822u16.to_le_bytes());
        b[4..6].copy_from_slice(&9u16.to_le_bytes());
        b[6] = 9;
        b[7] = 15;
        b[0x18] = 0x10;
        for (at, value) in [
            (0x20, 0x80200000u32),
            (0x24, 4),
            (0x3c, 0x80030000),
            (0x30, 8),
            (0x38, 0x80100000),
            (0x34, 2),
        ] {
            b[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (i, x) in b[64..].iter_mut().enumerate() {
            *x = i as u8;
        }
        b
    }
    fn ax_fixture() -> Vec<u8> {
        let mut b = vec![0u8; 32 + 32 + 12 + 512 + 3];
        b[4..8].copy_from_slice(&[1, 2, 3, 4]);
        b[24..28].copy_from_slice(&(2u32 << 8).to_le_bytes());
        b[32..36].copy_from_slice(&0xb8000000u32.to_le_bytes());
        b[36..40].copy_from_slice(&(4u32 | 1 << 28 | 1 << 29 | 9 << 24).to_le_bytes());
        b[40..44].copy_from_slice(&1u32.to_le_bytes());
        b[48..52].copy_from_slice(&0xb9000000u32.to_le_bytes());
        b[52..56].copy_from_slice(&(3u32 | 2 << 24).to_le_bytes());
        b
    }
    fn container_fixture() -> Vec<u8> {
        let image = ax_fixture();
        let mut b = vec![0u8; 16 + 4 * 16];
        b[0] = 255;
        b[1] = 4;
        for (i, (cut, kind, mp)) in [(2, 1, 0), (1, 5, 0), (2, 5, 1), (0, 255, 0)]
            .into_iter()
            .enumerate()
        {
            let at = 16 + i * 16;
            let offset = b.len();
            b[at] = cut;
            b[at + 1] = kind;
            b[at + 2] = mp;
            b[at + 4..at + 8].copy_from_slice(&(offset as u32).to_le_bytes());
            b[at + 8..at + 12].copy_from_slice(&(image.len() as u32).to_le_bytes());
            b.extend_from_slice(&image);
        }
        b.extend_from_slice(&[0xa5; 17]);
        b
    }
    #[test]
    fn legacy_layout_borrows_exact_checksum_inclusive_memory_regions() {
        let b = legacy_fixture();
        let p = Rtw88::parse(&b).unwrap();
        assert_eq!(p.sections.len(), 3);
        assert_eq!(p.version, 9);
        for (s, (start, len, addr)) in
            p.sections
                .iter()
                .zip([(64, 12, 0x200000), (76, 16, 0x30000), (92, 10, 0x100000)])
        {
            assert_eq!(s.range, start..start + len);
            assert_eq!(s.data, &b[start..start + len]);
            assert_eq!(s.data.as_ptr(), b[start..].as_ptr());
            assert_eq!(s.download_address, addr);
        }
        for cut in 0..b.len() {
            assert!(Rtw88::parse(&b[..cut]).is_err());
        }
        let mut trailing = b.clone();
        trailing.push(0);
        assert_eq!(Rtw88::parse(&trailing).unwrap_err(), ParseError::Length);
        let mut huge = b.clone();
        huge[0x24..0x28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Rtw88::parse(&huge).is_err());
        let mut no_emem = b[..92].to_vec();
        no_emem[0x18] = 0;
        assert_eq!(Rtw88::parse(&no_emem).unwrap().sections.len(), 2);
    }
    #[test]
    fn ax_sections_retain_checksum_security_signatures_flags_and_raw_addresses() {
        let b = ax_fixture();
        let p = AxImage::parse(&b).unwrap();
        assert_eq!(p.sections.len(), 2);
        assert_eq!(p.part_bytes, 2020);
        let s = &p.sections[0];
        assert!(s.checksum && s.redownload);
        assert_eq!(s.kind, 9);
        assert_eq!(s.raw_address, 0xb8000000);
        assert_eq!(s.download_address, 0x18000000);
        assert_eq!(s.data.len(), 12);
        assert_eq!(s.signatures.len(), 512);
        assert_eq!(s.mssc, 1);
        for n in 0..b.len() {
            assert!(AxImage::parse(&b[..n]).is_err());
        }
        let mut f = b.clone();
        f[40..44].copy_from_slice(&255u32.to_le_bytes());
        assert_eq!(
            AxImage::parse(&f).unwrap_err(),
            ParseError::UnsupportedFormattedSecurity(255)
        );
        f = b.clone();
        f[15] = 1;
        assert_eq!(
            AxImage::parse(&f).unwrap_err(),
            ParseError::UnsupportedHeader(1)
        );
        f = b.clone();
        f[25] = 11;
        assert_eq!(
            AxImage::parse(&f).unwrap_err(),
            ParseError::TooManySections(11)
        );
    }
    #[test]
    fn closest_production_ce_cut_wins_independently_of_entry_order() {
        let b = container_fixture();
        for cut in 1..16 {
            let p = Rtw89::parse(&b, cut).unwrap();
            assert_eq!(p.selected, 1);
            assert_eq!(p.entries.len(), 4);
            assert_eq!(p.trailing_elements, &[0xa5; 17]);
            assert_eq!(p.entries[3].kind, 255);
            assert_eq!(p.entries[2].mp, 1);
        }
        assert_eq!(
            Rtw89::parse(&b, 0).unwrap_err(),
            ParseError::NoCompatibleFirmware { cut: 0 }
        );
        let mut f = b.clone();
        f[16 + 16 + 1] = 3;
        let p = Rtw89::parse(&f, 2).unwrap();
        assert_eq!(p.selected, 0);
        let mut f = b.clone();
        f[16 + 4..16 + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Rtw89::parse(&f, 2).is_err());
        let mut f = b;
        f[1] = 0;
        assert_eq!(Rtw89::parse(&f, 2).unwrap_err(), ParseError::EmptyContainer);
    }
    #[test]
    fn dynamic_header_length_is_checked_before_any_section_payload() {
        let b = ax_fixture();
        let mut f = b.clone();
        f[28..32].copy_from_slice(&(1u32 << 16).to_le_bytes());
        f[14] = 68;
        f.splice(64..64, [4u8, 0, 0, 0]);
        assert_eq!(AxImage::parse(&f).unwrap().dynamic_header, &[4, 0, 0, 0]);
        f[64] = 8;
        assert_eq!(AxImage::parse(&f).unwrap_err(), ParseError::DynamicHeader);
        f[14] = 32;
        assert_eq!(AxImage::parse(&f).unwrap_err(), ParseError::DynamicHeader);
    }
    #[test]
    #[ignore = "requires STELA_REALTEK_WIFI_IMAGES from pinned linux-firmware"]
    fn actual_vendor_layouts_are_borrowed_complete_and_versioned() {
        extern crate std;
        let root = std::path::PathBuf::from(std::env::var("STELA_REALTEK_WIFI_IMAGES").unwrap());
        let b = std::fs::read(root.join("rtw88/rtw8822c_fw.bin")).unwrap();
        let p = Rtw88::parse(&b).unwrap();
        assert_eq!(
            (p.version, p.subversion, p.subindex, p.h2c_format),
            (9, 9, 15, 15)
        );
        assert_eq!(
            p.sections.iter().map(|s| s.data.len()).collect::<Vec<_>>(),
            [19336, 54072, 129128]
        );
        let b = std::fs::read(root.join("rtw89/rtw8852b_fw-2.bin")).unwrap();
        for cut in 1..16 {
            let p = Rtw89::parse(&b, cut).unwrap();
            assert_eq!(p.entries.len(), 5);
            assert_eq!(p.entries[p.selected].cut, cut.min(2));
            assert_eq!(p.entries[p.selected].kind, 5);
            assert_eq!(p.image.sections.len(), 3);
            assert_eq!(p.image.dynamic_header.len(), 64);
            assert!(!p.trailing_elements.is_empty());
            assert_eq!(p.image.version, [0, 29, 29, 18]);
        }
    }

    #[test]
    #[ignore = "requires actual images and STELA_REALTEK_WIFI_ORACLE from the pinned C script"]
    fn unchanged_linux_selection_and_complete_payloads_agree() {
        extern crate std;
        fn word(trace: &[u8], at: &mut usize) -> u32 {
            let value = le32(trace, *at).unwrap();
            *at += 4;
            value
        }
        let root = std::path::PathBuf::from(std::env::var("STELA_REALTEK_WIFI_IMAGES").unwrap());
        let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_ORACLE").unwrap()).unwrap();
        let mut at = 0;
        assert_eq!(word(&trace, &mut at), 0x38385752);
        let legacy = std::fs::read(root.join("rtw88/rtw8822c_fw.bin")).unwrap();
        let parsed = Rtw88::parse(&legacy).unwrap();
        for section in parsed.sections {
            assert_eq!(word(&trace, &mut at), section.download_address);
            assert_eq!(word(&trace, &mut at) as usize, section.data.len());
            assert_eq!(word(&trace, &mut at) as usize, section.range.start);
            assert_eq!(&trace[at..at + section.data.len()], section.data);
            at += section.data.len();
        }
        assert_eq!(word(&trace, &mut at), 0x39385752);
        let ax = std::fs::read(root.join("rtw89/rtw8852b_fw-2.bin")).unwrap();
        for cut in 0..16 {
            assert_eq!(word(&trace, &mut at), u32::from(cut));
            let status = word(&trace, &mut at);
            let parsed = Rtw89::parse(&ax, cut);
            if status != 0 {
                assert_eq!(
                    parsed.unwrap_err(),
                    ParseError::NoCompatibleFirmware { cut }
                );
                continue;
            }
            let parsed = parsed.unwrap();
            let selected = &parsed.entries[parsed.selected];
            assert_eq!(word(&trace, &mut at), u32::from(selected.kind));
            assert_eq!(word(&trace, &mut at) as usize, selected.range.start);
            assert_eq!(word(&trace, &mut at) as usize, selected.data.len());
            assert_eq!(
                word(&trace, &mut at) as usize,
                32 + 16 * parsed.image.sections.len() + parsed.image.dynamic_header.len()
            );
            assert_eq!(
                word(&trace, &mut at) as usize,
                parsed.image.dynamic_header.len()
            );
            assert_eq!(word(&trace, &mut at) as usize, parsed.image.part_bytes);
            assert_eq!(word(&trace, &mut at) as usize, parsed.image.sections.len());
            for section in parsed.image.sections {
                assert_eq!(word(&trace, &mut at), u32::from(section.kind));
                assert_eq!(word(&trace, &mut at), section.download_address);
                assert_eq!(word(&trace, &mut at) as usize, section.data.len());
                assert_eq!(word(&trace, &mut at), u32::from(section.redownload));
                assert_eq!(word(&trace, &mut at), section.mssc);
                assert_eq!(word(&trace, &mut at) as usize, section.range.start);
                assert_eq!(&trace[at..at + section.data.len()], section.data);
                at += section.data.len();
                assert_eq!(
                    &trace[at..at + section.signatures.len()],
                    section.signatures
                );
                at += section.signatures.len();
            }
        }
        assert_eq!(at, trace.len());
    }
}
