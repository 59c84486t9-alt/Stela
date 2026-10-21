// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Bounded Connac2 patch and RAM images. Parsing follows mt76_connac_mcu.c;
//! every descriptor and payload is checked before any download command.
//! Manifest integrity and these headers do not establish vendor authentication.
use super::identity::{Chip, Identity};
use crate::firmware::{self as resources, Image, Provider, Requirement, Target};
use alloc::{string::String, vec::Vec};
use core::fmt;

const PATCH_HEADER: usize = 96;
const PATCH_SECTION: usize = 64;
const RAM_TRAILER: usize = 36;
const RAM_REGION: usize = 40;
const MAX_REGIONS: usize = 64;
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const NEED_RESPONSE: u32 = 1 << 31;
const ENCRYPT: u32 = 1;
const RESET_SEC_IV: u32 = 1 << 3;
const ENCRYPT_SCRAMBLE: u32 = 1 << 6;
const FEATURE_ENCRYPT: u8 = 1;
const FEATURE_KEY: u8 = 6;
const FEATURE_SCRAMBLE: u8 = 1 << 4;
const FEATURE_OVERRIDE: u8 = 1 << 5;
const FEATURE_NON_DOWNLOAD: u8 = 1 << 6;
const KNOWN_FEATURES: u8 =
    FEATURE_ENCRYPT | FEATURE_KEY | FEATURE_SCRAMBLE | FEATURE_OVERRIDE | FEATURE_NON_DOWNLOAD;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    ImageSize,
    RegionCount,
    RegionTable,
    RegionPayload,
    DeviceAddress,
    SectionType(u32),
    PatchEncryption(u32),
    UnknownFeature(u8),
    CompressedRegion,
    RamFormat(u8),
}
impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MediaTek firmware: {self:?}")
    }
}
impl core::error::Error for FormatError {}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn checked_address(address: u32, bytes: u32) -> Result<(), FormatError> {
    if bytes == 0 || u64::from(address) + u64::from(bytes) > (1u64 << 32) {
        Err(FormatError::DeviceAddress)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PatchHeader {
    pub build_date: [u8; 16],
    pub platform: [u8; 4],
    pub hardware_software_version: u32,
    pub patch_version: u32,
    pub checksum: u16,
    pub descriptor_version: u32,
    pub subsystem: u32,
    pub feature: u32,
    pub crc: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PatchRegion<'a> {
    pub section_type: u32,
    pub file_offset: u32,
    pub stored_bytes: u32,
    pub address: u32,
    pub security: u32,
    pub alignment_bytes: u32,
    pub mode: u32,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub struct Patch<'a> {
    pub header: PatchHeader,
    regions: Vec<PatchRegion<'a>>,
}
impl<'a> Patch<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FormatError> {
        if bytes.len() < PATCH_HEADER || bytes.len() > MAX_IMAGE_BYTES {
            return Err(FormatError::ImageSize);
        }
        let count = be32(bytes, 44) as usize;
        if count == 0 || count > MAX_REGIONS {
            return Err(FormatError::RegionCount);
        }
        let table_end = PATCH_HEADER + count * PATCH_SECTION;
        if table_end > bytes.len() {
            return Err(FormatError::RegionTable);
        }
        let mut regions = Vec::with_capacity(count);
        for descriptor in bytes[PATCH_HEADER..table_end]
            .as_chunks::<PATCH_SECTION>()
            .0
        {
            let section_type = be32(descriptor, 0);
            if section_type & 0xffff != 2 {
                return Err(FormatError::SectionType(section_type));
            }
            let offset = be32(descriptor, 4);
            let stored_bytes = be32(descriptor, 8);
            let address = be32(descriptor, 12);
            let length = be32(descriptor, 16);
            let security = be32(descriptor, 20);
            checked_address(address, length)?;
            if (offset as usize) < table_end || length > stored_bytes {
                return Err(FormatError::RegionPayload);
            }
            let stored_end = (offset as usize)
                .checked_add(stored_bytes as usize)
                .ok_or(FormatError::RegionPayload)?;
            let payload_end = (offset as usize)
                .checked_add(length as usize)
                .ok_or(FormatError::RegionPayload)?;
            if stored_end > bytes.len() {
                return Err(FormatError::RegionPayload);
            }
            let mode = patch_mode(security)?;
            regions.push(PatchRegion {
                section_type,
                file_offset: offset,
                stored_bytes,
                address,
                security,
                alignment_bytes: be32(descriptor, 24),
                mode,
                payload: &bytes[offset as usize..payload_end],
            });
        }
        Ok(Self {
            header: PatchHeader {
                build_date: bytes[..16].try_into().unwrap(),
                platform: bytes[16..20].try_into().unwrap(),
                hardware_software_version: be32(bytes, 20),
                patch_version: be32(bytes, 24),
                checksum: u16::from_be_bytes(bytes[28..30].try_into().unwrap()),
                descriptor_version: be32(bytes, 32),
                subsystem: be32(bytes, 36),
                feature: be32(bytes, 40),
                crc: be32(bytes, 48),
            },
            regions,
        })
    }
    pub fn regions(&self) -> &[PatchRegion<'a>] {
        &self.regions
    }
}

fn patch_mode(security: u32) -> Result<u32, FormatError> {
    let mode = if security == u32::MAX {
        0
    } else {
        match security >> 24 {
            0 => 0,
            1 => ENCRYPT | RESET_SEC_IV | ((security & 0xff) << 1 & 6),
            2 => ENCRYPT | RESET_SEC_IV | ENCRYPT_SCRAMBLE,
            _ => return Err(FormatError::PatchEncryption(security)),
        }
    };
    Ok(mode | NEED_RESPONSE)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RamHeader {
    pub chip_id: u8,
    pub eco_code: u8,
    pub format_version: u8,
    pub format_flag: u8,
    pub version: [u8; 10],
    pub build_date: [u8; 15],
    pub crc: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RamRegion<'a> {
    pub file_offset: usize,
    pub address: u32,
    pub features: u8,
    pub kind: u8,
    pub payload: &'a [u8],
}
impl RamRegion<'_> {
    pub fn non_download(&self) -> bool {
        self.features & FEATURE_NON_DOWNLOAD != 0
    }
    pub fn overrides_start(&self) -> bool {
        self.features & FEATURE_OVERRIDE != 0
    }
    /// WM download mode from mt76_connac_mcu_gen_dl_mode. The cipher/key
    /// fields are protocol encodings, not a host-side authentication claim.
    pub fn mode(&self) -> u32 {
        NEED_RESPONSE
            | u32::from(self.features & FEATURE_KEY)
            | if self.features & FEATURE_ENCRYPT != 0 {
                ENCRYPT | RESET_SEC_IV
            } else {
                0
            }
            | if self.features & FEATURE_SCRAMBLE != 0 {
                ENCRYPT_SCRAMBLE
            } else {
                0
            }
    }
}

#[derive(Debug)]
pub struct Ram<'a> {
    pub header: RamHeader,
    regions: Vec<RamRegion<'a>>,
    /// Release/feature information between payloads and the region table.
    /// It is retained for capability/CLC consumers, never sent as an extra
    /// implicit firmware region or discarded as though it were padding.
    pub release_information: &'a [u8],
}
impl<'a> Ram<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FormatError> {
        if bytes.len() < RAM_TRAILER || bytes.len() > MAX_IMAGE_BYTES {
            return Err(FormatError::ImageSize);
        }
        let trailer_at = bytes.len() - RAM_TRAILER;
        let trailer = &bytes[trailer_at..];
        let count = usize::from(trailer[2]);
        if count == 0 || count > MAX_REGIONS {
            return Err(FormatError::RegionCount);
        }
        if trailer[3] != 2 {
            return Err(FormatError::RamFormat(trailer[3]));
        }
        let table_at = trailer_at
            .checked_sub(count * RAM_REGION)
            .ok_or(FormatError::RegionTable)?;
        let mut regions = Vec::with_capacity(count);
        let mut offset = 0usize;
        for descriptor in bytes[table_at..trailer_at].as_chunks::<RAM_REGION>().0 {
            if le32(descriptor, 0) != 0 || le32(descriptor, 4) != 0 || le32(descriptor, 8) != 0 {
                return Err(FormatError::CompressedRegion);
            }
            let address = le32(descriptor, 16);
            let length = le32(descriptor, 20);
            let features = descriptor[24];
            if features & !KNOWN_FEATURES != 0 {
                return Err(FormatError::UnknownFeature(features));
            }
            let end = offset
                .checked_add(length as usize)
                .filter(|end| *end <= table_at)
                .ok_or(FormatError::RegionPayload)?;
            if features & FEATURE_NON_DOWNLOAD == 0 {
                checked_address(address, length)?;
            }
            regions.push(RamRegion {
                file_offset: offset,
                address,
                features,
                kind: descriptor[25],
                payload: &bytes[offset..end],
            });
            offset = end;
        }
        Ok(Self {
            header: RamHeader {
                chip_id: trailer[0],
                eco_code: trailer[1],
                format_version: trailer[3],
                format_flag: trailer[4],
                version: trailer[7..17].try_into().unwrap(),
                build_date: trailer[17..32].try_into().unwrap(),
                crc: le32(trailer, 32),
            },
            regions,
            release_information: &bytes[offset..table_at],
        })
    }
    pub fn regions(&self) -> &[RamRegion<'a>] {
        &self.regions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Requests {
    pub chip: Chip,
    pub hardware: String,
    pub revision: String,
}
impl Requests {
    pub fn new(identity: &Identity) -> Self {
        Self {
            chip: identity.chip,
            hardware: identity.hardware_key(),
            revision: identity.revision_key(),
        }
    }
    fn requirement(&self, patch: bool) -> Requirement<'_> {
        Requirement {
            name: if patch {
                self.chip.patch_name()
            } else {
                self.chip.ram_name()
            },
            target: Target {
                driver: "wifi-mt792x",
                hardware: &self.hardware,
                revision: &self.revision,
                board: None,
            },
            minimum_bytes: if patch {
                PATCH_HEADER + PATCH_SECTION
            } else {
                RAM_TRAILER + RAM_REGION
            },
        }
    }
    /// Both exact resources are requested before returning a missing member,
    /// making setup requirements observable without any device mutation.
    pub fn load<'a>(&self, provider: &'a dyn Provider) -> Result<Prepared<'a>, LoadError> {
        let patch = provider.load(self.requirement(true));
        let ram = provider.load(self.requirement(false));
        match (patch, ram) {
            (Ok(patch_image), Ok(ram_image)) => {
                let patch =
                    Patch::parse(patch_image.bytes()).map_err(|error| LoadError::Format {
                        requests: self.clone(),
                        patch: true,
                        error,
                    })?;
                let ram = Ram::parse(ram_image.bytes()).map_err(|error| LoadError::Format {
                    requests: self.clone(),
                    patch: false,
                    error,
                })?;
                Ok(Prepared {
                    requests: self.clone(),
                    patch_image,
                    ram_image,
                    patch,
                    ram,
                })
            }
            (patch, ram) => {
                let errors = [patch.err(), ram.err()].into_iter().flatten().collect();
                Err(LoadError::Resources {
                    requests: self.clone(),
                    errors,
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct Prepared<'a> {
    pub(crate) requests: Requests,
    pub(crate) patch_image: Image<'a>,
    pub(crate) ram_image: Image<'a>,
    pub(crate) patch: Patch<'a>,
    pub(crate) ram: Ram<'a>,
}
impl<'a> Prepared<'a> {
    pub fn requests(&self) -> &Requests {
        &self.requests
    }
    pub fn patch(&self) -> &Patch<'a> {
        &self.patch
    }
    pub fn ram(&self) -> &Ram<'a> {
        &self.ram
    }
    pub fn patch_image(&self) -> Image<'a> {
        self.patch_image
    }
    pub fn ram_image(&self) -> Image<'a> {
        self.ram_image
    }
}
#[derive(Debug)]
pub enum LoadError {
    Resources {
        requests: Requests,
        errors: Vec<resources::Error>,
    },
    Format {
        requests: Requests,
        patch: bool,
        error: FormatError,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MediaTek firmware load: {self:?}")
    }
}
impl core::error::Error for LoadError {}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn patch_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; PATCH_HEADER + PATCH_SECTION + 17];
        bytes[44..48].copy_from_slice(&1u32.to_be_bytes());
        for (offset, value) in [
            (0, 2u32),
            (4, 160),
            (8, 17),
            (12, 0x900000),
            (16, 17),
            (20, 0x0100_0003),
        ] {
            bytes[96 + offset..100 + offset].copy_from_slice(&value.to_be_bytes());
        }
        bytes[160..].fill(0x57);
        bytes
    }
    pub(crate) fn ram_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; 11 + 7 + 2 * RAM_REGION + RAM_TRAILER];
        bytes[..11].fill(0x61);
        bytes[11..18].fill(0x72);
        for (at, address, length, features, kind) in
            [(18, 0x910000u32, 11u32, 0x21, 0), (58, 0, 7, 0x40, 2)]
        {
            bytes[at + 16..at + 20].copy_from_slice(&address.to_le_bytes());
            bytes[at + 20..at + 24].copy_from_slice(&length.to_le_bytes());
            bytes[at + 24] = features;
            bytes[at + 25] = kind;
        }
        let at = bytes.len() - 36;
        bytes[at..at + 5].copy_from_slice(&[0x10, 0, 2, 2, 1]);
        bytes
    }
    pub(crate) fn requests(chip: Chip) -> Requests {
        Requests {
            chip,
            hardware: "pci:fixture:full-subsystem-identity".into(),
            revision: "chip:fixture-full-revision".into(),
        }
    }
    pub(crate) fn catalog(requests: &Requests, patch: Vec<u8>, ram: Vec<u8>) -> resources::Catalog {
        use sha2::{Digest, Sha256};
        let entries = [(true, patch), (false, ram)].into_iter().map(|(is_patch, bytes)| {
            let req = requests.requirement(is_patch);
            resources::Resource { name: req.name, target: req.target,
                provenance: resources::Provenance { source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/firmware/linux-firmware", revision: "59f9fc2ef8d1e312d2a613d4e1ffad2ff31a0a01", member: req.name, license: "LICENCE.mediatek" },
                expected_length: bytes.len(), expected_sha256: Sha256::digest(&bytes).into(), bytes }
        }).collect();
        resources::Catalog::from_handoff(entries).unwrap()
    }
    #[test]
    fn both_mandatory_resources_and_exact_target_are_required() {
        let requests = requests(Chip::Mt7922);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let LoadError::Resources { errors, .. } = requests.load(&empty).unwrap_err() else {
            panic!()
        };
        assert_eq!(errors.len(), 2);
        assert!(
            errors
                .iter()
                .all(|e| e.kind == resources::ErrorKind::Missing)
        );
        let provider = catalog(&requests, patch_bytes(), ram_bytes());
        let prepared = requests.load(&provider).unwrap();
        assert_eq!(prepared.requests(), &requests);
        assert_eq!(prepared.ram().regions()[1].payload, &[0x72; 7]);
        assert_eq!(prepared.ram_image().target().hardware, requests.hardware);
        let wrong = Requests {
            revision: "different-hardware-revision".into(),
            ..requests
        };
        let LoadError::Resources { errors, .. } = wrong.load(&provider).unwrap_err() else {
            panic!()
        };
        assert_eq!(errors.len(), 2);
        assert!(
            errors
                .iter()
                .all(|e| e.kind == resources::ErrorKind::WrongTarget)
        );
    }
    #[test]
    fn patch_and_ram_retain_endianness_security_and_non_download_regions() {
        let p = patch_bytes();
        let parsed = Patch::parse(&p).unwrap();
        assert_eq!(parsed.regions()[0].mode, 0x8000_000f);
        assert_eq!(parsed.regions()[0].payload, &p[160..]);
        let r = ram_bytes();
        let parsed = Ram::parse(&r).unwrap();
        assert_eq!(parsed.regions()[0].address, 0x910000);
        assert_eq!(parsed.regions()[0].mode(), 0x8000_0009);
        assert!(parsed.regions()[0].overrides_start());
        assert!(parsed.regions()[1].non_download());
        assert_eq!(parsed.regions()[1].kind, 2);
        assert_eq!(parsed.regions()[1].payload, &r[11..18]);
        for (input, expected) in [
            (0, 0x80000000),
            (u32::MAX, 0x80000000),
            (0x01000002, 0x8000000d),
            (0x02000123, 0x80000049),
        ] {
            assert_eq!(patch_mode(input), Ok(expected));
        }
        assert!(matches!(
            patch_mode(0x03000000),
            Err(FormatError::PatchEncryption(_))
        ));
    }
    #[test]
    fn malformed_tables_lengths_and_future_effects_fail_before_download() {
        let patch = patch_bytes();
        for len in 0..160 {
            assert!(Patch::parse(&patch[..len]).is_err());
        }
        for (at, value) in [
            (44, 65u32),
            (96, 1),
            (100, 0),
            (104, 16),
            (108, u32::MAX),
            (112, u32::MAX),
            (116, 0x03000000),
        ] {
            let mut p = patch.clone();
            p[at..at + 4].copy_from_slice(&value.to_be_bytes());
            assert!(Patch::parse(&p).is_err(), "at={at}");
        }
        let ram = ram_bytes();
        for len in 0..36 {
            assert!(Ram::parse(&ram[..len]).is_err());
        }
        for at in [18, 22, 26, 38] {
            let mut r = ram.clone();
            r[at..at + 4].fill(0xff);
            assert!(Ram::parse(&r).is_err(), "at={at}");
        }
        for mask in [8u8, 0x80] {
            let mut r = ram.clone();
            r[42] |= mask;
            assert!(matches!(
                Ram::parse(&r),
                Err(FormatError::UnknownFeature(_))
            ));
        }
        let mut r = ram;
        let at = r.len() - RAM_TRAILER + 3;
        r[at] = 3;
        assert!(matches!(Ram::parse(&r), Err(FormatError::RamFormat(3))));
    }
    #[test]
    #[ignore = "requires exact redistributable images identified by STELA_MT792X_FIRMWARE"]
    fn actual_pinned_images_preserve_all_regions_and_release_information() {
        extern crate std;
        let root = std::path::PathBuf::from(std::env::var("STELA_MT792X_FIRMWARE").unwrap());
        for (chip, patch_count, ram_count, patch_hash, ram_hash) in [
            (
                Chip::Mt7921,
                1,
                5,
                "a276c06c2b772adb50b86639d33c82824ff4c21d617feb78caea74c040b873f6",
                "b94217a951518a9c14095765f367bc5dd7698f2dc033941d6f18fc2ebd6a2ab9",
            ),
            (
                Chip::Mt7922,
                1,
                6,
                "7fc9075d6d54b31e0539734614ca971fa52caf41b642a3000c8a4501591a4d98",
                "d100e5e04c324fc8da6302112d1e0b4fac952286447d2419eabcd8fb0a1f5b93",
            ),
            (
                Chip::Mt7925,
                2,
                5,
                "67ff85f1a39d1a100a51abd8e2a26edd2f198d7052514b6b8981948b231e5016",
                "329c0e27f780550789e4eba47452731b1723f69f9e67f525d0e50bf3cd2978ac",
            ),
        ] {
            let patch = std::fs::read(root.join(chip.patch_name())).unwrap();
            let ram = std::fs::read(root.join(chip.ram_name())).unwrap();
            use sha2::{Digest, Sha256};
            assert_eq!(alloc::format!("{:x}", Sha256::digest(&patch)), patch_hash);
            assert_eq!(alloc::format!("{:x}", Sha256::digest(&ram)), ram_hash);
            let p = Patch::parse(&patch).unwrap();
            let r = Ram::parse(&ram).unwrap();
            assert_eq!(p.regions().len(), patch_count);
            assert_eq!(r.regions().len(), ram_count);
            assert!(!r.release_information.is_empty());
            assert!(r.regions().iter().any(|r| r.non_download() && r.kind == 2));
        }
    }
}
