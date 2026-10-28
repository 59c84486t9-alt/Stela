// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Owned non-download resources from the exact accepted RAM image. Selection
//! follows the pinned PCI CLC loaders; parsed facts grant no radio authority.
use super::{Chip, Prepared, RamHeader, Requests};
use alloc::{string::String, vec::Vec};

const CLC_KIND: u8 = 2;
const RECORD_HEADER: usize = 16;
const CLC_SLOTS: usize = 4;

#[derive(Debug)]
pub struct Provenance {
    pub source: String,
    pub revision: String,
    pub member: String,
    pub license: String,
}
#[derive(Debug)]
pub struct Region {
    file_offset: usize,
    address: u32,
    features: u8,
    kind: u8,
    bytes: Vec<u8>,
}
impl Region {
    pub fn file_offset(&self) -> usize {
        self.file_offset
    }
    pub fn address(&self) -> u32 {
        self.address
    }
    pub fn features(&self) -> u8 {
        self.features
    }
    pub fn kind(&self) -> u8 {
        self.kind
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Independent owned bytes and exact source identity, bounded by the prepared
/// image's 16MiB/64-region limits. Retain this owner through every regulatory/
/// capability consumer. It may outlive the Provider; no firmware pointer or
/// provider borrow escapes. This does not prove download or the current epoch.
#[derive(Debug)]
pub struct Auxiliary {
    requests: Requests,
    name: String,
    digest: [u8; 32],
    provenance: Provenance,
    header: RamHeader,
    regions: Vec<Region>,
    release_information: Vec<u8>,
}
impl Prepared<'_> {
    pub fn retain_auxiliary(&self) -> Auxiliary {
        let provenance = self.ram_image.provenance();
        Auxiliary {
            requests: self.requests.clone(),
            name: self.ram_image.name().into(),
            digest: self.ram_image.sha256(),
            provenance: Provenance {
                source: provenance.source.into(),
                revision: provenance.revision.into(),
                member: provenance.member.into(),
                license: provenance.license.into(),
            },
            header: self.ram.header,
            regions: self
                .ram
                .regions()
                .iter()
                .filter(|r| r.non_download())
                .map(|r| Region {
                    file_offset: r.file_offset,
                    address: r.address,
                    features: r.features,
                    kind: r.kind,
                    bytes: r.payload.to_vec(),
                })
                .collect(),
            release_information: self.ram.release_information.to_vec(),
        }
    }
}
impl Auxiliary {
    pub fn requests(&self) -> &Requests {
        &self.requests
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.digest
    }
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }
    pub fn header(&self) -> RamHeader {
        self.header
    }
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }
    pub fn release_information(&self) -> &[u8] {
        &self.release_information
    }

    /// Pure selection using a supplied actual EEPROM byte. This API neither
    /// queries EEPROM nor authenticates the caller's observation. A native
    /// regulatory owner must separately bind the actual read, image, device/
    /// reset/firmware epoch and successful policy commands. Never default a
    /// missing EEPROM byte to zero or infer regulatory authority from a slot.
    pub fn select_clc(&self, eeprom_byte: u8) -> Result<Selection<'_>, Error> {
        let chip = self.requests.chip;
        let encapsulation = eeprom_byte & if chip == Chip::Mt7925 { 3 } else { 1 };
        let region = self.regions.iter().find(|r| r.kind == CLC_KIND);
        let mut selected = Selection {
            chip,
            eeprom_byte,
            encapsulation,
            eeprom_offset: if chip == Chip::Mt7925 { 0xa71 } else { 0x55b },
            region,
            records: [None; CLC_SLOTS],
            stopped_at_unknown: None,
        };
        let Some(region) = region else {
            return Ok(selected);
        };
        let mut offset = 0;
        while offset < region.bytes.len() {
            let remaining = &region.bytes[offset..];
            if remaining.len() < RECORD_HEADER {
                return Err(Error::TruncatedHeader { offset });
            }
            let length = u32::from_le_bytes(remaining[..4].try_into().unwrap()) as usize;
            if length < RECORD_HEADER || length > remaining.len() {
                return Err(Error::RecordLength { offset, length });
            }
            let bytes = &remaining[..length];
            let index = bytes[4] as usize;
            if index >= CLC_SLOTS {
                // Connac2 continues over newer records; Connac3 stops at the
                // first unknown index. Preserve that source distinction.
                if chip == Chip::Mt7925 {
                    selected.stopped_at_unknown = Some(offset);
                    break;
                }
            } else if selected.records[index].is_none() {
                let matches = if chip == Chip::Mt7925 {
                    // Both union offsets are checked by the actual helper
                    // for BE_CTRL; do not simplify this to only t2.type.
                    (index != 2 || bytes[6] & 3 == encapsulation) && bytes[7] & 3 == encapsulation
                } else {
                    index != 0 || bytes[7] & 1 == encapsulation
                };
                if matches {
                    selected.records[index] = Some(Record { offset, bytes });
                }
            }
            offset += length;
        }
        Ok(selected)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    TruncatedHeader { offset: usize },
    RecordLength { offset: usize, length: usize },
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek CLC records: {self:?}")
    }
}
impl core::error::Error for Error {}
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    offset: usize,
    bytes: &'a [u8],
}
impl<'a> Record<'a> {
    pub fn offset(self) -> usize {
        self.offset
    }
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    pub fn index(self) -> u8 {
        self.bytes[4]
    }
    pub fn version(self) -> u8 {
        self.bytes[5]
    }
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[RECORD_HEADER..]
    }
}
#[derive(Debug)]
pub struct Selection<'a> {
    chip: Chip,
    eeprom_byte: u8,
    encapsulation: u8,
    eeprom_offset: u32,
    region: Option<&'a Region>,
    records: [Option<Record<'a>>; CLC_SLOTS],
    stopped_at_unknown: Option<usize>,
}
impl<'a> Selection<'a> {
    pub fn chip(&self) -> Chip {
        self.chip
    }
    pub fn eeprom_byte(&self) -> u8 {
        self.eeprom_byte
    }
    pub fn encapsulation(&self) -> u8 {
        self.encapsulation
    }
    pub fn eeprom_offset(&self) -> u32 {
        self.eeprom_offset
    }
    pub fn region(&self) -> Option<&'a Region> {
        self.region
    }
    /// Slots0..3 are POWER, POWER_EXT, BE_CTRL and REGD respectively. An
    /// absent slot remains absent; no world-country or power fallback exists.
    pub fn records(&self) -> &[Option<Record<'a>>; CLC_SLOTS] {
        &self.records
    }
    pub fn stopped_at_unknown(&self) -> Option<usize> {
        self.stopped_at_unknown
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        Ram,
        tests::{catalog, patch_bytes, requests},
    };
    use super::*;
    extern crate std;

    fn ram(clc: &[u8]) -> Vec<u8> {
        let mut bytes = clc.to_vec();
        bytes.extend_from_slice(b"release-info");
        let mut descriptor = [0; 40];
        descriptor[20..24].copy_from_slice(&(clc.len() as u32).to_le_bytes());
        descriptor[24] = 64;
        descriptor[25] = 2;
        bytes.extend_from_slice(&descriptor);
        let mut trailer = [0; 36];
        trailer[2] = 1;
        trailer[3] = 2;
        bytes.extend_from_slice(&trailer);
        bytes
    }
    fn record(index: u8, type0: u8, type2: u8) -> Vec<u8> {
        let mut bytes = vec![0; 20];
        bytes[..4].copy_from_slice(&20u32.to_le_bytes());
        bytes[4] = index;
        bytes[5] = 7;
        bytes[6] = type2;
        bytes[7] = type0;
        bytes[16..].copy_from_slice(&[9, 8, 7, 6]);
        bytes
    }
    fn retain(chip: Chip, bytes: Vec<u8>) -> Auxiliary {
        let req = requests(chip);
        let catalog = catalog(&req, patch_bytes(), bytes);
        let prepared = req.load(&catalog).unwrap();
        prepared.retain_auxiliary()
        // Provider and Prepared both drop here; all selected data stays owned.
    }
    #[test]
    fn owned_regions_release_and_source_identity_outlive_the_provider() {
        let clc = record(0, 1, 0);
        let bytes = ram(&clc);
        let expected_digest = {
            use sha2::{Digest, Sha256};
            <[u8; 32]>::from(Sha256::digest(&bytes))
        };
        let owner = retain(Chip::Mt7922, bytes);
        assert_eq!(owner.requests(), &requests(Chip::Mt7922));
        assert_eq!(owner.name(), Chip::Mt7922.ram_name());
        assert_eq!(owner.sha256(), expected_digest);
        assert_eq!(owner.provenance().member, owner.name());
        assert_eq!(owner.provenance().license, "LICENCE.mediatek");
        assert_eq!(owner.release_information(), b"release-info");
        assert_eq!(owner.regions().len(), 1);
        assert_eq!(owner.regions()[0].bytes(), clc);
        assert_eq!(owner.regions()[0].features(), 64);
        assert_eq!(owner.regions()[0].file_offset(), 0);
        assert_eq!(owner.regions()[0].address(), 0);
        let selected = owner.select_clc(0xfd).unwrap();
        assert_eq!(selected.eeprom_byte(), 0xfd);
        assert_eq!(selected.encapsulation(), 1);
        assert_eq!(selected.eeprom_offset(), 0x55b);
        assert_eq!(selected.records()[0].unwrap().payload(), &[9, 8, 7, 6]);
        assert!(selected.records()[1..].iter().all(Option::is_none));
    }
    #[test]
    fn source_first_slot_unknown_index_and_both_union_selectors_are_exact() {
        let mut bytes = record(0, 0, 0);
        bytes.extend_from_slice(&record(0, 0, 0));
        bytes.extend_from_slice(&record(9, 0, 0));
        bytes.extend_from_slice(&record(1, 0, 0));
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let owner = retain(chip, ram(&bytes));
            let selected = owner.select_clc(0).unwrap();
            assert_eq!(selected.records()[0].unwrap().offset(), 0);
            if chip == Chip::Mt7925 {
                assert_eq!(selected.stopped_at_unknown(), Some(40));
                assert!(selected.records()[1].is_none());
            } else {
                assert_eq!(selected.records()[1].unwrap().offset(), 60);
                assert_eq!(selected.stopped_at_unknown(), None);
            }
        }
        for type0 in 0..4 {
            for type2 in 0..4 {
                for raw in 0..=255 {
                    let owner = retain(Chip::Mt7925, ram(&record(2, type0, type2)));
                    let selected = owner.select_clc(raw).unwrap();
                    assert_eq!(selected.eeprom_offset(), 0xa71);
                    assert_eq!(
                        selected.records()[2].is_some(),
                        type0 == raw & 3 && type2 == raw & 3
                    );
                }
            }
        }
    }
    #[test]
    fn malformed_record_bounds_refuse_atomically_and_never_publish_partial_slots() {
        for length in 0..16 {
            let owner = retain(Chip::Mt7921, ram(&vec![0; length]));
            if length == 0 {
                assert!(owner.select_clc(0).is_ok());
            } else {
                assert_eq!(
                    owner.select_clc(0).unwrap_err(),
                    Error::TruncatedHeader { offset: 0 }
                );
            }
        }
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for declared in [0, 1, 15, 21, u32::MAX] {
                let mut invalid = record(0, 0, 0);
                invalid[..4].copy_from_slice(&declared.to_le_bytes());
                let owner = retain(chip, ram(&invalid));
                assert!(matches!(
                    owner.select_clc(0),
                    Err(Error::RecordLength { offset: 0, .. })
                ));
                let mut tail = record(1, 0, 0);
                tail.extend_from_slice(&invalid);
                let owner = retain(chip, ram(&tail));
                assert!(matches!(
                    owner.select_clc(0),
                    Err(Error::RecordLength { offset: 20, .. })
                ));
            }
        }
    }
    #[test]
    #[ignore = "oracle: STELA_MT792X_CLC_ORACLE"]
    fn full_linux_clc_loaders_match_selected_bytes_and_owned_auxiliary_resources() {
        let root = std::path::PathBuf::from(std::env::var("STELA_MT792X_CLC_ORACLE").unwrap());
        for (chip, number) in [
            (Chip::Mt7921, 7921),
            (Chip::Mt7922, 7922),
            (Chip::Mt7925, 7925),
        ] {
            let trace = std::fs::read(root.join(alloc::format!("{number}.trace"))).unwrap();
            let mut at = 0;
            for _ in 0..260 {
                let length = u32::from_le_bytes(trace[at..at + 4].try_into().unwrap()) as usize;
                at += 4;
                let raw = trace[at];
                at += 1;
                let image = &trace[at..at + length];
                at += length;
                let parsed = Ram::parse(image).unwrap();
                let owner = retain(chip, image.to_vec());
                assert_eq!(owner.release_information(), parsed.release_information);
                let nondownload: Vec<_> = parsed
                    .regions()
                    .iter()
                    .filter(|r| r.non_download())
                    .collect();
                assert_eq!(owner.regions().len(), nondownload.len());
                for (owned, source) in owner.regions().iter().zip(nondownload) {
                    assert_eq!(owned.file_offset(), source.file_offset);
                    assert_eq!(owned.bytes(), source.payload);
                    assert_eq!(owned.kind(), source.kind);
                    assert_eq!(owned.features(), source.features);
                }
                let selected = owner.select_clc(raw).unwrap();
                for slot in selected.records() {
                    let n = u32::from_le_bytes(trace[at..at + 4].try_into().unwrap()) as usize;
                    at += 4;
                    if n == 0 {
                        assert!(slot.is_none());
                    } else {
                        assert_eq!(slot.unwrap().bytes(), &trace[at..at + n]);
                        at += n;
                    }
                }
            }
            assert_eq!(at, trace.len());
        }
    }
}
