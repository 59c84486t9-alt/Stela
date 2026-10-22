// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2020-2026 Intel Corporation
//! Bare-TLV PNVM and reduced-power SKU selection from pinned fw/{pnvm,uefi}.c.
//! Selection is not calibration, regulatory permission or PNVM upload/ACK.
use super::{firmware::Tlv, identity::Profile};
use alloc::vec::Vec;
use core::ops::Range;
const SKU: u32 = 64;
const HW: u32 = 58;
const VERSION: u32 = 62;
const SECTION: u32 = 19;
const MEM_DESC: u32 = 7;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Size,
    Truncated { offset: usize },
    Limit,
    Length { kind: u32 },
    MissingSku,
    MissingHardware,
    Empty,
    DuplicateVersion,
    UnknownSku,
    NoHardwareMatch,
    MemoryDescriptorSize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkKind {
    SectionMarker(u32),
    /// Retained source metadata, never a host physical/DMA address.
    MemoryDescriptor {
        address: u32,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk<'a> {
    pub kind: ChunkKind,
    pub data: &'a [u8],
    pub tlv_index: usize,
}
#[derive(Clone, Debug)]
struct Group {
    sku: [u32; 3],
    tlvs: Range<usize>,
}
#[derive(Debug)]
pub struct Pnvm<'a> {
    tlvs: Vec<Tlv<'a>>,
    groups: Vec<Group>,
}
#[derive(Debug)]
pub struct Selection<'a> {
    sku: [u32; 3],
    version: Option<u32>,
    hardware: [u16; 2],
    chunks: Vec<Chunk<'a>>,
}
fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().expect("checked word"))
}
/// Reduced-power packages have SKU-scoped MEM_DESC payloads, with no PNVM
/// hardware/version requirement. Actual ALIVE selection remains mandatory.
#[derive(Debug)]
pub struct ReducedPower<'a> {
    pub sku: [u32; 3],
    chunks: Vec<Chunk<'a>>,
}
impl<'a> ReducedPower<'a> {
    pub fn chunks(&self) -> &[Chunk<'a>] {
        &self.chunks
    }
}
fn memory_chunk<'a>(tlv: &Tlv<'a>, index: usize) -> Result<Chunk<'a>, Error> {
    if word(&tlv.data[4..]) as usize != tlv.data.len() - 8 {
        return Err(Error::MemoryDescriptorSize);
    }
    if tlv.data.len() == 8 {
        return Err(Error::Empty);
    }
    Ok(Chunk {
        kind: ChunkKind::MemoryDescriptor {
            address: word(tlv.data),
        },
        data: &tlv.data[8..],
        tlv_index: index,
    })
}
impl<'a> Pnvm<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
            return Err(Error::Size);
        }
        let mut pnvm = Self {
            tlvs: Vec::new(),
            groups: Vec::new(),
        };
        let mut at = 0;
        while at < bytes.len() {
            if pnvm.tlvs.len() == 4096 {
                return Err(Error::Limit);
            }
            let header = bytes
                .get(at..at + 8)
                .ok_or(Error::Truncated { offset: at })?;
            let kind = word(header);
            let len = word(&header[4..]) as usize;
            let aligned = len
                .checked_next_multiple_of(4)
                .ok_or(Error::Truncated { offset: at })?;
            let start = at + 8;
            let end = start
                .checked_add(aligned)
                .filter(|end| *end <= bytes.len())
                .ok_or(Error::Truncated { offset: at })?;
            let data = &bytes[start..start + len];
            let minimum = match kind {
                SKU => 12,
                HW | VERSION | SECTION => 4,
                MEM_DESC => 8,
                _ => 0,
            };
            if len < minimum {
                return Err(Error::Length { kind });
            }
            if kind == SKU {
                if pnvm.groups.len() == 256 {
                    return Err(Error::Limit);
                }
                if let Some(last) = pnvm.groups.last_mut() {
                    last.tlvs.end = pnvm.tlvs.len();
                }
                pnvm.groups.push(Group {
                    sku: [word(data), word(&data[4..]), word(&data[8..])],
                    tlvs: pnvm.tlvs.len() + 1..pnvm.tlvs.len() + 1,
                });
            }
            pnvm.tlvs.push(Tlv {
                kind,
                data,
                padding: &bytes[start + len..end],
                range: at..end,
            });
            at = end;
        }
        if let Some(last) = pnvm.groups.last_mut() {
            last.tlvs.end = pnvm.tlvs.len();
        } else {
            return Err(Error::MissingSku);
        }
        Ok(pnvm)
    }
    pub fn tlvs(&self) -> &[Tlv<'a>] {
        &self.tlvs
    }
    pub fn sku_ids(&self) -> impl Iterator<Item = [u32; 3]> + '_ {
        self.groups.iter().map(|g| g.sku)
    }
    pub fn select_reduced_power(&self, observed_sku: [u32; 3]) -> Result<ReducedPower<'a>, Error> {
        let mut found = false;
        for group in &self.groups {
            if group.sku != observed_sku {
                continue;
            }
            found = true;
            let mut chunks = Vec::new();
            for index in group.tlvs.clone() {
                let tlv = &self.tlvs[index];
                if tlv.kind == MEM_DESC {
                    if chunks.len() == 64 {
                        return Err(Error::Limit);
                    }
                    chunks.push(memory_chunk(tlv, index)?);
                }
            }
            if !chunks.is_empty() {
                return Ok(ReducedPower {
                    sku: observed_sku,
                    chunks,
                });
            }
        }
        Err(if found {
            Error::Empty
        } else {
            Error::UnknownSku
        })
    }
    /// `observed_sku` must be the actual ALIVE notification's three SKU words;
    /// there is no first-board/default/zero-SKU fallback. The eventual transport
    /// must also bind that notification to its current reset/firmware epoch.
    pub fn select(
        &self,
        profile: &Profile,
        observed_sku: [u32; 3],
    ) -> Result<Selection<'a>, Error> {
        let observed = profile.observed();
        let hardware = [
            ((observed.hardware_revision & 0xfff0) >> 4) as u16,
            ((observed.radio_id & 0xfff000) >> 12) as u16,
        ];
        let mut found = false;
        for group in &self.groups {
            if group.sku != observed_sku {
                continue;
            }
            found = true;
            let mut matched = false;
            let mut seen_hw = false;
            let mut version = None;
            let mut chunks = Vec::new();
            for index in group.tlvs.clone() {
                let tlv = &self.tlvs[index];
                match tlv.kind {
                    HW => {
                        seen_hw = true;
                        let actual = [
                            u16::from_le_bytes(tlv.data[..2].try_into().unwrap()),
                            u16::from_le_bytes(tlv.data[2..4].try_into().unwrap()),
                        ];
                        matched |= actual == hardware;
                    }
                    VERSION => {
                        if version.replace(word(tlv.data)).is_some() {
                            return Err(Error::DuplicateVersion);
                        }
                    }
                    SECTION => {
                        let marker = word(tlv.data);
                        if marker == 0xddddeeee {
                            continue;
                        }
                        if chunks.len() == 64 {
                            return Err(Error::Limit);
                        }
                        if tlv.data.len() == 4 {
                            return Err(Error::Empty);
                        }
                        chunks.push(Chunk {
                            kind: ChunkKind::SectionMarker(marker),
                            data: &tlv.data[4..],
                            tlv_index: index,
                        });
                    }
                    MEM_DESC => {
                        if chunks.len() == 64 {
                            return Err(Error::Limit);
                        }
                        chunks.push(memory_chunk(tlv, index)?);
                    }
                    _ => {}
                }
            }
            if !seen_hw {
                return Err(Error::MissingHardware);
            }
            if !matched {
                continue;
            }
            if chunks.is_empty() {
                return Err(Error::Empty);
            }
            return Ok(Selection {
                sku: observed_sku,
                version,
                hardware,
                chunks,
            });
        }
        Err(if found {
            Error::NoHardwareMatch
        } else {
            Error::UnknownSku
        })
    }
}
impl<'a> Selection<'a> {
    pub fn sku(&self) -> [u32; 3] {
        self.sku
    }
    pub fn version(&self) -> Option<u32> {
        self.version
    }
    pub fn hardware(&self) -> [u16; 2] {
        self.hardware
    }
    pub fn chunks(&self) -> &[Chunk<'a>] {
        &self.chunks
    }
}

#[cfg(test)]
mod tests {
    use super::super::identity::Observed;
    use super::*;
    fn profile() -> Profile {
        Profile::select(Observed {
            vendor: 0x8086,
            device: 0x2725,
            subsystem_vendor: 0x8086,
            subsystem_device: 0x84,
            pci_revision: 0x1a,
            hardware_revision: 0x420,
            radio_id: 0x10d000,
        })
        .unwrap()
    }
    fn tlv(out: &mut Vec<u8>, kind: u32, data: &[u8]) {
        out.extend(kind.to_le_bytes());
        out.extend((data.len() as u32).to_le_bytes());
        out.extend(data);
        while !out.len().is_multiple_of(4) {
            out.push(0xee);
        }
    }
    fn fixture() -> Vec<u8> {
        let mut bytes = Vec::new();
        tlv(&mut bytes, 99, &[7, 8, 9]);
        for sku in [1u32, 2] {
            let mut id = sku.to_le_bytes().to_vec();
            id.resize(12, 0);
            tlv(&mut bytes, SKU, &id);
            tlv(&mut bytes, HW, &[0x42, 0, 0x0d, 1, 0, 0, 0, 0]);
            tlv(&mut bytes, VERSION, &[1, 2, 3, 4]);
            tlv(&mut bytes, SECTION, &[0xee, 0xee, 0xdd, 0xdd]);
            tlv(
                &mut bytes,
                SECTION,
                &[0xad, 0xde, 0xfe, 0xca, sku as u8, 20, 30],
            );
        }
        bytes
    }
    #[test]
    fn exact_sku_hardware_borrowed_payload_unknown_metadata_and_legacy_separator() {
        let bytes = fixture();
        let pnvm = Pnvm::parse(&bytes).unwrap();
        assert_eq!(
            pnvm.sku_ids().collect::<Vec<_>>(),
            vec![[1, 0, 0], [2, 0, 0]]
        );
        assert_eq!(pnvm.tlvs()[0].kind, 99);
        assert_eq!(pnvm.tlvs()[0].padding, &[0xee]);
        for sku in [1, 2] {
            let selected = pnvm.select(&profile(), [sku, 0, 0]).unwrap();
            assert_eq!(selected.sku(), [sku, 0, 0]);
            assert_eq!(selected.hardware(), [0x42, 0x10d]);
            assert_eq!(selected.version(), Some(0x04030201));
            assert_eq!(selected.chunks().len(), 1);
            let chunk = selected.chunks()[0];
            assert_eq!(chunk.kind, ChunkKind::SectionMarker(0xcafedead));
            assert_eq!(chunk.data, &[sku as u8, 20, 30]);
            assert_eq!(
                chunk.data.as_ptr(),
                pnvm.tlvs()[chunk.tlv_index].data[4..].as_ptr()
            );
        }
        assert_eq!(
            pnvm.select(&profile(), [0, 0, 0]).unwrap_err(),
            Error::UnknownSku
        );
        assert_eq!(
            pnvm.select(&profile(), [3, 0, 0]).unwrap_err(),
            Error::UnknownSku
        );
        let mut other = fixture();
        let hw = Pnvm::parse(&other)
            .unwrap()
            .tlvs()
            .iter()
            .find(|t| t.kind == HW)
            .unwrap()
            .range
            .start
            + 8;
        other[hw] = 0x34;
        assert_eq!(
            Pnvm::parse(&other)
                .unwrap()
                .select(&profile(), [1, 0, 0])
                .unwrap_err(),
            Error::NoHardwareMatch
        );
    }
    #[test]
    fn every_truncation_malformed_length_memory_descriptor_and_duplicate_version_refuse() {
        let bytes = fixture();
        let pnvm = Pnvm::parse(&bytes).unwrap();
        let boundaries: Vec<_> = pnvm.tlvs().iter().map(|t| t.range.end).collect();
        for end in 0..bytes.len() {
            if !boundaries.contains(&end) {
                assert!(Pnvm::parse(&bytes[..end]).is_err(), "truncation {end}");
            }
        }
        for (kind, length) in [
            (SKU, 11),
            (HW, 3),
            (VERSION, 3),
            (SECTION, 3),
            (MEM_DESC, 7),
        ] {
            let mut bytes = Vec::new();
            tlv(&mut bytes, kind, &vec![0; length]);
            assert!(matches!(Pnvm::parse(&bytes),Err(Error::Length{kind:got}) if got==kind));
        }
        let mut short = vec![0; 8];
        short[..4].copy_from_slice(&SKU.to_le_bytes());
        short[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(Pnvm::parse(&short), Err(Error::Truncated { .. })));
        let mut one = Vec::new();
        tlv(&mut one, SKU, &[0; 12]);
        tlv(&mut one, HW, &[0x42, 0, 0xd, 1]);
        tlv(&mut one, VERSION, &[1, 2, 3, 4]);
        tlv(&mut one, SECTION, &[0, 0, 0, 0, 5]);
        tlv(&mut one, MEM_DESC, &[0; 16]);
        assert_eq!(
            Pnvm::parse(&one)
                .unwrap()
                .select(&profile(), [0; 3])
                .unwrap_err(),
            Error::MemoryDescriptorSize
        );
        let mut duplicate = fixture();
        tlv(&mut duplicate, VERSION, &[1, 2, 3, 4]);
        assert_eq!(
            Pnvm::parse(&duplicate)
                .unwrap()
                .select(&profile(), [2, 0, 0])
                .unwrap_err(),
            Error::DuplicateVersion
        );
    }
    fn memory_fixture() -> Vec<u8> {
        let mut bytes = Vec::new();
        for sku in [1u32, 2] {
            let mut id = sku.to_le_bytes().to_vec();
            id.resize(12, 0);
            tlv(&mut bytes, SKU, &id);
            // Reduced-power has no HW/version gate and ignores SEC_RT payloads.
            tlv(&mut bytes, SECTION, &[0, 0, 0, 0, 0xaa]);
            for address in [0xfffffff0u32, 0x12345678] {
                let mut desc = address.to_le_bytes().to_vec();
                desc.extend(3u32.to_le_bytes());
                desc.extend([sku as u8, 0xaa, 0xbb]);
                tlv(&mut bytes, MEM_DESC, &desc);
            }
        }
        bytes
    }
    #[test]
    fn inline_memory_descriptors_preserve_addresses_and_reduced_power_ignores_pnvm_metadata() {
        let bytes = memory_fixture();
        let parsed = Pnvm::parse(&bytes).unwrap();
        for sku in [1, 2] {
            let selection = parsed.select_reduced_power([sku, 0, 0]).unwrap();
            assert_eq!(selection.sku, [sku, 0, 0]);
            assert_eq!(selection.chunks().len(), 2);
            for (chunk, address) in selection.chunks().iter().zip([0xfffffff0, 0x12345678]) {
                assert_eq!(chunk.kind, ChunkKind::MemoryDescriptor { address });
                assert_eq!(chunk.data, [sku as u8, 0xaa, 0xbb]);
                assert_eq!(
                    chunk.data.as_ptr(),
                    parsed.tlvs()[chunk.tlv_index].data[8..].as_ptr()
                );
            }
        }
        assert_eq!(
            parsed.select_reduced_power([0; 3]).unwrap_err(),
            Error::UnknownSku
        );
        let mut bios = Vec::new();
        tlv(&mut bios, SKU, &[0; 12]);
        tlv(&mut bios, HW, &[0x34, 0, 0x0a, 1]);
        tlv(
            &mut bios,
            MEM_DESC,
            &[0xf0, 0xff, 0xff, 0xff, 1, 0, 0, 0, 0x55],
        );
        let mut observed = profile().observed();
        observed.device = 0x2723;
        observed.hardware_revision = 0x340;
        observed.radio_id = 0x10a000;
        let parsed = Pnvm::parse(&bios).unwrap();
        let selection = parsed
            .select(&Profile::select(observed).unwrap(), [0; 3])
            .unwrap();
        assert_eq!(selection.version(), None);
        assert_eq!(selection.chunks()[0].data, [0x55]);
        for length in [0u32, 2, u32::MAX] {
            let mut bad = bios.clone();
            let at = parsed.tlvs().last().unwrap().range.start + 12;
            bad[at..at + 4].copy_from_slice(&length.to_le_bytes());
            let bad = Pnvm::parse(&bad).unwrap();
            assert_eq!(
                bad.select_reduced_power([0; 3]).unwrap_err(),
                Error::MemoryDescriptorSize
            );
        }
    }
    #[test]
    #[ignore = "requires unchanged Linux UEFI helper trace; see THIRD_PARTY.md"]
    fn unchanged_linux_inline_descriptor_and_reduced_power_oracle() {
        extern crate std;
        use core::fmt::Write;
        use sha2::{Digest, Sha256};
        let trace =
            std::fs::read(std::env::var("STELA_IWLWIFI_UEFI_ORACLE").expect("UEFI trace")).unwrap();
        let digest: alloc::string::String = Sha256::digest(&trace)
            .iter()
            .map(|b| alloc::format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            "4e817e80eba3b908dfb582936cfd6050ffef94f5274dda863ea0a2bd3eddd0f5"
        );
        let bytes = memory_fixture();
        let parsed = Pnvm::parse(&bytes).unwrap();
        let mut actual = alloc::string::String::new();
        for sku in 0..=2 {
            match parsed.select_reduced_power([sku, 0, 0]) {
                Ok(selected) => {
                    writeln!(actual, "case {sku} ok {}", selected.chunks().len()).unwrap();
                    for chunk in selected.chunks() {
                        let ChunkKind::MemoryDescriptor { address } = chunk.kind else {
                            panic!()
                        };
                        let fnv = chunk.data.iter().fold(0xcbf29ce484222325u64, |h, b| {
                            (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
                        });
                        writeln!(actual, "chunk {address:x} {} {fnv:016x}", chunk.data.len())
                            .unwrap();
                    }
                }
                Err(Error::UnknownSku) => writeln!(actual, "case {sku} missing 0").unwrap(),
                other => panic!("unexpected selection {other:?}"),
            }
        }
        for n in 0..=64 {
            let mut bytes = Vec::new();
            tlv(&mut bytes, SKU, &[0; 12]);
            for _ in 0..=n {
                tlv(&mut bytes, MEM_DESC, &[0, 0, 0, 0, 1, 0, 0, 0, 0xaa]);
            }
            match Pnvm::parse(&bytes).unwrap().select_reduced_power([0; 3]) {
                Ok(selected) => {
                    assert_eq!(selected.chunks().len(), n + 1);
                    writeln!(actual, "limit {n} ok {}", n + 1).unwrap();
                }
                Err(Error::Limit) => writeln!(actual, "limit {n} invalid {n}").unwrap(),
                other => panic!("unexpected limit {other:?}"),
            }
        }
        assert_eq!(actual.as_bytes(), trace);
    }
    #[test]
    fn payload_count_and_image_tlv_budgets_are_bounded() {
        let mut bytes = Vec::new();
        tlv(&mut bytes, SKU, &[0; 12]);
        tlv(&mut bytes, HW, &[0x42, 0, 0xd, 1]);
        tlv(&mut bytes, VERSION, &[1, 2, 3, 4]);
        for _ in 0..65 {
            tlv(&mut bytes, SECTION, &[0, 0, 0, 0, 1]);
        }
        assert_eq!(
            Pnvm::parse(&bytes)
                .unwrap()
                .select(&profile(), [0; 3])
                .unwrap_err(),
            Error::Limit
        );
        let mut bytes = fixture();
        for _ in 0..4096 {
            tlv(&mut bytes, 99, &[]);
        }
        assert!(matches!(Pnvm::parse(&bytes), Err(Error::Limit)));
        assert!(matches!(
            Pnvm::parse(&vec![0; 4 * 1024 * 1024 + 1]),
            Err(Error::Size)
        ));
    }

    #[test]
    #[ignore = "requires pinned PNVM asset and unchanged Linux selector trace; see THIRD_PARTY.md"]
    fn actual_ax210_skus_match_unchanged_linux_selector() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let directory = std::env::var("STELA_IWLWIFI_IMAGES").expect("firmware directory");
        let image =
            std::fs::read(std::path::Path::new(&directory).join("iwlwifi-ty-a0-gf-a0.pnvm"))
                .unwrap();
        let hex = |bytes: &[u8]| -> alloc::string::String {
            bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
        };
        assert_eq!(
            hex(&Sha256::digest(&image)),
            "9697e327f8171454b3c19b1ec9449753d5b934d4e91722f469616818a6d477b0"
        );
        let trace =
            std::fs::read(std::env::var("STELA_IWLWIFI_PNVM_ORACLE").expect("PNVM trace")).unwrap();
        assert_eq!(
            hex(&Sha256::digest(&trace)),
            "dd3d1af306e523be4df2fbb19084deb30cb9dbd0e2c22ac985ac0743bd926a08"
        );
        let pnvm = Pnvm::parse(&image).unwrap();
        assert_eq!(pnvm.tlvs().len(), 20);
        assert_eq!(
            pnvm.sku_ids().collect::<Vec<_>>(),
            vec![
                [0x610d0, 0, 0],
                [0x510d0, 0, 0],
                [0x4510d0, 0, 0],
                [0x4610d0, 0, 0]
            ]
        );
        let text = core::str::from_utf8(&trace).unwrap();
        let mut lines = text.lines();
        let mut matches = 0;
        let mut misses = 0;
        while let Some(line) = lines.next() {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert_eq!(fields[0], "case");
            let sku = u32::from_str_radix(fields[1], 16).unwrap();
            match fields[2] {
                "ok" => {
                    let selection = pnvm.select(&profile(), [sku, 0, 0]).unwrap();
                    assert_eq!(
                        selection.version(),
                        Some(u32::from_str_radix(fields[3], 16).unwrap())
                    );
                    assert_eq!(selection.chunks().len(), fields[4].parse().unwrap());
                    for chunk in selection.chunks() {
                        let fields: Vec<_> = lines.next().unwrap().split_whitespace().collect();
                        assert_eq!(fields[0], "chunk");
                        assert_eq!(chunk.data.len(), fields[1].parse().unwrap());
                        let fnv = chunk.data.iter().fold(0xcbf29ce484222325u64, |h, b| {
                            (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
                        });
                        assert_eq!(fnv, u64::from_str_radix(fields[2], 16).unwrap());
                        assert_eq!(
                            chunk.kind,
                            ChunkKind::SectionMarker(u32::from_str_radix(fields[3], 16).unwrap())
                        );
                    }
                    matches += 1;
                }
                "missing" => {
                    assert_eq!(
                        pnvm.select(&profile(), [sku, 0, 0]).unwrap_err(),
                        Error::UnknownSku
                    );
                    misses += 1;
                }
                other => panic!("unexpected source result {other}"),
            }
        }
        assert_eq!(matches, 4);
        assert_eq!(misses, 2);
    }
}
