// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2020-2026 Intel Corporation
//! Bare-TLV PNVM and reduced-power SKU selection from pinned fw/{pnvm,uefi}.c.
//! Selection is not calibration, regulatory permission or PNVM upload/ACK.
use super::{firmware::Tlv, identity::Profile};
use crate::bytes::le32;
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
    /// Source metadata, never a host physical/DMA address.
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
/// Reduced-power packages have SKU-scoped MEM_DESC payloads, with no PNVM
/// hardware/version requirement. ALIVE selection remains mandatory.
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
    if le32(tlv.data, 4) as usize != tlv.data.len() - 8 {
        return Err(Error::MemoryDescriptorSize);
    }
    if tlv.data.len() == 8 {
        return Err(Error::Empty);
    }
    Ok(Chunk {
        kind: ChunkKind::MemoryDescriptor {
            address: le32(tlv.data, 0),
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
            let kind = le32(header, 0);
            let len = le32(header, 4) as usize;
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
                    sku: [le32(data, 0), le32(data, 4), le32(data, 8)],
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
    /// `observed_sku` must be the ALIVE notification's three SKU words;
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
                        if version.replace(le32(tlv.data, 0)).is_some() {
                            return Err(Error::DuplicateVersion);
                        }
                    }
                    SECTION => {
                        let marker = le32(tlv.data, 0);
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
mod tests;
