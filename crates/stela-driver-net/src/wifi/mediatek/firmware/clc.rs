// SPDX-License-Identifier: BSD-3-Clause-Clear AND ISC
// Copyright (C) 2020-2023 MediaTek Inc.
// Environment ABI: Copyright 2008-2009 Luis R. Rodriguez <mcgrof@qca.qualcomm.com>
// Copyright (C) 2018 Intel Corporation
//! Bounded source CLC country requests. This is a wire plan, never an applied
//! country/power policy, trusted location, command ACK or usable radio.
use super::{
    Chip,
    auxiliary::{Record, Selection},
};
use crate::bytes::le32;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Environment {
    Any = 0,
    Indoor = 1,
    Outdoor = 2,
}
/// Explicit observations consumed by the Connac2 helper. Connac3's helper
/// leaves its ACPI byte zero; these fields do not invent ACPI/SAR permission.
#[derive(Clone, Copy, Debug)]
pub struct Inputs {
    pub alpha2: [u8; 2],
    pub environment: Environment,
    pub chip_capabilities: u64,
    pub power_limits_node: bool,
    pub power_type: u8,
    pub acpi_flags: u8,
    pub mtcl_configuration: u32,
    /// MTCL lookup for the source fallback country00, separately from
    /// the requested country lookup. They may select different ACPI entries.
    pub world_mtcl_configuration: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// Source firmware offers no reply for this C2 command. DMA completion
    /// cannot become an observed CLC reply or invented successful status.
    OneWay,
    Connac2Info,
    /// Generic sequence-matched response; not a station-style status record.
    Connac3Response,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    chip: Chip,
    slot: u8,
    alpha2: [u8; 2],
    environment: Environment,
    fallback: bool,
    body: Vec<u8>,
    completion: Completion,
    /// Source's pending per-rule flags, not an applied-policy receipt.
    pending_channel_flags: Option<u8>,
}
impl Request {
    pub fn chip(&self) -> Chip {
        self.chip
    }
    pub fn slot(&self) -> u8 {
        self.slot
    }
    pub fn alpha2(&self) -> [u8; 2] {
        self.alpha2
    }
    pub fn environment(&self) -> Environment {
        self.environment
    }
    pub fn is_world_fallback(&self) -> bool {
        self.fallback
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn completion(&self) -> Completion {
        self.completion
    }
    pub fn pending_channel_flags(&self) -> Option<u8> {
        self.pending_channel_flags
    }
}
#[derive(Debug)]
pub struct Plan {
    chip: Chip,
    requested_alpha2: [u8; 2],
    requested_environment: Environment,
    requests: Vec<Request>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    MalformedRule { slot: u8, offset: usize },
    SegmentTable { slot: u8 },
    SegmentIndex { slot: u8, index: u8 },
    SegmentRange { slot: u8, index: u8 },
    MissingCountry { slot: u8, requested: [u8; 2] },
    UnsupportedTransfer { slot: u8, bytes: usize },
    TooManyCommands,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek CLC plan: {self:?}")
    }
}
impl core::error::Error for Error {}
impl Plan {
    /// Match source slot order and its explicit "00"/Indoor retry when the
    /// requested country is absent. Fallback is held as a visible fact;
    /// it never broadens hardware/OS/location permissions. No requests
    /// are published until the complete bounded plan validates atomically.
    pub fn build(selection: &Selection<'_>, inputs: Inputs) -> Result<Self, Error> {
        let mut plan = Self {
            chip: selection.chip(),
            requested_alpha2: inputs.alpha2,
            requested_environment: inputs.environment,
            requests: Vec::new(),
        };
        for slot in 0..4 {
            if slot == 3 || (plan.chip == Chip::Mt7925 && slot == 2) {
                continue;
            }
            let Some(record) = selection.records()[slot] else {
                continue;
            };
            let start = plan.requests.len();
            plan.country(record, inputs, false)?;
            if plan.requests.len() == start {
                plan.country(
                    record,
                    Inputs {
                        alpha2: *b"00",
                        environment: Environment::Indoor,
                        mtcl_configuration: inputs.world_mtcl_configuration,
                        ..inputs
                    },
                    true,
                )?;
                if plan.requests.len() == start {
                    return Err(Error::MissingCountry {
                        slot: slot as u8,
                        requested: inputs.alpha2,
                    });
                }
            }
        }
        Ok(plan)
    }
    pub fn chip(&self) -> Chip {
        self.chip
    }
    pub fn requested_alpha2(&self) -> [u8; 2] {
        self.requested_alpha2
    }
    pub fn requested_environment(&self) -> Environment {
        self.requested_environment
    }
    pub fn requests(&self) -> &[Request] {
        &self.requests
    }
    fn country(&mut self, record: Record<'_>, inputs: Inputs, fallback: bool) -> Result<(), Error> {
        if self.chip == Chip::Mt7925 {
            self.connac3(record, inputs, fallback)
        } else {
            self.connac2(record, inputs, fallback)
        }
    }
    fn push(&mut self, request: Request) -> Result<(), Error> {
        if self.requests.len() == 1024 {
            return Err(Error::TooManyCommands);
        }
        self.requests.push(request);
        Ok(())
    }
    fn connac2(&mut self, record: Record<'_>, inputs: Inputs, fallback: bool) -> Result<(), Error> {
        let data = record.payload();
        let mut at = 0;
        let slot = record.index();
        // Exact donor stop condition: the last <=16 bytes are not iterated.
        while data.len() - at > 16 {
            let length = usize::from(u16::from_le_bytes(data[at + 4..at + 6].try_into().unwrap()));
            let end = at + 6 + length;
            if end > data.len() {
                return Err(Error::MalformedRule { slot, offset: at });
            }
            let rule = &data[at..end];
            at = end;
            if rule[..2] != inputs.alpha2 {
                continue;
            }
            let bytes = 76 + length;
            if bytes + 64 > 4096 {
                return Err(Error::UnsupportedTransfer { slot, bytes });
            }
            let mut body = vec![0; bytes];
            body[0] = 1;
            body[2..4].copy_from_slice(&(bytes as u16).to_le_bytes());
            body[4] = slot;
            body[5] = inputs.environment as u8;
            body[6] = inputs.acpi_flags;
            body[7] = u8::from(inputs.chip_capabilities & 1 != 0)
                | u8::from(inputs.power_limits_node) << 1;
            body[8..12].copy_from_slice(&rule[..4]);
            body[12] = inputs.power_type;
            body[13] = inputs.mtcl_configuration as u8; // source u32→u8 field assignment
            body[76..].copy_from_slice(&rule[6..]);
            self.push(Request {
                chip: self.chip,
                slot,
                alpha2: inputs.alpha2,
                environment: inputs.environment,
                fallback,
                body,
                completion: if inputs.chip_capabilities & 1 != 0 {
                    Completion::Connac2Info
                } else {
                    Completion::OneWay
                },
                pending_channel_flags: None,
            })?;
        }
        Ok(())
    }
    fn connac3(&mut self, record: Record<'_>, inputs: Inputs, fallback: bool) -> Result<(), Error> {
        let slot = record.index();
        let data = record.payload();
        let count = record.bytes()[8] as usize;
        let table = count * 16;
        if count == 0 || table > data.len() || data.len() < 8 {
            return Err(Error::SegmentTable { slot });
        }
        let rule_end = le32(data, 4) as usize;
        if rule_end < table || rule_end > data.len() || !(rule_end - table).is_multiple_of(8) {
            return Err(Error::SegmentTable { slot });
        }
        for rule in data[table..rule_end].as_chunks::<8>().0 {
            if rule[..2] != inputs.alpha2 {
                continue;
            }
            let index = rule[4];
            if index == 0 || index as usize > count {
                return Err(Error::SegmentIndex { slot, index });
            }
            let segment = &data[(index as usize - 1) * 16..index as usize * 16];
            let offset = le32(segment, 4) as usize;
            let length = le32(segment, 8) as usize;
            let end = offset
                .checked_add(length)
                .filter(|&end| end <= data.len())
                .ok_or(Error::SegmentRange { slot, index })?;
            let bytes = 84 + length;
            if bytes + 48 > 4096 {
                return Err(Error::UnsupportedTransfer { slot, bytes });
            }
            let mut body = vec![0; bytes];
            body[4..6].copy_from_slice(&3u16.to_le_bytes());
            body[6..8].copy_from_slice(&((bytes - 4) as u16).to_le_bytes());
            body[8] = record.version();
            body[10..12].copy_from_slice(&(length as u16).to_le_bytes());
            body[12] = slot;
            body[13] = inputs.environment as u8;
            body[16..20].copy_from_slice(&rule[..4]);
            body[84..].copy_from_slice(&data[offset..end]);
            self.push(Request {
                chip: self.chip,
                slot,
                alpha2: inputs.alpha2,
                environment: inputs.environment,
                fallback,
                body,
                completion: Completion::Connac3Response,
                pending_channel_flags: Some(if record.version() == 1 { 0xff } else { rule[5] }),
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
