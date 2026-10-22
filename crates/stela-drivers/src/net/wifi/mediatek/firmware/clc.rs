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
/// leaves its ACPI byte zero; these fields do not invent ACPI/SAR authority.
#[derive(Clone, Copy, Debug)]
pub struct Inputs {
    pub alpha2: [u8; 2],
    pub environment: Environment,
    pub chip_capabilities: u64,
    pub power_limits_node: bool,
    pub power_type: u8,
    pub acpi_flags: u8,
    pub mtcl_configuration: u32,
    /// Actual MTCL lookup for the source fallback country00, separately from
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
    /// Source's pending per-rule flags, not an actual applied-policy receipt.
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
    /// requested country is absent. Fallback is retained as a visible fact;
    /// it never broadens actual hardware/OS/location permissions. No requests
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
            body[13] = inputs.mtcl_configuration as u8; // actual source u32→u8 field assignment
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
mod tests {
    use super::super::{
        auxiliary::Auxiliary,
        tests::{catalog, patch_bytes, requests},
    };
    use super::*;
    extern crate std;
    fn auxiliary_owner(chip: Chip, clc: &[u8]) -> Auxiliary {
        let mut bytes = clc.to_vec();
        let mut descriptor = [0; 40];
        descriptor[20..24].copy_from_slice(&(clc.len() as u32).to_le_bytes());
        descriptor[24] = 64;
        descriptor[25] = 2;
        bytes.extend_from_slice(&descriptor);
        let mut trailer = [0; 36];
        trailer[2] = 1;
        trailer[3] = 2;
        bytes.extend_from_slice(&trailer);
        let req = requests(chip);
        let provider = catalog(&req, patch_bytes(), bytes);
        req.load(&provider).unwrap().retain_auxiliary()
    }
    fn inputs(country: [u8; 2]) -> Inputs {
        Inputs {
            alpha2: country,
            environment: Environment::Outdoor,
            chip_capabilities: 1,
            power_limits_node: false,
            power_type: 2,
            acpi_flags: 0xa5,
            mtcl_configuration: 0x123456aa,
            world_mtcl_configuration: 0x876543bb,
        }
    }
    fn c2(slot: u8, country: &[u8; 2], payload: usize) -> Vec<u8> {
        let mut record = vec![0; 16];
        record[4] = slot;
        record[5] = 1;
        record.extend_from_slice(country);
        record.extend_from_slice(&[7, 9]);
        record.extend_from_slice(&(payload as u16).to_le_bytes());
        record.extend(core::iter::repeat_n(0x5a, payload));
        let length = record.len() as u32;
        record[..4].copy_from_slice(&length.to_le_bytes());
        record
    }
    fn c3() -> Vec<u8> {
        let mut record = vec![0; 16];
        record[4] = 0;
        record[5] = 2;
        record[8] = 1;
        let mut segment = [0; 16];
        segment[0] = 1;
        segment[4..8].copy_from_slice(&24u32.to_le_bytes());
        segment[8..12].copy_from_slice(&20u32.to_le_bytes());
        record.extend_from_slice(&segment);
        record.extend_from_slice(b"US");
        record.extend_from_slice(&[7, 9, 1, 0xa3, 0, 0]);
        record.extend_from_slice(&[0x5a; 20]);
        let length = record.len() as u32;
        record[..4].copy_from_slice(&length.to_le_bytes());
        record
    }
    #[test]
    fn world_retry_is_explicit_with_separate_mtcl_and_no_invented_ack() {
        let bytes = c2(0, b"00", 20);
        let owner = auxiliary_owner(Chip::Mt7921, &bytes);
        let selection = owner.select_clc(0).unwrap();
        let mut input = inputs(*b"ZZ");
        input.chip_capabilities = 0;
        let plan = Plan::build(&selection, input).unwrap();
        assert_eq!(plan.requested_alpha2(), *b"ZZ");
        assert_eq!(plan.requested_environment(), Environment::Outdoor);
        let request = &plan.requests()[0];
        assert_eq!(request.alpha2(), *b"00");
        assert_eq!(request.environment(), Environment::Indoor);
        assert!(request.is_world_fallback());
        assert_eq!(request.body()[13], 0xbb);
        assert_eq!(request.completion(), Completion::OneWay);
        assert_eq!(request.pending_channel_flags(), None);
        let owner = owner_without_country();
        let selection = owner.select_clc(0).unwrap();
        assert_eq!(
            Plan::build(&selection, inputs(*b"ZZ")).unwrap_err(),
            Error::MissingCountry {
                slot: 0,
                requested: *b"ZZ"
            }
        );
    }
    fn owner_without_country() -> Auxiliary {
        auxiliary_owner(Chip::Mt7921, &c2(0, b"US", 20))
    }
    #[test]
    fn source_c2_short_tail_is_not_a_rule_and_later_malformed_rule_is_atomic() {
        // The donor's >16-byte loop intentionally never consumes this valid
        // six-byte rule header with ten bytes of data.
        let owner = auxiliary_owner(Chip::Mt7922, &c2(0, b"US", 10));
        let selection = owner.select_clc(0).unwrap();
        assert!(matches!(
            Plan::build(&selection, inputs(*b"US")),
            Err(Error::MissingCountry { .. })
        ));
        let mut bytes = c2(0, b"US", 20);
        let mut malformed = c2(0, b"US", 20)[16..].to_vec();
        malformed[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
        bytes.extend_from_slice(&malformed);
        let length = bytes.len() as u32;
        bytes[..4].copy_from_slice(&length.to_le_bytes());
        let owner = auxiliary_owner(Chip::Mt7921, &bytes);
        let selection = owner.select_clc(0).unwrap();
        assert!(matches!(
            Plan::build(&selection, inputs(*b"US")),
            Err(Error::MalformedRule { offset: 26, .. })
        ));
    }
    #[test]
    fn c3_tables_indices_ranges_and_current_transport_limits_refuse_atomically() {
        let bytes = c3();
        let owner = auxiliary_owner(Chip::Mt7925, &bytes);
        let selection = owner.select_clc(0).unwrap();
        let plan = Plan::build(&selection, inputs(*b"US")).unwrap();
        let request = &plan.requests()[0];
        assert_eq!(request.body().len(), 104);
        assert_eq!(request.pending_channel_flags(), Some(0xa3));
        assert_eq!(request.body()[14], 0);
        for index in [0, 2, 255] {
            let mut malformed = bytes.clone();
            malformed[36] = index;
            let owner = auxiliary_owner(Chip::Mt7925, &malformed);
            let selection = owner.select_clc(0).unwrap();
            assert!(matches!(
                Plan::build(&selection, inputs(*b"US")),
                Err(Error::SegmentIndex { .. })
            ));
        }
        for end in [0u32, 15, 17, 23, 25, u32::MAX] {
            let mut malformed = bytes.clone();
            malformed[20..24].copy_from_slice(&end.to_le_bytes());
            let owner = auxiliary_owner(Chip::Mt7925, &malformed);
            let selection = owner.select_clc(0).unwrap();
            assert!(matches!(
                Plan::build(&selection, inputs(*b"US")),
                Err(Error::SegmentTable { .. })
            ));
        }
        let mut malformed = bytes.clone();
        malformed[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        let owner = auxiliary_owner(Chip::Mt7925, &malformed);
        let selection = owner.select_clc(0).unwrap();
        assert!(matches!(
            Plan::build(&selection, inputs(*b"US")),
            Err(Error::SegmentRange { .. })
        ));
        let owner = auxiliary_owner(Chip::Mt7921, &c2(0, b"US", 4000));
        let selection = owner.select_clc(0).unwrap();
        assert!(matches!(
            Plan::build(&selection, inputs(*b"US")),
            Err(Error::UnsupportedTransfer { .. })
        ));
        let mut repeated = Vec::new();
        for _ in 0..1025 {
            repeated.extend_from_slice(&c2(0, b"US", 20)[16..]);
        }
        let mut bytes = c2(0, b"US", 20)[..16].to_vec();
        bytes.extend_from_slice(&repeated);
        let length = bytes.len() as u32;
        bytes[..4].copy_from_slice(&length.to_le_bytes());
        let owner = auxiliary_owner(Chip::Mt7921, &bytes);
        let selection = owner.select_clc(0).unwrap();
        assert_eq!(
            Plan::build(&selection, inputs(*b"US")).unwrap_err(),
            Error::TooManyCommands
        );
    }
    #[test]
    #[ignore = "requires full unchanged loaders/country helpers and actual firmware oracle"]
    fn complete_linux_country_helpers_match_every_request_and_fallback_fact() {
        let root =
            std::path::PathBuf::from(std::env::var("STELA_MT792X_CLC_COUNTRY_ORACLE").unwrap());
        for (chip, number) in [
            (Chip::Mt7921, 7921),
            (Chip::Mt7922, 7922),
            (Chip::Mt7925, 7925),
        ] {
            let trace = std::fs::read(root.join(alloc::format!("{number}.trace"))).unwrap();
            let mut at = 0;
            for _ in 0..108 {
                let meta = &trace[at..at + 23];
                at += 23;
                let n = le32(&trace, at) as usize;
                at += 4;
                let owner = auxiliary_owner(chip, &trace[at..at + n]);
                at += n;
                let selection = owner.select_clc(meta[0]).unwrap();
                let input = Inputs {
                    alpha2: meta[1..3].try_into().unwrap(),
                    environment: match meta[3] {
                        0 => Environment::Any,
                        1 => Environment::Indoor,
                        2 => Environment::Outdoor,
                        _ => panic!("source environment"),
                    },
                    acpi_flags: meta[4],
                    power_type: meta[5],
                    power_limits_node: meta[6] != 0,
                    chip_capabilities: u64::from_le_bytes(meta[7..15].try_into().unwrap()),
                    mtcl_configuration: le32(meta, 15),
                    world_mtcl_configuration: le32(meta, 19),
                };
                let plan = Plan::build(&selection, input).unwrap();
                let count = usize::from(u16::from_le_bytes(trace[at..at + 2].try_into().unwrap()));
                at += 2;
                assert_eq!(plan.requests().len(), count);
                for request in plan.requests() {
                    let command = le32(&trace, at);
                    let wait = trace[at + 4] != 0;
                    let flags = trace[at + 5];
                    let n = usize::from(u16::from_le_bytes(
                        trace[at + 6..at + 8].try_into().unwrap(),
                    ));
                    at += 8;
                    assert_eq!(
                        command,
                        if chip == Chip::Mt7925 {
                            (1 << 17) | 0x2c
                        } else {
                            (1 << 18) | 0x5c
                        }
                    );
                    assert_eq!(request.body(), &trace[at..at + n]);
                    at += n;
                    assert_eq!(wait, request.completion() != Completion::OneWay);
                    if chip == Chip::Mt7925 {
                        assert_eq!(request.pending_channel_flags(), Some(flags));
                    }
                    assert_eq!(
                        request.is_world_fallback(),
                        request.alpha2() != input.alpha2
                    );
                    assert_eq!(
                        request.environment(),
                        if request.is_world_fallback() {
                            Environment::Indoor
                        } else {
                            input.environment
                        }
                    );
                }
            }
            assert_eq!(at, trace.len());
        }
    }

    #[test]
    #[ignore = "requires full country-helper/MCU-writer composed source oracle"]
    fn exact_country_requests_cross_complete_source_mcu_writers() {
        let root = std::path::PathBuf::from(std::env::var("STELA_MT792X_CLC_WIRE_ORACLE").unwrap());
        for (chip, number) in [
            (Chip::Mt7921, 7921),
            (Chip::Mt7922, 7922),
            (Chip::Mt7925, 7925),
        ] {
            let country =
                std::fs::read(root.join(alloc::format!("country/{number}.trace"))).unwrap();
            let wire = std::fs::read(root.join(alloc::format!("{number}.trace"))).unwrap();
            let mut encoder = crate::net::wifi::mediatek::mcu::Encoder::default();
            let mut at = 0;
            let mut wire_at = 0;
            for _ in 0..108 {
                let meta = &country[at..at + 23];
                at += 23;
                let n = le32(&country, at) as usize;
                at += 4;
                let owner = auxiliary_owner(chip, &country[at..at + n]);
                at += n;
                let selection = owner.select_clc(meta[0]).unwrap();
                let input = Inputs {
                    alpha2: meta[1..3].try_into().unwrap(),
                    environment: match meta[3] {
                        0 => Environment::Any,
                        1 => Environment::Indoor,
                        2 => Environment::Outdoor,
                        _ => panic!("source environment"),
                    },
                    acpi_flags: meta[4],
                    power_type: meta[5],
                    power_limits_node: meta[6] != 0,
                    chip_capabilities: u64::from_le_bytes(meta[7..15].try_into().unwrap()),
                    mtcl_configuration: le32(meta, 15),
                    world_mtcl_configuration: le32(meta, 19),
                };
                let plan = Plan::build(&selection, input).unwrap();
                let count =
                    usize::from(u16::from_le_bytes(country[at..at + 2].try_into().unwrap()));
                at += 2;
                assert_eq!(plan.requests().len(), count);
                for request in plan.requests() {
                    let n = usize::from(u16::from_le_bytes(
                        country[at + 6..at + 8].try_into().unwrap(),
                    ));
                    at += 8 + n;
                    let packet = encoder.encode_clc(request);
                    assert_eq!(packet.chip(), chip);
                    assert_eq!(packet.completion(), request.completion());
                    let n = usize::from(u16::from_le_bytes(
                        wire[wire_at..wire_at + 2].try_into().unwrap(),
                    ));
                    wire_at += 2;
                    assert_eq!(packet.bytes(), &wire[wire_at..wire_at + n]);
                    wire_at += n;
                }
            }
            assert_eq!(at, country.len());
            assert_eq!(wire_at, wire.len());
        }
    }
}
