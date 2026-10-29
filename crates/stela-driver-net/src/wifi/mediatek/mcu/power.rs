// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
// Copyright (C) 2020-2023 MediaTek Inc.
//! Source SAR arithmetic, rate-SKU placement and complete per-band wire batches.
//! Explicit resolved inputs are data, not trusted platform/OS power permission.
use super::{Encoder, Event};
use crate::wifi::{Band, mediatek::identity::Chip};
use alloc::vec::Vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Half-dBm values already resolved against per-rate board, SAR,
    /// regulatory, chain and requested-power constraints. No absent-data default.
    pub cck: [i8; 4],
    pub ofdm: [i8; 8],
    pub mcs: [[i8; 10]; 4],
    pub ru: [[i8; 12]; 7],
    pub eht: [[i8; 16]; 16],
}
impl Limits {
    /// Explicit uniform data, matching the source no-DTS resolution only when
    /// its real input permission proves that condition. No permission
    /// or missing-power fallback is created by this pure constructor.
    pub fn uniform(half_dbm: i8) -> Self {
        Self {
            cck: [half_dbm; 4],
            ofdm: [half_dbm; 8],
            mcs: [[half_dbm; 10]; 4],
            ru: [[half_dbm; 12]; 7],
            eht: [[half_dbm; 16]; 16],
        }
    }
    pub fn sku(&self, chip: Chip, band: Band) -> Vec<u8> {
        let c3 = chip == Chip::Mt7925;
        // Source127 is only protocol padding for unpopulated/unused rate slots.
        // It is never substituted for a missing requested or permitted power.
        let mut out = vec![127; if c3 { 449 } else { 161 }];
        let copy = |out: &mut [u8], at: usize, values: &[i8]| {
            for (dest, value) in out[at..at + values.len()].iter_mut().zip(values) {
                *dest = *value as u8;
            }
        };
        if band == Band::Ghz2 {
            copy(&mut out, 0, &self.cck);
        }
        copy(&mut out, 4, &self.ofdm);
        let mut at = if c3 { 44 } else { 12 };
        for mcs in &self.mcs[..2] {
            copy(&mut out, at, &mcs[..8]);
            at += 8;
        }
        out[at] = self.mcs[0][0] as u8;
        at += 1;
        for mcs in &self.mcs {
            copy(&mut out, at, mcs);
            at += 12;
        }
        for ru in &self.ru {
            copy(&mut out, at, ru);
            at += 12;
        }
        if c3 {
            for eht in &self.eht {
                copy(&mut out, at, eht);
                at += 16;
            }
        }
        debug_assert_eq!(at, out.len());
        out
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SarRange {
    pub start_mhz: u32,
    pub end_mhz: u32,
    /// Source cfg80211 SAR input unit is quarter-dBm, converted by signed >>1.
    pub quarter_dbm: i32,
}
/// Match the source first configured half-open MHz range and signed quarter→
/// half-dBm conversion. Invalid ranges/out-of-range source127 fallback refuse
/// explicitly; they never become a permissive native power default. An empty
/// resolved range list is data only, not proof that platform SAR is absent.
pub fn sar_limit(
    power_half_dbm: i16,
    frequency_mhz: u32,
    ranges: &[Option<SarRange>],
) -> Result<i8, Error> {
    let power = i8::try_from(power_half_dbm)
        .ok()
        .filter(|&p| p != i8::MIN)
        .ok_or(Error::PowerRange)?;
    for range in ranges.iter().flatten() {
        if range.start_mhz >= range.end_mhz {
            return Err(Error::SarRange);
        }
        let limit = range.quarter_dbm >> 1;
        if !(-127..=127).contains(&limit) {
            return Err(Error::PowerRange);
        }
    }
    for range in ranges.iter().flatten() {
        if frequency_mhz >= range.start_mhz && frequency_mhz < range.end_mhz {
            return Ok(power.min((range.quarter_dbm >> 1) as i8));
        }
    }
    Ok(power)
}
#[derive(Clone, Debug)]
pub struct Channel {
    pub hardware_value: u8,
    pub limits: Limits,
}
pub struct Inputs<'a> {
    pub alpha2: [u8; 2],
    /// None means this band is excluded from the source plan;
    /// capability/CLC/trusted policy must prove that choice separately.
    pub ghz2: Option<&'a [Channel]>,
    pub ghz5: Option<&'a [Channel]>,
    pub ghz6: Option<&'a [Channel]>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    PowerRange,
    SarRange,
    Channels {
        band: Band,
        expected: usize,
        actual: usize,
    },
    ChannelOrder {
        band: Band,
        index: usize,
        expected: u8,
        actual: u8,
    },
    OneWayCommand,
    Event(super::Error),
    TruncatedFlush,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek SAR/rate power: {self:?}")
    }
}
impl core::error::Error for Error {}
const CH2: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
const CH5_C2: &[u8] = &[
    36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 110, 112,
    114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155,
    157, 159, 161, 165, 169, 173, 177,
];
const CH5_C3: &[u8] = &[
    36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 110, 112,
    114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155,
    157, 159, 161, 165, 167,
];
const CH6: &[u8] = &[
    1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 33, 35, 37, 39, 41, 43, 45, 47, 49, 51,
    53, 55, 57, 59, 61, 65, 67, 69, 71, 73, 75, 77, 79, 81, 83, 85, 87, 89, 91, 93, 97, 99, 101,
    103, 105, 107, 109, 111, 113, 115, 117, 119, 121, 123, 125, 129, 131, 133, 135, 137, 139, 141,
    143, 145, 147, 149, 151, 153, 155, 157, 161, 163, 165, 167, 169, 171, 173, 175, 177, 179, 181,
    183, 185, 187, 189, 193, 195, 197, 199, 201, 203, 205, 207, 209, 211, 213, 215, 217, 219, 221,
    225, 227, 229, 233,
];
pub fn channels(chip: Chip, band: Band) -> &'static [u8] {
    match band {
        Band::Ghz2 => CH2,
        Band::Ghz5 => {
            if chip == Chip::Mt7925 {
                CH5_C3
            } else {
                CH5_C2
            }
        }
        Band::Ghz6 => CH6,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    RatePower,
    PseFlush,
}
#[derive(Debug)]
pub struct Request {
    chip: Chip,
    kind: Kind,
    body: Vec<u8>,
}
impl Request {
    pub fn chip(&self) -> Chip {
        self.chip
    }
    pub fn kind(&self) -> Kind {
        self.kind
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn expects_response(&self) -> bool {
        self.chip == Chip::Mt7925 || self.kind == Kind::PseFlush
    }
}
#[derive(Debug)]
pub struct Plan {
    chip: Chip,
    alpha2: [u8; 2],
    bands: [bool; 3],
    requests: Vec<Request>,
}
impl Plan {
    pub fn build(chip: Chip, input: Inputs<'_>) -> Result<Self, Error> {
        let bands = [
            (Band::Ghz2, input.ghz2),
            (Band::Ghz5, input.ghz5),
            (Band::Ghz6, input.ghz6),
        ];
        for (band, provided) in bands {
            if let Some(provided) = provided {
                let expected = channels(chip, band);
                if provided.len() != expected.len() {
                    return Err(Error::Channels {
                        band,
                        expected: expected.len(),
                        actual: provided.len(),
                    });
                }
                for (index, (given, &wanted)) in provided.iter().zip(expected).enumerate() {
                    if given.hardware_value != wanted {
                        return Err(Error::ChannelOrder {
                            band,
                            index,
                            expected: wanted,
                            actual: given.hardware_value,
                        });
                    }
                }
            }
        }
        let c3 = chip == Chip::Mt7925;
        let mut requests = Vec::new();
        let last = bands
            .iter()
            .rev()
            .find_map(|(band, provided)| provided.map(|_| *channels(chip, *band).last().unwrap()));
        for (band, provided) in bands {
            let Some(provided) = provided else {
                continue;
            };
            for batch in provided.chunks(if c3 { 3 } else { 8 }) {
                let mut body = vec![0; if c3 { 52 } else { 44 }];
                let offset = if c3 { 8 } else { 0 };
                body[offset + 4] = batch.len() as u8;
                body[offset + 5] = match band {
                    Band::Ghz2 => 1,
                    Band::Ghz5 => 2,
                    Band::Ghz6 => 3,
                };
                body[offset + 6] = u8::from(
                    Some(batch.last().unwrap().hardware_value)
                        == if c3 {
                            channels(chip, band).last().copied()
                        } else {
                            last
                        },
                );
                body[offset + 8..offset + 10].copy_from_slice(&input.alpha2);
                for entry in batch {
                    body.push(entry.hardware_value);
                    body.extend_from_slice(&entry.limits.sku(chip, band));
                }
                if c3 {
                    body[4..6].copy_from_slice(&1u16.to_le_bytes());
                    let n = (body.len() - 4) as u16;
                    body[6..8].copy_from_slice(&n.to_le_bytes());
                }
                requests.push(Request {
                    chip,
                    kind: Kind::RatePower,
                    body,
                });
                if !c3 {
                    requests.push(Request {
                        chip,
                        kind: Kind::PseFlush,
                        body: [0x820c8000u32.to_le_bytes(), 0u32.to_le_bytes()].concat(),
                    });
                }
            }
        }
        Ok(Self {
            chip,
            alpha2: input.alpha2,
            bands: [
                input.ghz2.is_some(),
                input.ghz5.is_some(),
                input.ghz6.is_some(),
            ],
            requests,
        })
    }
    pub fn chip(&self) -> Chip {
        self.chip
    }
    pub fn alpha2(&self) -> [u8; 2] {
        self.alpha2
    }
    pub fn bands(&self) -> [bool; 3] {
        self.bands
    }
    pub fn requests(&self) -> &[Request] {
        &self.requests
    }
}
pub struct Packet {
    chip: Chip,
    kind: Kind,
    sequence: u8,
    bytes: Vec<u8>,
}
impl Packet {
    pub fn chip(&self) -> Chip {
        self.chip
    }
    pub fn kind(&self) -> Kind {
        self.kind
    }
    pub fn sequence(&self) -> u8 {
        self.sequence
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn expects_response(&self) -> bool {
        self.chip == Chip::Mt7925 || self.kind == Kind::PseFlush
    }
}
impl Encoder {
    pub fn encode_power(&mut self, request: &Request) -> Packet {
        let c3 = request.chip == Chip::Mt7925;
        let header = if c3 { 48 } else { 64 };
        let sequence = self.next_sequence();
        let length = header + request.body.len();
        let mut bytes = vec![0; length];
        bytes[..4].copy_from_slice(&(length as u32 | (2 << 23) | (0x20 << 25)).to_le_bytes());
        bytes[4..8].copy_from_slice(&(1u32 << 16 | if c3 { 0 } else { 1 << 31 }).to_le_bytes());
        bytes[32..34].copy_from_slice(&((length - 32) as u16).to_le_bytes());
        bytes[37] = 0xa0;
        bytes[39] = sequence;
        if c3 {
            bytes[34..36].copy_from_slice(&0x2cu16.to_le_bytes());
            bytes[43] = 7;
        } else {
            bytes[34..36].copy_from_slice(&0x8000u16.to_le_bytes());
            bytes[36] = if request.kind == Kind::PseFlush {
                0xc0
            } else {
                0x5d
            };
            bytes[38] = u8::from(request.kind != Kind::PseFlush);
        }
        bytes[header..].copy_from_slice(request.body());
        Packet {
            chip: request.chip,
            kind: request.kind,
            sequence,
            bytes,
        }
    }
}
impl Event<'_> {
    pub fn power_payload<'a>(&'a self, packet: &Packet) -> Result<&'a [u8], Error> {
        if !packet.expects_response() {
            return Err(Error::OneWayCommand);
        }
        if self.unsolicited || self.sequence == 0 {
            return Err(Error::Event(super::Error::Unsolicited));
        }
        if self.sequence != packet.sequence {
            return Err(Error::Event(super::Error::UnexpectedSequence {
                expected: packet.sequence,
                actual: self.sequence,
            }));
        }
        Ok(self.payload)
    }
}
pub fn flush_value(body: &[u8]) -> Result<(u32, u32), Error> {
    if body.len() < 8 {
        return Err(Error::TruncatedFlush);
    }
    Ok((
        u32::from_le_bytes(body[..4].try_into().unwrap()),
        u32::from_le_bytes(body[4..8].try_into().unwrap()),
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    extern crate std;

    pub(crate) struct Wire {
        pub command: u32,
        pub wait: bool,
        pub body: Vec<u8>,
        pub packet: Vec<u8>,
    }
    pub(crate) struct Source {
        pub alpha2: [u8; 2],
        pub bands: [Vec<Channel>; 3],
        pub wire: Vec<Wire>,
        pub hardware_bands: [bool; 3],
        pub clc_nonzero: bool,
    }
    impl Source {
        pub fn inputs(&self) -> Inputs<'_> {
            Inputs {
                alpha2: self.alpha2,
                ghz2: (!self.bands[0].is_empty()).then_some(self.bands[0].as_slice()),
                ghz5: (!self.bands[1].is_empty()).then_some(self.bands[1].as_slice()),
                ghz6: (!self.bands[2].is_empty()).then_some(self.bands[2].as_slice()),
            }
        }
    }
    fn word16(bytes: &[u8], at: &mut usize) -> usize {
        let n = usize::from(u16::from_le_bytes(bytes[*at..*at + 2].try_into().unwrap()));
        *at += 2;
        n
    }
    pub(crate) fn sources(root: &std::path::Path, chip: Chip) -> Vec<Source> {
        let number = match chip {
            Chip::Mt7921 => 7921,
            Chip::Mt7922 => 7922,
            Chip::Mt7925 => 7925,
        };
        let limits = std::fs::read(root.join(alloc::format!("{number}.limits"))).unwrap();
        let wire = std::fs::read(root.join(alloc::format!("{number}.trace"))).unwrap();
        let (mut at, mut wt) = (0, 0);
        let mut out = Vec::new();
        for case in 0..24 {
            let counts: [usize; 3] = core::array::from_fn(|_| word16(&limits, &mut at));
            let alpha2 = limits[at..at + 2].try_into().unwrap();
            at += 2;
            let mut bands: [Vec<Channel>; 3] = core::array::from_fn(|_| Vec::new());
            for (band, &count) in counts.iter().enumerate() {
                for _ in 0..count {
                    let channel = limits[at];
                    assert_eq!(limits[at + 1], [0, 1, 3][band]);
                    at += 2;
                    let mut take = |n: usize| {
                        let values = limits[at..at + n]
                            .iter()
                            .map(|&n| n as i8)
                            .collect::<Vec<_>>();
                        at += n;
                        values
                    };
                    let cck = take(4).try_into().unwrap();
                    let ofdm = take(8).try_into().unwrap();
                    let mcs = core::array::from_fn(|_| take(10).try_into().unwrap());
                    let ru = core::array::from_fn(|_| take(12).try_into().unwrap());
                    let eht = core::array::from_fn(|_| take(16).try_into().unwrap());
                    bands[band].push(Channel {
                        hardware_value: channel,
                        limits: Limits {
                            cck,
                            ofdm,
                            mcs,
                            ru,
                            eht,
                        },
                    });
                }
            }
            let count = word16(&wire, &mut wt);
            let mut packets = Vec::new();
            for _ in 0..count {
                let command = u32::from_le_bytes(wire[wt..wt + 4].try_into().unwrap());
                let wait = wire[wt + 4] != 0;
                wt += 5;
                let n = word16(&wire, &mut wt);
                let mut body = wire[wt..wt + n].to_vec();
                wt += n;
                let n = word16(&wire, &mut wt);
                let mut packet = wire[wt..wt + n].to_vec();
                wt += n;
                if chip == Chip::Mt7925 {
                    // These source heap-header fields are unwritten;
                    // canary allocation exposes them. Native zeroes
                    // them, preserving all source-defined bytes exactly.
                    for range in [0..4, 8..12, 15..16, 18..52] {
                        assert!(body[range.clone()].iter().all(|&b| b == 0x5a));
                        body[range.clone()].fill(0);
                        packet[48 + range.start..48 + range.end].fill(0);
                    }
                }
                packets.push(Wire {
                    command,
                    wait,
                    body,
                    packet,
                });
            }
            out.push(Source {
                alpha2,
                bands,
                wire: packets,
                hardware_bands: {
                    let mask = 1 + case % 7;
                    [mask & 1 != 0, mask & 2 != 0, mask & 4 != 0]
                },
                clc_nonzero: case % 4 != 0,
            });
        }
        assert_eq!(at, limits.len());
        assert_eq!(wt, wire.len());
        out
    }
    #[test]
    fn sar_signed_units_first_configured_half_open_range_and_invalid_fallback_refusal() {
        let ranges = [
            None,
            Some(SarRange {
                start_mhz: 2400,
                end_mhz: 2500,
                quarter_dbm: -3,
            }),
            Some(SarRange {
                start_mhz: 2400,
                end_mhz: 2600,
                quarter_dbm: -30,
            }),
        ];
        assert_eq!(sar_limit(20, 2399, &ranges), Ok(20));
        assert_eq!(sar_limit(20, 2400, &ranges), Ok(-2));
        assert_eq!(sar_limit(20, 2499, &ranges), Ok(-2));
        assert_eq!(sar_limit(20, 2500, &ranges), Ok(-15));
        assert_eq!(sar_limit(20, 2600, &ranges), Ok(20));
        assert_eq!(sar_limit(-50, 2400, &ranges), Ok(-50));
        assert_eq!(sar_limit(-128, 2400, &ranges), Err(Error::PowerRange));
        assert_eq!(sar_limit(128, 2400, &ranges), Err(Error::PowerRange));
        assert_eq!(
            sar_limit(
                20,
                2400,
                &[Some(SarRange {
                    start_mhz: 2400,
                    end_mhz: 2500,
                    quarter_dbm: -255
                })]
            ),
            Err(Error::PowerRange)
        );
        assert_eq!(
            sar_limit(
                20,
                2400,
                &[Some(SarRange {
                    start_mhz: 2500,
                    end_mhz: 2400,
                    quarter_dbm: 0
                })]
            ),
            Err(Error::SarRange)
        );
        let mut invalid_later = ranges.to_vec();
        invalid_later.push(Some(SarRange {
            start_mhz: 2500,
            end_mhz: 2400,
            quarter_dbm: 0,
        }));
        assert_eq!(sar_limit(20, 2400, &invalid_later), Err(Error::SarRange));
    }
    #[test]
    fn exact_fixed_channel_counts_order_and_flush_payload_bounds_refuse_before_publication() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut entries: Vec<_> = channels(chip, Band::Ghz2)
                .iter()
                .map(|&hardware_value| Channel {
                    hardware_value,
                    limits: Limits::uniform(-2),
                })
                .collect();
            entries[1].hardware_value = 0;
            assert!(matches!(
                Plan::build(
                    chip,
                    Inputs {
                        alpha2: *b"US",
                        ghz2: Some(&entries),
                        ghz5: None,
                        ghz6: None
                    }
                ),
                Err(Error::ChannelOrder { index: 1, .. })
            ));
            assert!(matches!(
                Plan::build(
                    chip,
                    Inputs {
                        alpha2: *b"US",
                        ghz2: Some(&entries[..13]),
                        ghz5: None,
                        ghz6: None
                    }
                ),
                Err(Error::Channels {
                    expected: 14,
                    actual: 13,
                    ..
                })
            ));
        }
        for n in 0..8 {
            assert_eq!(flush_value(&vec![0; n]), Err(Error::TruncatedFlush));
        }
        assert_eq!(
            flush_value(&[0, 128, 12, 130, 255, 255, 255, 255, 0xaa]),
            Ok((0x820c8000, 0xffff_ffff))
        );
    }
    #[test]
    #[ignore = "oracle: STELA_MT792X_POWER_ORACLE"]
    fn complete_source_sar_arithmetic_and_all_rate_batches_match_defined_bytes() {
        let root = std::path::PathBuf::from(std::env::var("STELA_MT792X_POWER_ORACLE").unwrap());
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut encoder = Encoder::default();
            for fixture in sources(&root, chip) {
                let plan = Plan::build(chip, fixture.inputs()).unwrap();
                assert_eq!(plan.requests().len(), fixture.wire.len());
                for (request, wire) in plan.requests().iter().zip(&fixture.wire) {
                    assert_eq!(
                        wire.command,
                        if chip == Chip::Mt7925 {
                            (1 << 17) | 0x2c
                        } else {
                            (1 << 18)
                                | if request.kind() == Kind::PseFlush {
                                    (1 << 16) | 0xc0
                                } else {
                                    0x5d
                                }
                        }
                    );
                    assert_eq!(wire.wait, request.expects_response());
                    assert_eq!(request.body(), wire.body);
                    let packet = encoder.encode_power(request);
                    assert_eq!(packet.bytes(), wire.packet);
                }
            }
        }
        let trace = std::fs::read(root.join("sar.trace")).unwrap();
        assert_eq!(trace.len(), 1024 * 46);
        let mut at = 0;
        for _ in 0..1024 {
            let power = i16::from_le_bytes(trace[at..at + 2].try_into().unwrap());
            let frequency = u32::from_le_bytes(trace[at + 2..at + 6].try_into().unwrap());
            at += 6;
            let ranges: [Option<SarRange>; 3] = core::array::from_fn(|_| {
                let present = trace[at] != 0;
                let start_mhz = u32::from_le_bytes(trace[at + 1..at + 5].try_into().unwrap());
                let end_mhz = u32::from_le_bytes(trace[at + 5..at + 9].try_into().unwrap());
                let quarter_dbm = i32::from_le_bytes(trace[at + 9..at + 13].try_into().unwrap());
                at += 13;
                present.then_some(SarRange {
                    start_mhz,
                    end_mhz,
                    quarter_dbm,
                })
            });
            assert_eq!(sar_limit(power, frequency, &ranges), Ok(trace[at] as i8));
            at += 1;
        }
    }
}
