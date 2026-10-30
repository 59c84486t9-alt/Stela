// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Per-chip NIC capability requests and bounded owned observations.
//! Firmware-reported capabilities do not allocate resources, establish board
//! calibration/regulatory policy or authorize unsupported radio modes.
use super::{Encoder, Event};
use crate::{Mac, wifi::mediatek::identity::Chip};
use alloc::vec::Vec;

const MAX_BYTES: usize = 65536;
const MAX_ELEMENTS: usize = 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    TooLarge,
    TooManyElements,
    InvalidElementLength,
    InvalidKnownLength {
        tag: u32,
        minimum: usize,
        actual: usize,
    },
    UnsupportedNss(u8),
    Unsolicited,
    UnexpectedSequence {
        expected: u8,
        actual: u8,
    },
    WrongEvent {
        expected: u8,
        actual: u8,
    },
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek NIC capabilities: {self:?}")
    }
}
impl core::error::Error for Error {}

pub struct Packet {
    chip: Chip,
    sequence: u8,
    bytes: Vec<u8>,
}
impl Packet {
    pub fn chip(&self) -> Chip {
        self.chip
    }
    pub fn sequence(&self) -> u8 {
        self.sequence
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl Encoder {
    pub fn encode_capabilities(&mut self, chip: Chip) -> Packet {
        let connac3 = chip == Chip::Mt7925;
        let sequence = self.next_sequence();
        let mut bytes = vec![0; if connac3 { 56 } else { 64 }];
        let length = bytes.len();
        bytes[..4].copy_from_slice(&(length as u32 | (2 << 23) | (0x20 << 25)).to_le_bytes());
        bytes[4..8]
            .copy_from_slice(&(1u32 << 16 | if connac3 { 0 } else { 1 << 31 }).to_le_bytes());
        bytes[32..34].copy_from_slice(&((length - 32) as u16).to_le_bytes());
        bytes[37] = 0xa0;
        bytes[39] = sequence;
        if connac3 {
            bytes[34..36].copy_from_slice(&14u16.to_le_bytes()); // UNI CHIP_CONFIG
            bytes[43] = 6; // EXT_ACK7 with ACKbit0 cleared by source
            bytes[52..54].copy_from_slice(&3u16.to_le_bytes()); // NIC_CAPA
            bytes[54..56].copy_from_slice(&4u16.to_le_bytes());
        } else {
            bytes[34..36].copy_from_slice(&0x8000u16.to_le_bytes());
            bytes[36] = 0x8a; // CE GET_NIC_CAPAB, no QUERY modifier
            bytes[38] = 1; // source CE set_query=SET1
        }
        Packet {
            chip,
            sequence,
            bytes,
        }
    }
}
impl Event<'_> {
    /// Match the chip-specific capability event, rather than accepting
    /// a station UNI status ACK or unrelated same-sequence notification.
    pub fn capability_payload<'a>(&'a self, packet: &Packet) -> Result<&'a [u8], Error> {
        if self.unsolicited || self.sequence == 0 {
            return Err(Error::Unsolicited);
        }
        if self.sequence != packet.sequence {
            return Err(Error::UnexpectedSequence {
                expected: packet.sequence,
                actual: self.sequence,
            });
        }
        // Connac2's source matches only the owned sequence here; its
        // CE command number is not an independently specified event ID. Never
        // invent EID0x8a from CID0x8a. Connac3 has an explicit NIC_CAPAB event.
        let expected = 0x43;
        if packet.chip == Chip::Mt7925 && self.event_id != expected {
            return Err(Error::WrongEvent {
                expected,
                actual: self.event_id,
            });
        }
        Ok(self.payload)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Phy {
    pub ht: u8,
    pub vht: u8,
    pub reported_5g: u8,
    pub max_bw: u8,
    pub nss: u8,
    pub dbdc: u8,
    pub tx_ldpc: u8,
    pub rx_ldpc: u8,
    pub tx_stbc: u8,
    pub rx_stbc: u8,
    pub hw_path: u8,
    pub he: u8,
    pub eht: Option<u8>,
}
impl Phy {
    /// Source HW-path facts, independent of negotiated MAC/radio support.
    pub fn has_2ghz(self) -> bool {
        self.hw_path & 1 != 0
    }
    pub fn has_5ghz(self) -> bool {
        self.hw_path & 2 != 0
    }
    /// The shared native chain metadata currently has four entries. A zero or
    /// larger count is explicit unsupported evidence, never a guessed 1x1/2x2.
    pub fn antenna_mask(self) -> Result<u8, Error> {
        if !(1..=4).contains(&self.nss) {
            return Err(Error::UnsupportedNss(self.nss));
        }
        Ok((1u8 << self.nss) - 1)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Element {
    pub tag: u32,
    pub body: Vec<u8>,
}
/// Owned full report, including unknown fields and trailing bytes. Optional
/// decoded facts distinguish omitted information from a reported false/zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    chip: Chip,
    raw: Vec<u8>,
    reserved: [u8; 2],
    elements: Vec<Element>,
    trailing: Vec<u8>,
    mac: Option<Mac>,
    phy: Option<Phy>,
    six_ghz: Option<bool>,
    chip_flags: Option<u64>,
    eml: Option<u16>,
}
impl Capabilities {
    pub fn parse(chip: Chip, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        if bytes.len() < 4 {
            return Err(Error::Truncated);
        }
        let count = usize::from(u16::from_le_bytes(bytes[..2].try_into().unwrap()));
        if count > MAX_ELEMENTS {
            return Err(Error::TooManyElements);
        }
        let mut result = Self {
            chip,
            raw: bytes.to_vec(),
            reserved: bytes[2..4].try_into().unwrap(),
            elements: Vec::new(),
            trailing: Vec::new(),
            mac: None,
            phy: None,
            six_ghz: None,
            chip_flags: None,
            eml: None,
        };
        let connac3 = chip == Chip::Mt7925;
        let header = if connac3 { 4 } else { 8 };
        let mut cursor = 4usize;
        for _ in 0..count {
            let prefix = bytes.get(cursor..cursor + header).ok_or(Error::Truncated)?;
            let (tag, length) = if connac3 {
                let total = usize::from(u16::from_le_bytes(prefix[2..4].try_into().unwrap()));
                if total < header {
                    return Err(Error::InvalidElementLength);
                }
                (
                    u32::from(u16::from_le_bytes(prefix[..2].try_into().unwrap())),
                    total - header,
                )
            } else {
                (
                    u32::from_le_bytes(prefix[..4].try_into().unwrap()),
                    u32::from_le_bytes(prefix[4..8].try_into().unwrap()) as usize,
                )
            };
            cursor += header;
            let end = cursor
                .checked_add(length)
                .ok_or(Error::InvalidElementLength)?;
            let body = bytes.get(cursor..end).ok_or(Error::Truncated)?;
            let minimum = match tag {
                7 => 6,
                8 => {
                    if connac3 {
                        13
                    } else {
                        12
                    }
                }
                0x18 => 1,
                0x20 => 8,
                0x22 if connac3 => 12,
                _ => 0,
            };
            if body.len() < minimum {
                return Err(Error::InvalidKnownLength {
                    tag,
                    minimum,
                    actual: body.len(),
                });
            }
            match tag {
                7 => result.mac = Some(Mac(body[..6].try_into().unwrap())),
                8 => {
                    result.phy = Some(Phy {
                        ht: body[0],
                        vht: body[1],
                        reported_5g: body[2],
                        max_bw: body[3],
                        nss: body[4],
                        dbdc: body[5],
                        tx_ldpc: body[6],
                        rx_ldpc: body[7],
                        tx_stbc: body[8],
                        rx_stbc: body[9],
                        hw_path: body[10],
                        he: body[11],
                        eht: connac3.then(|| body[12]),
                    })
                }
                0x18 => result.six_ghz = Some(body[0] != 0),
                0x20 => result.chip_flags = Some(u64::from_le_bytes(body[..8].try_into().unwrap())),
                0x22 if connac3 => {
                    result.eml = Some(u16::from_le_bytes(body[4..6].try_into().unwrap()))
                }
                _ => (),
            }
            result.elements.push(Element {
                tag,
                body: body.to_vec(),
            });
            cursor = end;
        }
        result.trailing = bytes[cursor..].to_vec();
        Ok(result)
    }
    pub fn chip(&self) -> Chip {
        self.chip
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn reserved(&self) -> [u8; 2] {
        self.reserved
    }
    pub fn elements(&self) -> &[Element] {
        &self.elements
    }
    pub fn trailing(&self) -> &[u8] {
        &self.trailing
    }
    /// Raw firmware-reported address; it is not replaced with a random/default
    /// address if zero/multicast. The native policy owner validates usability.
    pub fn mac(&self) -> Option<Mac> {
        self.mac
    }
    pub fn phy(&self) -> Option<Phy> {
        self.phy
    }
    pub fn six_ghz(&self) -> Option<bool> {
        self.six_ghz
    }
    pub fn chip_flags(&self) -> Option<u64> {
        self.chip_flags
    }
    pub fn eml(&self) -> Option<u16> {
        self.eml
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    fn report(chip: Chip, entries: &[(u32, &[u8])]) -> Vec<u8> {
        let mut bytes = vec![entries.len() as u8, (entries.len() >> 8) as u8, 0xa5, 0x5a];
        for &(tag, body) in entries {
            if chip == Chip::Mt7925 {
                bytes.extend_from_slice(&(tag as u16).to_le_bytes());
                bytes.extend_from_slice(&((body.len() + 4) as u16).to_le_bytes());
            } else {
                bytes.extend_from_slice(&tag.to_le_bytes());
                bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            }
            bytes.extend_from_slice(body);
        }
        bytes
    }
    #[test]
    fn owned_report_keeps_missing_duplicate_unknown_zero_and_trailing_observations() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let empty = Capabilities::parse(chip, &[0, 0, 0, 0]).unwrap();
            assert_eq!(empty.mac(), None);
            assert_eq!(empty.phy(), None);
            assert_eq!(empty.six_ghz(), None);
            assert_eq!(empty.chip_flags(), None);
            let mut phy = [0u8; 16];
            phy[4] = 2;
            phy[10] = 1;
            phy[12] = 7;
            let mut bytes = report(
                chip,
                &[
                    (7, &[2, 1, 2, 3, 4, 5]),
                    (8, &phy),
                    (0x18, &[0]),
                    (0x20, &[1, 2, 3, 4, 5, 6, 7, 8]),
                    (0xbeef, &[9, 8]),
                    (7, &[0; 6]),
                ],
            );
            bytes.extend_from_slice(&[0xf1, 0xf2]);
            let parsed = Capabilities::parse(chip, &bytes).unwrap();
            assert_eq!(parsed.raw(), bytes);
            drop(bytes); // owned report and fields survive input lifetime
            assert_eq!(parsed.reserved(), [0xa5, 0x5a]);
            assert_eq!(parsed.trailing(), &[0xf1, 0xf2]);
            assert_eq!(parsed.elements()[4].tag, 0xbeef);
            assert_eq!(parsed.elements()[4].body, [9, 8]);
            assert_eq!(parsed.mac(), Some(Mac([0; 6]))); // last observed, no invented fallback
            assert_eq!(parsed.six_ghz(), Some(false));
            assert_eq!(parsed.chip_flags(), Some(0x0807060504030201));
            let phy = parsed.phy().unwrap();
            assert_eq!(phy.antenna_mask(), Ok(3));
            assert!(phy.has_2ghz());
            assert!(!phy.has_5ghz());
            assert_eq!(phy.eht, (chip == Chip::Mt7925).then_some(7));
        }
    }
    #[test]
    fn malformed_known_tlvs_and_unsupported_chain_counts_never_supply_default_caps() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut known = vec![
                (7, 6),
                (8, if chip == Chip::Mt7925 { 13 } else { 12 }),
                (0x18, 1),
                (0x20, 8),
            ];
            if chip == Chip::Mt7925 {
                known.push((0x22, 12));
            }
            for (tag, minimum) in known {
                for n in 0..minimum {
                    assert!(matches!(
                        Capabilities::parse(chip, &report(chip, &[(tag, &vec![0; n])])),
                        Err(Error::InvalidKnownLength { .. })
                    ));
                }
            }
            let full = report(chip, &[(7, &[2; 6]), (8, &[1; 16]), (0x20, &[8; 8])]);
            for n in 0..full.len() {
                assert!(Capabilities::parse(chip, &full[..n]).is_err());
            }
            for nss in [0, 5, 8, 31, 32, 255] {
                let mut bytes = [1; 16];
                bytes[4] = nss;
                let phy = Capabilities::parse(chip, &report(chip, &[(8, &bytes)]))
                    .unwrap()
                    .phy()
                    .unwrap();
                assert_eq!(phy.nss, nss);
                assert_eq!(phy.antenna_mask(), Err(Error::UnsupportedNss(nss)));
            }
        }
        for length in [0u16, 1, 2, 3] {
            let mut bytes = vec![1, 0, 0, 0, 8, 0];
            bytes.extend_from_slice(&length.to_le_bytes());
            assert_eq!(
                Capabilities::parse(Chip::Mt7925, &bytes),
                Err(Error::InvalidElementLength)
            );
        }
        assert_eq!(
            Capabilities::parse(Chip::Mt7925, &vec![0; MAX_BYTES + 1]),
            Err(Error::TooLarge)
        );
        assert_eq!(
            Capabilities::parse(Chip::Mt7925, &[1, 4, 0, 0]),
            Err(Error::TooManyElements)
        );
    }
    #[test]
    fn capability_query_matches_response_kind() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut encoder = Encoder::default();
            for _ in 0..20 {
                let before = encoder
                    .encode(chip, super::super::Command::PatchSemaphore, &[1, 0, 0, 0])
                    .unwrap()
                    .sequence;
                let packet = encoder.encode_capabilities(chip);
                assert_eq!(packet.sequence(), before % 15 + 1);
                assert_eq!(packet.chip(), chip);
                assert_eq!(packet.bytes()[39], packet.sequence());
                let next = encoder
                    .encode_uni(chip, super::super::runtime::Command::StationRecord, &[0; 8])
                    .unwrap();
                assert_eq!(next.sequence(), packet.sequence() % 15 + 1);
                let base = if chip == Chip::Mt7925 { 32 } else { 24 };
                let mut frame = vec![0; base + 16];
                frame[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
                frame[base + 4] = if chip == Chip::Mt7925 { 0x43 } else { 0x55 }; // C2 source has no specified EID check
                frame[base + 5] = packet.sequence();
                let event = Event::parse(chip, &frame).unwrap();
                assert_eq!(event.capability_payload(&packet), Ok(&[0, 0, 0, 0][..]));
                frame[base + 5] = packet.sequence() % 15 + 1;
                assert!(matches!(
                    Event::parse(chip, &frame)
                        .unwrap()
                        .capability_payload(&packet),
                    Err(Error::UnexpectedSequence { .. })
                ));
                frame[base + 5] = packet.sequence();
                frame[base + 6] = 4;
                assert_eq!(
                    Event::parse(chip, &frame)
                        .unwrap()
                        .capability_payload(&packet),
                    Err(Error::Unsolicited)
                );
                frame[base + 6] = 0;
                frame[base + 5] = 0;
                assert_eq!(
                    Event::parse(chip, &frame)
                        .unwrap()
                        .capability_payload(&packet),
                    Err(Error::Unsolicited)
                );
                if chip == Chip::Mt7925 {
                    frame[base + 5] = packet.sequence();
                    frame[base + 4] = 1;
                    assert!(matches!(
                        Event::parse(chip, &frame)
                            .unwrap()
                            .capability_payload(&packet),
                        Err(Error::WrongEvent { .. })
                    ));
                }
            }
        }
    }
    #[test]
    #[ignore = "oracle: STELA_MT792X_CAP_WIRE_ORACLE"]
    fn unchanged_full_mcu_writers_match_all_capability_command_bytes() {
        let root = std::path::PathBuf::from(
            std::env::var_os("STELA_MT792X_CAP_WIRE_ORACLE").expect("capability wire oracle"),
        );
        for (chip, name) in [
            (Chip::Mt7921, "7921"),
            (Chip::Mt7922, "7922"),
            (Chip::Mt7925, "7925"),
        ] {
            let trace = std::fs::read(root.join(alloc::format!("{name}-cap.trace"))).unwrap();
            let mut cursor = 0;
            let mut encoder = Encoder::default();
            for _ in 0..90 {
                let packet = encoder.encode_capabilities(chip);
                let prefix = &trace[cursor..cursor + 4];
                cursor += 4;
                assert_eq!(prefix[0], if chip == Chip::Mt7925 { 14 } else { 0x8a });
                assert_eq!(prefix[1], packet.sequence());
                let n = usize::from(u16::from_le_bytes(prefix[2..4].try_into().unwrap()));
                assert_eq!(packet.bytes(), &trace[cursor..cursor + n]);
                cursor += n;
            }
            assert_eq!(cursor, trace.len());
        }
    }
    #[test]
    #[ignore = "oracle: STELA_MT792X_CAPABILITIES_ORACLE"]
    fn unchanged_full_capability_helpers_match_report_observations() {
        let root = std::path::PathBuf::from(
            std::env::var_os("STELA_MT792X_CAPABILITIES_ORACLE").expect("capability parser oracle"),
        );
        for (chip, name) in [
            (Chip::Mt7921, "7921"),
            (Chip::Mt7922, "7922"),
            (Chip::Mt7925, "7925"),
        ] {
            let trace = std::fs::read(root.join(alloc::format!("{name}.trace"))).unwrap();
            let mut cursor = 0;
            for _ in 0..1024 {
                let n = usize::from(u16::from_le_bytes(
                    trace[cursor..cursor + 2].try_into().unwrap(),
                ));
                cursor += 2;
                let input = &trace[cursor..cursor + n];
                cursor += n;
                let parsed = Capabilities::parse(chip, input).unwrap();
                let expected = &trace[cursor..cursor + 22];
                cursor += 22;
                assert_eq!(parsed.raw(), input);
                assert_eq!(parsed.trailing(), &[0x31, 0x32]);
                assert_eq!(parsed.mac().unwrap_or(Mac([0; 6])).0, expected[..6]);
                let mask = parsed.phy().map_or(0, |p| p.antenna_mask().unwrap());
                assert_eq!(mask, expected[6]);
                assert_eq!(mask, expected[7]);
                assert_eq!(parsed.phy().is_some_and(|p| p.has_2ghz()), expected[8] != 0);
                assert_eq!(parsed.phy().is_some_and(|p| p.has_5ghz()), expected[9] != 0);
                assert_eq!(parsed.six_ghz().unwrap_or(false), expected[10] != 0);
                assert_eq!(
                    parsed.chip_flags().unwrap_or(0).to_le_bytes(),
                    expected[12..20]
                );
                assert_eq!(parsed.eml().unwrap_or(0).to_le_bytes(), expected[20..22]);
                // Missing facts remain None despite the legacy C model's
                // zero-initialized storage; never publish those zeros as facts.
                assert_eq!(
                    parsed.mac().is_some(),
                    parsed.elements().iter().any(|e| e.tag == 7)
                );
                assert_eq!(
                    parsed.phy().is_some(),
                    parsed.elements().iter().any(|e| e.tag == 8)
                );
            }
            assert_eq!(cursor, trace.len());
        }
    }
}
