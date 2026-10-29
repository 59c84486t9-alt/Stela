// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Exact CLC envelopes and raw response facts. No parsed flag or generic
//! completion grants an applied country, power, location or radio permission.
use super::{Encoder, Error as EventError, Event};
use crate::wifi::mediatek::{
    firmware::clc::{Completion, Request},
    identity::Chip,
};
use alloc::vec::Vec;

pub struct Packet {
    chip: Chip,
    sequence: u8,
    completion: Completion,
    bytes: Vec<u8>,
}
impl Packet {
    pub fn chip(&self) -> Chip {
        self.chip
    }
    pub fn sequence(&self) -> u8 {
        self.sequence
    }
    pub fn completion(&self) -> Completion {
        self.completion
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl Encoder {
    /// Chip comes from the bounded private-built request. A caller cannot
    /// attach Connac2 CLC bytes to a Connac3 envelope by passing a chip ID.
    pub fn encode_clc(&mut self, request: &Request) -> Packet {
        let chip = request.chip();
        let c3 = chip == Chip::Mt7925;
        let header = if c3 { 48 } else { 64 };
        let sequence = self.next_sequence();
        let length = header + request.body().len();
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
            bytes[36] = 0x5c;
            bytes[38] = 1;
        }
        bytes[header..].copy_from_slice(request.body());
        Packet {
            chip,
            sequence,
            completion: request.completion(),
            bytes,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Event(EventError),
    OneWayCommand,
    TooLarge,
    Truncated { minimum: usize, actual: usize },
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek CLC response: {self:?}")
    }
}
impl core::error::Error for Error {}
impl Event<'_> {
    pub fn clc_payload<'a>(&'a self, packet: &Packet) -> Result<&'a [u8], Error> {
        if packet.completion == Completion::OneWay {
            return Err(Error::OneWayCommand);
        }
        if self.unsolicited || self.sequence == 0 {
            return Err(Error::Event(EventError::Unsolicited));
        }
        if self.sequence != packet.sequence {
            return Err(Error::Event(EventError::UnexpectedSequence {
                expected: packet.sequence,
                actual: self.sequence,
            }));
        }
        // These source response parser paths remove the generic header;
        // neither specifies a station result record or an expected EID here.
        Ok(self.payload)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Connac2Info {
    pub prefix: [u8; 4],
    pub tag: u16,
    pub length: u16,
    pub channel_flags: u8,
    pub reserved: [u8; 63],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    raw: Vec<u8>,
    info: Option<Connac2Info>,
}
impl Response {
    pub fn parse(packet: &Packet, body: &[u8]) -> Result<Self, Error> {
        if packet.completion == Completion::OneWay {
            return Err(Error::OneWayCommand);
        }
        if body.len() > 64 * 1024 {
            return Err(Error::TooLarge);
        }
        let info = if packet.chip != Chip::Mt7925 {
            if body.len() < 72 {
                return Err(Error::Truncated {
                    minimum: 72,
                    actual: body.len(),
                });
            }
            Some(Connac2Info {
                prefix: body[..4].try_into().unwrap(),
                tag: u16::from_le_bytes(body[4..6].try_into().unwrap()),
                length: u16::from_le_bytes(body[6..8].try_into().unwrap()),
                channel_flags: body[8],
                reserved: body[9..72].try_into().unwrap(),
            })
        } else {
            None
        };
        // Connac3's source generic response may have an empty body. It is an
        // observed completion, never an invented status0 or channel flagFF.
        Ok(Self {
            raw: body.to_vec(),
            info,
        })
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn connac2(&self) -> Option<&Connac2Info> {
        self.info.as_ref()
    }
    pub fn trailing(&self) -> &[u8] {
        if self.info.is_some() {
            &self.raw[72..]
        } else {
            &[]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_packet(chip: Chip, completion: Completion) -> Packet {
        Packet {
            chip,
            sequence: 7,
            completion,
            bytes: Vec::new(),
        }
    }
    #[test]
    fn full_connac2_info_stays_raw_and_one_way_never_becomes_a_reply() {
        let mut bytes: Vec<_> = (0u8..72).collect();
        bytes.extend_from_slice(&[0xaa, 0xbb]);
        for chip in [Chip::Mt7921, Chip::Mt7922] {
            let packet = fixture_packet(chip, Completion::Connac2Info);
            for n in 0..72 {
                assert!(matches!(
                    Response::parse(&packet, &bytes[..n]),
                    Err(Error::Truncated { minimum: 72, .. })
                ));
            }
            let parsed = Response::parse(&packet, &bytes).unwrap();
            assert_eq!(parsed.raw(), bytes);
            let info = parsed.connac2().unwrap();
            assert_eq!(info.prefix, [0, 1, 2, 3]);
            assert_eq!(info.tag, 0x0504);
            assert_eq!(info.length, 0x0706);
            assert_eq!(info.channel_flags, 8);
            assert_eq!(info.reserved.as_slice(), &bytes[9..72]);
            assert_eq!(parsed.trailing(), &[0xaa, 0xbb]);
            let one_way = fixture_packet(chip, Completion::OneWay);
            assert_eq!(
                Response::parse(&one_way, &bytes).unwrap_err(),
                Error::OneWayCommand
            );
        }
    }
    #[test]
    fn generic_connac3_completion_never_invents_status_or_channel_flags() {
        let packet = fixture_packet(Chip::Mt7925, Completion::Connac3Response);
        for bytes in [&[][..], &[0xff, 0xfe, 0xfd][..]] {
            let parsed = Response::parse(&packet, bytes).unwrap();
            assert_eq!(parsed.raw(), bytes);
            assert!(parsed.connac2().is_none());
            assert!(parsed.trailing().is_empty());
        }
        assert_eq!(
            Response::parse(&packet, &vec![0; 65537]).unwrap_err(),
            Error::TooLarge
        );
    }
    #[test]
    fn only_owned_response_sequence_can_match_and_no_eid_is_invented() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let completion = if chip == Chip::Mt7925 {
                Completion::Connac3Response
            } else {
                Completion::Connac2Info
            };
            let packet = fixture_packet(chip, completion);
            let base = if chip == Chip::Mt7925 { 32 } else { 24 };
            let mut bytes = vec![0; base + 12];
            bytes[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
            bytes[base + 4] = 0x55;
            bytes[base + 5] = 7;
            bytes.extend_from_slice(&[0; 72]);
            assert_eq!(
                Event::parse(chip, &bytes)
                    .unwrap()
                    .clc_payload(&packet)
                    .unwrap(),
                &[0; 72]
            );
            bytes[base + 5] = 8;
            assert!(
                Event::parse(chip, &bytes)
                    .unwrap()
                    .clc_payload(&packet)
                    .is_err()
            );
            bytes[base + 5] = 7;
            bytes[base + 6] = 4;
            assert_eq!(
                Event::parse(chip, &bytes)
                    .unwrap()
                    .clc_payload(&packet)
                    .unwrap_err(),
                Error::Event(EventError::Unsolicited)
            );
            bytes[base + 6] = 0;
            let one_way = fixture_packet(chip, Completion::OneWay);
            assert_eq!(
                Event::parse(chip, &bytes)
                    .unwrap()
                    .clc_payload(&one_way)
                    .unwrap_err(),
                Error::OneWayCommand
            );
        }
    }
}
