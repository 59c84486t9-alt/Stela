// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Exact PCI encapsulation EEPROM query and bounded raw observations. The
//! donor ignores validity/version/size/magic fields; retain them without
//! inventing their meaning or treating this observation as radio authority.
use super::{Encoder, Error as EventError, Event};
use crate::net::wifi::mediatek::identity::Chip;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    TooLarge,
    Truncated { minimum: usize, actual: usize },
    WrongAddress { expected: u32, actual: u32 },
    Event(EventError),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek encapsulation EEPROM: {self:?}")
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
    pub fn offset(&self) -> u32 {
        offset(self.chip)
    }
}
fn offset(chip: Chip) -> u32 {
    if chip == Chip::Mt7925 { 0xa71 } else { 0x55b }
}
impl Encoder {
    /// Only the source-defined hardware encapsulation address is admitted.
    /// The same four-bit command sequence owner is used through boot/runtime.
    pub fn encode_encapsulation_query(&mut self, chip: Chip) -> Packet {
        let c3 = chip == Chip::Mt7925;
        let sequence = self.next_sequence();
        let mut bytes = vec![0; if c3 { 80 } else { 88 }];
        let length = bytes.len();
        bytes[..4].copy_from_slice(&(length as u32 | (2 << 23) | (0x20 << 25)).to_le_bytes());
        bytes[4..8].copy_from_slice(&(1u32 << 16 | if c3 { 0 } else { 1 << 31 }).to_le_bytes());
        bytes[32..34].copy_from_slice(&((length - 32) as u16).to_le_bytes());
        bytes[37] = 0xa0;
        bytes[39] = sequence;
        let addr_at = if c3 {
            bytes[34..36].copy_from_slice(&0x2du16.to_le_bytes()); // UNI EFUSE_CTRL
            bytes[43] = 3; // QUERY_ACK, not SET7 or NIC_CAPA6
            bytes[52..54].copy_from_slice(&1u16.to_le_bytes());
            bytes[54..56].copy_from_slice(&28u16.to_le_bytes());
            56
        } else {
            bytes[34..36].copy_from_slice(&0x8000u16.to_le_bytes());
            bytes[36] = 0xed; // EXT_CID
            bytes[38] = 0; // QUERY
            bytes[41] = 1; // EFUSE_ACCESS
            bytes[43] = 1; // ext_cid_ack
            64
        };
        bytes[addr_at..addr_at + 4].copy_from_slice(&(offset(chip) & !15).to_le_bytes());
        Packet {
            chip,
            sequence,
            bytes,
        }
    }
}
impl Event<'_> {
    pub fn encapsulation_payload<'a>(&'a self, packet: &Packet) -> Result<&'a [u8], Error> {
        if self.unsolicited || self.sequence == 0 {
            return Err(Error::Event(EventError::Unsolicited));
        }
        if self.sequence != packet.sequence {
            return Err(Error::Event(EventError::UnexpectedSequence {
                expected: packet.sequence,
                actual: self.sequence,
            }));
        }
        // Both actual response parsers use the owned sequence and generic
        // header removal for these queries; no source-specific EID is invented.
        Ok(self.payload)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Connac3 {
    pub reserved: [u8; 4],
    pub tag: u16,
    pub length: u16,
    pub version: u32,
    pub size: u32,
    pub magic: u32,
    pub kind: u32,
    pub reserved_words: [u32; 4],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    chip: Chip,
    raw: Vec<u8>,
    address: u32,
    valid: u32,
    connac3: Option<Connac3>,
    data_offset: usize,
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
impl Observation {
    pub fn parse(chip: Chip, body: &[u8]) -> Result<Self, Error> {
        if body.len() > 64 * 1024 {
            return Err(Error::TooLarge);
        }
        let c3 = chip == Chip::Mt7925;
        let minimum = if c3 { 80 } else { 24 };
        if body.len() < minimum {
            return Err(Error::Truncated {
                minimum,
                actual: body.len(),
            });
        }
        let address = word(body, if c3 { 12 } else { 0 });
        let expected = offset(chip) & !15;
        // Conservative addition: Linux ignores this echo. Do not select a
        // different physical block's byte as this hardware's encapsulation.
        if address != expected {
            return Err(Error::WrongAddress {
                expected,
                actual: address,
            });
        }
        Ok(Self {
            chip,
            raw: body.to_vec(),
            address,
            valid: word(body, if c3 { 16 } else { 4 }),
            connac3: c3.then(|| Connac3 {
                reserved: body[..4].try_into().unwrap(),
                tag: u16::from_le_bytes(body[4..6].try_into().unwrap()),
                length: u16::from_le_bytes(body[6..8].try_into().unwrap()),
                version: word(body, 8),
                size: word(body, 20),
                magic: word(body, 24),
                kind: word(body, 28),
                reserved_words: core::array::from_fn(|i| word(body, 32 + i * 4)),
            }),
            data_offset: if c3 { 48 } else { 8 },
        })
    }
    pub fn chip(&self) -> Chip {
        self.chip
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn offset(&self) -> u32 {
        offset(self.chip)
    }
    pub fn block_address(&self) -> u32 {
        self.address
    }
    pub fn raw_valid(&self) -> u32 {
        self.valid
    }
    pub fn connac3(&self) -> Option<&Connac3> {
        self.connac3.as_ref()
    }
    pub fn data(&self) -> &[u8] {
        &self.raw
            [self.data_offset..self.data_offset + if self.chip == Chip::Mt7925 { 32 } else { 16 }]
    }
    pub fn byte(&self) -> u8 {
        self.data()[self.offset() as usize % 16]
    }
    pub fn encapsulation(&self) -> u8 {
        self.byte() & if self.chip == Chip::Mt7925 { 3 } else { 1 }
    }
    pub fn trailing(&self) -> &[u8] {
        &self.raw[self.data_offset + if self.chip == Chip::Mt7925 { 32 } else { 16 }..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    fn body(chip: Chip, value: u8) -> Vec<u8> {
        let c3 = chip == Chip::Mt7925;
        let mut bytes = vec![0; if c3 { 80 } else { 24 }];
        let at = if c3 { 12 } else { 0 };
        bytes[at..at + 4].copy_from_slice(&(offset(chip) & !15).to_le_bytes());
        bytes[if c3 { 49 } else { 19 }] = value;
        bytes
    }
    #[test]
    fn exact_source_offsets_query_headers_and_shared_sequence_have_no_default_read() {
        let mut encoder = Encoder::default();
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for i in 0..=255 {
                let packet = encoder.encode_encapsulation_query(chip);
                assert_ne!(packet.sequence(), 0);
                let c3 = chip == Chip::Mt7925;
                assert_eq!(packet.bytes().len(), if c3 { 80 } else { 88 });
                assert_eq!(packet.bytes()[43], if c3 { 3 } else { 1 });
                let bytes = body(chip, i);
                let parsed = Observation::parse(chip, &bytes).unwrap();
                assert_eq!(parsed.byte(), i);
                assert_eq!(parsed.encapsulation(), i & if c3 { 3 } else { 1 });
                assert_eq!(parsed.raw_valid(), 0); // Unknown meaning stays raw.
                assert_eq!(parsed.offset(), packet.offset());
                assert_eq!(parsed.raw(), bytes);
            }
        }
    }
    #[test]
    fn bounds_echo_mismatch_and_unmatched_events_never_publish_wrong_block_data() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let bytes = body(chip, 0xfe);
            for n in 0..bytes.len() {
                assert!(matches!(
                    Observation::parse(chip, &bytes[..n]),
                    Err(Error::Truncated { .. })
                ));
            }
            let mut wrong = bytes.clone();
            wrong[if chip == Chip::Mt7925 { 12 } else { 0 }] ^= 16;
            assert!(matches!(
                Observation::parse(chip, &wrong),
                Err(Error::WrongAddress { .. })
            ));
            assert_eq!(
                Observation::parse(chip, &vec![0; 65537]).unwrap_err(),
                Error::TooLarge
            );
            let mut extra = bytes.clone();
            extra.extend_from_slice(&[9, 8, 7]);
            assert_eq!(
                Observation::parse(chip, &extra).unwrap().trailing(),
                &[9, 8, 7]
            );
            let packet = Encoder::default().encode_encapsulation_query(chip);
            let base = if chip == Chip::Mt7925 { 32 } else { 24 };
            let mut frame = vec![0; base + 12];
            frame[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
            frame[base + 4] = 1;
            frame[base + 5] = packet.sequence();
            frame.extend_from_slice(&bytes);
            let event = Event::parse(chip, &frame).unwrap();
            assert_eq!(event.encapsulation_payload(&packet).unwrap(), bytes);
            frame[base + 5] = packet.sequence() % 15 + 1;
            assert!(
                Event::parse(chip, &frame)
                    .unwrap()
                    .encapsulation_payload(&packet)
                    .is_err()
            );
            frame[base + 5] = packet.sequence();
            frame[base + 6] = 4;
            assert!(
                Event::parse(chip, &frame)
                    .unwrap()
                    .encapsulation_payload(&packet)
                    .is_err()
            );
        }
    }
    #[test]
    #[ignore = "requires unchanged full EEPROM helpers and MCU fill writers"]
    fn full_unchanged_eeprom_helpers_match_requests_bytes_and_selected_observations() {
        let root = std::path::PathBuf::from(std::env::var("STELA_MT792X_EEPROM_ORACLE").unwrap());
        for (chip, number) in [
            (Chip::Mt7921, 7921),
            (Chip::Mt7922, 7922),
            (Chip::Mt7925, 7925),
        ] {
            let trace = std::fs::read(root.join(alloc::format!("{number}.trace"))).unwrap();
            let mut encoder = Encoder::default();
            let mut at = 0;
            for _ in 0..512 {
                let n = u16::from_le_bytes(trace[at..at + 2].try_into().unwrap()) as usize;
                at += 2;
                let packet = encoder.encode_encapsulation_query(chip);
                assert_eq!(packet.bytes(), &trace[at..at + n]);
                at += n;
                let n = u16::from_le_bytes(trace[at..at + 2].try_into().unwrap()) as usize;
                at += 2;
                let observed = Observation::parse(chip, &trace[at..at + n]).unwrap();
                assert_eq!(observed.raw(), &trace[at..at + n]);
                at += n;
                assert_eq!(observed.byte(), trace[at]);
                at += 1;
                if let Some(c3) = observed.connac3() {
                    assert_eq!(c3.version, word(observed.raw(), 8));
                    assert_eq!(
                        c3.reserved_words,
                        core::array::from_fn(|i| word(observed.raw(), 32 + i * 4))
                    );
                }
            }
            assert_eq!(at, trace.len());
        }
    }
}
