// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Unified WM device/BSS/station command envelopes and result records.
//! Command-specific payload construction and native mailbox ownership remain
//! independent; an encoded packet is never an installed firmware context.
use super::{Encoder, Event};
use crate::wifi::mediatek::identity::Chip;
use alloc::vec::Vec;

const HEADER: usize = 48;
const MAX_TRANSFER: usize = 4096;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Command {
    DeviceInfo = 1,
    BssInfo = 2,
    StationRecord = 3,
    Edca = 4,
    RssiMonitor = 0x41,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPayload,
    Event(super::Error),
    WrongEvent(u8),
    WrongCommand { expected: u8, actual: u8 },
}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::Event(e)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek UNI command: {self:?}")
    }
}
impl core::error::Error for Error {}

pub struct Packet {
    command: Command,
    sequence: u8,
    bytes: Vec<u8>,
}
impl Packet {
    pub fn command(&self) -> Command {
        self.command
    }
    pub fn sequence(&self) -> u8 {
        self.sequence
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultRecord<'a> {
    pub command: Command,
    pub sequence: u8,
    /// Little-endian firmware status. Nonzero is firmware failure, not
    /// a host sequence mismatch and never an installed-context acknowledgement.
    pub status: u32,
    pub reserved: [u8; 3],
    pub raw_payload: &'a [u8],
}
impl Encoder {
    /// Use the same serialized sequence owner through boot and runtime. The
    /// body must be the exact chip-specific device/BSS/station request, including
    /// its real payload header/TLV count/layout; this envelope does not validate
    /// opaque command semantics or select a guessed station/key/rate context.
    pub fn encode_uni(
        &mut self,
        chip: Chip,
        command: Command,
        payload: &[u8],
    ) -> Result<Packet, Error> {
        let minimum = if command == Command::StationRecord {
            8
        } else {
            4
        };
        if payload.len() < minimum || payload.len() > MAX_TRANSFER - HEADER {
            return Err(Error::InvalidPayload);
        }
        let sequence = self.next_sequence();
        let length = HEADER + payload.len();
        let mut bytes = vec![0; length];
        let txd0 = length as u32 | (2 << 23) | (0x20 << 25);
        let txd1 = (1u32 << 16) | if chip == Chip::Mt7925 { 0 } else { 1 << 31 };
        bytes[..4].copy_from_slice(&txd0.to_le_bytes());
        bytes[4..8].copy_from_slice(&txd1.to_le_bytes());
        bytes[32..34].copy_from_slice(&((length - 32) as u16).to_le_bytes());
        bytes[34..36].copy_from_slice(&(command as u16).to_le_bytes());
        bytes[37] = 0xa0;
        bytes[39] = sequence;
        bytes[43] = 7; // source UNI extended ACK + UNI + SET, WM destination0
        bytes[HEADER..].copy_from_slice(payload);
        Ok(Packet {
            command,
            sequence,
            bytes,
        })
    }
}
impl<'a> Event<'a> {
    /// Check a real non-unsolicited UNI result against the outstanding command
    /// and sequence. The owner additionally requires TX DMA completion,
    /// RX provenance/fresh epoch and deadline/no-late-reply serialization.
    /// Scan/radio/key transitions cannot be inferred from an unrelated event.
    pub fn uni_result(&self, packet: &Packet) -> Result<ResultRecord<'a>, Error> {
        if self.unsolicited || self.sequence == 0 {
            return Err(super::Error::Unsolicited.into());
        }
        if self.sequence != packet.sequence {
            return Err(super::Error::UnexpectedSequence {
                expected: packet.sequence,
                actual: self.sequence,
            }
            .into());
        }
        if self.event_id != 1 {
            return Err(Error::WrongEvent(self.event_id));
        }
        if self.payload.len() < 8 {
            return Err(super::Error::Truncated.into());
        }
        let actual = self.payload[0];
        if actual != packet.command as u8 {
            return Err(Error::WrongCommand {
                expected: packet.command as u8,
                actual,
            });
        }
        Ok(ResultRecord {
            command: packet.command,
            sequence: self.sequence,
            status: u32::from_le_bytes(self.payload[4..8].try_into().expect("four bytes")),
            reserved: self.payload[1..4].try_into().expect("three bytes"),
            raw_payload: self.payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(chip: Chip, sequence: u8, command: Command, status: u32) -> Vec<u8> {
        let base = if chip == Chip::Mt7925 { 32 } else { 24 };
        let mut bytes = vec![0; base + 12 + 8];
        bytes[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
        bytes[base + 4] = 1;
        bytes[base + 5] = sequence;
        bytes[base + 6] = 2;
        bytes[base + 12] = command as u8;
        bytes[base + 13..base + 16].copy_from_slice(&[4, 5, 6]);
        bytes[base + 16..].copy_from_slice(&status.to_le_bytes());
        bytes
    }
    #[test]
    fn unified_runtime_uses_same_sequence_owner_and_exact_short_header_after_boot() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut encoder = Encoder::default();
            for n in 0..90 {
                let boot = encoder
                    .encode(chip, super::super::Command::PatchSemaphore, &[1, 0, 0, 0])
                    .unwrap();
                let payload = [n; 100];
                let packet = encoder
                    .encode_uni(chip, Command::StationRecord, &payload)
                    .unwrap();
                assert_eq!(packet.sequence(), (n * 2 + 1) % 15 + 1);
                assert_eq!(boot.sequence, (n * 2) % 15 + 1);
                assert_eq!(packet.bytes.len(), 148);
                assert_eq!(&packet.bytes[..4], &0x41000094u32.to_le_bytes());
                assert_eq!(&packet.bytes[32..36], &[116, 0, 3, 0]);
                assert_eq!(
                    &packet.bytes[36..44],
                    &[0, 0xa0, 0, packet.sequence(), 0, 0, 0, 7]
                );
                assert_eq!(&packet.bytes[44..48], &[0; 4]);
                assert_eq!(&packet.bytes[48..], &payload);
            }
        }
    }
    #[test]
    fn wrong_event_sequence_command_unsolicited_and_truncation_cannot_acknowledge_context() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            let packet = Encoder::default()
                .encode_uni(chip, Command::BssInfo, &[0; 4])
                .unwrap();
            let raw = event(chip, packet.sequence(), packet.command(), 0x78563412);
            let parsed = Event::parse(chip, &raw).unwrap();
            let result = parsed.uni_result(&packet).unwrap();
            assert_eq!(result.status, 0x78563412);
            assert_eq!(result.reserved, [4, 5, 6]);
            assert_eq!(result.raw_payload, &raw[raw.len() - 8..]);
            let base = if chip == Chip::Mt7925 { 32 } else { 24 };
            for n in 0..raw.len() {
                assert!(
                    Event::parse(chip, &raw[..n])
                        .and_then(|e| e
                            .uni_result(&packet)
                            .map_err(|_| super::super::Error::NotResponse))
                        .is_err()
                );
            }
            for (at, value) in [
                (base + 4, 2),
                (base + 5, 0),
                (base + 5, packet.sequence() + 1),
                (base + 6, 6),
                (base + 12, Command::DeviceInfo as u8),
            ] {
                let mut invalid = raw.clone();
                invalid[at] = value;
                assert!(
                    Event::parse(chip, &invalid)
                        .unwrap()
                        .uni_result(&packet)
                        .is_err()
                );
            }
        }
    }
    #[test]
    fn invalid_payload_does_not_consume_sequence_or_invent_body_validation() {
        let mut encoder = Encoder::default();
        for command in [
            Command::DeviceInfo,
            Command::BssInfo,
            Command::StationRecord,
        ] {
            for bytes in [0, 1, 3, 4049] {
                let payload = &vec![0; bytes];
                assert!(matches!(
                    encoder.encode_uni(Chip::Mt7921, command, payload),
                    Err(Error::InvalidPayload)
                ));
            }
        }
        for bytes in [4, 7] {
            assert!(matches!(
                encoder.encode_uni(Chip::Mt7921, Command::StationRecord, &vec![0; bytes]),
                Err(Error::InvalidPayload)
            ));
        }
        let packet = encoder
            .encode_uni(Chip::Mt7921, Command::DeviceInfo, &[0; 4048])
            .unwrap();
        assert_eq!(packet.sequence(), 1);
        assert_eq!(packet.bytes().len(), 4096);
    }

    #[test]
    #[ignore = "oracle: STELA_MT792X_UNI_ORACLE"]
    fn unchanged_unified_writers_match_all_bytes_across_sequence_wraps() {
        extern crate std;
        let directory = std::path::PathBuf::from(
            std::env::var_os("STELA_MT792X_UNI_ORACLE").expect("STELA_MT792X_UNI_ORACLE"),
        );
        for (chip, name) in [
            (Chip::Mt7921, "7921"),
            (Chip::Mt7922, "7922"),
            (Chip::Mt7925, "7925"),
        ] {
            let trace = std::fs::read(directory.join(alloc::format!("{name}-uni.trace"))).unwrap();
            let mut at = 0;
            let mut encoder = Encoder::default();
            for i in 0..90usize {
                let header = &trace[at..at + 4];
                let command = match i % 3 {
                    0 => Command::DeviceInfo,
                    1 => Command::BssInfo,
                    _ => Command::StationRecord,
                };
                let len = u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize;
                let payload: Vec<_> = (0..8 + (i * 37) % 1000)
                    .map(|n| (i * 17 + n) as u8)
                    .collect();
                let packet = encoder.encode_uni(chip, command, &payload).unwrap();
                assert_eq!(header[0], command as u8);
                assert_eq!(header[1], packet.sequence());
                assert_eq!(&trace[at + 4..at + 4 + len], packet.bytes());
                at += 4 + len;
            }
            assert_eq!(at, trace.len());
        }
    }
}
