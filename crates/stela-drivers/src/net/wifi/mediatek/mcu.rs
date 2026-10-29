// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! PCIe boot MCU messages from mt76_connac2_mcu_fill_message and
//! mt7925_mcu_fill_message. The boot entry point admits only the legacy WM
//! downloader commands. `runtime` separately implements bounded device/BSS/
//! station UNI status envelopes using this same serialized sequence owner.
use super::identity::Chip;
use alloc::vec::Vec;

pub mod capabilities;
pub mod clc;
pub mod client;
pub mod device;
pub mod domain;
pub mod eeprom;
pub mod init;
pub mod key;
pub mod power;
pub mod runtime;

const TX_HEADER: usize = 64;
const MAX_TX_BYTES: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Command {
    Download = 0x01,
    StartFirmware = 0x02,
    PatchStart = 0x05,
    PatchFinish = 0x07,
    PatchSemaphore = 0x10,
    Scatter = 0xee,
}
impl TryFrom<u8> for Command {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Download),
            2 => Ok(Self::StartFirmware),
            5 => Ok(Self::PatchStart),
            7 => Ok(Self::PatchFinish),
            0x10 => Ok(Self::PatchSemaphore),
            0xee => Ok(Self::Scatter),
            _ => Err(Error::UnsupportedCommand(value)),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Queue {
    Wm,
    FirmwareDownload,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedCommand(u8),
    InvalidPayload,
    Truncated,
    UnexpectedSequence { expected: u8, actual: u8 },
    NotResponse,
    Unsolicited,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek boot MCU: {self:?}")
    }
}
impl core::error::Error for Error {}

/// An encoded transfer, kept until TX-DMA completion by its owner.
/// The four-bit sequence advances even for headerless firmware scatter.
pub struct Packet {
    pub sequence: u8,
    pub queue: Queue,
    pub command: Command,
    pub bytes: Vec<u8>,
}
impl Packet {
    pub fn expects_response(&self) -> bool {
        self.command != Command::Scatter
    }
}

/// Used by a serialized, single-outstanding MCU mailbox. Four-bit sequence
/// wrap does not resolve a timed-out command: that owner must quarantine its
/// mailbox epoch instead of accepting a stale response after wrap.
#[derive(Default)]
pub struct Encoder {
    sequence: u8,
}
impl Encoder {
    fn next_sequence(&mut self) -> u8 {
        self.sequence = self.sequence % 15 + 1;
        self.sequence
    }
    pub fn encode(
        &mut self,
        chip: Chip,
        command: Command,
        payload: &[u8],
    ) -> Result<Packet, Error> {
        let valid = match command {
            Command::Download | Command::PatchStart => payload.len() == 12,
            Command::StartFirmware => payload.len() == 8,
            Command::PatchFinish | Command::PatchSemaphore => payload.len() == 4,
            Command::Scatter => !payload.is_empty() && payload.len() <= 4096,
        };
        if !valid || payload.len() + TX_HEADER > MAX_TX_BYTES {
            return Err(Error::InvalidPayload);
        }
        let sequence = self.next_sequence();
        if command == Command::Scatter {
            return Ok(Packet {
                sequence,
                queue: Queue::FirmwareDownload,
                command,
                bytes: payload.to_vec(),
            });
        }
        let length = payload.len() + TX_HEADER;
        let mut bytes = vec![0u8; length];
        let txd0 = length as u32 | (2 << 23) | (0x20 << 25);
        let txd1: u32 = (1 << 16) | if chip == Chip::Mt7925 { 0 } else { 1 << 31 };
        bytes[0..4].copy_from_slice(&txd0.to_le_bytes());
        bytes[4..8].copy_from_slice(&txd1.to_le_bytes());
        bytes[32..34].copy_from_slice(&((length - 32) as u16).to_le_bytes());
        bytes[34..36].copy_from_slice(&0x8000u16.to_le_bytes()); // MCU_PQ_ID(1, 0x20)
        bytes[36] = command as u8;
        bytes[37] = 0xa0;
        bytes[38] = 3; // MCU_Q_NA for legacy boot commands
        bytes[39] = sequence;
        bytes[TX_HEADER..].copy_from_slice(payload);
        Ok(Packet {
            sequence,
            queue: Queue::Wm,
            command,
            bytes,
        })
    }
}

/// Bounded event envelope keeping fields the donor event dispatcher uses.
/// A ring owner must supply the complete RX-event packet; no ordinary
/// data RX descriptor or command enqueue receipt is a command response.
pub struct Event<'a> {
    pub sequence: u8,
    pub event_id: u8,
    pub extended_event_id: u8,
    pub option: u8,
    pub packet_type_id: u16,
    pub declared_length: u16,
    pub payload: &'a [u8],
    status: u8,
    unsolicited: bool,
}
impl<'a> Event<'a> {
    pub fn is_unsolicited(&self) -> bool {
        self.unsolicited
    }
    pub fn parse(chip: Chip, bytes: &'a [u8]) -> Result<Self, Error> {
        let words = if chip == Chip::Mt7925 { 8 } else { 6 };
        let base = words * 4;
        let header = base + 12;
        if bytes.len() < header {
            return Err(Error::Truncated);
        }
        // MT_RXD0_PKT_TYPE == PKT_TYPE_RX_EVENT (7), flag1 is normal MCU RX.
        let rxd0 = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        if (rxd0 >> 27) & 31 != 7 || (rxd0 >> 16) & 15 == 1 {
            return Err(Error::NotResponse);
        }
        let eid = bytes[base + 4];
        let seq = bytes[base + 5];
        let ext = bytes[base + 8];
        let unsolicited = bytes[base + 6] & 4 != 0
            || (chip != Chip::Mt7925
                && eid != 6
                && (ext == 0x87
                    || matches!(eid, 0x07 | 0x0d | 0x0f | 0x13 | 0x23 | 0x27 | 0x96 | 0xf0)
                    || seq == 0));
        Ok(Self {
            unsolicited,
            sequence: bytes[base + 5],
            event_id: bytes[base + 4],
            extended_event_id: bytes[base + 8],
            option: bytes[base + 6],
            packet_type_id: u16::from_le_bytes(bytes[base + 2..base + 4].try_into().unwrap()),
            declared_length: u16::from_le_bytes(bytes[base..base + 2].try_into().unwrap()),
            payload: &bytes[header..],
            status: bytes[header - 4],
        })
    }
    /// Caller dispatches unsolicited events separately and keeps unmatched
    /// sequences until its deadline; this function never turns one
    /// into a successful acknowledgement.
    pub fn boot_result(&self, packet: &Packet) -> Result<u32, Error> {
        if !packet.expects_response() {
            return Err(Error::NotResponse);
        }
        if self.unsolicited || self.sequence == 0 {
            return Err(Error::Unsolicited);
        }
        if packet.sequence != self.sequence {
            return Err(Error::UnexpectedSequence {
                expected: packet.sequence,
                actual: self.sequence,
            });
        }
        Ok(
            if matches!(
                packet.command,
                Command::PatchSemaphore | Command::PatchFinish
            ) {
                u32::from(self.status)
            } else {
                0
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(chip: Chip, seq: u8, status: u8) -> Vec<u8> {
        let base = if chip == Chip::Mt7925 { 32 } else { 24 };
        let mut bytes = vec![0; base + 12];
        bytes[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
        bytes[base..base + 2].copy_from_slice(&12u16.to_le_bytes());
        bytes[base + 5] = seq;
        bytes[base + 8] = status;
        bytes
    }
    #[test]
    fn chip_specific_descriptor_and_scatter_sequence_wrap_are_exact() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut enc = Encoder::default();
            for i in 0..60 {
                let p = enc
                    .encode(chip, Command::PatchSemaphore, &[1, 0, 0, 0])
                    .unwrap();
                assert_eq!(p.sequence, (i % 15 + 1) as u8);
                assert_eq!(p.bytes.len(), 68);
                assert_eq!(&p.bytes[..4], &0x41000044u32.to_le_bytes());
                assert_eq!(
                    &p.bytes[4..8],
                    &(if chip == Chip::Mt7925 {
                        0x10000u32
                    } else {
                        0x80010000
                    })
                    .to_le_bytes()
                );
                assert_eq!(
                    &p.bytes[32..40],
                    &[36, 0, 0, 0x80, 0x10, 0xa0, 3, p.sequence]
                );
                assert_eq!(&p.bytes[64..], &[1, 0, 0, 0]);
            }
            let p = enc.encode(chip, Command::Scatter, &[9; 4096]).unwrap();
            assert_eq!(p.sequence, 1);
            assert_eq!(p.queue, Queue::FirmwareDownload);
            assert_eq!(p.bytes, [9; 4096]);
            assert!(!p.expects_response());
            assert_eq!(
                enc.encode(chip, Command::StartFirmware, &[0; 8])
                    .unwrap()
                    .sequence,
                2
            );
            assert!(matches!(
                enc.encode(chip, Command::Scatter, &[0; 4097]),
                Err(Error::InvalidPayload)
            ));
            assert!(matches!(
                enc.encode(chip, Command::PatchFinish, &[0; 3]),
                Err(Error::InvalidPayload)
            ));
        }
    }
    #[test]
    fn responses_use_real_chip_offsets_and_never_accept_stale_or_unsolicited_events() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let p = Encoder::default()
                .encode(chip, Command::PatchSemaphore, &[1, 0, 0, 0])
                .unwrap();
            for status in [0, 1, 2, 3, 255] {
                let bytes = event(chip, 1, status);
                let e = Event::parse(chip, &bytes).unwrap();
                assert_eq!(e.boot_result(&p), Ok(u32::from(status)));
                for end in 0..bytes.len() {
                    assert!(matches!(
                        Event::parse(chip, &bytes[..end]),
                        Err(Error::Truncated)
                    ));
                }
            }
            let bytes = event(chip, 2, 2);
            assert_eq!(
                Event::parse(chip, &bytes).unwrap().boot_result(&p),
                Err(Error::UnexpectedSequence {
                    expected: 1,
                    actual: 2
                })
            );
            let bytes = event(chip, 0, 2);
            assert_eq!(
                Event::parse(chip, &bytes).unwrap().boot_result(&p),
                Err(Error::Unsolicited)
            );
            let mut bytes = event(chip, 1, 2);
            let n = bytes.len();
            bytes[n - 6] = 4;
            assert_eq!(
                Event::parse(chip, &bytes).unwrap().boot_result(&p),
                Err(Error::Unsolicited)
            );
            bytes[..4].fill(0);
            assert!(matches!(
                Event::parse(chip, &bytes),
                Err(Error::NotResponse)
            ));
        }
    }
    #[test]
    #[ignore = "oracle: STELA_MT792X_MCU_ORACLE"]
    fn unchanged_pinned_mcu_encoders_match_all_bytes_over_repeated_sequence_wraps() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let root = std::path::PathBuf::from(std::env::var("STELA_MT792X_MCU_ORACLE").unwrap());
        for (chip, number, hash) in [
            (
                Chip::Mt7921,
                7921,
                "1af3c268982e5bf296393bcf6458b9ee8fcffab2b8e530fadc3c1f11d7ae4e48",
            ),
            (
                Chip::Mt7922,
                7922,
                "1af3c268982e5bf296393bcf6458b9ee8fcffab2b8e530fadc3c1f11d7ae4e48",
            ),
            (
                Chip::Mt7925,
                7925,
                "2b9695ce96709eb7efec14c3de9182f4df704b94f9eeb15cf3df86232f413856",
            ),
        ] {
            let expected = std::fs::read(root.join(alloc::format!("{number}.trace"))).unwrap();
            assert_eq!(alloc::format!("{:x}", Sha256::digest(&expected)), hash);
            let mut encoder = Encoder::default();
            let mut trace = Vec::new();
            let commands = [
                Command::Download,
                Command::StartFirmware,
                Command::PatchStart,
                Command::PatchFinish,
                Command::PatchSemaphore,
                Command::Scatter,
            ];
            for i in 0..90 {
                let command = commands[i % 6];
                let n = match command {
                    Command::Download | Command::PatchStart => 12,
                    Command::StartFirmware => 8,
                    Command::Scatter => 4096,
                    _ => 4,
                };
                let payload: Vec<u8> = (0..n).map(|j| (i * 17 + j) as u8).collect();
                let packet = encoder.encode(chip, command, &payload).unwrap();
                trace.extend_from_slice(&[command as u8, packet.sequence]);
                trace.extend_from_slice(&(packet.bytes.len() as u16).to_le_bytes());
                trace.extend_from_slice(&packet.bytes);
            }
            assert_eq!(trace, expected, "chip {number}");
        }
    }
}
