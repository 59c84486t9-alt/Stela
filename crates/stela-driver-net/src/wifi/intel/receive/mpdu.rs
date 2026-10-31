// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2025 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! Source RX-MPDU descriptor observations from CPU-owned notification bytes.
//! This preserves raw status; it does not authenticate a frame, resolve a key
//! generation/association epoch, validate replay, normalize a MAC or release DMA.
use super::Packet;
use crate::bytes::{le16, le32, le64};
pub mod normalize;
use crate::wifi::intel::firmware::{Family, Firmware};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotMpdu,
    PacketLength,
    Version(Option<u8>),
    DescriptorLength { minimum: usize, actual: usize },
    MpduLength { declared: usize, available: usize },
}
// `IWL_RX_MPDU_STATUS_*` bits and the `IWL_RX_MPDU_STATUS_SEC_*` values of
// `Status::cipher_code`, from iwlwifi `fw/api/rx.h`.
const STATUS_SRC_STA_FOUND: u32 = 1 << 2;
const STATUS_KEY_VALID: u32 = 1 << 3;
const STATUS_ICV_OK: u32 = 1 << 5;
const STATUS_MIC_OK: u32 = 1 << 6;
const STATUS_REPLAY_ERROR: u32 = 1 << 7;
const STATUS_DECRYPTED: u32 = 1 << 11;
const STATUS_DUPLICATE: u32 = 1 << 22;
pub const SEC_NONE: u8 = 0;
pub const SEC_WEP: u8 = 1;
pub const SEC_CCM: u8 = 2;
pub const SEC_TKIP: u8 = 3;
pub const SEC_EXT_ENC: u8 = 4;
pub const SEC_GCM: u8 = 5;
pub const SEC_UNKNOWN: u8 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    raw: u32,
    deprecate_ttak: bool,
}
impl Status {
    pub fn raw(self) -> u32 {
        self.raw
    }
    pub fn failed_fcs_or_overrun(self) -> bool {
        self.raw & 3 != 3
    }
    pub fn key_valid_bit(self) -> bool {
        self.raw & STATUS_KEY_VALID != 0
    }
    pub fn icv_ok_bit(self) -> bool {
        self.raw & STATUS_ICV_OK != 0
    }
    pub fn mic_ok_bit(self) -> bool {
        self.raw & STATUS_MIC_OK != 0
    }
    pub fn decrypted_bit(self) -> bool {
        self.raw & STATUS_DECRYPTED != 0
    }
    pub fn duplicate_bit(self) -> bool {
        self.raw & STATUS_DUPLICATE != 0
    }
    pub fn cipher_code(self) -> u8 {
        ((self.raw >> 8) & 7) as u8
    }
    pub fn station_id(self) -> Option<u8> {
        (self.raw & STATUS_SRC_STA_FOUND != 0).then_some(((self.raw >> 24) & 31) as u8)
    }
    /// These remain bit observations. A false replay-error bit is never a
    /// software PN check or proof of a current installed key.
    pub fn replay_or_ttak(self) -> ReplayOrTtak {
        if self.deprecate_ttak {
            ReplayOrTtak::ReplayError(self.raw & STATUS_REPLAY_ERROR != 0)
        } else {
            ReplayOrTtak::TtakOk(self.raw & STATUS_REPLAY_ERROR != 0)
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayOrTtak {
    TtakOk(bool),
    ReplayError(bool),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reorder {
    pub raw: u32,
    pub next_sequence: u16,
    pub sequence: u16,
    pub ba_id: Option<u8>,
    pub old_sequence: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timestamp {
    Counter(u64),
    Overloaded { low: u32, high: u32 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    /// Unvalidated source two-bit code; reserved 3 is not changed to 5 GHz.
    Explicit(u8),
    /// Source fallback when BAND_IN_RX_DATA API 59 is not present.
    ChannelInferred { five_ghz: bool },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Radio {
    /// Negotiated notification 4/5 carries this unchanged hardware rate word.
    /// The separate complete source rates-ABI check is needed before decoding.
    pub raw_rate: u32,
    pub energy: [u8; 2],
    pub channel: u8,
    pub mac_context: u8,
    pub mac_phy_band: u8,
    pub band: Band,
    pub gp2_on_air_rise: u32,
    pub timestamp: Timestamp,
    pub raw_timestamp: u64,
    pub phy_data0: u32,
    pub phy_data1: u32,
    pub phy_data2: u32,
    pub phy_data3: u32,
    pub phy_word4: u32,
    pub phy_data5: Option<u32>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mac {
    pub flags1: u8,
    pub flags2: u8,
    pub amsdu_info: u8,
    pub phy_info: u16,
}
impl Mac {
    pub fn padding_bytes(self) -> usize {
        if self.flags2 & 0x20 != 0 { 2 } else { 0 }
    }
    pub fn mic_crc_tail_bytes(self) -> usize {
        usize::from(self.flags1 >> 4) * 2
    }
    pub fn reported_header_bytes(self) -> usize {
        usize::from(self.flags2 & 31) * 2
    }
    pub fn amsdu(self) -> bool {
        self.flags2 & 0x40 != 0
    }
    pub fn amsdu_index(self) -> u8 {
        self.amsdu_info & 127
    }
    pub fn amsdu_last(self) -> bool {
        self.amsdu_info & 128 != 0
    }
    pub fn ampdu(self) -> bool {
        self.phy_info & 0x20 != 0
    }
    pub fn ampdu_toggle(self) -> bool {
        self.phy_info & 0x40 != 0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation<'a> {
    packet_flags: u32,
    descriptor: &'a [u8],
    raw_mpdu: &'a [u8],
    trailing: &'a [u8],
    pub mac: Mac,
    pub status: Status,
    pub reorder: Reorder,
    pub radio: Radio,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub mac: Mac,
    pub status: Status,
    pub reorder: Reorder,
    pub radio: Radio,
}
impl<'a> Observation<'a> {
    pub fn parse(fw: &Firmware<'_>, family: Family, packet: &Packet<'a>) -> Result<Self, Error> {
        Self::parse_raw(fw, family, packet.raw())
    }
    pub(crate) fn parse_raw(
        fw: &Firmware<'_>,
        family: Family,
        raw: &'a [u8],
    ) -> Result<Self, Error> {
        if raw.len() < 8 || (le32(raw, 0) & 0x3fff) as usize + 4 != raw.len() {
            return Err(Error::PacketLength);
        }
        // Public Packet diagnostics are mutable; bind command identity to its
        // immutable raw bytes, not a caller-retagged command/group.
        if raw[4..6] != [0xc1, 0] {
            return Err(Error::NotMpdu);
        }
        let version = fw.command_version(0, 0xc1).map(|v| v.notification_version);
        let accepted = match family {
            Family::Ax200 => 4..=4,
            Family::Ax210 => 5..=5,
            Family::Bz | Family::Sc => 6..=8,
        };
        if !version.is_some_and(|version| accepted.contains(&version)) {
            return Err(Error::Version(version));
        }
        let packet_flags = le32(raw, 0);
        let d = &raw[8..];
        let size = if family == Family::Ax200 { 48 } else { 64 };
        if d.len() < size {
            return Err(Error::DescriptorLength {
                minimum: size,
                actual: d.len(),
            });
        }
        let len = usize::from(le16(d, 0));
        let available = d.len() - size;
        if len > available {
            return Err(Error::MpduLength {
                declared: len,
                available,
            });
        }
        let mac = Mac {
            flags1: d[2],
            flags2: d[3],
            amsdu_info: d[4],
            phy_info: le16(d, 5),
        };
        let status = Status {
            raw: le32(d, 12),
            deprecate_ttak: fw.supports_api(41),
        };
        let raw = le32(d, 16);
        let ba = ((raw >> 24) & 127) as u8;
        let reorder = Reorder {
            raw,
            next_sequence: (raw & 0xfff) as u16,
            sequence: ((raw >> 12) & 0xfff) as u16,
            ba_id: (ba != 127).then_some(ba),
            old_sequence: raw >> 31 != 0,
        };
        let (rate, energy, gp2, tsf, p2, p3, p5) = if family == Family::Ax200 {
            (28, 32, 36, 40, 20, 24, None)
        } else {
            (36, 40, 44, 48, 24, 20, Some(le32(d, 56)))
        };
        let raw_timestamp = le64(d, tsf);
        let timestamp = if mac.phy_info & 0x100 != 0 {
            Timestamp::Overloaded {
                low: le32(d, tsf),
                high: le32(d, tsf + 4),
            }
        } else {
            Timestamp::Counter(raw_timestamp)
        };
        let channel = d[energy + 2];
        let radio = Radio {
            raw_rate: le32(d, rate),
            energy: [d[energy], d[energy + 1]],
            channel,
            mac_context: d[energy + 3],
            mac_phy_band: d[7],
            band: if fw.supports_api(59) {
                Band::Explicit(d[7] >> 6)
            } else {
                Band::ChannelInferred {
                    five_ghz: channel > 14,
                }
            },
            gp2_on_air_rise: le32(d, gp2),
            timestamp,
            raw_timestamp,
            phy_data0: le32(d, tsf),
            phy_data1: le32(d, tsf + 4),
            phy_data2: le32(d, p2),
            phy_data3: le32(d, p3),
            phy_word4: le32(d, 8),
            phy_data5: p5,
        };
        Ok(Self {
            packet_flags,
            descriptor: &d[..size],
            raw_mpdu: &d[size..size + len],
            trailing: &d[size + len..],
            mac,
            status,
            reorder,
            radio,
        })
    }
    pub fn descriptor(&self) -> &'a [u8] {
        self.descriptor
    }
    /// Still includes source IV, optional padding after MAC+IV, and the
    /// represented MIC/CRC tail. This is not a normalized shared MAC frame.
    pub fn raw_mpdu(&self) -> &'a [u8] {
        self.raw_mpdu
    }
    pub fn trailing(&self) -> &'a [u8] {
        self.trailing
    }
    pub fn metadata(&self) -> Metadata {
        Metadata {
            mac: self.mac,
            status: self.status,
            reorder: self.reorder,
            radio: self.radio,
        }
    }
}

#[cfg(test)]
mod tests;
