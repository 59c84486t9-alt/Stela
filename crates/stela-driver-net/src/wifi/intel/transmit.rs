// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2005-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! Pure initial non-QoS new-TX-API command serialization. This is not a
//! station/key/regulatory lease, DMA publication or proof of transmission.
use super::{
    command::{FIRST_TB_BYTES, Tfd},
    context::Region,
    firmware::{Family, Firmware},
};
use alloc::vec::Vec;
pub mod queue;
pub mod response;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    MissingApi { group: u8, command: u8 },
    CommandVersion(u8),
    RateVersions,
    FrameLength,
    FrameControl,
    Fragment,
    Encryption,
    Antenna,
    Queue,
    Split,
    Descriptor(super::command::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyRate {
    Cck1,
    Cck2,
    Cck5_5,
    Cck11,
    Ofdm6,
    Ofdm9,
    Ofdm12,
    Ofdm18,
    Ofdm24,
    Ofdm36,
    Ofdm48,
    Ofdm54,
}
impl LegacyRate {
    fn rate_v2(self) -> u32 {
        match self {
            Self::Cck1 => 0,
            Self::Cck2 => 1,
            Self::Cck5_5 => 2,
            Self::Cck11 => 3,
            Self::Ofdm6 => 0x100,
            Self::Ofdm9 => 0x101,
            Self::Ofdm12 => 0x102,
            Self::Ofdm18 => 0x103,
            Self::Ofdm24 => 0x104,
            Self::Ofdm36 => 0x105,
            Self::Ofdm48 => 0x106,
            Self::Ofdm54 => 0x107,
        }
    }
}
/// Pure inputs corresponding to the source station and rate selection. These
/// copied observations grant no station, antenna, rate or key permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub station_authorized: Option<bool>,
    /// Source explicit host/injected-rate path, distinct from firmware RS.
    pub force_host_rate: bool,
    pub host_rate: LegacyRate,
    /// Source selected A=1 or B=2, not a PHY mask/default selection.
    pub host_antenna: u8,
    /// Future owner must keep the generation-bound firmware key and
    /// firmware nonce context through publication and all completion/drain.
    pub firmware_encryption: bool,
}
#[derive(Debug)]
pub struct Prepared {
    family: Family,
    command_and_mac: Vec<u8>,
    payload: Vec<u8>,
    mpdu_bytes: u16,
    host_rate: Option<u32>,
}
/// Complete source command/notification consistency for the admitted initial
/// format-2 families. Shared by native TX preparation and RX normalization.
pub(crate) fn rate_format_2(fw: &Firmware<'_>, family: Family) -> Result<(), Error> {
    let lookup = |group, command| {
        fw.command_version(group, command)
            .ok_or(Error::MissingApi { group, command })
    };
    let tx = lookup(1, 0x1c)?;
    let expected = if family == Family::Ax200 { 9 } else { 10 };
    if tx.command_version != expected {
        return Err(Error::CommandVersion(tx.command_version));
    }
    // Complete source ops.c format2/3 consistency checks. This initial
    // encoder admits only the source-matched format2 schemas above.
    let tlc = lookup(5, 0xf7)?.notification_version;
    let rx = lookup(0, 0xc1)?.notification_version;
    let checks2 = [
        tx.command_version >= 8,
        tlc >= 3,
        rx >= 4,
        tx.notification_version >= 6,
    ];
    let checks3 = [
        tx.command_version >= 11,
        tlc >= 4,
        rx >= 6,
        fw.command_version(5, 0xf5)
            .is_some_and(|v| v.notification_version >= 4),
        tx.notification_version >= 9,
    ];
    if !checks2.iter().all(|v| *v) || checks3.iter().any(|v| *v) {
        return Err(Error::RateVersions);
    }
    Ok(())
}
impl Prepared {
    pub fn prepare(
        fw: &Firmware<'_>,
        family: Family,
        mpdu: &[u8],
        parameters: Parameters,
    ) -> Result<Self, Error> {
        rate_format_2(fw, family)?;
        // Explicit bounded initial profile: full 24-byte non-QoS MAC header,
        // ordinary ToDS data or management; no fragmentation, MFP, checksum,
        // aggregation, four-address, HT-control or host-generated crypto bytes.
        if !(24..=4096).contains(&mpdu.len()) {
            return Err(Error::FrameLength);
        }
        let fc = u16::from_le_bytes(mpdu[..2].try_into().unwrap());
        let data = fc & 0x00fc == 0x0008;
        let management = fc & 0x000c == 0;
        if fc & 3 != 0
            || fc & 0x8000 != 0
            || !(data || management)
            || (data && fc & 0x0300 != 0x0100)
            || (management && fc & 0x0300 != 0)
        {
            return Err(Error::FrameControl);
        }
        if fc & 0x0400 != 0 || mpdu[22] & 0x0f != 0 {
            return Err(Error::Fragment);
        }
        if parameters.firmware_encryption != (fc & 0x4000 != 0)
            || (management && parameters.firmware_encryption)
        {
            return Err(Error::Encryption);
        }
        let use_host = parameters.station_authorized.is_none()
            || parameters.force_host_rate
            || !data
            || parameters.station_authorized != Some(true);
        let rate = if use_host {
            if ![1, 2].contains(&parameters.host_antenna) {
                return Err(Error::Antenna);
            }
            Some(parameters.host_rate.rate_v2() | u32::from(parameters.host_antenna) << 14)
        } else {
            None
        };
        let flags = u16::from(use_host) | if parameters.firmware_encryption { 0 } else { 2 };
        let mut bytes = alloc::vec![0; if family == Family::Ax200 {20} else {28}];
        bytes[..2].copy_from_slice(&(mpdu.len() as u16).to_le_bytes());
        if family == Family::Ax200 {
            bytes[2..4].copy_from_slice(&0x0c00u16.to_le_bytes());
            bytes[4..8].copy_from_slice(&u32::from(flags).to_le_bytes());
        } else {
            bytes[2..4].copy_from_slice(&flags.to_le_bytes());
            bytes[4..8].copy_from_slice(&0x0c00u32.to_le_bytes());
        }
        // DRAM security info (8..16) is firmware-owned storage, not an observed
        // PN or host seed. AX210 reserved tail (20..28) stays zero.
        bytes[16..20].copy_from_slice(&rate.unwrap_or(0).to_le_bytes());
        bytes.extend(&mpdu[..24]);
        Ok(Self {
            family,
            command_and_mac: bytes,
            payload: mpdu[24..].to_vec(),
            mpdu_bytes: mpdu.len() as u16,
            host_rate: rate,
        })
    }
    pub fn command_and_mac(&self) -> &[u8] {
        &self.command_and_mac
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn host_rate(&self) -> Option<u32> {
        self.host_rate
    }
    /// TVQM queue identity is 9-bit; the source echo sequence
    /// contains only its low5 bits. Completion must use the complete
    /// source response queue and kept epoch, never this echo alone.
    pub fn encode(&self, queue: u16, index: u16) -> Result<Encoded, Error> {
        if queue >= 512 {
            return Err(Error::Queue);
        }
        let sequence = ((queue & 0x1f) << 8) | (index & 0xff);
        let mut command = alloc::vec![0x1c, 0];
        command.extend(sequence.to_le_bytes());
        command.extend(&self.command_and_mac);
        Ok(Encoded {
            family: self.family,
            queue,
            sequence,
            command,
            payload: self.payload.clone(),
            mpdu_bytes: self.mpdu_bytes,
        })
    }
}
#[derive(Debug)]
pub struct Encoded {
    family: Family,
    queue: u16,
    sequence: u16,
    command: Vec<u8>,
    payload: Vec<u8>,
    mpdu_bytes: u16,
}
impl Encoded {
    pub fn queue(&self) -> u16 {
        self.queue
    }
    pub fn sequence(&self) -> u16 {
        self.sequence
    }
    pub fn command(&self) -> &[u8] {
        &self.command
    }
    /// Source TB0 is bidirectional coherent firmware storage; callers
    /// must not map it read-only or overwrite before a real CPU handoff.
    pub fn first_tb(&self) -> &[u8] {
        &self.command[..FIRST_TB_BYTES]
    }
    pub fn second_tb(&self) -> &[u8] {
        &self.command[FIRST_TB_BYTES..]
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Wire inputs only; Region values do not prove live mappings/visibility.
    pub fn tfd(
        &self,
        first: Region,
        second: Region,
        payload: Option<Region>,
    ) -> Result<(Tfd, u16), Error> {
        if first.bytes != self.first_tb().len() || second.bytes != self.second_tb().len() {
            return Err(Error::Split);
        }
        let mut regions = alloc::vec![first, second];
        match (self.payload.is_empty(), payload) {
            (true, None) => (),
            (false, Some(region)) if region.bytes == self.payload.len() => regions.push(region),
            _ => return Err(Error::Split),
        }
        let tfd = Tfd::encode(&regions).map_err(Error::Descriptor)?;
        // Two/three TBs occupy <=64 bytes, hence zero fetch-chunk extension.
        let byte_count = if self.family == Family::Ax200 {
            self.mpdu_bytes.div_ceil(4)
        } else {
            self.mpdu_bytes
        };
        Ok((tfd, byte_count))
    }
}

#[cfg(test)]
mod tests;
