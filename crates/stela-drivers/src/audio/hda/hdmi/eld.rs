// SPDX-License-Identifier: GPL-2.0-only
//! Copyright(c) 2008 Intel Corporation
//! Copyright (c) 2013 Anssi Hannula <anssi.hannula@iki.fi>
//! ELD header fields: Copyright © 2023 Intel Corporation (MIT).
//! See audio/THIRD_PARTY.md for the MIT permission/warranty notice.
//! ELD/SAD constraints from Linux pcm_drm_eld.c and HDMI eld.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See audio/THIRD_PARTY.md.
use crate::audio::{Error, PcmFormat};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Connection {
    Hdmi,
    DisplayPort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioDescriptor {
    pub coding_type: u8,
    pub channels: u8,
    pub rates: u8,
    /// LPCM SAD sample-size bits: 16, 20, 24 in bits 0, 1, 2.
    pub sample_bits: u8,
}

/// Codec ELD snapshot. Parsing bytes alone never grants a route, port,
/// sink identity or PCM capability; the controller reads and binds the snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eld {
    raw: Vec<u8>,
    pub version: u8,
    pub connection: Connection,
    pub port_id: u64,
    pub manufacturer: u16,
    pub product: u16,
    pub monitor_name: Vec<u8>,
    pub speakers: u8,
    pub audio_sync_delay_ms: u16,
    pub supports_hdcp: bool,
    pub supports_ai: bool,
    pub descriptors: Vec<AudioDescriptor>,
}

impl Eld {
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if !(20..=256).contains(&raw.len()) || !matches!(raw[0] >> 3, 2 | 31) {
            return Err(Error::InvalidEld);
        }
        let name = usize::from(raw[4] & 31);
        let count = usize::from(raw[5] >> 4);
        let baseline = 4 + usize::from(raw[2]) * 4;
        let end = 20 + name + 3 * count;
        if name > 16 || end > raw.len() || baseline < end || baseline > raw.len() {
            return Err(Error::InvalidEld);
        }
        let connection = match (raw[5] >> 2) & 3 {
            0 => Connection::Hdmi,
            1 => Connection::DisplayPort,
            _ => return Err(Error::InvalidEld),
        };
        let descriptors = raw[20 + name..end]
            .as_chunks::<3>()
            .0
            .iter()
            .map(|sad| AudioDescriptor {
                coding_type: (sad[0] >> 3) & 15,
                channels: (sad[0] & 7) + 1,
                rates: sad[1] & 127,
                sample_bits: if (sad[0] >> 3) & 15 == 1 {
                    sad[2] & 7
                } else {
                    0
                },
            })
            .collect();
        Ok(Self {
            raw: raw.to_vec(),
            version: raw[0] >> 3,
            connection,
            port_id: u64::from_le_bytes(raw[8..16].try_into().unwrap()),
            manufacturer: u16::from_le_bytes(raw[16..18].try_into().unwrap()),
            product: u16::from_le_bytes(raw[18..20].try_into().unwrap()),
            monitor_name: raw[20..20 + name].to_vec(),
            speakers: raw[7] & 127,
            audio_sync_delay_ms: u16::from(raw[6]) * 2,
            supports_hdcp: raw[5] & 1 != 0,
            supports_ai: raw[5] & 2 != 0,
            descriptors,
        })
    }
    /// Keep rate/channel/size restrictions from the SAME LPCM SAD. Compressed
    /// descriptors never widen PCM. Basic 2ch/16bit 32/44.1/48k is the donor's
    /// mandatory HDMI audio baseline, only after a real valid ELD was observed.
    pub fn supports(&self, format: PcmFormat) -> bool {
        if format.encode().is_err() || !matches!(format.channels, 2 | 4 | 6 | 8) {
            return false;
        }
        let rate = match format.rate {
            32000 => 0,
            44100 => 1,
            48000 => 2,
            88200 => 3,
            96000 => 4,
            176400 => 5,
            192000 => 6,
            _ => return false,
        };
        let bits = match format.bits {
            16 => 1,
            20 => 2,
            24 => 4,
            _ => return false,
        };
        (format.channels == 2 && bits == 1 && rate <= 2)
            || self.descriptors.iter().any(|sad| {
                sad.coding_type == 1
                    && sad.channels >= format.channels
                    && sad.rates & (1 << rate) != 0
                    && sad.sample_bits & bits != 0
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes() -> [u8; 32] {
        let mut b = [0; 32];
        b[0] = 0x10;
        b[2] = 7;
        b[5] = 0x20;
        b[7] = 0x4f;
        b[20] = 0x0f;
        b[21] = 0x40;
        b[22] = 4;
        b[23] = 0x09;
        b[24] = 4;
        b[25] = 1;
        b
    }
    #[test]
    fn sad_constraints_are_per_descriptor() {
        let eld = Eld::parse(&bytes()).unwrap();
        assert!(eld.supports(PcmFormat {
            rate: 192000,
            bits: 24,
            channels: 8
        }));
        assert!(!eld.supports(PcmFormat {
            rate: 48000,
            bits: 24,
            channels: 8
        }));
        assert!(eld.supports(PcmFormat {
            rate: 48000,
            bits: 16,
            channels: 2
        }));
        let mut b = bytes();
        b[20] = 0x17;
        let eld = Eld::parse(&b).unwrap();
        assert!(!eld.supports(PcmFormat {
            rate: 192000,
            bits: 24,
            channels: 8
        }));
    }
    #[test]
    fn malformed_lengths_versions_and_connection_are_rejected() {
        for index in 0..5 {
            let mut b = bytes();
            match index {
                0 => b[0] = 8,
                1 => b[4] = 31,
                2 => b[2] = 1,
                3 => b[5] = 0xf0,
                _ => b[5] |= 8,
            };
            assert_eq!(Eld::parse(&b), Err(Error::InvalidEld));
        }
        assert_eq!(Eld::parse(&[0; 19]), Err(Error::InvalidEld));
    }
}
