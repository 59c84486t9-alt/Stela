// SPDX-License-Identifier: GPL-2.0-only
//! Bounded ELD/CTA SAD fields adapted from Linux sound/core/pcm_drm_eld.c
//! (GPL-2.0-only), include/drm/drm_eld.h (MIT, Copyright © 2023 Intel
//! Corporation), and sound/hda/codecs/hdmi/eld.c. See audio/THIRD_PARTY.md.
use super::{DigitalError, PIN_DP, PIN_HDMI};
use crate::PcmFormat;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigitalConnection {
    Hdmi,
    DisplayPort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortAudioDescriptor {
    raw: [u8; 3],
}
impl ShortAudioDescriptor {
    pub fn raw(self) -> [u8; 3] {
        self.raw
    }
    pub fn coding(self) -> u8 {
        (self.raw[0] >> 3) & 15
    }
    pub fn channels(self) -> u8 {
        (self.raw[0] & 7) + 1
    }
    pub fn rates(self) -> u8 {
        self.raw[1] & 127
    }
    fn supports(self, format: PcmFormat) -> bool {
        let rate = match format.rate {
            32_000 => 0,
            44_100 => 1,
            48_000 => 2,
            88_200 => 3,
            96_000 => 4,
            176_400 => 5,
            192_000 => 6,
            _ => return false,
        };
        let bits = match format.bits {
            16 => 0,
            20 => 1,
            24 => 2,
            _ => return false,
        };
        self.coding() == 1
            && (1..=self.channels()).contains(&format.channels)
            && self.rates() & (1 << rate) != 0
            && self.raw[2] & (1 << bits) != 0
    }
}

/// Historical metadata, never a display-session or protection grant.
#[derive(Debug)]
pub struct DigitalSink {
    raw: Vec<u8>,
    pub version: u8,
    pub partial: bool,
    pub connection: DigitalConnection,
    pub edid_version: u8,
    pub port_id: u64,
    pub manufacturer: u16,
    pub product: u16,
    pub speaker_mask: u8,
    pub sync_delay_ms: u16,
    pub supports_ai: bool,
    pub reports_hdcp: bool,
    monitor_name: Vec<u8>,
    descriptors: Vec<ShortAudioDescriptor>,
}
impl DigitalSink {
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn monitor_name(&self) -> &[u8] {
        &self.monitor_name
    }
    pub fn descriptors(&self) -> &[ShortAudioDescriptor] {
        &self.descriptors
    }
    /// Checks this historical ELD alone; use Controller::digital_pcm_supported
    /// for a fresh poll and converter/link-capability intersection.
    /// Canned/partial ELD never grants PCM and no basic-audio fallback is invented.
    pub fn supports_pcm(&self, format: PcmFormat) -> bool {
        !self.partial
            && format.encode().is_ok()
            && self.descriptors.iter().any(|sad| sad.supports(format))
    }
}

pub(super) fn parse(raw: Vec<u8>, pin_caps: u32) -> Result<DigitalSink, DigitalError> {
    if !(20..=256).contains(&raw.len()) {
        return Err(DigitalError::InvalidEld);
    }
    let version = raw[0] >> 3;
    if version != 2 && version != 31 {
        return Err(DigitalError::UnsupportedEldVersion(version));
    }
    let connection = match (raw[5] >> 2) & 3 {
        0 if pin_caps & PIN_HDMI != 0 => DigitalConnection::Hdmi,
        1 if pin_caps & PIN_DP != 0 => DigitalConnection::DisplayPort,
        _ => return Err(DigitalError::UnsupportedConnection),
    };
    let name_length = usize::from(raw[4] & 31);
    let count = usize::from(raw[5] >> 4);
    let baseline_end = 4 + usize::from(raw[2]) * 4;
    let descriptor_start = 20 + name_length;
    let descriptor_end = descriptor_start + count * 3;
    if name_length > 16 || descriptor_end > baseline_end || baseline_end > raw.len() {
        return Err(DigitalError::InvalidEld);
    }
    let descriptors = raw[descriptor_start..descriptor_end]
        .as_chunks::<3>()
        .0
        .iter()
        .map(|sad| ShortAudioDescriptor {
            raw: [sad[0], sad[1], sad[2]],
        })
        .collect();
    Ok(DigitalSink {
        version,
        partial: version == 31,
        connection,
        edid_version: raw[4] >> 5,
        port_id: u64::from_le_bytes(
            raw[8..16]
                .try_into()
                .map_err(|_| DigitalError::InvalidEld)?,
        ),
        manufacturer: u16::from_le_bytes([raw[16], raw[17]]),
        product: u16::from_le_bytes([raw[18], raw[19]]),
        speaker_mask: raw[7] & 127,
        sync_delay_ms: u16::from(raw[6]) * 2,
        supports_ai: raw[5] & 2 != 0,
        reports_hdcp: raw[5] & 1 != 0,
        monitor_name: raw[20..descriptor_start].to_vec(),
        descriptors,
        raw,
    })
}
