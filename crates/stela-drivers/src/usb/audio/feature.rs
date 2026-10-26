// SPDX-License-Identifier: GPL-2.0-or-later
//! Descriptor-qualified scalar feature controls, adapted from Linux mixer.c.
//! Copyright (c) 2002 Takashi Iwai; original audio.c contributions by Alan Cox
//! and Thomas Sailer. See audio/THIRD_PARTY.md for exact donor and limits.
use super::{Control, Error, Graph, UAC1, UAC2, UAC3, control};
use alloc::vec::Vec;

/// Standard scalar feature controls beyond the existing mute/volume API.
/// Graphic equalizer, overflow/underflow and latency have distinct protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FeatureControl {
    Bass = 3,
    Mid = 4,
    Treble = 5,
    AutomaticGain = 7,
    Delay = 8,
    BassBoost = 9,
    Loudness = 10,
    InputGain = 11,
    InputGainPad = 12,
    PhaseInverter = 13,
}

/// Native device units. Tone is the signed eight-bit feature value; gain uses
/// 1/256 dB. Delay preserves the protocol's raw unsigned delay units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureValue {
    Tone(i8),
    GainDb256(i16),
    Delay(u32),
    Enabled(bool),
}

/// One actual numeric range in the selected control's native device units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureRange {
    pub min: i64,
    pub max: i64,
    pub resolution: u32,
}
impl FeatureRange {
    fn contains(self, value: i64) -> bool {
        value >= self.min
            && value <= self.max
            && if self.resolution == 0 {
                value == self.min && self.min == self.max
            } else {
                (value - self.min) % i64::from(self.resolution) == 0
            }
    }
}

#[derive(Clone, Copy)]
enum Layout {
    Tone,
    Gain,
    Delay16,
    Delay32,
    Boolean,
}
impl FeatureControl {
    pub(super) fn from_selector(selector: u8) -> Option<Self> {
        Some(match selector {
            3 => Self::Bass,
            4 => Self::Mid,
            5 => Self::Treble,
            7 => Self::AutomaticGain,
            8 => Self::Delay,
            9 => Self::BassBoost,
            10 => Self::Loudness,
            11 => Self::InputGain,
            12 => Self::InputGainPad,
            13 => Self::PhaseInverter,
            _ => return None,
        })
    }
    pub(super) fn selector(self) -> u8 {
        self as u8
    }
    fn layout(self, protocol: u8) -> Result<Layout, Error> {
        if !matches!(protocol, UAC1 | UAC2 | UAC3) {
            return Err(Error::Unsupported("scalar feature control protocol"));
        }
        Ok(match self {
            Self::Bass | Self::Mid | Self::Treble => Layout::Tone,
            Self::AutomaticGain | Self::BassBoost | Self::Loudness => Layout::Boolean,
            Self::Delay if protocol == UAC1 => Layout::Delay16,
            Self::Delay => Layout::Delay32,
            Self::InputGain | Self::InputGainPad if protocol != UAC1 => Layout::Gain,
            Self::PhaseInverter if protocol != UAC1 => Layout::Boolean,
            _ => return Err(Error::Unsupported("UAC2/UAC3-only feature control")),
        })
    }
    pub(super) fn has_range(self) -> bool {
        matches!(
            self,
            Self::Bass
                | Self::Mid
                | Self::Treble
                | Self::Delay
                | Self::InputGain
                | Self::InputGainPad
        )
    }
}
impl Layout {
    fn bytes(self) -> usize {
        match self {
            Self::Tone | Self::Boolean => 1,
            Self::Gain | Self::Delay16 => 2,
            Self::Delay32 => 4,
        }
    }
    fn numeric(self, bytes: &[u8], resolution: bool) -> i64 {
        match self {
            Self::Tone if !resolution => i64::from(bytes[0] as i8),
            Self::Gain if !resolution => i64::from(i16::from_le_bytes(bytes.try_into().unwrap())),
            Self::Tone | Self::Boolean => i64::from(bytes[0]),
            Self::Gain | Self::Delay16 => i64::from(u16::from_le_bytes(bytes.try_into().unwrap())),
            Self::Delay32 => i64::from(u32::from_le_bytes(bytes.try_into().unwrap())),
        }
    }
    fn decode(self, bytes: &[u8]) -> Result<FeatureValue, Error> {
        Ok(match self {
            Self::Tone => FeatureValue::Tone(bytes[0] as i8),
            Self::Gain => FeatureValue::GainDb256(i16::from_le_bytes(bytes.try_into().unwrap())),
            Self::Delay16 | Self::Delay32 => FeatureValue::Delay(self.numeric(bytes, false) as u32),
            Self::Boolean => match bytes[0] {
                0 => FeatureValue::Enabled(false),
                1 => FeatureValue::Enabled(true),
                _ => return Err(Error::ControlReadback),
            },
        })
    }
    fn encode(self, value: FeatureValue) -> Result<(i64, [u8; 4]), Error> {
        let (numeric, bytes) = match (self, value) {
            (Self::Tone, FeatureValue::Tone(v)) => (i64::from(v), [v as u8, 0, 0, 0]),
            (Self::Gain, FeatureValue::GainDb256(v)) => {
                let [lo, hi] = v.to_le_bytes();
                (i64::from(v), [lo, hi, 0, 0])
            }
            (Self::Delay16, FeatureValue::Delay(v)) if v <= u32::from(u16::MAX) => {
                (i64::from(v), v.to_le_bytes())
            }
            (Self::Delay32, FeatureValue::Delay(v)) => (i64::from(v), v.to_le_bytes()),
            (Self::Boolean, FeatureValue::Enabled(v)) => (i64::from(v), [u8::from(v), 0, 0, 0]),
            _ => return Err(Error::Format),
        };
        Ok((numeric, bytes))
    }
}

impl Graph {
    pub fn feature_value<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        channel: u8,
        feature: FeatureControl,
    ) -> Result<FeatureValue, Error> {
        let layout = feature.layout(self.protocol)?;
        self.feature(id, channel, feature.selector(), false)?;
        let request = if self.protocol == UAC1 { 0x81 } else { 1 };
        let bytes = control::get(
            io,
            self.control_interface,
            id,
            feature.selector(),
            channel,
            request,
            layout.bytes() as u16,
        )?;
        layout.decode(&bytes)
    }
    /// Read actual numeric ranges before a set. Booleans have CUR only.
    pub fn feature_ranges<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        channel: u8,
        feature: FeatureControl,
    ) -> Result<Vec<FeatureRange>, Error> {
        let layout = feature.layout(self.protocol)?;
        self.feature(id, channel, feature.selector(), false)?;
        if !feature.has_range() {
            return Err(Error::Unsupported("boolean feature control has no RANGE"));
        }
        let width = layout.bytes();
        let get = |io: &mut C, request, bytes| {
            control::get(
                io,
                self.control_interface,
                id,
                feature.selector(),
                channel,
                request,
                bytes,
            )
        };
        let bytes = if self.protocol == UAC1 {
            let mut bytes = Vec::with_capacity(width * 3);
            for request in [0x82, 0x83, 0x84] {
                bytes.extend_from_slice(&get(io, request, width as u16)?);
            }
            bytes
        } else {
            let count = u16::from_le_bytes(get(io, 2, 2)?.try_into().unwrap());
            if !(1..=64).contains(&count) {
                return Err(Error::Descriptor("scalar feature range count"));
            }
            let bytes = get(io, 2, (2 + usize::from(count) * 3 * width) as u16)?;
            if u16::from_le_bytes(bytes[..2].try_into().unwrap()) != count {
                return Err(Error::ControlReadback);
            }
            bytes[2..].to_vec()
        };
        let mut ranges = Vec::with_capacity(bytes.len() / (3 * width));
        for raw in bytes.chunks_exact(3 * width) {
            let range = FeatureRange {
                min: layout.numeric(&raw[..width], false),
                max: layout.numeric(&raw[width..width * 2], false),
                resolution: layout.numeric(&raw[width * 2..], true) as u32,
            };
            if range.min > range.max || (range.resolution == 0 && range.min != range.max) {
                return Err(Error::Descriptor("scalar feature range"));
            }
            ranges.push(range);
        }
        Ok(ranges)
    }
    pub fn set_feature_value<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        channel: u8,
        feature: FeatureControl,
        value: FeatureValue,
    ) -> Result<(), Error> {
        let layout = feature.layout(self.protocol)?;
        self.feature(id, channel, feature.selector(), true)?;
        let (numeric, bytes) = layout.encode(value)?;
        if feature.has_range()
            && !self
                .feature_ranges(io, id, channel, feature)?
                .iter()
                .any(|range| range.contains(numeric))
        {
            return Err(Error::Format);
        }
        control::set(
            io,
            self.control_interface,
            id,
            feature.selector(),
            channel,
            &bytes[..layout.bytes()],
        )?;
        if self.feature_value(io, id, channel, feature)? != value {
            return Err(Error::ControlReadback);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
