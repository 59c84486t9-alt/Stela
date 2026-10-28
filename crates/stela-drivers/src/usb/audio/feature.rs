// SPDX-License-Identifier: GPL-2.0-or-later
//! Descriptor-qualified scalar feature controls, adapted from Linux mixer.c.
//! Copyright (c) 2002 Takashi Iwai; original audio.c contributions by Alan Cox
//! and Thomas Sailer. See audio/THIRD_PARTY.md for exact donor and limits.
use super::{
    Control, Error, Graph, MixerRange, UAC1, UAC2, UAC3,
    control::{self, Width},
};

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
    /// The donor's `audio_feature_info` value types: S8 tone, S16 gain, U16
    /// or (UAC2 and later) U32 delay, booleans.
    fn width(self) -> Width {
        let (bytes, signed) = match self {
            Self::Tone => (1, true),
            Self::Boolean => (1, false),
            Self::Gain => (2, true),
            Self::Delay16 => (2, false),
            Self::Delay32 => (4, false),
        };
        Width { bytes, signed }
    }
    /// A boolean reads as `!!val`, as `get_relative_value` has it.
    fn decode(self, bytes: &[u8]) -> FeatureValue {
        let value = self.width().decode(bytes);
        match self {
            Self::Tone => FeatureValue::Tone(value as i8),
            Self::Gain => FeatureValue::GainDb256(value as i16),
            Self::Delay16 | Self::Delay32 => FeatureValue::Delay(value as u32),
            Self::Boolean => FeatureValue::Enabled(value != 0),
        }
    }
    fn numeric(self, value: FeatureValue) -> Result<i64, Error> {
        Ok(match (self, value) {
            (Self::Tone, FeatureValue::Tone(v)) => i64::from(v),
            (Self::Gain, FeatureValue::GainDb256(v)) => i64::from(v),
            (Self::Delay16, FeatureValue::Delay(v)) if v <= u32::from(u16::MAX) => i64::from(v),
            (Self::Delay32, FeatureValue::Delay(v)) => i64::from(v),
            (Self::Boolean, FeatureValue::Enabled(v)) => i64::from(v),
            _ => return Err(Error::Format),
        })
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
            layout.width().bytes,
        )?;
        Ok(layout.decode(&bytes))
    }
    /// Probe a numeric control's range once, before its first set, as
    /// `get_min_max_with_quirks` does. Booleans have CUR only.
    pub fn feature_range<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        channel: u8,
        feature: FeatureControl,
    ) -> Result<MixerRange, Error> {
        let layout = feature.layout(self.protocol)?;
        self.feature(id, channel, feature.selector(), false)?;
        if !feature.has_range() {
            return Err(Error::Unsupported("boolean feature control has no RANGE"));
        }
        control::probe_range(
            io,
            self.protocol,
            self.control_interface,
            id,
            feature.selector(),
            channel,
            layout.width(),
        )
    }
    /// Write CUR with no readback and return the value written. A numeric
    /// value lands on the step at or below it in the probed `range`, clamped,
    /// as `get_abs_value` does.
    pub fn set_feature_value<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        channel: u8,
        feature: FeatureControl,
        range: Option<MixerRange>,
        value: FeatureValue,
    ) -> Result<FeatureValue, Error> {
        let layout = feature.layout(self.protocol)?;
        self.feature(id, channel, feature.selector(), true)?;
        let mut numeric = layout.numeric(value)?;
        if feature.has_range() {
            numeric = range.ok_or(Error::Format)?.snap(numeric);
        }
        let bytes = layout.width().encode(numeric);
        control::set(
            io,
            self.control_interface,
            id,
            feature.selector(),
            channel,
            &bytes,
        )?;
        Ok(layout.decode(&bytes))
    }
}

#[cfg(test)]
mod tests;
