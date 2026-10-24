// SPDX-License-Identifier: GPL-2.0-only
//! HDMI/DP codec discovery with restored device-entry selection on an owned HDA controller.
//! Adapted from Linux sound/hda/codecs/hdmi/eld.c and include/sound/hda_verbs.h
//! at a804c5742bff224d4cb4d25dd383554d598be32b. Copyright(c) 2008 Intel
//! Corporation; Copyright (c) 2013 Anssi Hannula. Selected-device handling also
//! adapts hdmi.c/common/codec.c: Copyright(c) 2008-2010 Intel Corporation;
//! Copyright (c) 2006 ATI Technologies Inc.; Copyright (c) 2008 NVIDIA Corp.
//! All rights reserved.; Copyright (c) 2008 Wei Ni <wni@nvidia.com>;
//! Copyright (c) 2004 Takashi Iwai <tiwai@suse.de>. See audio/THIRD_PARTY.md.
//!
//! Observations are not display-link/sink-generation ownership. No stream,
//! converter, DIP, pin-enable, protection or GPU power state is programmed.
//! Per-entry selection is bounded and restored with actual codec readbacks;
//! uncertain restoration poisons the retained controller. PCI admission
//! remains unchanged; this module cannot manufacture a powered GPU controller.
use super::{Controller, ControllerToken, PcmCapabilities, Registers, Verb, WidgetKind};
use crate::{
    audio::{Error, PcmFormat},
    bus::i2c::Timer,
};
use alloc::vec::Vec;

mod eld;
pub use eld::{DigitalConnection, DigitalSink, ShortAudioDescriptor};
#[cfg(test)]
mod tests;

const GET_PARAMETER: u16 = 0xf00;
const PAR_DEVICE_LIST_LENGTH: u8 = 0x15;
const DEVLIST_LEN_MASK: u32 = 0x3f;
const GET_DEVICE_SELECTION: u16 = 0xf35;
const SET_DEVICE_SELECTION: u16 = 0x735;
const GET_PIN_SENSE: u16 = 0xf09;
const GET_DIP_SIZE: u16 = 0xf2e;
const GET_ELD_DATA: u16 = 0xf2f;
const ELD_BUFFER: u8 = 1 << 3;
const PRESENT: u32 = 1 << 31;
const ELD_VALID: u32 = 1 << 30;
const DIGITAL: u32 = 1 << 9;
const PIN_OUTPUT: u32 = 1 << 4;
const PIN_HDMI: u32 = 1 << 7;
const PIN_DP: u32 = 1 << 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigitalError {
    Controller(Error),
    StaleSession,
    SequenceExhausted,
    InvalidDeviceList,
    DeviceEntryGone,
    DeviceSelection,
    RestoreFailed,
    UnsupportedTopology,
    InvalidEldSize(u32),
    InvalidEldByte(u8),
    InvalidEld,
    UnsupportedEldVersion(u8),
    UnsupportedConnection,
    UnstableSink,
}
impl From<Error> for DigitalError {
    fn from(value: Error) -> Self {
        Self::Controller(value)
    }
}

/// Converter capabilities read from the actual graph, not a caller-edited one.
#[derive(Debug)]
pub struct DigitalConverter {
    node: u8,
    connection_index: u8,
    channels: u8,
    pcm: PcmCapabilities,
}
impl DigitalConverter {
    pub fn node(&self) -> u8 {
        self.node
    }
    pub fn connection_index(&self) -> u8 {
        self.connection_index
    }
    pub fn channels(&self) -> u8 {
        self.channels
    }
    pub fn pcm(&self) -> PcmCapabilities {
        self.pcm
    }
}

/// Non-cloneable session tied to the actual controller/reset generation.
#[derive(Debug)]
pub struct DigitalPin {
    token: ControllerToken,
    codec: u8,
    group: u8,
    node: u8,
    capabilities: u32,
    entry: u8,
    converters: Vec<DigitalConverter>,
    attempt: u64,
    observed: Option<DigitalSink>,
}
impl DigitalPin {
    pub fn codec(&self) -> u8 {
        self.codec
    }
    pub fn function_group(&self) -> u8 {
        self.group
    }
    pub fn node(&self) -> u8 {
        self.node
    }
    pub fn device_entry(&self) -> u8 {
        self.entry
    }
    pub fn converters(&self) -> &[DigitalConverter] {
        &self.converters
    }
    pub fn attempt(&self) -> u64 {
        self.attempt
    }
    /// Historical observation only. It may already be obsolete after unplug,
    /// reset or shutdown; only a fresh controller poll checks current state.
    pub fn last_observation(&self) -> Option<&DigitalSink> {
        self.observed.as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigitalPresence {
    Disconnected,
    AwaitingEld,
    Stable,
}

impl<R: Registers, T: Timer> Controller<R, T> {
    fn digital_ready(&self) -> Result<(), DigitalError> {
        if self.lifecycle_failed || self.command_poisoned || self.routing_failed {
            return Err(Error::NeedsReset.into());
        }
        if self.stopped {
            return Err(Error::Shutdown.into());
        }
        Ok(())
    }
    fn digital_read(
        &mut self,
        codec: u8,
        node: u8,
        verb: u16,
        payload: u8,
    ) -> Result<u32, DigitalError> {
        Ok(self.verb(Verb::short(codec, node, verb, payload)?)?)
    }
    fn device_count(&mut self, codec: u8, node: u8) -> Result<u8, DigitalError> {
        let count = self.digital_read(codec, node, GET_PARAMETER, PAR_DEVICE_LIST_LENGTH)?;
        if count == u32::MAX {
            return Err(DigitalError::InvalidDeviceList);
        }
        Ok((count & DEVLIST_LEN_MASK) as u8 + 1)
    }
    fn device_selection(&mut self, codec: u8, node: u8, count: u8) -> Result<u8, DigitalError> {
        let selected = self.digital_read(codec, node, GET_DEVICE_SELECTION, 0)?;
        if selected >= u32::from(count) {
            return Err(DigitalError::DeviceSelection);
        }
        Ok(selected as u8)
    }
    fn select_device(&mut self, codec: u8, node: u8, entry: u8) -> Result<(), DigitalError> {
        // Refresh immediately before every selector publication, including restore.
        let count = self.device_count(codec, node)?;
        if entry >= count {
            return Err(DigitalError::DeviceEntryGone);
        }
        self.digital_read(codec, node, SET_DEVICE_SELECTION, entry)?;
        if self.device_selection(codec, node, count)? != entry {
            return Err(DigitalError::DeviceSelection);
        }
        Ok(())
    }
    fn with_device_entry<U>(
        &mut self,
        codec: u8,
        node: u8,
        entry: u8,
        operation: impl FnOnce(&mut Self) -> Result<U, DigitalError>,
    ) -> Result<U, DigitalError> {
        let count = self.device_count(codec, node)?;
        if entry >= count {
            return Err(DigitalError::DeviceEntryGone);
        }
        let saved = self.device_selection(codec, node, count)?;
        let changed = saved != entry;
        let result = if changed {
            self.select_device(codec, node, entry)
                .and_then(|()| operation(self))
        } else {
            operation(self)
        };
        let result = result.and_then(|value| {
            let count = self.device_count(codec, node)?;
            if entry >= count || self.device_selection(codec, node, count)? != entry {
                return Err(DigitalError::UnstableSink);
            }
            Ok(value)
        });
        // Even an operation error must restore the original selector. A transport
        // fault can prevent that; keep the original owner and require reset.
        let restore = if changed {
            self.select_device(codec, node, saved)
        } else {
            self.device_count(codec, node)
                .and_then(|count| self.device_selection(codec, node, count))
                .and_then(|actual| {
                    if actual == saved {
                        Ok(())
                    } else {
                        Err(DigitalError::RestoreFailed)
                    }
                })
        };
        if let Err(error) = restore {
            self.lifecycle_failed = true;
            return match result {
                Err(original) => Err(original),
                Ok(_) => Err(error),
            };
        }
        result
    }
    /// Enumerate fresh hardware capabilities for every live device entry. Each
    /// selected-entry graph is read independently; selectors/mixers in the audio
    /// path remain unsupported. Device selection is restored before return.
    pub fn discover_digital_pins(&mut self, codec: u8) -> Result<Vec<DigitalPin>, DigitalError> {
        self.digital_ready()?;
        let graph = self.enumerate_codec(codec)?;
        let mut pins = Vec::new();
        for group in &graph.groups {
            if group.function_type & 0xff != 1 {
                continue;
            }
            for pin in &group.widgets {
                if !digital_pin(pin) {
                    continue;
                }
                let count = self.device_count(codec, pin.node)?;
                for entry in 0..count {
                    let session = self.with_device_entry(codec, pin.node, entry, |controller| {
                        let selected = controller.enumerate_codec(codec)?;
                        let selected_group = selected
                            .groups
                            .iter()
                            .find(|candidate| {
                                candidate.node == group.node && candidate.function_type & 0xff == 1
                            })
                            .ok_or(DigitalError::UnsupportedTopology)?;
                        let selected_pin = selected_group
                            .widgets
                            .iter()
                            .find(|candidate| candidate.node == pin.node && digital_pin(candidate))
                            .ok_or(DigitalError::UnsupportedTopology)?;
                        let mut converters = Vec::new();
                        for (index, target) in selected_pin.connections.iter().enumerate() {
                            let converter = selected_group
                                .widgets
                                .iter()
                                .find(|widget| widget.node == *target)
                                .ok_or(DigitalError::UnsupportedTopology)?;
                            if converter.kind != WidgetKind::Output
                                || converter.capabilities & DIGITAL == 0
                            {
                                return Err(DigitalError::UnsupportedTopology);
                            }
                            converters.push(DigitalConverter {
                                node: *target,
                                connection_index: index as u8,
                                channels: converter.channels(),
                                pcm: converter.pcm,
                            });
                        }
                        if converters.is_empty() {
                            return Err(DigitalError::UnsupportedTopology);
                        }
                        Ok(DigitalPin {
                            token: controller.token,
                            codec,
                            group: group.node,
                            node: pin.node,
                            capabilities: selected_pin.pin_capabilities.unwrap_or(0),
                            entry,
                            converters,
                            attempt: 0,
                            observed: None,
                        })
                    })?;
                    pins.push(session);
                }
            }
        }
        Ok(pins)
    }
    fn digital_size(&mut self, pin: &DigitalPin) -> Result<usize, DigitalError> {
        let size = self.digital_read(pin.codec, pin.node, GET_DIP_SIZE, ELD_BUFFER)?;
        if !(20..=256).contains(&size) {
            return Err(DigitalError::InvalidEldSize(size));
        }
        Ok(size as usize)
    }
    fn digital_image(&mut self, pin: &DigitalPin, size: usize) -> Result<Vec<u8>, DigitalError> {
        let mut image = Vec::with_capacity(size);
        for index in 0..size {
            let word = self.digital_read(pin.codec, pin.node, GET_ELD_DATA, index as u8)?;
            if word & PRESENT == 0 || (index == 0 && word as u8 == 0) {
                return Err(DigitalError::InvalidEldByte(index as u8));
            }
            image.push(word as u8);
        }
        Ok(image)
    }
    fn digital_stable_flags(&mut self, pin: &DigitalPin, size: usize) -> Result<(), DigitalError> {
        let sense = self.digital_read(pin.codec, pin.node, GET_PIN_SENSE, 0)?;
        if sense & (PRESENT | ELD_VALID) != (PRESENT | ELD_VALID) || self.digital_size(pin)? != size
        {
            return Err(DigitalError::UnstableSink);
        }
        let count = self.device_count(pin.codec, pin.node)?;
        if pin.entry >= count || self.device_selection(pin.codec, pin.node, count)? != pin.entry {
            return Err(DigitalError::UnstableSink);
        }
        Ok(())
    }
    /// Read two complete matching ELD images with surrounding presence, size
    /// and selected-entry checks. This bounded observation cannot replace an
    /// atomic GPU/link generation for subsequent stream activation.
    pub fn poll_digital_pin(
        &mut self,
        pin: &mut DigitalPin,
    ) -> Result<DigitalPresence, DigitalError> {
        pin.observed = None;
        pin.attempt = pin
            .attempt
            .checked_add(1)
            .ok_or(DigitalError::SequenceExhausted)?;
        if pin.token != self.token {
            return Err(DigitalError::StaleSession);
        }
        self.digital_ready()?;
        let (presence, observation) =
            self.with_device_entry(pin.codec, pin.node, pin.entry, |controller| {
                controller.poll_selected_digital_pin(pin)
            })?;
        pin.observed = observation;
        Ok(presence)
    }
    fn poll_selected_digital_pin(
        &mut self,
        pin: &DigitalPin,
    ) -> Result<(DigitalPresence, Option<DigitalSink>), DigitalError> {
        // Per-entry connections/caps may change without a controller reset.
        // Re-read instead of granting support from old mutable codec state.
        let graph = self.enumerate_codec(pin.codec)?;
        let group = graph
            .groups
            .iter()
            .find(|group| group.node == pin.group && group.function_type & 0xff == 1)
            .ok_or(DigitalError::StaleSession)?;
        let current = group
            .widgets
            .iter()
            .find(|widget| widget.node == pin.node && digital_pin(widget))
            .ok_or(DigitalError::StaleSession)?;
        if current.pin_capabilities != Some(pin.capabilities)
            || current.connections.len() != pin.converters.len()
        {
            return Err(DigitalError::StaleSession);
        }
        for (node, retained) in current.connections.iter().zip(&pin.converters) {
            let converter = group
                .widgets
                .iter()
                .find(|widget| widget.node == *node)
                .ok_or(DigitalError::StaleSession)?;
            if *node != retained.node
                || converter.kind != WidgetKind::Output
                || converter.capabilities & DIGITAL == 0
                || converter.channels() != retained.channels
                || converter.pcm.rates_and_bits != retained.pcm.rates_and_bits
                || converter.pcm.stream_formats != retained.pcm.stream_formats
            {
                return Err(DigitalError::StaleSession);
            }
        }
        let sense = self.digital_read(pin.codec, pin.node, GET_PIN_SENSE, 0)?;
        if sense & PRESENT == 0 {
            return Ok((DigitalPresence::Disconnected, None));
        }
        if sense & ELD_VALID == 0 {
            return Ok((DigitalPresence::AwaitingEld, None));
        }
        let size = self.digital_size(pin)?;
        let first = self.digital_image(pin, size)?;
        self.digital_stable_flags(pin, size)?;
        let second = self.digital_image(pin, size)?;
        self.digital_stable_flags(pin, size)?;
        if first != second {
            return Err(DigitalError::UnstableSink);
        }
        Ok((
            DigitalPresence::Stable,
            Some(eld::parse(first, pin.capabilities)?),
        ))
    }
    /// Fresh capability intersection for one converter and one complete LPCM
    /// SAD. This reserves no bandwidth and grants no route/display ownership.
    /// Shared link reservations must still be checked by future PCM activation.
    pub fn digital_pcm_supported(
        &mut self,
        pin: &mut DigitalPin,
        converter: u8,
        format: PcmFormat,
    ) -> Result<bool, DigitalError> {
        if self.poll_digital_pin(pin)? != DigitalPresence::Stable {
            return Ok(false);
        }
        let encoded = match format.encode() {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let words =
            (u16::from(format.bits) * u16::from(format.channels) * (((encoded >> 11) & 7) + 1))
                .div_ceil(16);
        let caps = self.capabilities;
        Ok(caps.output_streams != 0
            && words <= caps.output_payload_words
            && (caps.output_stream_payload_words == 0 || words <= caps.output_stream_payload_words)
            && pin.converters.iter().any(|candidate| {
                candidate.node == converter
                    && candidate.channels >= format.channels
                    && candidate.pcm.supports(format)
            })
            && pin
                .observed
                .as_ref()
                .is_some_and(|sink| sink.supports_pcm(format)))
    }
}

fn digital_pin(pin: &super::Widget) -> bool {
    let caps = pin.pin_capabilities.unwrap_or(0);
    pin.kind == WidgetKind::Pin
        && pin.capabilities & DIGITAL != 0
        && caps & PIN_OUTPUT != 0
        && caps & (PIN_HDMI | PIN_DP) != 0
        && pin.pin_default.is_some_and(|value| value >> 30 != 1)
}
