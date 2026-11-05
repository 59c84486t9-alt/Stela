// SPDX-License-Identifier: GPL-2.0-only
//! Standard pin metadata, analog endpoint discovery and polled jack sense.
//! Encodings and trigger ordering adapt Linux include/sound/hda_verbs.h and
//! sound/hda/common/{auto_parser,jack}.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//! Copyright (c) 2011-2012 Takashi Iwai <tiwai@suse.de>
//!
//! Firmware defaults describe candidates, not permission to infer electrical,
//! GPIO, amplifier, headset, jack inversion or OEM routing policy.
use super::{AnalogRoute, CodecGraph, Controller, Registers, Verb, Widget, WidgetKind};
use crate::{Direction, Error, PcmFormat, Timer};
use alloc::vec::Vec;

const DIGITAL: u32 = 1 << 9;
const IMPEDANCE: u32 = 1;
const TRIGGER: u32 = 1 << 1;
const PRESENCE: u32 = 1 << 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinConnection {
    Jack,
    None,
    Fixed,
    JackAndFixed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinDevice {
    LineOut,
    Speaker,
    Headphone,
    Cd,
    SpdifOut,
    DigitalOut,
    ModemLine,
    ModemHandset,
    LineIn,
    Auxiliary,
    Microphone,
    Telephony,
    SpdifIn,
    DigitalIn,
    Reserved,
    Other,
}

/// Exact firmware configuration-default bits. Association/sequence are ordering
/// hints; they neither choose a route nor establish working OEM wiring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinConfiguration {
    pub raw: u32,
}
impl PinConfiguration {
    pub fn connection(self) -> PinConnection {
        match self.raw >> 30 {
            0 => PinConnection::Jack,
            1 => PinConnection::None,
            2 => PinConnection::Fixed,
            _ => PinConnection::JackAndFixed,
        }
    }
    pub fn device(self) -> PinDevice {
        match (self.raw >> 20) & 15 {
            0 => PinDevice::LineOut,
            1 => PinDevice::Speaker,
            2 => PinDevice::Headphone,
            3 => PinDevice::Cd,
            4 => PinDevice::SpdifOut,
            5 => PinDevice::DigitalOut,
            6 => PinDevice::ModemLine,
            7 => PinDevice::ModemHandset,
            8 => PinDevice::LineIn,
            9 => PinDevice::Auxiliary,
            10 => PinDevice::Microphone,
            11 => PinDevice::Telephony,
            12 => PinDevice::SpdifIn,
            13 => PinDevice::DigitalIn,
            14 => PinDevice::Reserved,
            _ => PinDevice::Other,
        }
    }
    pub fn location(self) -> u8 {
        ((self.raw >> 24) & 63) as u8
    }
    pub fn connector(self) -> u8 {
        ((self.raw >> 16) & 15) as u8
    }
    pub fn color(self) -> u8 {
        ((self.raw >> 12) & 15) as u8
    }
    pub fn association(self) -> u8 {
        ((self.raw >> 4) & 15) as u8
    }
    pub fn sequence(self) -> u8 {
        (self.raw & 15) as u8
    }
    pub fn no_presence_detection(self) -> bool {
        self.raw & (1 << 8) != 0
    }
    fn analog(self, direction: Direction) -> bool {
        self.raw != u32::MAX
            && self.connection() != PinConnection::None
            && match direction {
                Direction::Playback => matches!(
                    self.device(),
                    PinDevice::LineOut | PinDevice::Speaker | PinDevice::Headphone
                ),
                Direction::Capture => matches!(
                    self.device(),
                    PinDevice::Microphone
                        | PinDevice::LineIn
                        | PinDevice::Auxiliary
                        | PinDevice::Cd
                ),
            }
    }
}
impl Widget {
    pub fn pin_configuration(&self) -> Option<PinConfiguration> {
        (self.kind == WidgetKind::Pin)
            .then_some(self.pin_default)
            .flatten()
            .map(|raw| PinConfiguration { raw })
    }
}

/// One real same-function-group PCM path, ordered by firmware association,
/// sequence and node IDs. The caller still supplies explicit PinOptions and
/// resolves shared converters/route reservations and OEM board requirements.
#[derive(Clone, Debug)]
pub struct AnalogEndpoint {
    pub route: AnalogRoute,
    pub configuration: PinConfiguration,
}
impl CodecGraph {
    pub fn analog_endpoints(
        &self,
        direction: Direction,
        format: PcmFormat,
    ) -> Result<Vec<AnalogEndpoint>, Error> {
        format.encode()?;
        if format.channels > 2 {
            return Err(Error::UnsupportedTopology);
        }
        let mut result = Vec::new();
        for group in &self.groups {
            if group.function_type & 255 != 1 {
                continue;
            }
            for pin in &group.widgets {
                let Some(configuration) = pin
                    .pin_configuration()
                    .filter(|value| value.analog(direction))
                else {
                    continue;
                };
                if pin.capabilities & DIGITAL != 0 {
                    continue;
                }
                for converter in &group.widgets {
                    if converter.capabilities & DIGITAL != 0
                        || !converter.pcm.supports(format)
                        || converter.channels() < format.channels
                    {
                        continue;
                    }
                    if let Ok(route) = self.analog_route(direction, pin.node, converter.node) {
                        result.push(AnalogEndpoint {
                            route,
                            configuration,
                        });
                    }
                }
            }
        }
        result.sort_by_key(|endpoint| {
            (
                endpoint.configuration.association(),
                endpoint.configuration.sequence(),
                endpoint.route.pin(),
                endpoint.route.converter(),
            )
        });
        if result.is_empty() {
            return Err(Error::UnsupportedTopology);
        }
        Ok(result)
    }
}

/// Raw standard measurement; no debounce, jack inversion, headset type or ELD
/// interpretation is inferred. Impedance is held as a codec response code,
/// without claiming calibrated ohms. An unavailable impedance code is None.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinSense {
    pub raw: u32,
    pub present: bool,
    pub impedance_code: Option<u32>,
}
impl<R: Registers, T: Timer> Controller<R, T> {
    /// Standard polling works without unsolicited interrupts. Trigger-required
    /// pins receive SET_PIN_SENSE before GET_PIN_SENSE, as in jack.c. Managed
    /// SigmaTel codecs keep no-trigger sense; IDT83xxx also synchronizes its
    /// source port-power map. Standard polling changes no power or GPIO.
    pub fn poll_pin_sense(&mut self, graph: &CodecGraph, pin: u8) -> Result<PinSense, Error> {
        self.minimum_guard()?;
        if self.manages_realtek_codec(graph.address) {
            return self.poll_realtek_pin_sense(graph, pin);
        }
        if self.manages_sigmatel_codec(graph.address) {
            return self.poll_sigmatel_pin_sense(graph, pin);
        }
        if self.manages_cirrus_codec(graph.address) {
            return self.poll_cirrus_pin_sense(graph, pin);
        }
        self.poll_pin_sense_policy(graph, pin, true)
    }
    pub(super) fn poll_pin_sense_policy(
        &mut self,
        graph: &CodecGraph,
        pin: u8,
        allow_trigger: bool,
    ) -> Result<PinSense, Error> {
        self.minimum_guard()?;
        if graph.token != self.token {
            return Err(Error::InvalidCodecGraph);
        }
        let widget = graph.widget(pin).ok_or(Error::InvalidCodecGraph)?;
        let caps = widget.pin_capabilities.ok_or(Error::UnsupportedTopology)?;
        let configuration = widget
            .pin_configuration()
            .ok_or(Error::UnsupportedTopology)?;
        if widget.capabilities & DIGITAL != 0
            || caps == u32::MAX
            || caps & PRESENCE == 0
            || configuration.no_presence_detection()
        {
            return Err(Error::UnsupportedTopology);
        }
        if allow_trigger && caps & TRIGGER != 0 {
            self.verb(Verb::short(graph.address, pin, 0x709, 0)?)?;
        }
        let raw = self.verb(Verb::short(graph.address, pin, 0xf09, 0)?)?;
        let code = raw & 0x7fff_ffff;
        Ok(PinSense {
            raw,
            present: raw & (1 << 31) != 0,
            impedance_code: (caps & IMPEDANCE != 0 && code != 0x7fff_ffff).then_some(code),
        })
    }
}
