// SPDX-License-Identifier: GPL-2.0-only
//! Codec verb packing, capability inheritance and connection expansion adapted
//! from Linux sound/hda/core/device.c and include/sound/hda_verbs.h.
use super::super::{Error, PcmFormat};
use super::{Controller, ControllerToken, Registers};
use crate::bus::i2c::Timer;
use alloc::vec::Vec;

const GET_PARAMETER: u16 = 0xf00;
const GET_CONNECTIONS: u16 = 0xf02;
const GET_CONFIG_DEFAULT: u16 = 0xf1c;
const PAR_VENDOR: u8 = 0;
const PAR_REVISION: u8 = 2;
const PAR_NODE_COUNT: u8 = 4;
const PAR_FUNCTION: u8 = 5;
const PAR_WIDGET: u8 = 9;
const PAR_PCM: u8 = 0x0a;
const PAR_STREAM: u8 = 0x0b;
const PAR_PIN: u8 = 0x0c;
const PAR_AMP_IN: u8 = 0x0d;
const PAR_CONNECTIONS: u8 = 0x0e;
const PAR_POWER: u8 = 0x0f;
const PAR_AMP_OUT: u8 = 0x12;
const WCAP_IN_AMP: u32 = 1 << 1;
const WCAP_OUT_AMP: u32 = 1 << 2;
const WCAP_AMP_OVERRIDE: u32 = 1 << 3;
const WCAP_FORMAT_OVERRIDE: u32 = 1 << 4;
const WCAP_CONNECTIONS: u32 = 1 << 8;
const WCAP_POWER: u32 = 1 << 10;

/// An encoded codec command. Node IDs are seven bits; codec address 15 is
/// broadcast/reserved here and never used for solicited command matching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verb(u32);

impl Verb {
    pub fn short(codec: u8, node: u8, verb: u16, payload: u8) -> Result<Self, Error> {
        if codec > 14 || node > 127 || verb > 0xfff {
            return Err(Error::InvalidVerb);
        }
        Ok(Self(
            (u32::from(codec) << 28)
                | (u32::from(node) << 20)
                | (u32::from(verb) << 8)
                | u32::from(payload),
        ))
    }
    pub fn long(codec: u8, node: u8, verb: u8, payload: u16) -> Result<Self, Error> {
        if verb > 15 {
            return Err(Error::InvalidVerb);
        }
        Self::short(codec, node, u16::from(verb) << 8, 0)
            .map(|command| Self(command.0 | u32::from(payload)))
    }
    pub(super) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
    pub fn codec(self) -> u8 {
        (self.0 >> 28) as u8
    }
    pub fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WidgetKind {
    Output,
    Input,
    Mixer,
    Selector,
    Pin,
    Power,
    Volume,
    Beep,
    Vendor(u8),
}

impl WidgetKind {
    fn from_capabilities(value: u32) -> Self {
        match ((value >> 20) & 15) as u8 {
            0 => Self::Output,
            1 => Self::Input,
            2 => Self::Mixer,
            3 => Self::Selector,
            4 => Self::Pin,
            5 => Self::Power,
            6 => Self::Volume,
            7 => Self::Beep,
            other => Self::Vendor(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PcmCapabilities {
    pub rates_and_bits: u32,
    pub stream_formats: u32,
}

impl PcmCapabilities {
    pub fn supports(self, format: PcmFormat) -> bool {
        if format.encode().is_err()
            || self.stream_formats & 1 == 0
            || self.stream_formats == u32::MAX
            || self.rates_and_bits == u32::MAX
        {
            return false;
        }
        let rate = match format.rate {
            8_000 => 0,
            11_025 => 1,
            16_000 => 2,
            22_050 => 3,
            32_000 => 4,
            44_100 => 5,
            48_000 => 6,
            88_200 => 7,
            96_000 => 8,
            176_400 => 9,
            192_000 => 10,
            _ => return false,
        };
        let bits = match format.bits {
            8 => 16,
            16 => 17,
            20 => 18,
            24 => 19,
            32 => 20,
            _ => return false,
        };
        self.rates_and_bits & (1 << rate) != 0 && self.rates_and_bits & (1 << bits) != 0
    }
}

#[derive(Clone, Debug)]
pub struct Widget {
    pub node: u8,
    pub kind: WidgetKind,
    pub capabilities: u32,
    pub connections: Vec<u8>,
    /// Effective converter capabilities after function-group inheritance.
    pub pcm: PcmCapabilities,
    pub input_amplifier: Option<u32>,
    pub output_amplifier: Option<u32>,
    /// Effective declared widget states; zero raw capability inherits its FG.
    pub power_states: Option<u32>,
    pub pin_capabilities: Option<u32>,
    pub pin_default: Option<u32>,
}

impl Widget {
    pub fn channels(&self) -> u8 {
        widget_channels(self.capabilities)
    }
}
pub(super) fn widget_channels(capabilities: u32) -> u8 {
    (((capabilities >> 13) & 7) as u8 * 2) + (capabilities as u8 & 1) + 1
}

#[derive(Clone, Debug)]
pub struct FunctionGroup {
    pub node: u8,
    /// Low byte 1 identifies an audio function group. Other types are reported
    /// without inventing audio widgets for modem/vendor-specific groups.
    pub function_type: u32,
    pub pcm: PcmCapabilities,
    /// Standard audio-function-group power states; absent for non-audio groups.
    pub power_states: Option<u32>,
    pub widgets: Vec<Widget>,
}

#[derive(Clone, Debug)]
pub struct CodecGraph {
    pub(super) token: ControllerToken,
    pub address: u8,
    pub vendor_id: u32,
    pub revision_id: u32,
    pub groups: Vec<FunctionGroup>,
}

impl CodecGraph {
    pub fn widget(&self, node: u8) -> Option<&Widget> {
        self.groups
            .iter()
            .flat_map(|group| &group.widgets)
            .find(|widget| widget.node == node)
    }
}

impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn parameter(&mut self, codec: u8, node: u8, parameter: u8) -> Result<u32, Error> {
        self.verb(Verb::short(codec, node, GET_PARAMETER, parameter)?)
    }

    /// Read the standard graph without changing pins, gains, power or routes.
    /// Invalid node/range encodings fail explicitly. Digital and vendor widgets
    /// remain represented in the graph; their policy is not inferred.
    /// `probe_codec`: the vendor ID read, which never falls back.
    pub(super) fn probe_codec(&mut self, address: u8) -> Result<(), Error> {
        self.probing = true;
        let result = self.parameter(address, 0, PAR_VENDOR);
        self.probing = false;
        match result? {
            u32::MAX => Err(Error::InvalidCodecGraph),
            _ => Ok(()),
        }
    }
    pub fn enumerate_codec(&mut self, address: u8) -> Result<CodecGraph, Error> {
        if address > 14 {
            return Err(Error::InvalidVerb);
        }
        let vendor_id = self.parameter(address, 0, PAR_VENDOR)?;
        if vendor_id == 0 || vendor_id == u32::MAX {
            return Err(Error::InvalidCodecGraph);
        }
        let revision_id = self.parameter(address, 0, PAR_REVISION)?;
        let nodes = node_range(self.parameter(address, 0, PAR_NODE_COUNT)?)?;
        let mut graph = CodecGraph {
            token: self.token,
            address,
            vendor_id,
            revision_id,
            groups: Vec::new(),
        };
        let mut seen = [false; 128];
        seen[0] = true;
        for node in nodes.clone() {
            seen[usize::from(node)] = true;
        }
        let mut audio_groups = 0;
        for node in nodes {
            let function_type = self.parameter(address, node, PAR_FUNCTION)?;
            let mut group = FunctionGroup {
                node,
                function_type,
                pcm: PcmCapabilities::default(),
                power_states: None,
                widgets: Vec::new(),
            };
            if function_type & 0xff != 1 {
                graph.groups.push(group);
                continue;
            }
            audio_groups += 1;
            group.power_states = Some(self.parameter(address, node, PAR_POWER)?);
            group.pcm.rates_and_bits = self.parameter(address, node, PAR_PCM)?;
            group.pcm.stream_formats = self.parameter(address, node, PAR_STREAM)?;
            let input_amp = self.parameter(address, node, PAR_AMP_IN)?;
            let output_amp = self.parameter(address, node, PAR_AMP_OUT)?;
            let widgets = node_range(self.parameter(address, node, PAR_NODE_COUNT)?)?;
            for widget in widgets.clone() {
                if seen[usize::from(widget)] {
                    return Err(Error::InvalidCodecGraph);
                }
                seen[usize::from(widget)] = true;
                let capabilities = self.parameter(address, widget, PAR_WIDGET)?;
                let kind = WidgetKind::from_capabilities(capabilities);
                let mut pcm = PcmCapabilities::default();
                if matches!(kind, WidgetKind::Output | WidgetKind::Input) {
                    pcm = group.pcm;
                    if capabilities & WCAP_FORMAT_OVERRIDE != 0 {
                        let override_pcm = self.parameter(address, widget, PAR_PCM)?;
                        if override_pcm != 0 && override_pcm != u32::MAX {
                            pcm.rates_and_bits = override_pcm;
                        }
                    }
                    let streams = self.parameter(address, widget, PAR_STREAM)?;
                    if streams != 0 && streams != u32::MAX {
                        pcm.stream_formats = streams;
                    }
                }
                let input_amplifier = if capabilities & WCAP_IN_AMP != 0 {
                    Some(if capabilities & WCAP_AMP_OVERRIDE != 0 {
                        self.parameter(address, widget, PAR_AMP_IN)?
                    } else {
                        input_amp
                    })
                } else {
                    None
                };
                let output_amplifier = if capabilities & WCAP_OUT_AMP != 0 {
                    Some(if capabilities & WCAP_AMP_OVERRIDE != 0 {
                        self.parameter(address, widget, PAR_AMP_OUT)?
                    } else {
                        output_amp
                    })
                } else {
                    None
                };
                let connections = if capabilities & WCAP_CONNECTIONS != 0 {
                    self.connections(address, widget)?
                } else {
                    Vec::new()
                };
                if connections
                    .iter()
                    .any(|connection| !widgets.contains(connection))
                {
                    return Err(Error::InvalidConnectionList);
                }
                let power_states = if capabilities & WCAP_POWER != 0 {
                    let states = self.parameter(address, widget, PAR_POWER)?;
                    // HDA 1.0a §7.3.4.12: optional widget parameter returning
                    // zero inherits the required function-group power states.
                    Some(if states == 0 {
                        group.power_states.unwrap_or(0)
                    } else {
                        states
                    })
                } else {
                    None
                };
                let (pin_capabilities, pin_default) = if kind == WidgetKind::Pin {
                    (
                        Some(self.parameter(address, widget, PAR_PIN)?),
                        Some(self.verb(Verb::short(address, widget, GET_CONFIG_DEFAULT, 0)?)?),
                    )
                } else {
                    (None, None)
                };
                group.widgets.push(Widget {
                    node: widget,
                    kind,
                    capabilities,
                    connections,
                    pcm,
                    input_amplifier,
                    output_amplifier,
                    power_states,
                    pin_capabilities,
                    pin_default,
                });
            }
            graph.groups.push(group);
        }
        if audio_groups == 0 {
            return Err(Error::UnsupportedTopology);
        }
        Ok(graph)
    }

    pub(super) fn connections(&mut self, codec: u8, node: u8) -> Result<Vec<u8>, Error> {
        let length = self.parameter(codec, node, PAR_CONNECTIONS)?;
        let count = (length & 0x7f) as u8;
        let long = length & 0x80 != 0;
        let shift = if long { 16 } else { 8 };
        let per_word = 32 / shift;
        let range_bit = 1 << (shift - 1);
        let mask = range_bit - 1;
        let mut entries = Vec::new();
        let mut previous = None;
        let mut value = 0;
        for index in 0..count {
            if u32::from(index) % per_word == 0 {
                value = self.verb(Verb::short(codec, node, GET_CONNECTIONS, index)?)?;
            }
            let raw = value & ((1 << shift) - 1);
            value >>= shift;
            let target = raw & mask;
            if target == 0 || target > 127 {
                return Err(Error::InvalidConnectionList);
            }
            let target = target as u8;
            if raw & range_bit != 0 {
                let first = previous
                    .filter(|previous| *previous < target)
                    .ok_or(Error::InvalidConnectionList)?;
                entries.extend(first + 1..=target);
            } else {
                entries.push(target);
            }
            if entries.len() > 127 {
                return Err(Error::InvalidConnectionList);
            }
            previous = Some(target);
        }
        Ok(entries)
    }
}

/// Revalidated standard analog authority shared by vendor backends. This
/// preserves the observed pin inventory without inferring electrical policy.
pub(super) struct LiveAnalogCodec {
    pub group: u8,
    pub subsystem: u32,
    pub pins: Vec<(u8, u32)>,
}
impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn validate_live_input_amplifier(
        &mut self,
        address: u8,
        group: u8,
        widget: &Widget,
    ) -> Result<u32, Error> {
        if widget.capabilities & WCAP_IN_AMP == 0 || widget.input_amplifier.is_none() {
            return Err(Error::UnsupportedTopology);
        }
        let node = if widget.capabilities & WCAP_AMP_OVERRIDE != 0 {
            widget.node
        } else {
            group
        };
        let caps = self.parameter(address, node, PAR_AMP_IN)?;
        if caps == u32::MAX || widget.input_amplifier != Some(caps) {
            return Err(Error::InvalidCodecGraph);
        }
        Ok(caps)
    }
    pub(super) fn validate_live_output_amplifier(
        &mut self,
        address: u8,
        group: u8,
        widget: &Widget,
    ) -> Result<u32, Error> {
        if widget.capabilities & WCAP_OUT_AMP == 0 || widget.output_amplifier.is_none() {
            return Err(Error::UnsupportedTopology);
        }
        let node = if widget.capabilities & WCAP_AMP_OVERRIDE != 0 {
            widget.node
        } else {
            group
        };
        let caps = self.parameter(address, node, PAR_AMP_OUT)?;
        if caps == u32::MAX || widget.output_amplifier != Some(caps) {
            return Err(Error::InvalidCodecGraph);
        }
        Ok(caps)
    }
    pub(super) fn validate_live_analog_codec(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<LiveAnalogCodec, Error> {
        if graph.token != self.token {
            return Err(Error::InvalidCodecGraph);
        }
        let vendor = self.parameter(graph.address, 0, PAR_VENDOR)?;
        let revision = self.parameter(graph.address, 0, PAR_REVISION)?;
        if vendor == 0
            || vendor == u32::MAX
            || vendor != graph.vendor_id
            || revision != graph.revision_id
            || revision == u32::MAX
        {
            return Err(Error::InvalidCodecGraph);
        }
        let groups: Vec<_> = graph
            .groups
            .iter()
            .filter(|group| group.function_type & 255 == 1)
            .collect();
        let [group] = groups.as_slice() else {
            return Err(Error::UnsupportedTopology);
        };
        let roots = node_range(self.parameter(graph.address, 0, PAR_NODE_COUNT)?)?;
        if !roots.contains(&group.node)
            || self.parameter(graph.address, group.node, PAR_FUNCTION)? != group.function_type
        {
            return Err(Error::InvalidCodecGraph);
        }
        let power = self.parameter(graph.address, group.node, PAR_POWER)?;
        if power == u32::MAX || power & 1 == 0 || group.power_states != Some(power) {
            return Err(Error::InvalidCodecGraph);
        }
        let nodes = node_range(self.parameter(graph.address, group.node, PAR_NODE_COUNT)?)?;
        if nodes.start <= group.node || group.widgets.len() != usize::from(nodes.end - nodes.start)
        {
            return Err(Error::InvalidCodecGraph);
        }
        let mut pins = Vec::new();
        for node in nodes {
            let caps = self.parameter(graph.address, node, PAR_WIDGET)?;
            let cached = group
                .widgets
                .iter()
                .find(|widget| widget.node == node)
                .ok_or(Error::InvalidCodecGraph)?;
            if caps == u32::MAX
                || cached.capabilities != caps
                || cached.kind != WidgetKind::from_capabilities(caps)
            {
                return Err(Error::InvalidCodecGraph);
            }
            if cached.kind == WidgetKind::Pin {
                let pin = self.parameter(graph.address, node, PAR_PIN)?;
                if pin == u32::MAX || cached.pin_capabilities != Some(pin) {
                    return Err(Error::InvalidCodecGraph);
                }
                pins.push((node, pin));
            }
        }
        let subsystem = self.verb(Verb::short(graph.address, group.node, 0xf20, 0)?)?;
        if subsystem == u32::MAX {
            return Err(Error::InvalidCodecGraph);
        }
        Ok(LiveAnalogCodec {
            group: group.node,
            subsystem,
            pins,
        })
    }
}

fn node_range(value: u32) -> Result<core::ops::Range<u8>, Error> {
    let start = ((value >> 16) & 0xff) as u8;
    let count = (value & 0xff) as u8;
    let end = start
        .checked_add(count)
        .filter(|end| *end <= 128)
        .ok_or(Error::InvalidCodecGraph)?;
    if start == 0 || count == 0 {
        return Err(Error::InvalidCodecGraph);
    }
    Ok(start..end)
}
