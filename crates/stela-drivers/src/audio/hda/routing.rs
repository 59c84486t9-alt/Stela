// SPDX-License-Identifier: GPL-2.0-only
//! Standard analog codec route selection, power, pin and amplifier controls.
//! Verb/capability layouts adapt Linux include/sound/hda_verbs.h and common
//! codec control sequencing from sound/hda/common/codec.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//!
//! Explicit pin/converter choices and electrical options belong to platform
//! policy. No vendor fixup, GPIO amplifier, jack policy or digital route is
//! inferred from a codec name, pin default, or successful DMA completion.
use super::super::{Direction, Error, Phase};
use super::{
    CodecGraph, Controller, ControllerToken, FunctionGroup, Registers, StreamId, Verb, Widget,
    WidgetKind,
};
use crate::bus::i2c::Timer;
use alloc::vec::Vec;

const GET_SELECT: u16 = 0xf01;
const SET_SELECT: u16 = 0x701;
const GET_POWER: u16 = 0xf05;
const SET_POWER: u16 = 0x705;
const GET_PIN: u16 = 0xf07;
const SET_PIN: u16 = 0x707;
const GET_EAPD: u16 = 0xf0c;
const SET_EAPD: u16 = 0x70c;
const GET_AMP: u8 = 0xb;
const SET_AMP: u8 = 3;
const WCAP_DIGITAL: u32 = 1 << 9;
const PIN_HEADPHONE: u32 = 1 << 3;
const PIN_OUTPUT: u32 = 1 << 4;
const PIN_INPUT: u32 = 1 << 5;
const PIN_EAPD: u32 = 1 << 16;
const PIN_VREF: u32 = 0x37 << 8;
const PIN_INPUT_ENABLE: u8 = 1 << 5;
const PIN_OUTPUT_ENABLE: u8 = 1 << 6;
const PIN_HEADPHONE_ENABLE: u8 = 1 << 7;
const EAPD_ENABLE: u8 = 1 << 1;
const POWER_D0_SUPPORTED: u32 = 1;
const POWER_REQUESTED: u32 = 0xf;
const POWER_ACTUAL: u32 = 0xf << 4;
const POWER_ERROR: u32 = 1 << 8;
const AMP_GAIN: u16 = 0x7f;
const AMP_MUTE: u16 = 1 << 7;
const AMP_MUTE_SUPPORTED: u32 = 1 << 31;
const AMP_LEFT: u16 = 1 << 13;
const AMP_RIGHT: u16 = 1 << 12;
const AMP_INPUT: u16 = 1 << 14;
const AMP_OUTPUT: u16 = 1 << 15;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vref {
    HighImpedance,
    Half,
    Ground,
    EightyPercent,
    Full,
}
impl Vref {
    fn encoding(self) -> u8 {
        match self {
            Self::HighImpedance => 0,
            Self::Half => 1,
            Self::Ground => 2,
            Self::EightyPercent => 4,
            Self::Full => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinOptions {
    Playback { headphone: bool, eapd: Option<bool> },
    Capture { vref: Vref },
}

/// One explicit same-function-group path, in sink-to-source connection order.
/// The route reserves its widget path until full controller reinitialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalogRoute {
    token: ControllerToken,
    codec: u8,
    group: u8,
    direction: Direction,
    pin: u8,
    converter: u8,
    nodes: Vec<u8>,
}
impl AnalogRoute {
    pub(super) fn codec_address(&self) -> u8 {
        self.codec
    }
    pub(super) fn group_node(&self) -> u8 {
        self.group
    }

    pub fn nodes(&self) -> &[u8] {
        &self.nodes
    }
    pub fn pin(&self) -> u8 {
        self.pin
    }
    pub fn converter(&self) -> u8 {
        self.converter
    }
    pub fn direction(&self) -> Direction {
        self.direction
    }
}

fn widget(group: &FunctionGroup, node: u8) -> Result<&Widget, Error> {
    group
        .widgets
        .iter()
        .find(|widget| widget.node == node)
        .ok_or(Error::InvalidCodecGraph)
}

fn find_path(
    group: &FunctionGroup,
    node: u8,
    target: u8,
    path: &mut Vec<u8>,
    visited: &mut [bool; 128],
) -> bool {
    if node == 0 || node > 127 || visited[usize::from(node)] {
        return false;
    }
    visited[usize::from(node)] = true;
    let Ok(current) = widget(group, node) else {
        return false;
    };
    if current.capabilities == u32::MAX || current.capabilities & WCAP_DIGITAL != 0 {
        return false;
    }
    path.push(node);
    if node == target {
        return true;
    }
    if (path.len() > 1 && !matches!(current.kind, WidgetKind::Mixer | WidgetKind::Selector))
        || !matches!(
            current.kind,
            WidgetKind::Pin | WidgetKind::Input | WidgetKind::Mixer | WidgetKind::Selector
        )
    {
        path.pop();
        return false;
    }
    for source in &current.connections {
        if find_path(group, *source, target, path, visited) {
            return true;
        }
    }
    path.pop();
    false
}

impl CodecGraph {
    /// Select a real analog path between explicitly chosen standard endpoints.
    /// Pin defaults do not authorize OEM amplifier or electrical policy.
    pub fn analog_route(
        &self,
        direction: Direction,
        pin: u8,
        converter: u8,
    ) -> Result<AnalogRoute, Error> {
        if self.address > 14 {
            return Err(Error::InvalidVerb);
        }
        let group = self
            .groups
            .iter()
            .find(|group| {
                group.function_type & 0xff == 1
                    && group.widgets.iter().any(|w| w.node == pin)
                    && group.widgets.iter().any(|w| w.node == converter)
            })
            .ok_or(Error::InvalidCodecGraph)?;
        if group.node == 0 || group.node > 127 {
            return Err(Error::InvalidCodecGraph);
        }
        let pin_widget = widget(group, pin)?;
        let converter_widget = widget(group, converter)?;
        let (expected, required, sink, source) = match direction {
            Direction::Playback => (WidgetKind::Output, PIN_OUTPUT, pin, converter),
            Direction::Capture => (WidgetKind::Input, PIN_INPUT, converter, pin),
        };
        if pin_widget.kind != WidgetKind::Pin
            || converter_widget.kind != expected
            || pin_widget
                .pin_capabilities
                .is_none_or(|caps| caps == u32::MAX || caps & required == 0)
            || converter_widget.channels() > 2
        {
            return Err(Error::UnsupportedTopology);
        }
        let mut nodes = Vec::new();
        if !find_path(group, sink, source, &mut nodes, &mut [false; 128]) {
            return Err(Error::UnsupportedTopology);
        }
        Ok(AnalogRoute {
            token: self.token,
            codec: self.address,
            group: group.node,
            direction,
            pin,
            converter,
            nodes,
        })
    }
}

#[derive(Clone, Copy)]
struct Amplifier {
    node: u8,
    output: bool,
    index: u8,
    channels: u8,
    gain: u8,
    mute: bool,
}

pub(super) struct Plan {
    power: Vec<u8>,
    selectors: Vec<(u8, u8)>,
    amplifiers: Vec<Amplifier>,
    pin_control: u8,
    eapd: Option<bool>,
}

fn amplifier(
    node: u8,
    output: bool,
    index: usize,
    channels: u8,
    caps: u32,
    mute: bool,
) -> Result<Amplifier, Error> {
    let gain = (caps & 0x7f) as u8;
    let steps = ((caps >> 8) & 0x7f) as u8;
    if caps == u32::MAX
        || index > 15
        || channels > 2
        || gain > steps
        || (mute && caps & AMP_MUTE_SUPPORTED == 0)
    {
        return Err(Error::UnsupportedTopology);
    }
    Ok(Amplifier {
        node,
        output,
        index: index as u8,
        channels,
        gain,
        mute,
    })
}

fn plan(graph: &CodecGraph, route: &AnalogRoute, options: PinOptions) -> Result<Plan, Error> {
    if graph.analog_route(route.direction, route.pin, route.converter)? != *route {
        return Err(Error::InvalidCodecGraph);
    }
    let group = graph
        .groups
        .iter()
        .find(|group| group.node == route.group)
        .ok_or(Error::InvalidCodecGraph)?;
    if group
        .power_states
        .is_none_or(|caps| caps == u32::MAX || caps & POWER_D0_SUPPORTED == 0)
    {
        return Err(Error::UnsupportedTopology);
    }
    let pin = widget(group, route.pin)?;
    let caps = pin.pin_capabilities.ok_or(Error::InvalidCodecGraph)?;
    let (pin_control, eapd) = match (route.direction, options) {
        (Direction::Playback, PinOptions::Playback { headphone, eapd }) => {
            if (headphone && caps & PIN_HEADPHONE == 0) || (eapd.is_some() && caps & PIN_EAPD == 0)
            {
                return Err(Error::InvalidPinControl);
            }
            (
                PIN_OUTPUT_ENABLE | if headphone { PIN_HEADPHONE_ENABLE } else { 0 },
                eapd,
            )
        }
        (Direction::Capture, PinOptions::Capture { vref }) => {
            let value = vref.encoding();
            // No VREF circuit means clearing bias bits is the only valid mode.
            if (caps & PIN_VREF == 0 && value != 0)
                || (caps & PIN_VREF != 0 && caps & (1 << (8 + value)) == 0)
            {
                return Err(Error::InvalidPinControl);
            }
            (PIN_INPUT_ENABLE | value, None)
        }
        _ => return Err(Error::InvalidPinControl),
    };
    let mut plan = Plan {
        power: Vec::new(),
        selectors: Vec::new(),
        amplifiers: Vec::new(),
        pin_control,
        eapd,
    };
    plan.power.push(group.node);
    let channels = widget(group, route.converter)?.channels();
    for (offset, node) in route.nodes.iter().enumerate() {
        let current = widget(group, *node)?;
        if current.channels() > 2 || current.channels() < channels {
            return Err(Error::UnsupportedTopology);
        }
        if let Some(power) = current.power_states {
            if power == u32::MAX || power & POWER_D0_SUPPORTED == 0 {
                return Err(Error::UnsupportedTopology);
            }
            plan.power.push(*node);
        }
        let selected = route
            .nodes
            .get(offset + 1)
            .map(|source| {
                current
                    .connections
                    .iter()
                    .position(|node| node == source)
                    .ok_or(Error::InvalidCodecGraph)
            })
            .transpose()?;
        if let Some(index) = selected {
            if current.kind != WidgetKind::Mixer && current.connections.len() > 1 {
                plan.selectors.push((
                    *node,
                    u8::try_from(index).map_err(|_| Error::UnsupportedTopology)?,
                ));
            }
            if current.kind == WidgetKind::Mixer
                && current.connections.len() > 1
                && current.input_amplifier.is_none()
            {
                return Err(Error::UnsupportedTopology);
            }
        }
        let (input, output) = match current.kind {
            WidgetKind::Output => (false, true),
            WidgetKind::Input => (true, false),
            WidgetKind::Pin => (
                route.direction == Direction::Capture,
                route.direction == Direction::Playback,
            ),
            WidgetKind::Mixer | WidgetKind::Selector => (true, true),
            _ => return Err(Error::UnsupportedTopology),
        };
        if input && let Some(caps) = current.input_amplifier {
            let index = selected.unwrap_or(0);
            if current.kind == WidgetKind::Mixer {
                for other in 0..current.connections.len() {
                    plan.amplifiers.push(amplifier(
                        *node,
                        false,
                        other,
                        current.channels(),
                        caps,
                        other != index,
                    )?);
                }
            } else {
                plan.amplifiers.push(amplifier(
                    *node,
                    false,
                    index,
                    current.channels(),
                    caps,
                    false,
                )?);
            }
        }
        if output && let Some(caps) = current.output_amplifier {
            plan.amplifiers
                .push(amplifier(*node, true, 0, current.channels(), caps, false)?);
        }
    }
    Ok(plan)
}

impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn route_control(
        &mut self,
        codec: u8,
        node: u8,
        set: u16,
        get: u16,
        value: u8,
    ) -> Result<(), Error> {
        self.verb(Verb::short(codec, node, set, value)?)?;
        let readback = self.verb(Verb::short(codec, node, get, 0)?)?;
        if readback != u32::from(value) {
            return Err(Error::RouteRejected);
        }
        Ok(())
    }

    pub(super) fn power_d0(&mut self, codec: u8, node: u8) -> Result<(), Error> {
        self.verb(Verb::short(codec, node, SET_POWER, 0)?)?;
        let start = self.timer.now_us();
        loop {
            let state = self.verb(Verb::short(codec, node, GET_POWER, 0)?)?;
            if state == u32::MAX || state & (POWER_REQUESTED | POWER_ERROR) != 0 {
                return Err(Error::RouteRejected);
            }
            if state & POWER_ACTUAL == 0 {
                return Ok(());
            }
            if self.timer.now_us().wrapping_sub(start)
                >= u64::from(self.config.transition_timeout_us)
            {
                return Err(Error::Timeout(Phase::CodecPower));
            }
            self.timer.relax();
        }
    }

    fn route_amplifier(&mut self, codec: u8, amp: Amplifier) -> Result<(), Error> {
        let value = u16::from(amp.gain) | if amp.mute { AMP_MUTE } else { 0 };
        let channels = AMP_LEFT | if amp.channels == 2 { AMP_RIGHT } else { 0 };
        let payload = if amp.output { AMP_OUTPUT } else { AMP_INPUT }
            | channels
            | (u16::from(amp.index) << 8)
            | value;
        self.verb(Verb::long(codec, amp.node, SET_AMP, payload)?)?;
        for channel in 0..amp.channels {
            let get = if amp.output { AMP_OUTPUT } else { 0 }
                | if channel == 0 { AMP_LEFT } else { 0 }
                | u16::from(amp.index);
            let actual = self.verb(Verb::long(codec, amp.node, GET_AMP, get)?)?;
            if actual == u32::MAX || actual & u32::from(AMP_GAIN | AMP_MUTE) != u32::from(value) {
                return Err(Error::RouteRejected);
            }
        }
        Ok(())
    }

    /// Pure typed validation shared with codec-specific startup transactions.
    pub(super) fn preflight_analog_route(
        &self,
        graph: &CodecGraph,
        route: &AnalogRoute,
        id: StreamId,
        channel: u8,
        options: PinOptions,
    ) -> Result<Plan, Error> {
        if graph.token != self.token || route.token != self.token {
            return Err(Error::InvalidCodecGraph);
        }
        if self.routing_failed {
            return Err(Error::NeedsReset);
        }
        self.require_routing_stopped()?;
        if self.stream_direction(id)? != route.direction {
            return Err(Error::InvalidStream);
        }
        self.validate_converter(graph, route.converter, id, channel)?;
        let plan = plan(graph, route, options)?;
        if self.routes.iter().any(|(owner, previous)| {
            *owner == id
                || (previous.codec == route.codec
                    && previous.nodes.iter().any(|node| route.nodes.contains(node)))
        }) {
            return Err(Error::RouteInUse);
        }
        Ok(plan)
    }

    /// Program one explicit standard analog route while every stream is stopped.
    /// Uses 0dB amp offsets, isolates unselected mixer inputs, waits for D0 and
    /// reads every written control back. Successful widget paths are reserved;
    /// sharing/reconfiguration needs full controller reinitialization. Any
    /// hardware failure after programming begins blocks future route/stream
    /// starts until reinitialization; partial codec effects are not rolled back.
    /// OEM GPIO/amp sequencing, jack detection and digital audio remain separate.
    pub fn configure_analog_route(
        &mut self,
        graph: &CodecGraph,
        route: &AnalogRoute,
        id: StreamId,
        channel: u8,
        options: PinOptions,
    ) -> Result<(), Error> {
        let plan = self.preflight_analog_route(graph, route, id, channel, options)?;
        let result = (|| {
            for node in plan.power {
                self.power_d0(route.codec, node)?;
            }
            // Mute-capable selected amps are silenced before changing selectors.
            // Unselected mixer inputs remain muted when selected amps unmute.
            for amp in &plan.amplifiers {
                let group = graph
                    .groups
                    .iter()
                    .find(|group| group.node == route.group)
                    .ok_or(Error::InvalidCodecGraph)?;
                let current = widget(group, amp.node)?;
                let caps = if amp.output {
                    current.output_amplifier
                } else {
                    current.input_amplifier
                }
                .ok_or(Error::InvalidCodecGraph)?;
                if caps & AMP_MUTE_SUPPORTED != 0 {
                    self.route_amplifier(route.codec, Amplifier { mute: true, ..*amp })?;
                }
            }
            for (node, index) in plan.selectors {
                self.route_control(route.codec, node, SET_SELECT, GET_SELECT, index)?;
            }
            self.bind_converter(graph, route.converter, id, channel)?;
            self.route_control(route.codec, route.pin, SET_PIN, GET_PIN, plan.pin_control)?;
            if let Some(enabled) = plan.eapd {
                let old = self.verb(Verb::short(route.codec, route.pin, GET_EAPD, 0)?)?;
                if old > 7 {
                    return Err(Error::RouteRejected);
                }
                let value = old as u8 & !EAPD_ENABLE | if enabled { EAPD_ENABLE } else { 0 };
                self.route_control(route.codec, route.pin, SET_EAPD, GET_EAPD, value)?;
            }
            for amp in plan.amplifiers {
                self.route_amplifier(route.codec, amp)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.routing_failed = true;
        } else {
            self.routes.push((id, route.clone()));
        }
        result
    }
}
