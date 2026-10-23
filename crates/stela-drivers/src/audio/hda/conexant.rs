// SPDX-License-Identifier: GPL-2.0-or-later
//! Conexant standard-route backend adapted from Linux conexant.c and generic.c.
//! Linux a804c5742bff224d4cb4d25dd383554d598be32b.
//! generic.c Copyright (c) 2004 Takashi Iwai.
//! Copyright (c) 2006 Pototskiy Akex, Takashi Iwai and Tobin Davis.
//! EAPD count selects the donor's global/dynamic heuristic; no OEM GPIO, ACPI,
//! LED or pin override policy is inferred from a codec ID. Fixed-node headset
//! procedures require the separate source-bound headset initialization entry.
use super::routing::RoutePolicy;
use super::{
    AnalogRoute, CodecGraph, Controller, PinOptions, Registers, StreamId, Verb, WidgetKind,
};
use crate::{
    audio::{Direction, Error},
    bus::i2c::Timer,
};
use alloc::vec::Vec;

mod headset;
pub use headset::{ConexantHeadsetInitialization, ConexantHeadsetKind, ConexantHeadsetReport};

const GET_EAPD: u16 = 0xf0c;
const SET_EAPD: u16 = 0x70c;
const PIN_EAPD: u32 = 1 << 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConexantEapdMode {
    Global,
    Dynamic,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConexantReport {
    pub codec_id: u32,
    pub revision_id: u32,
    pub subsystem_id: u32,
    pub function_group: u8,
    /// Inferred from the donor's count heuristic, not a silicon capability bit.
    pub eapd_mode: ConexantEapdMode,
    /// Actual pin IDs and observed EAPD controls after initialization.
    pub eapd: Vec<(u8, u8)>,
    pub single_adc_amplifier: bool,
}
#[derive(Clone)]
pub(super) struct State {
    address: u8,
    codec_id: u32,
    revision_id: u32,
    group: u8,
    pins: Vec<u8>,
    active: bool,
    retired: bool,
    authority_lost: bool,
    headset: Option<headset::State>,
}
fn route_policy(id: u32) -> Result<RoutePolicy, Error> {
    if profile(id)? {
        Ok(RoutePolicy::SingleAdc)
    } else if id == 0x14f1_5051 {
        Ok(RoutePolicy::ConexantCx20561)
    } else {
        Ok(RoutePolicy::Standard)
    }
}
fn profile(id: u32) -> Result<bool, Error> {
    match id {
        // CX20549 uses a single ADC amp regardless of selected input index.
        0x14f1_5045 => Ok(true),
        0x14f1_2008 | 0x14f1_20d0 | 0x14f1_20d1 | 0x14f1_5047 | 0x14f1_5051 | 0x14f1_5066
        | 0x14f1_5067 | 0x14f1_5068 | 0x14f1_5069 | 0x14f1_506c | 0x14f1_506e | 0x14f1_5097
        | 0x14f1_5098 | 0x14f1_50a1 | 0x14f1_50a2 | 0x14f1_50ab | 0x14f1_50ac | 0x14f1_50b8
        | 0x14f1_50b9 | 0x14f1_50f1 | 0x14f1_50f2 | 0x14f1_50f3 | 0x14f1_50f4 | 0x14f1_510f
        | 0x14f1_5110 | 0x14f1_5111 | 0x14f1_5113 | 0x14f1_5114 | 0x14f1_5115 | 0x14f1_51d7 => {
            Ok(false)
        }
        0x14f1_1f86 | 0x14f1_1f87 => Ok(false),
        _ => Err(Error::UnsupportedTopology),
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn manages_conexant_codec(&self, address: u8) -> bool {
        self.conexant_codecs
            .iter()
            .any(|state| state.address == address)
    }
    fn conexant_guard(&self, graph: &CodecGraph) -> Result<(), Error> {
        if graph.token != self.token {
            return Err(Error::InvalidCodecGraph);
        }
        if self.routing_failed || self.lifecycle_failed || self.command_poisoned {
            return Err(Error::NeedsReset);
        }
        if self.stopped {
            return Err(Error::Shutdown);
        }
        profile(graph.vendor_id)?;
        Ok(())
    }
    fn conexant_identity(&mut self, graph: &CodecGraph) -> Result<(u8, u32, Vec<u8>), Error> {
        let live = self.validate_live_analog_codec(graph)?;
        let pins: Vec<_> = live
            .pins
            .iter()
            .filter_map(|(node, caps)| (caps & PIN_EAPD != 0).then_some(*node))
            .collect();
        if pins.len() > 4 {
            return Err(Error::UnsupportedTopology);
        }
        Ok((live.group, live.subsystem, pins))
    }
    fn conexant_eapd(&mut self, codec: u8, pin: u8, enabled: bool) -> Result<u8, Error> {
        // Match cx_auto_turn_eapd exactly, including its whole control value.
        let value = if enabled { 2 } else { 0 };
        self.route_control(codec, pin, SET_EAPD, GET_EAPD, value)?;
        Ok(value)
    }
    /// Initialize held-D0 standard analog control ownership. The graph must
    /// describe the actual codec. Dynamic EAPD retains its observed value until
    /// the caller explicitly applies the master output switch. OEM pin/GPIO,
    /// ACPI, headset protocols, unsolicited events and suspend are separate.
    pub fn initialize_conexant_codec(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<ConexantReport, Error> {
        self.conexant_guard(graph)?;
        if headset::is_profile(graph.vendor_id) {
            return Err(Error::UnsupportedTopology);
        }
        self.initialize_conexant_common(graph)
    }
    fn initialize_conexant_common(&mut self, graph: &CodecGraph) -> Result<ConexantReport, Error> {
        self.conexant_guard(graph)?;
        self.require_routing_stopped()?;
        if self.manages_sigmatel_codec(graph.address)
            || self.manages_cirrus_codec(graph.address)
            || self
                .routes
                .iter()
                .any(|(_, r)| r.codec_address() == graph.address)
            || self
                .codec_controls
                .iter()
                .any(|(_, c, _)| *c == graph.address)
            || self
                .conexant_codecs
                .iter()
                .any(|c| c.address == graph.address)
        {
            return Err(Error::RouteInUse);
        }
        let single_adc = profile(graph.vendor_id)?;
        let (group, subsystem, pins) = self.conexant_identity(graph)?;
        let mode = if pins.len() > 2 {
            ConexantEapdMode::Dynamic
        } else {
            ConexantEapdMode::Global
        };
        let index = self.conexant_codecs.len();
        // Retain the exact verified pin set before any power/EAPD effects.
        self.conexant_codecs.push(State {
            address: graph.address,
            codec_id: graph.vendor_id,
            revision_id: graph.revision_id,
            group,
            pins: pins.clone(),
            active: false,
            retired: false,
            authority_lost: false,
            headset: None,
        });
        let result = (|| {
            self.power_d0(graph.address, group)?;
            let mut observed = Vec::new();
            for pin in pins {
                let value = if mode == ConexantEapdMode::Global {
                    self.conexant_eapd(graph.address, pin, true)?
                } else {
                    let value = self.verb(Verb::short(graph.address, pin, GET_EAPD, 0)?)?;
                    if value > 7 {
                        return Err(Error::RouteRejected);
                    }
                    value as u8
                };
                observed.push((pin, value));
            }
            Ok(ConexantReport {
                codec_id: graph.vendor_id,
                revision_id: graph.revision_id,
                subsystem_id: subsystem,
                function_group: group,
                eapd_mode: mode,
                eapd: observed,
                single_adc_amplifier: single_adc,
            })
        })();
        if result.is_ok() {
            self.conexant_codecs[index].active = true;
        } else {
            self.routing_failed = true;
        }
        result
    }
    fn conexant_active(&mut self, graph: &CodecGraph) -> Result<State, Error> {
        self.conexant_guard(graph)?;
        let state = self
            .conexant_codecs
            .iter()
            .find(|c| c.address == graph.address && c.active && !c.retired)
            .cloned()
            .ok_or(Error::NeedsReset)?;
        let identity = self.conexant_identity(graph).and_then(|(group, _, pins)| {
            if group != state.group
                || pins != state.pins
                || graph.vendor_id != state.codec_id
                || graph.revision_id != state.revision_id
            {
                return Err(Error::InvalidCodecGraph);
            }
            Ok(())
        });
        if let Err(error) = identity {
            // Once this codec is owned, a lost live authority check makes its
            // already configured routes uncertain too. Retain their resources
            // and prevent any later start until actual reset.
            self.routing_failed = true;
            if let Some(owned) = self
                .conexant_codecs
                .iter_mut()
                .find(|owned| owned.address == graph.address)
            {
                owned.authority_lost = true;
            }
            return Err(error);
        }
        Ok(state)
    }
    /// Configure an explicit analog path using the codec's ADC amp policy.
    /// EAPD stays under codec ownership: pass None in playback options and use
    /// set_conexant_outputs_enabled for the master output switch.
    pub fn configure_conexant_route(
        &mut self,
        graph: &CodecGraph,
        route: &AnalogRoute,
        id: StreamId,
        channel: u8,
        options: PinOptions,
    ) -> Result<(), Error> {
        self.conexant_guard(graph)?;
        let policy = route_policy(graph.vendor_id)?;
        self.preflight_analog_route_policy(graph, route, id, channel, options, policy)?;
        let state = self.conexant_active(graph)?;
        if let Some(headset) = &state.headset {
            headset::route_options(headset, route, options)?;
        }
        // own_eapd_ctl in cx_probe suppresses generic per-pin EAPD updates.
        // Both global and dynamic codecs use the separate whole-value master
        // operation, so routing cannot silently rewrite that policy.
        if route.direction() == Direction::Playback
            && state.pins.contains(&route.pin())
            && matches!(options, PinOptions::Playback { eapd: Some(_), .. })
        {
            return Err(Error::InvalidPinControl);
        }
        self.configure_analog_route_policy(graph, route, id, channel, options, policy)
    }
    /// Linux's vmaster EAPD operation. Live DMA may continue; any failed effect
    /// blocks future starts until reset, while all buffers remain retained.
    pub fn set_conexant_outputs_enabled(
        &mut self,
        graph: &CodecGraph,
        enabled: bool,
    ) -> Result<(), Error> {
        if self.streams.iter().flatten().any(|s| s.poisoned) {
            return Err(Error::NeedsReset);
        }
        let state = self.conexant_active(graph)?;
        for pin in state.pins {
            if let Err(error) = self.conexant_eapd(graph.address, pin, enabled) {
                self.routing_failed = true;
                return Err(error);
            }
        }
        Ok(())
    }
    /// Mute/unmute a retained CX20561 DAC route at its advertised 0dB gain.
    /// The two source-authorized DACs use physical minimum gain when no mute
    /// bit exists. Existing PCM DMA may continue. No mixer cache or external
    /// volume is inferred; unmute explicitly reapplies this route's 0dB level.
    pub fn set_conexant_cx20561_converter_muted(
        &mut self,
        graph: &CodecGraph,
        converter: u8,
        muted: bool,
    ) -> Result<(), Error> {
        self.conexant_guard(graph)?;
        if graph.vendor_id != 0x14f1_5051 || !matches!(converter, 0x10 | 0x11) {
            return Err(Error::UnsupportedTopology);
        }
        if self.streams.iter().flatten().any(|stream| stream.poisoned) {
            return Err(Error::NeedsReset);
        }
        if !self.routes.iter().any(|(_, route)| {
            route.codec_address() == graph.address
                && route.converter() == converter
                && route.direction() == Direction::Playback
        }) {
            return Err(Error::RouteInUse);
        }
        let widget = graph.widget(converter).ok_or(Error::InvalidCodecGraph)?;
        let caps = widget.output_amplifier.ok_or(Error::UnsupportedTopology)?;
        if widget.kind != WidgetKind::Output
            || (widget.capabilities >> 20) & 15 != 0
            || caps == u32::MAX
            || widget.channels() > 2
            || (caps & 127) > ((caps >> 8) & 127)
            || (caps & (1 << 31) == 0 && caps & 127 == 0)
        {
            return Err(Error::UnsupportedTopology);
        }
        let state = self.conexant_active(graph)?;
        let result = (|| {
            self.validate_live_output_amplifier(graph.address, state.group, widget)?;
            self.minimum_gain_mute(graph.address, widget, muted)
        })();
        if result.is_err() {
            self.routing_failed = true;
        }
        result
    }

    /// Called only after every actual stream stop has acknowledged, before CORB
    /// and RIRB stop. Unknown codec effects remain retained through error/reset.
    pub(super) fn shutdown_conexant_codecs(&mut self) -> Result<(), Error> {
        for index in 0..self.conexant_codecs.len() {
            let state = self.conexant_codecs[index].clone();
            if state.retired {
                continue;
            }
            if state.authority_lost || self.stopped || self.command_poisoned {
                return Err(Error::NeedsReset);
            }
            for pin in state.pins {
                self.conexant_eapd(state.address, pin, false)?;
            }
            self.conexant_codecs[index].active = false;
            self.conexant_codecs[index].retired = true;
        }
        Ok(())
    }
}
