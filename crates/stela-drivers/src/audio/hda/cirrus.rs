// SPDX-License-Identifier: GPL-2.0-only
//! Cirrus held-D0 analog startup adapted from Linux
//! sound/hda/codecs/cirrus/cs420x.c and cs421x.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright (c) 2009 Takashi Iwai <tiwai@suse.de>.
//! GPL version2 combines the upstream GPL-2.0-or-later codec with native HDA.
use super::{
    AnalogRoute, CodecGraph, Controller, PinOptions, PinSense, Registers, StreamId, Verb,
    WidgetKind, routing::RoutePolicy,
};
use crate::{audio::Error, bus::i2c::Timer};
use alloc::vec::Vec;

mod cs4208;
mod cs420x;
mod cs4210;
mod power;
pub use cs4210::CirrusSpeakerBoost;
const GROUP: u8 = 1;
const PROCESSING: u32 = 1 << 6;
const POWER: u32 = 1 << 10;
const DIGITAL: u32 = 1 << 9;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CirrusProfile {
    Cs420x,
    Cs4208,
    Cs4210,
    /// CS4213 shares the DAC range policy but has no CS4210 coefficient recipe.
    Cs4213,
}
impl CirrusProfile {
    fn vendor(self) -> u8 {
        match self {
            Self::Cs420x => 0x11,
            Self::Cs4208 => 0x24,
            Self::Cs4210 => 0x0b,
            Self::Cs4213 => 0x09,
        }
    }
    fn coefficient_count(self) -> u32 {
        match self {
            Self::Cs420x => 24,
            Self::Cs4208 => 53,
            Self::Cs4210 => 28,
            Self::Cs4213 => 0,
        }
    }
    fn route_policy(self) -> RoutePolicy {
        match self {
            Self::Cs420x => RoutePolicy::SingleAdc,
            Self::Cs4208 => RoutePolicy::CirrusCs4208,
            Self::Cs4210 | Self::Cs4213 => RoutePolicy::CirrusCs4210,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CirrusInputAmplifier {
    pub node: u8,
    pub observed_caps: u32,
    pub effective_caps: u32,
    pub effective_channels: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CirrusOutputAmplifier {
    pub node: u8,
    pub observed_caps: u32,
    pub effective_caps: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CirrusCoefficient {
    pub index: u16,
    pub value: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CirrusReport {
    pub profile: CirrusProfile,
    pub processing_node: u8,
    pub input_amplifiers: Vec<CirrusInputAmplifier>,
    pub output_amplifiers: Vec<CirrusOutputAmplifier>,
    pub codec_id: u32,
    pub revision_id: u32,
    pub subsystem_id: u32,
    /// CS4206/7 acknowledge six protected errata coefficient writes; CS4210
    /// acknowledges five and CS4208 has no such sequence. No transient-key
    /// stable getters are invented.
    pub errata_coefficients_acknowledged: usize,
    pub shared_pins: Vec<(u8, u32)>,
    /// Final ordinary configuration values, each read back through real verbs.
    pub coefficients: Vec<CirrusCoefficient>,
}
#[derive(Clone, PartialEq, Eq)]
struct Authority {
    profile: CirrusProfile,
    input_amplifiers: Vec<CirrusInputAmplifier>,
    output_amplifiers: Vec<CirrusOutputAmplifier>,
    processing_caps: Option<u32>,
    pin_defaults: Vec<(u8, u32)>,
    shared_pins: Vec<(u8, u32)>,
    power_nodes: Vec<(u8, u32)>,
}
#[derive(Clone)]
pub(super) struct State {
    address: u8,
    codec_id: u32,
    revision_id: u32,
    pins: Vec<(u8, u32)>,
    authority: Authority,
    coefficients: Vec<CirrusCoefficient>,
    active: bool,
    quiet: bool,
    authority_lost: bool,
    suspended: bool,
    replaying: bool,
    routes: Vec<power::SavedRoute>,
    suspended_speaker_control: Option<u16>,
}
#[cfg(test)]
impl State {
    pub(super) fn authority_lost(&self) -> bool {
        self.authority_lost
    }
    pub(super) fn suspended(&self) -> bool {
        self.suspended
    }
}

fn profile(id: u32) -> Result<CirrusProfile, Error> {
    match id {
        0x1013_4206 | 0x1013_4207 => Ok(CirrusProfile::Cs420x),
        0x1013_4208 => Ok(CirrusProfile::Cs4208),
        0x1013_4210 => Ok(CirrusProfile::Cs4210),
        0x1013_4213 => Ok(CirrusProfile::Cs4213),
        _ => Err(Error::UnsupportedTopology),
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn manages_cirrus_codec(&self, address: u8) -> bool {
        self.cirrus_codecs
            .iter()
            .any(|state| state.address == address)
    }
    fn cirrus_guard(&self, graph: &CodecGraph) -> Result<(), Error> {
        self.vendor_codec_guard(graph)?;
        profile(graph.vendor_id).map(|_| ())
    }
    fn cirrus_authority(&mut self, graph: &CodecGraph) -> Result<Authority, Error> {
        let group = graph
            .groups
            .iter()
            .find(|group| group.node == GROUP && group.function_type & 255 == 1)
            .ok_or(Error::UnsupportedTopology)?;
        let selected = profile(graph.vendor_id)?;
        let vendor_node = selected.vendor();
        let vendor = graph
            .widget(vendor_node)
            .ok_or(Error::UnsupportedTopology)?;
        if vendor.kind != WidgetKind::Vendor(15) {
            return Err(Error::UnsupportedTopology);
        }
        // cs421x_init skips every vendor/processing operation for
        // CS4213. Its node9 identifies the variant; it does not authorize the
        // CS4210 coefficient protocol or an invented processing capability.
        let processing_caps = if selected == CirrusProfile::Cs4213 {
            None
        } else {
            if vendor.capabilities & PROCESSING == 0 {
                return Err(Error::UnsupportedTopology);
            }
            let caps = self.verb(Verb::short(graph.address, vendor_node, 0xf00, 0x10)?)?;
            if caps == u32::MAX || (caps >> 8) & 255 < selected.coefficient_count() {
                return Err(Error::UnsupportedTopology);
            }
            Some(caps)
        };
        let mut power_nodes = Vec::new();
        let nodes = if selected == CirrusProfile::Cs420x {
            alloc::vec![
                (7, WidgetKind::Input),
                (8, WidgetKind::Output),
                (vendor_node, WidgetKind::Vendor(15))
            ]
        } else {
            alloc::vec![(vendor_node, WidgetKind::Vendor(15))]
        };
        for (node, kind) in nodes {
            let widget = graph.widget(node).ok_or(Error::UnsupportedTopology)?;
            if widget.kind != kind || (node != vendor_node && widget.capabilities & DIGITAL == 0) {
                return Err(Error::UnsupportedTopology);
            }
            if widget.capabilities & POWER == 0 {
                if node != vendor_node {
                    return Err(Error::UnsupportedTopology);
                }
                continue;
            }
            let caps = self.verb(Verb::short(graph.address, node, 0xf00, 0x0f)?)?;
            let effective = if caps == 0 {
                group.power_states.ok_or(Error::InvalidCodecGraph)?
            } else {
                caps
            };
            if effective == u32::MAX || effective & 1 == 0 || widget.power_states != Some(effective)
            {
                return Err(Error::InvalidCodecGraph);
            }
            power_nodes.push((node, effective));
        }
        let (shared_pins, input_amplifiers) = match selected {
            CirrusProfile::Cs420x => (self.cs420x_shared_pins(graph)?, Vec::new()),
            CirrusProfile::Cs4208 => (Vec::new(), self.cs4208_input_amplifiers(graph)?),
            CirrusProfile::Cs4210 | CirrusProfile::Cs4213 => (Vec::new(), Vec::new()),
        };
        let output_amplifiers = if matches!(selected, CirrusProfile::Cs4210 | CirrusProfile::Cs4213)
        {
            self.cs4210_output_amplifiers(graph)?
        } else {
            Vec::new()
        };
        let pin_defaults = if matches!(selected, CirrusProfile::Cs4210 | CirrusProfile::Cs4213) {
            self.cs4210_pin_defaults(graph)?
        } else {
            Vec::new()
        };
        Ok(Authority {
            pin_defaults,
            profile: selected,
            processing_caps,
            shared_pins,
            power_nodes,
            input_amplifiers,
            output_amplifiers,
        })
    }
    fn cirrus_index(&mut self, address: u8, vendor: u8, index: u16) -> Result<(), Error> {
        self.verb(Verb::long(address, vendor, 5, index)?)?;
        if self.verb(Verb::long(address, vendor, 13, 0)?)? != u32::from(index) {
            return Err(Error::CoefficientRejected {
                node: vendor,
                index,
            });
        }
        Ok(())
    }
    fn cirrus_read(&mut self, address: u8, vendor: u8, index: u16) -> Result<u16, Error> {
        self.cirrus_index(address, vendor, index)?;
        u16::try_from(self.verb(Verb::long(address, vendor, 12, 0)?)?).map_err(|_| {
            Error::CoefficientRejected {
                node: vendor,
                index,
            }
        })
    }
    fn cirrus_coefficient_ack(
        &mut self,
        address: u8,
        vendor: u8,
        index: u16,
        value: u16,
    ) -> Result<(), Error> {
        if self.verb(Verb::long(address, vendor, 5, index)?)? == u32::MAX
            || self.verb(Verb::long(address, vendor, 4, value)?)? == u32::MAX
        {
            return Err(Error::CoefficientRejected {
                node: vendor,
                index,
            });
        }
        Ok(())
    }
    fn cirrus_write(
        &mut self,
        address: u8,
        vendor: u8,
        index: u16,
        value: u16,
    ) -> Result<CirrusCoefficient, Error> {
        self.cirrus_coefficient_ack(address, vendor, index, value)?;
        if self.cirrus_read(address, vendor, index)? != value {
            return Err(Error::CoefficientRejected {
                node: vendor,
                index,
            });
        }
        Ok(CirrusCoefficient { index, value })
    }
    fn cirrus_processing(&mut self, address: u8, vendor: u8, state: u8) -> Result<(), Error> {
        self.route_control(address, vendor, 0x703, 0xf03, state)
    }
    fn cirrus_active(&mut self, graph: &CodecGraph) -> Result<State, Error> {
        self.cirrus_guard(graph)?;
        let state = self
            .cirrus_codecs
            .iter()
            .find(|state| state.address == graph.address && state.active && !state.quiet)
            .cloned()
            .ok_or(Error::NeedsReset)?;
        let result = (|| {
            let live = self.validate_live_analog_codec(graph)?;
            if live.group != GROUP
                || graph.vendor_id != state.codec_id
                || graph.revision_id != state.revision_id
                || live.pins != state.pins
                || self.cirrus_authority(graph)? != state.authority
            {
                return Err(Error::InvalidCodecGraph);
            }
            let vendor = state.authority.profile.vendor();
            if state.authority.processing_caps.is_some()
                && self.verb(Verb::short(graph.address, vendor, 0xf03, 0)?)? != 1
            {
                return Err(Error::RouteRejected);
            }
            for coefficient in &state.coefficients {
                if self.cirrus_read(graph.address, vendor, coefficient.index)? != coefficient.value
                {
                    return Err(Error::CoefficientRejected {
                        node: vendor,
                        index: coefficient.index,
                    });
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.routing_failed = true;
            if let Some(owned) = self
                .cirrus_codecs
                .iter_mut()
                .find(|owned| owned.address == graph.address)
            {
                owned.authority_lost = true;
            }
            return Err(error);
        }
        Ok(state)
    }
    /// Source-checked cold startup, shared-pin mux and analog capabilities.
    /// No OEM GPIO, pin rewrite, automute or digital-stream policy is inferred.
    pub fn initialize_cirrus_codec(&mut self, graph: &CodecGraph) -> Result<CirrusReport, Error> {
        self.cirrus_guard(graph)?;
        self.require_routing_stopped()?;
        if self
            .converter_bindings
            .iter()
            .any(|binding| binding.codec == graph.address)
            || self.manages_realtek_codec(graph.address)
            || self.manages_cirrus_codec(graph.address)
            || self.manages_conexant_codec(graph.address)
            || self.manages_sigmatel_codec(graph.address)
            || self
                .routes
                .iter()
                .any(|(_, route)| route.codec_address() == graph.address)
            || self
                .codec_controls
                .iter()
                .any(|(_, codec, _)| *codec == graph.address)
        {
            return Err(Error::RouteInUse);
        }
        let live = self.validate_live_analog_codec(graph)?;
        if live.group != GROUP {
            return Err(Error::UnsupportedTopology);
        }
        let authority = self.cirrus_authority(graph)?;
        let index = self.cirrus_codecs.len();
        self.cirrus_codecs.push(State {
            address: graph.address,
            codec_id: graph.vendor_id,
            revision_id: graph.revision_id,
            pins: live.pins,
            authority: authority.clone(),
            coefficients: Vec::new(),
            active: false,
            quiet: false,
            authority_lost: false,
            suspended: false,
            replaying: false,
            routes: Vec::new(),
            suspended_speaker_control: None,
        });
        let result = (|| {
            let selected = authority.profile;
            let vendor = selected.vendor();
            self.power_d0(graph.address, GROUP)?;
            if authority
                .power_nodes
                .iter()
                .any(|(node, _)| *node == vendor)
            {
                self.power_d0(graph.address, vendor)?;
            }
            let coefficients = match selected {
                CirrusProfile::Cs420x => self.initialize_cs420x_coefficients(graph, &authority)?,
                CirrusProfile::Cs4208 => self.initialize_cs4208_coefficients(graph)?,
                CirrusProfile::Cs4210 => self.initialize_cs4210_coefficients(graph)?,
                CirrusProfile::Cs4213 => Vec::new(),
            };
            Ok(CirrusReport {
                profile: selected,
                processing_node: vendor,
                input_amplifiers: authority.input_amplifiers.clone(),
                output_amplifiers: authority.output_amplifiers.clone(),
                codec_id: graph.vendor_id,
                revision_id: graph.revision_id,
                subsystem_id: live.subsystem,
                errata_coefficients_acknowledged: match selected {
                    CirrusProfile::Cs420x => cs420x::ERRATA_COEFFICIENT_WRITES,
                    CirrusProfile::Cs4208 | CirrusProfile::Cs4213 => 0,
                    CirrusProfile::Cs4210 => cs4210::ERRATA_COEFFICIENT_WRITES,
                },
                shared_pins: authority.shared_pins.clone(),
                coefficients,
            })
        })();
        match &result {
            Ok(report) => {
                self.cirrus_codecs[index].active = true;
                self.cirrus_codecs[index].coefficients = report.coefficients.clone();
            }
            Err(_) => self.routing_failed = true,
        }
        result
    }
    /// Use the analog path with the source ADC/stereo/gain
    /// policy. Per-pin EAPD follows the caller's explicit electrical options.
    pub fn configure_cirrus_route(
        &mut self,
        graph: &CodecGraph,
        route: &AnalogRoute,
        stream: StreamId,
        channel: u8,
        options: PinOptions,
    ) -> Result<(), Error> {
        self.cirrus_guard(graph)?;
        let policy = profile(graph.vendor_id)?.route_policy();
        self.preflight_analog_route_policy(graph, route, stream, channel, options, policy)?;
        self.cirrus_active(graph)?;
        self.configure_analog_route_policy(graph, route, stream, channel, options, policy)?;
        self.cirrus_codecs
            .iter_mut()
            .find(|state| state.address == graph.address)
            .ok_or(Error::NeedsReset)?
            .routes
            .push(power::SavedRoute {
                route: route.clone(),
                stream,
                channel,
                options,
            });
        Ok(())
    }
    pub fn poll_cirrus_pin_sense(
        &mut self,
        graph: &CodecGraph,
        pin: u8,
    ) -> Result<PinSense, Error> {
        self.cirrus_active(graph)?;
        let result = self.poll_pin_sense_policy(graph, pin, true);
        if result.as_ref().is_err_and(|error| {
            *error != Error::UnsupportedTopology && *error != Error::InvalidCodecGraph
        }) {
            self.routing_failed = true;
        }
        result
    }
    pub(super) fn shutdown_cirrus_codecs(&mut self) -> Result<(), Error> {
        for index in 0..self.cirrus_codecs.len() {
            let state = self.cirrus_codecs[index].clone();
            if state.quiet {
                continue;
            }
            if state.authority_lost || self.command_poisoned {
                return Err(Error::NeedsReset);
            }
            if state.suspended {
                // Successful D3hot already acknowledged pin quiet and rail
                // power-down. Do not issue pin writes to a sleeping function.
                self.cirrus_codecs[index].quiet = true;
                continue;
            }
            for (pin, _) in state.pins {
                self.route_control(state.address, pin, 0x707, 0xf07, 0)?;
            }
            self.cirrus_codecs[index].active = false;
            self.cirrus_codecs[index].quiet = true;
        }
        Ok(())
    }
}
