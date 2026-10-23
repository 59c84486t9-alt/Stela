// SPDX-License-Identifier: GPL-2.0-only
//! CS4206/CS4207 held-D0 analog startup adapted from Linux
//! sound/hda/codecs/cirrus/cs420x.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright (c) 2009 Takashi Iwai <tiwai@suse.de>.
//! GPL version2 combines the upstream GPL-2.0-or-later codec with native HDA.
use super::{
    AnalogRoute, CodecGraph, Controller, PinConnection, PinOptions, PinSense, Registers, StreamId,
    Verb, WidgetKind, routing::RoutePolicy,
};
use crate::{audio::Error, bus::i2c::Timer};
use alloc::vec::Vec;

const VENDOR: u8 = 0x11;
const GROUP: u8 = 1;
const PROCESSING: u32 = 1 << 6;
const POWER: u32 = 1 << 10;
const DIGITAL: u32 = 1 << 9;
const SHARED_PINS: [u8; 3] = [0x0e, 0x12, 0x15];
const DAC_CONFIG: u16 = 0x146a;
const ADC_CONFIG: u16 = 0x000a;
const BEEP_CONFIG: u16 = 0x0007;
const SPDIF_CONFIG: u16 = 0x000a;
const ERRATA_COEFFICIENT_WRITES: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CirrusCoefficient {
    pub index: u16,
    pub value: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CirrusReport {
    pub codec_id: u32,
    pub revision_id: u32,
    pub subsystem_id: u32,
    /// Six protected errata coefficient writes preserve source ordering. Their
    /// command acknowledgements do not invent getters for transient test keys.
    pub errata_coefficients_acknowledged: usize,
    pub shared_pins: Vec<(u8, u32)>,
    /// Final ordinary configuration values, each read back through real verbs.
    pub coefficients: Vec<CirrusCoefficient>,
}
#[derive(Clone, PartialEq, Eq)]
struct Authority {
    processing_caps: u32,
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
}
fn supported(id: u32) -> Result<(), Error> {
    if matches!(id, 0x1013_4206 | 0x1013_4207) {
        Ok(())
    } else {
        Err(Error::UnsupportedTopology)
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn manages_cirrus_codec(&self, address: u8) -> bool {
        self.cirrus_codecs
            .iter()
            .any(|state| state.address == address)
    }
    fn cirrus_guard(&self, graph: &CodecGraph) -> Result<(), Error> {
        if graph.token != self.token {
            return Err(Error::InvalidCodecGraph);
        }
        if self.routing_failed || self.lifecycle_failed || self.command_poisoned {
            return Err(Error::NeedsReset);
        }
        if self.stopped {
            return Err(Error::Shutdown);
        }
        supported(graph.vendor_id)
    }
    fn cirrus_authority(&mut self, graph: &CodecGraph) -> Result<Authority, Error> {
        let group = graph
            .groups
            .iter()
            .find(|group| group.node == GROUP && group.function_type & 255 == 1)
            .ok_or(Error::UnsupportedTopology)?;
        let vendor = graph.widget(VENDOR).ok_or(Error::UnsupportedTopology)?;
        if vendor.kind != WidgetKind::Vendor(15) || vendor.capabilities & PROCESSING == 0 {
            return Err(Error::UnsupportedTopology);
        }
        let processing_caps = self.verb(Verb::short(graph.address, VENDOR, 0xf00, 0x10)?)?;
        if processing_caps == u32::MAX || (processing_caps >> 8) & 255 < 24 {
            return Err(Error::UnsupportedTopology);
        }
        let mut power_nodes = Vec::new();
        for (node, kind) in [
            (7, WidgetKind::Input),
            (8, WidgetKind::Output),
            (VENDOR, WidgetKind::Vendor(15)),
        ] {
            let widget = graph.widget(node).ok_or(Error::UnsupportedTopology)?;
            if widget.kind != kind || (node != VENDOR && widget.capabilities & DIGITAL == 0) {
                return Err(Error::UnsupportedTopology);
            }
            if widget.capabilities & POWER == 0 {
                if node != VENDOR {
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
        let mut shared_pins = Vec::new();
        for node in SHARED_PINS {
            let pin = graph.widget(node).ok_or(Error::UnsupportedTopology)?;
            let caps = pin.pin_capabilities.ok_or(Error::UnsupportedTopology)?;
            let configuration = pin.pin_configuration().ok_or(Error::UnsupportedTopology)?;
            let direction = if node == 0x15 { 1 << 4 } else { 1 << 5 };
            if pin.kind != WidgetKind::Pin
                || pin.capabilities & DIGITAL == 0
                || caps == u32::MAX
                || caps & direction == 0
                || configuration.raw == u32::MAX
            {
                return Err(Error::UnsupportedTopology);
            }
            if self.verb(Verb::short(graph.address, node, 0xf1c, 0)?)? != configuration.raw {
                return Err(Error::InvalidCodecGraph);
            }
            shared_pins.push((node, configuration.raw));
        }
        Ok(Authority {
            processing_caps,
            shared_pins,
            power_nodes,
        })
    }
    fn cirrus_index(&mut self, address: u8, index: u16) -> Result<(), Error> {
        self.verb(Verb::long(address, VENDOR, 5, index)?)?;
        if self.verb(Verb::long(address, VENDOR, 13, 0)?)? != u32::from(index) {
            return Err(Error::CoefficientRejected {
                node: VENDOR,
                index,
            });
        }
        Ok(())
    }
    fn cirrus_read(&mut self, address: u8, index: u16) -> Result<u16, Error> {
        self.cirrus_index(address, index)?;
        u16::try_from(self.verb(Verb::long(address, VENDOR, 12, 0)?)?).map_err(|_| {
            Error::CoefficientRejected {
                node: VENDOR,
                index,
            }
        })
    }
    fn cirrus_coefficient_ack(&mut self, address: u8, index: u16, value: u16) -> Result<(), Error> {
        if self.verb(Verb::long(address, VENDOR, 5, index)?)? == u32::MAX
            || self.verb(Verb::long(address, VENDOR, 4, value)?)? == u32::MAX
        {
            return Err(Error::CoefficientRejected {
                node: VENDOR,
                index,
            });
        }
        Ok(())
    }
    fn cirrus_write(
        &mut self,
        address: u8,
        index: u16,
        value: u16,
    ) -> Result<CirrusCoefficient, Error> {
        self.cirrus_coefficient_ack(address, index, value)?;
        if self.cirrus_read(address, index)? != value {
            return Err(Error::CoefficientRejected {
                node: VENDOR,
                index,
            });
        }
        Ok(CirrusCoefficient { index, value })
    }
    fn cirrus_processing(&mut self, address: u8, state: u8) -> Result<(), Error> {
        self.route_control(address, VENDOR, 0x703, 0xf03, state)
    }
    fn cirrus_errata(&mut self, address: u8, authority: &Authority) -> Result<(), Error> {
        self.power_d0(address, GROUP)?;
        if authority
            .power_nodes
            .iter()
            .any(|(node, _)| *node == VENDOR)
        {
            self.power_d0(address, VENDOR)?;
        }
        self.cirrus_processing(address, 1)?;
        for (index, value) in [(8, 0x9999), (0x17, 0xa412), (1, 9)] {
            self.cirrus_coefficient_ack(address, index, value)?;
        }
        self.power_d0(address, 7)?;
        self.power_d0(address, 8)?;
        for (index, value) in [(0x17, 0x2412), (8, 0), (1, 8)] {
            self.cirrus_coefficient_ack(address, index, value)?;
        }
        self.cirrus_processing(address, 0)
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
            if self.verb(Verb::short(graph.address, VENDOR, 0xf03, 0)?)? != 1 {
                return Err(Error::RouteRejected);
            }
            for coefficient in &state.coefficients {
                if self.cirrus_read(graph.address, coefficient.index)? != coefficient.value {
                    return Err(Error::CoefficientRejected {
                        node: VENDOR,
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
    /// Source-qualified cold startup and shared-pin mux configuration only.
    /// No OEM GPIO, pin rewrite, automute or digital-stream policy is inferred.
    pub fn initialize_cirrus_codec(&mut self, graph: &CodecGraph) -> Result<CirrusReport, Error> {
        self.cirrus_guard(graph)?;
        self.require_routing_stopped()?;
        if self.manages_cirrus_codec(graph.address)
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
        });
        let result = (|| {
            // The donor applies this sequence unconditionally to both CS4206
            // and CS4207, regardless of revision; no source effect is skipped.
            self.cirrus_errata(graph.address, &authority)?;
            self.cirrus_processing(graph.address, 1)?;
            let mut coefficients = alloc::vec![
                self.cirrus_write(graph.address, 3, DAC_CONFIG)?,
                self.cirrus_write(graph.address, 2, ADC_CONFIG)?,
            ];
            self.cirrus_write(graph.address, 4, BEEP_CONFIG)?;
            let active = |node| {
                authority.shared_pins.iter().any(|(pin, raw)| {
                    *pin == node
                        && (super::PinConfiguration { raw: *raw }).connection()
                            != PinConnection::None
                })
            };
            let mut beep = self.cirrus_read(graph.address, 4)?;
            if active(0x12) {
                beep |= 1 << 4;
            }
            if active(0x0e) {
                beep |= 1 << 3;
            }
            coefficients.push(self.cirrus_write(graph.address, 4, beep)?);
            let spdif = SPDIF_CONFIG | if active(0x15) { 0x4000 } else { 0 };
            coefficients.push(self.cirrus_write(graph.address, 1, spdif)?);
            Ok(CirrusReport {
                codec_id: graph.vendor_id,
                revision_id: graph.revision_id,
                subsystem_id: live.subsystem,
                errata_coefficients_acknowledged: ERRATA_COEFFICIENT_WRITES,
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
    /// Use the actual analog path with source single_adc_amp index0. Standard
    /// per-pin EAPD still follows the caller's explicit electrical options.
    pub fn configure_cirrus_route(
        &mut self,
        graph: &CodecGraph,
        route: &AnalogRoute,
        stream: StreamId,
        channel: u8,
        options: PinOptions,
    ) -> Result<(), Error> {
        self.cirrus_guard(graph)?;
        self.preflight_analog_route_policy(
            graph,
            route,
            stream,
            channel,
            options,
            RoutePolicy::SingleAdc,
        )?;
        self.cirrus_active(graph)?;
        self.configure_analog_route_policy(
            graph,
            route,
            stream,
            channel,
            options,
            RoutePolicy::SingleAdc,
        )
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
            for (pin, _) in state.pins {
                self.route_control(state.address, pin, 0x707, 0xf07, 0)?;
            }
            self.cirrus_codecs[index].active = false;
            self.cirrus_codecs[index].quiet = true;
        }
        Ok(())
    }
}
