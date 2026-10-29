// SPDX-License-Identifier: GPL-2.0-only
//! CS421x D3hot and kept-route resume adapted from cs421x_suspend and
//! cs421x_init in Linux sound/hda/codecs/cirrus/cs421x.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b. Native route replay uses Stela's
//! graph/stream/amp permission, not an invented codec register cache.
use super::super::{
    AnalogRoute, CodecGraph, Controller, PinOptions, Registers, StreamId, Verb, WidgetKind,
};
use super::{CirrusProfile, GROUP, State};
use crate::{Error, Phase, bus::i2c::Timer};
use alloc::vec::Vec;

const DAC: u8 = 2;
const ADC: u8 = 3;
const D3: u8 = 3;
const D0_D3: u32 = 1 | (1 << D3);
const POWER_CAPABLE: u32 = 1 << 10;
const POWER_ERROR: u32 = 1 << 8;
const REQUESTED: u32 = 15;
const ACTUAL: u32 = 15 << 4;
const DEVICE_CONFIG: u16 = 1;
const PDREF: u16 = 4;
const SPEAKER_CONTROL: u16 = 4;

#[derive(Clone)]
pub(super) struct SavedRoute {
    pub route: AnalogRoute,
    pub stream: StreamId,
    pub channel: u8,
    pub options: PinOptions,
}

impl<R: Registers, T: Timer> Controller<R, T> {
    /// Called before the controller's SD_RUN write. A kept route
    /// never licenses DMA while its owning codec is suspended or replaying.
    pub(in crate::hda) fn require_cirrus_route_power(&self, id: StreamId) -> Result<(), Error> {
        for (_, route) in self.routes.iter().filter(|(stream, _)| *stream == id) {
            if self.cirrus_codecs.iter().any(|state| {
                state.address == route.codec_address() && (!state.active || state.suspended)
            }) {
                return Err(Error::NeedsReset);
            }
        }
        for binding in &self.converter_bindings {
            if binding.stream == id
                && self.cirrus_codecs.iter().any(|state| {
                    state.address == binding.codec && (!state.active || state.suspended)
                })
            {
                return Err(Error::NeedsReset);
            }
        }
        for (stream, address, _) in &self.codec_controls {
            if *stream == id
                && self
                    .cirrus_codecs
                    .iter()
                    .any(|state| state.address == *address && (!state.active || state.suspended))
            {
                return Err(Error::NeedsReset);
            }
        }
        Ok(())
    }

    pub(in crate::hda) fn require_cirrus_converter_power(&self, address: u8) -> Result<(), Error> {
        if self.cirrus_codecs.iter().any(|state| {
            state.address == address && (!state.active || state.suspended) && !state.replaying
        }) {
            return Err(Error::NeedsReset);
        }
        Ok(())
    }

    fn cirrus_d3_authority(&mut self, graph: &CodecGraph) -> Result<(), Error> {
        let group = graph
            .groups
            .iter()
            .find(|group| group.node == GROUP)
            .ok_or(Error::UnsupportedTopology)?;
        let live = self.verb(Verb::short(graph.address, GROUP, 0xf00, 0x0f)?)?;
        if live == u32::MAX || live & D0_D3 != D0_D3 || group.power_states != Some(live) {
            return Err(Error::UnsupportedTopology);
        }
        for (node, kind) in [(DAC, WidgetKind::Output), (ADC, WidgetKind::Input)] {
            let widget = graph.widget(node).ok_or(Error::UnsupportedTopology)?;
            if widget.kind != kind || widget.capabilities & POWER_CAPABLE == 0 {
                return Err(Error::UnsupportedTopology);
            }
            let caps = self.verb(Verb::short(graph.address, node, 0xf00, 0x0f)?)?;
            let effective = if caps == 0 { live } else { caps };
            if effective == u32::MAX
                || effective & D0_D3 != D0_D3
                || widget.power_states != Some(effective)
            {
                return Err(Error::UnsupportedTopology);
            }
        }
        Ok(())
    }

    fn cirrus_power_d3(&mut self, address: u8, node: u8) -> Result<(), Error> {
        self.verb(Verb::short(address, node, 0x705, D3)?)?;
        let start = self.timer.now_us();
        loop {
            let value = self.verb(Verb::short(address, node, 0xf05, 0)?)?;
            if value == u32::MAX || value & POWER_ERROR != 0 || value & REQUESTED != u32::from(D3) {
                return Err(Error::RouteRejected);
            }
            if value & ACTUAL == u32::from(D3) << 4 {
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

    /// Suspend a CS4210/CS4213 to D3hot after every DMA stream has
    /// acknowledged stop. Pin quiet precedes DAC/ADC D3; CS4210 then sets PDREF
    /// before AFG D3. The command link and every DMA/route allocation stay owned.
    /// This codec boundary does not claim PCI/ACPI system suspend support.
    pub fn suspend_cirrus_cs421x(&mut self, graph: &CodecGraph) -> Result<(), Error> {
        self.cirrus_guard(graph)?;
        self.require_routing_stopped()?;
        if !matches!(
            super::profile(graph.vendor_id)?,
            CirrusProfile::Cs4210 | CirrusProfile::Cs4213
        ) {
            return Err(Error::UnsupportedTopology);
        }
        let state = self.cirrus_active(graph)?;
        self.cirrus_d3_authority(graph)?;
        // Every kept route must have a replay recipe. Refuse any
        // unrelated converter/control owner instead of dropping its permission.
        let routes: Vec<_> = self
            .routes
            .iter()
            .filter(|(_, route)| route.codec_address() == graph.address)
            .collect();
        if routes.len() != state.routes.len()
            || state.routes.iter().any(|saved| {
                !routes
                    .iter()
                    .any(|(id, route)| *id == saved.stream && *route == saved.route)
            })
            || self
                .codec_controls
                .iter()
                .any(|(_, address, _)| *address == graph.address)
        {
            return Err(Error::RouteInUse);
        }
        if self.converter_bindings.iter().any(|binding| {
            binding.codec == graph.address
                && !state.routes.iter().any(|saved| {
                    saved.stream == binding.stream
                        && saved.route.converter() == binding.node
                        && saved.channel == binding.channel
                })
        }) {
            return Err(Error::RouteInUse);
        }
        // Hardware bindings can predate this native owner. Do not infer
        // retirement from an empty software route inventory or silently power
        // down a converter assigned to an unretained stream/channel.
        for converter in [DAC, ADC] {
            let binding = self.verb(Verb::short(graph.address, converter, 0xf06, 0)?)?;
            let saved = state
                .routes
                .iter()
                .find(|saved| saved.route.converter() == converter);
            let expected = saved.map_or(0, |saved| {
                u32::from((saved.stream.tag() << 4) | saved.channel)
            });
            if binding != expected {
                return Err(Error::RouteInUse);
            }
            if let Some(saved) = saved {
                let format = self.verb(Verb::short(graph.address, converter, 0xa00, 0)?)?;
                if format != u32::from(self.stream_format(saved.stream)?.encode()?) {
                    return Err(Error::ConverterRejected);
                }
            }
        }
        // The live boost control is outside the startup coefficient recipe.
        // Preserve the complete source control (including unrelated bits).
        let speaker = if state.authority.profile == CirrusProfile::Cs4210 {
            Some(self.cirrus_read(
                graph.address,
                state.authority.profile.vendor(),
                SPEAKER_CONTROL,
            )?)
        } else {
            None
        };
        let index = self
            .cirrus_codecs
            .iter()
            .position(|owned| owned.address == graph.address)
            .ok_or(Error::NeedsReset)?;
        // Keep the power transition before the first pin/rail effect.
        self.cirrus_codecs[index].active = false;
        self.cirrus_codecs[index].suspended = true;
        self.cirrus_codecs[index].suspended_speaker_control = speaker;
        let result = (|| {
            for (pin, _) in &state.pins {
                self.route_control(graph.address, *pin, 0x707, 0xf07, 0)?;
            }
            self.cirrus_power_d3(graph.address, DAC)?;
            self.cirrus_power_d3(graph.address, ADC)?;
            if state.authority.profile == CirrusProfile::Cs4210 {
                let vendor = state.authority.profile.vendor();
                let coefficient = self.cirrus_read(graph.address, vendor, DEVICE_CONFIG)?;
                self.cirrus_write(graph.address, vendor, DEVICE_CONFIG, coefficient | PDREF)?;
            }
            self.cirrus_power_d3(graph.address, GROUP)
        })();
        if result.is_err() {
            self.routing_failed = true;
            self.cirrus_codecs[index].authority_lost = true;
        }
        result
    }

    fn replay_cirrus_routes(&mut self, graph: &CodecGraph, state: &State) -> Result<(), Error> {
        let old_routes: Vec<_> = self
            .routes
            .iter()
            .filter(|(_, route)| route.codec_address() == graph.address)
            .cloned()
            .collect();
        let old_bindings: Vec<_> = self
            .converter_bindings
            .iter()
            .filter(|binding| binding.codec == graph.address)
            .copied()
            .collect();
        // The suspended codec remains in cirrus_codecs throughout replay, and
        // every stream remains stopped. No other backend can claim its address.
        self.routes
            .retain(|(_, route)| route.codec_address() != graph.address);
        self.converter_bindings
            .retain(|binding| binding.codec != graph.address);
        let result = (|| {
            for saved in &state.routes {
                self.configure_analog_route_policy(
                    graph,
                    &saved.route,
                    saved.stream,
                    saved.channel,
                    saved.options,
                    state.authority.profile.route_policy(),
                )?;
            }
            Ok(())
        })();
        if result.is_err() {
            // A failed replay cannot release any previously authoritative path
            // or converter. Partial effects are held until reset.
            self.routes
                .retain(|(_, route)| route.codec_address() != graph.address);
            self.routes.extend(old_routes);
            self.converter_bindings
                .retain(|binding| binding.codec != graph.address);
            self.converter_bindings.extend(old_bindings);
        }
        result
    }

    /// Resume an owned CS421x on the same live link and allocation generation.
    /// Revalidate capabilities/defaults after AFG wake, perform the exact
    /// source startup, restore the speaker control and replay
    /// stopped PCM routes. Any failure keeps all owners and requires reset.
    pub fn resume_cirrus_cs421x(&mut self, graph: &CodecGraph) -> Result<(), Error> {
        self.cirrus_guard(graph)?;
        self.require_routing_stopped()?;
        let index = self
            .cirrus_codecs
            .iter()
            .position(|state| {
                state.address == graph.address
                    && state.suspended
                    && !state.quiet
                    && !state.authority_lost
            })
            .ok_or(Error::NeedsReset)?;
        let state = self.cirrus_codecs[index].clone();
        if graph.vendor_id != state.codec_id || graph.revision_id != state.revision_id {
            return Err(Error::InvalidCodecGraph);
        }
        let result = (|| {
            self.power_d0(graph.address, GROUP)?;
            let live = self.validate_live_analog_codec(graph)?;
            if live.group != GROUP
                || live.pins != state.pins
                || self.cirrus_authority(graph)? != state.authority
            {
                return Err(Error::InvalidCodecGraph);
            }
            self.cirrus_d3_authority(graph)?;
            let vendor = state.authority.profile.vendor();
            if state
                .authority
                .power_nodes
                .iter()
                .any(|(node, _)| *node == vendor)
            {
                self.power_d0(graph.address, vendor)?;
            }
            let coefficients = match state.authority.profile {
                CirrusProfile::Cs4210 => self.initialize_cs4210_coefficients(graph)?,
                CirrusProfile::Cs4213 => Vec::new(),
                _ => return Err(Error::UnsupportedTopology),
            };
            self.power_d0(graph.address, DAC)?;
            self.power_d0(graph.address, ADC)?;
            if let Some(speaker) = state.suspended_speaker_control {
                self.cirrus_write(graph.address, vendor, SPEAKER_CONTROL, speaker)?;
            }
            self.cirrus_codecs[index].replaying = true;
            let replay = self.replay_cirrus_routes(graph, &state);
            self.cirrus_codecs[index].replaying = false;
            replay?;
            self.cirrus_codecs[index].coefficients = coefficients;
            Ok(())
        })();
        if result.is_ok() {
            self.cirrus_codecs[index].active = true;
            self.cirrus_codecs[index].suspended = false;
            self.cirrus_codecs[index].suspended_speaker_control = None;
        } else {
            self.routing_failed = true;
            self.cirrus_codecs[index].authority_lost = true;
        }
        result
    }
}
