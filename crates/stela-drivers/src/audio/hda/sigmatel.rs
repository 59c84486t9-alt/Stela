// SPDX-License-Identifier: GPL-2.0-only
//! SigmaTel STAC9200/9202/925x/922x and IDT73xx/83xxx held-D0 analog backends from Linux
//! sound/hda/codecs/sigmatel.c and common/codec.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright (c) 2005 Embedded Alley Solutions, Inc. Matt Porter.
//! Copyright (c) 2004 Takashi Iwai.
//! GPL-2.0-only combines the upstream GPL-2.0-or-later codec with existing
//! GPL-2.0-only HDA command/graph and native control sequencing.
use super::routing::{RoutePolicy, STAC922X_CAPTURE_AMP_CAPS};
use super::{
    AnalogRoute, CodecGraph, Controller, PinOptions, PinSense, Registers, StreamId, Verb,
    WidgetKind,
};
use crate::{audio::Error, bus::i2c::Timer};
use alloc::vec::Vec;
mod idt73;
mod idt83;
mod port_power;
pub use idt73::Idt73PowerReport;
pub use idt83::{Idt83PortPower, Idt83PowerReport};

const GET_GPIO_DATA: u16 = 0xf15;
const GET_GPIO_MASK: u16 = 0xf16;
const GET_GPIO_DIRECTION: u16 = 0xf17;
const SET_GPIO_DATA: u16 = 0x715;
const SET_GPIO_MASK: u16 = 0x716;
const SET_GPIO_DIRECTION: u16 = 0x717;
const SET_GPIO_CMOS: u16 = 0x7e7;
const PIN_EAPD: u32 = 1 << 16;
const WCAP_OUTPUT_AMP: u32 = 1 << 2;
const AMP_MUTE: u32 = 1 << 31;
const STAC922X_CAPTURE_MUX: u8 = 0x12;
const STAC922X_VOLUME_KNOB: u8 = 0x16;
const PAR_VOLUME_KNOB: u8 = 0x13;
const SET_VOLUME_KNOB: u16 = 0x70f;
const GET_VOLUME_KNOB: u16 = 0xf0f;
const DIRECT_MAX_VOLUME: u8 = 0xff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigmatelProfile {
    Stac9200,
    Stac925x,
    Stac922x,
    Stac9872,
    Idt92hd83xxx,
    Idt92hd73xx,
    Idt92hd95,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Idt95PowerReport {
    pub power_map: u8,
    pub ports: Vec<Idt83PortPower>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigmatelGpio {
    pub mask: u8,
    pub direction: u8,
    pub data: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigmatelReport {
    pub profile: SigmatelProfile,
    pub codec_id: u32,
    pub revision_id: u32,
    pub subsystem_id: u32,
    pub function_group: u8,
    pub gpio_capabilities: u32,
    /// Unclaimed GPIO bits are preserved; IDT73xx owns source-default GPIO0.
    /// No OEM GPIO or LED mask is inferred.
    pub gpio: SigmatelGpio,
    pub selector_node: Option<u8>,
    pub eapd: Option<(u8, u8)>,
    pub master_amplifier: Option<(u8, u8)>,
    /// Node/control after verified direct maximum-volume startup.
    pub volume_knob: Option<(u8, u8)>,
    /// Source-qualified effective output amp range; observed graph stays intact.
    pub capture_output_amplifier: Option<(u8, u32)>,
    pub idt83: Option<Idt83PowerReport>,
    pub idt73: Option<Idt73PowerReport>,
    pub idt95: Option<Idt95PowerReport>,
}
#[derive(Clone)]
pub(super) struct State {
    address: u8,
    codec_id: u32,
    revision_id: u32,
    group: u8,
    pins: Vec<(u8, u32)>,
    active: bool,
    quiet: bool,
    authority_lost: bool,
    knob_capabilities: Option<u32>,
    startup_amplifier: Option<(u8, u32)>,
    idt83: Option<idt83::State>,
    idt73: Option<idt73::State>,
    idt95: Option<port_power::State>,
}
fn profile(id: u32) -> Result<SigmatelProfile, Error> {
    match id {
        0x8384_7690 => Ok(SigmatelProfile::Stac9200),
        0x8384_7632..=0x8384_7637 => Ok(SigmatelProfile::Stac925x),
        0x8384_7882 | 0x8384_7880 | 0x8384_7680..=0x8384_7683 => Ok(SigmatelProfile::Stac922x),
        0x111d_7604
        | 0x111d_76d4
        | 0x111d_7605
        | 0x111d_76d5
        | 0x111d_76d1
        | 0x111d_76d9
        | 0x111d_7666..=0x111d_7669
        | 0x111d_76df
        | 0x111d_76e0
        | 0x111d_76e3
        | 0x111d_76e5
        | 0x111d_76e7..=0x111d_76f3 => Ok(SigmatelProfile::Idt92hd83xxx),
        0x111d_7674..=0x111d_7676 | 0x111d_76c0..=0x111d_76ce => Ok(SigmatelProfile::Idt92hd73xx),
        0x8384_7661 | 0x8384_7662 | 0x8384_7664 => Ok(SigmatelProfile::Stac9872),
        0x111d_7695 => Ok(SigmatelProfile::Idt92hd95),
        _ => Err(Error::UnsupportedTopology),
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn manages_sigmatel_codec(&self, address: u8) -> bool {
        self.sigmatel_codecs
            .iter()
            .any(|state| state.address == address)
    }
    fn sigmatel_guard(&self, graph: &CodecGraph) -> Result<(), Error> {
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
    fn sigmatel_active(&mut self, graph: &CodecGraph) -> Result<State, Error> {
        self.sigmatel_guard(graph)?;
        let state = self
            .sigmatel_codecs
            .iter()
            .find(|state| state.address == graph.address && state.active && !state.quiet)
            .cloned()
            .ok_or(Error::NeedsReset)?;
        let live = self.validate_live_analog_codec(graph).and_then(|live| {
            if live.group != state.group
                || live.pins != state.pins
                || graph.vendor_id != state.codec_id
                || graph.revision_id != state.revision_id
            {
                return Err(Error::InvalidCodecGraph);
            }
            if let Some(caps) = state.knob_capabilities {
                self.validate_live_output_amplifier(
                    graph.address,
                    state.group,
                    graph
                        .widget(STAC922X_CAPTURE_MUX)
                        .ok_or(Error::InvalidCodecGraph)?,
                )?;
                if self.sigmatel_knob_capabilities(graph.address, STAC922X_VOLUME_KNOB)? != caps {
                    return Err(Error::InvalidCodecGraph);
                }
            }
            if let Some((node, caps)) = state.startup_amplifier {
                if self.validate_live_output_amplifier(
                    graph.address,
                    state.group,
                    graph.widget(node).ok_or(Error::InvalidCodecGraph)?,
                )? != caps
                {
                    return Err(Error::InvalidCodecGraph);
                }
            }
            if let Some(idt83) = &state.idt83 {
                self.validate_idt83(graph, state.group, idt83)?;
            }
            if let Some(idt73) = &state.idt73 {
                self.validate_idt73(graph, state.group, idt73)?;
            }
            if let Some(idt95) = &state.idt95 {
                self.validate_idt_ports(graph, state.group, idt95)?;
            }
            Ok(())
        });
        if let Err(error) = live {
            self.routing_failed = true;
            if let Some(owned) = self
                .sigmatel_codecs
                .iter_mut()
                .find(|owned| owned.address == graph.address)
            {
                owned.authority_lost = true;
            }
            return Err(error);
        }
        Ok(state)
    }
    fn sigmatel_gpio_read(
        &mut self,
        address: u8,
        group: u8,
        verb: u16,
        allowed: u8,
    ) -> Result<u8, Error> {
        let value = self.verb(Verb::short(address, group, verb, 0)?)?;
        if value & !u32::from(allowed) != 0 {
            return Err(Error::RouteRejected);
        }
        Ok(value as u8)
    }
    fn sigmatel_gpio_program(
        &mut self,
        address: u8,
        group: u8,
        gpio: SigmatelGpio,
        allowed: u8,
        verify: u8,
    ) -> Result<SigmatelGpio, Error> {
        if self.verb(Verb::short(address, group, SET_GPIO_CMOS, 0)?)? == u32::MAX {
            return Err(Error::RouteRejected);
        }
        let control = |owner: &mut Self, set, get, value| {
            owner.verb(Verb::short(address, group, set, value)?)?;
            let actual = owner.sigmatel_gpio_read(address, group, get, allowed)?;
            // GPIO inputs can change between the preserving snapshot and GET.
            // Verify the caller's owned bits, while rejecting failed/undeclared
            // readback bits and reporting the actual observed complete value.
            if (actual ^ value) & verify != 0 {
                return Err(Error::RouteRejected);
            }
            Ok(actual)
        };
        let mask = control(self, SET_GPIO_MASK, GET_GPIO_MASK, gpio.mask)?;
        let direction = control(self, SET_GPIO_DIRECTION, GET_GPIO_DIRECTION, gpio.direction)?;
        self.delay(1000);
        let data = control(self, SET_GPIO_DATA, GET_GPIO_DATA, gpio.data)?;
        Ok(SigmatelGpio {
            data,
            mask,
            direction,
        })
    }
    fn sigmatel_startup_preflight(
        graph: &CodecGraph,
        selected: SigmatelProfile,
    ) -> Result<Option<u8>, Error> {
        if matches!(
            selected,
            SigmatelProfile::Idt92hd83xxx
                | SigmatelProfile::Idt92hd73xx
                | SigmatelProfile::Idt92hd95
        ) {
            return Ok(None);
        }
        if selected == SigmatelProfile::Stac9872 {
            let selector = graph.widget(0x15).ok_or(Error::UnsupportedTopology)?;
            if selector.kind != WidgetKind::Selector
                || selector.connections.len() < 2
                || selector.channels() != 2
                || selector.capabilities & WCAP_OUTPUT_AMP == 0
                || selector
                    .output_amplifier
                    .is_none_or(|caps| caps == u32::MAX)
            {
                return Err(Error::UnsupportedTopology);
            }
            return Ok(Some(0x15));
        }
        let selector = if selected == SigmatelProfile::Stac9200 {
            7
        } else {
            6
        };
        let groups: Vec<_> = graph
            .groups
            .iter()
            .filter(|group| group.function_type & 255 == 1)
            .collect();
        let [group] = groups.as_slice() else {
            return Err(Error::UnsupportedTopology);
        };
        let find = |node| {
            group
                .widgets
                .iter()
                .find(|widget| widget.node == node)
                .ok_or(Error::UnsupportedTopology)
        };
        if selected == SigmatelProfile::Stac922x {
            let mux = find(STAC922X_CAPTURE_MUX)?;
            if mux.kind != WidgetKind::Selector
                || mux.connections.is_empty()
                || mux.capabilities & WCAP_OUTPUT_AMP == 0
                || mux.output_amplifier.is_none()
                || find(STAC922X_VOLUME_KNOB)?.kind != WidgetKind::Volume
            {
                return Err(Error::UnsupportedTopology);
            }
            return Ok(None);
        }
        let mux = find(selector)?;
        if !matches!(
            mux.kind,
            WidgetKind::Selector | WidgetKind::Pin | WidgetKind::Input
        ) || mux.connections.is_empty()
        {
            return Err(Error::UnsupportedTopology);
        }
        if selected == SigmatelProfile::Stac9200 {
            let pin = find(8)?;
            if pin.kind != WidgetKind::Pin
                || pin
                    .pin_capabilities
                    .is_none_or(|caps| caps == u32::MAX || caps & PIN_EAPD == 0)
            {
                return Err(Error::UnsupportedTopology);
            }
        } else {
            let amp = find(0x0e)?;
            if amp.capabilities & WCAP_OUTPUT_AMP == 0
                || amp.channels() != 2
                || amp
                    .output_amplifier
                    .is_none_or(|caps| caps == u32::MAX || caps & AMP_MUTE == 0)
            {
                return Err(Error::UnsupportedTopology);
            }
        }
        Ok(Some(selector))
    }
    fn sigmatel_knob_capabilities(&mut self, address: u8, node: u8) -> Result<u32, Error> {
        let caps = self.verb(Verb::short(address, node, 0xf00, PAR_VOLUME_KNOB)?)?;
        // The source writes gain127 with direct control. Refuse hardware
        // that cannot express that complete control rather than clipping it.
        if caps & !0xff != 0 || caps & 0x7f != 0x7f {
            return Err(Error::InvalidCodecGraph);
        }
        Ok(caps)
    }
    /// Cold/link-startup standard analog ownership. IDT73xx explicitly applies
    /// source-default GPIO0 EAPD; OEM pin/GPIO/LED masks, beep, SPDIF and PM
    /// are separate. IDT73xx/83xxx retain source port maps and polled updates.
    pub fn initialize_sigmatel_codec(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<SigmatelReport, Error> {
        self.sigmatel_guard(graph)?;
        self.require_routing_stopped()?;
        if self
            .converter_bindings
            .iter()
            .any(|binding| binding.codec == graph.address)
            || self.manages_realtek_codec(graph.address)
            || self.manages_sigmatel_codec(graph.address)
            || self.manages_cirrus_codec(graph.address)
            || self.manages_conexant_codec(graph.address)
            || self
                .routes
                .iter()
                .any(|(_, route)| route.codec_address() == graph.address)
            || self
                .codec_controls
                .iter()
                .any(|(_, address, _)| *address == graph.address)
        {
            return Err(Error::RouteInUse);
        }
        let selected = profile(graph.vendor_id)?;
        let selector = Self::sigmatel_startup_preflight(graph, selected)?;
        let live = self.validate_live_analog_codec(graph)?;
        let group = live.group;
        if selected == SigmatelProfile::Stac925x {
            self.validate_live_output_amplifier(
                graph.address,
                group,
                graph.widget(0x0e).ok_or(Error::InvalidCodecGraph)?,
            )?;
        }
        let knob_capabilities = if selected == SigmatelProfile::Stac922x {
            self.validate_live_output_amplifier(
                graph.address,
                group,
                graph
                    .widget(STAC922X_CAPTURE_MUX)
                    .ok_or(Error::InvalidCodecGraph)?,
            )?;
            Some(self.sigmatel_knob_capabilities(graph.address, STAC922X_VOLUME_KNOB)?)
        } else {
            None
        };
        let startup_amplifier = if selected == SigmatelProfile::Stac9872 {
            Some((
                0x15,
                self.validate_live_output_amplifier(
                    graph.address,
                    group,
                    graph.widget(0x15).ok_or(Error::InvalidCodecGraph)?,
                )?,
            ))
        } else {
            None
        };
        let mut idt83 = if selected == SigmatelProfile::Idt92hd83xxx {
            Some(self.preflight_idt83(graph, group)?)
        } else {
            None
        };
        let mut idt95 = if selected == SigmatelProfile::Idt92hd95 {
            Some(self.preflight_idt_ports(graph, group, &[0x0a, 0x0b, 0x0c, 0x0d])?)
        } else {
            None
        };
        let gpio_caps = self.verb(Verb::short(graph.address, group, 0xf00, 0x11)?)?;
        if gpio_caps == u32::MAX {
            return Err(Error::InvalidCodecGraph);
        }
        let count = gpio_caps & 255;
        if count > 8 {
            return Err(Error::UnsupportedTopology);
        }
        let allowed = ((1u16 << count) - 1) as u8;
        let mut idt73 = if selected == SigmatelProfile::Idt92hd73xx {
            Some(self.preflight_idt73(graph, group, gpio_caps)?)
        } else {
            None
        };
        let index = self.sigmatel_codecs.len();
        self.sigmatel_codecs.push(State {
            address: graph.address,
            codec_id: graph.vendor_id,
            revision_id: graph.revision_id,
            group,
            pins: live.pins,
            active: false,
            quiet: false,
            authority_lost: false,
            knob_capabilities,
            startup_amplifier,
            idt83: idt83.clone(),
            idt73: idt73.clone(),
            idt95: idt95.clone(),
        });
        let result = (|| {
            self.power_d0(graph.address, group)?;
            let mut gpio = SigmatelGpio {
                data: self.sigmatel_gpio_read(graph.address, group, GET_GPIO_DATA, allowed)?,
                mask: self.sigmatel_gpio_read(graph.address, group, GET_GPIO_MASK, allowed)?,
                direction: self.sigmatel_gpio_read(
                    graph.address,
                    group,
                    GET_GPIO_DIRECTION,
                    allowed,
                )?,
            };
            // Source probe_stac92hd73xx explicitly assigns GPIO0 to EAPD/high.
            // Every other admitted profile's unselected OEM masks remain zero.
            if selected == SigmatelProfile::Idt92hd73xx {
                gpio.data |= idt73::EAPD;
                gpio.mask |= idt73::EAPD;
                gpio.direction |= idt73::EAPD;
            }
            let gpio = self.sigmatel_gpio_program(
                graph.address,
                group,
                gpio,
                allowed,
                if selected == SigmatelProfile::Idt92hd73xx {
                    idt73::EAPD
                } else {
                    allowed
                },
            )?;
            if let Some(selector) = selector {
                self.route_control(
                    graph.address,
                    selector,
                    0x701,
                    0xf01,
                    if selected == SigmatelProfile::Stac9872 {
                        1
                    } else {
                        0
                    },
                )?;
            }
            let (eapd, master_amplifier) = if selected == SigmatelProfile::Stac9200 {
                self.route_control(graph.address, 8, 0x70c, 0xf0c, 2)?;
                (Some((8, 2)), None)
            } else if selected == SigmatelProfile::Stac925x {
                self.verb(Verb::long(graph.address, 0x0e, 3, 0xb080)?)?;
                for channel in [0xa000, 0x8000] {
                    if self.verb(Verb::long(graph.address, 0x0e, 0xb, channel)?)? != 0x80 {
                        return Err(Error::RouteRejected);
                    }
                }
                (None, Some((0x0e, 0x80)))
            } else if selected == SigmatelProfile::Stac9872 {
                // stac9872_core_init selects input1 and physically unmutes
                // both output channels at gain0, not an inferred 0dB offset.
                self.verb(Verb::long(graph.address, 0x15, 3, 0xb000)?)?;
                for channel in [0xa000, 0x8000] {
                    if self.verb(Verb::long(graph.address, 0x15, 0xb, channel)?)? != 0 {
                        return Err(Error::RouteRejected);
                    }
                }
                (None, Some((0x15, 0)))
            } else if selected == SigmatelProfile::Stac922x {
                self.route_control(
                    graph.address,
                    STAC922X_VOLUME_KNOB,
                    SET_VOLUME_KNOB,
                    GET_VOLUME_KNOB,
                    DIRECT_MAX_VOLUME,
                )?;
                (None, None)
            } else if selected == SigmatelProfile::Idt92hd73xx {
                self.initialize_idt73(
                    graph,
                    group,
                    idt73.as_mut().ok_or(Error::InvalidCodecGraph)?,
                    gpio,
                )?;
                (None, None)
            } else if selected == SigmatelProfile::Idt92hd95 {
                let ports = idt95.as_mut().ok_or(Error::InvalidCodecGraph)?;
                self.observe_idt_port_map(graph, group, ports)?;
                self.refresh_idt_ports(graph, group, ports)?;
                (None, None)
            } else {
                self.initialize_idt83(
                    graph,
                    group,
                    idt83.as_mut().ok_or(Error::InvalidCodecGraph)?,
                )?;
                (None, None)
            };
            Ok(SigmatelReport {
                profile: selected,
                codec_id: graph.vendor_id,
                revision_id: graph.revision_id,
                subsystem_id: live.subsystem,
                function_group: group,
                gpio_capabilities: gpio_caps,
                gpio,
                selector_node: selector,
                eapd,
                master_amplifier,
                volume_knob: if selected == SigmatelProfile::Idt92hd73xx {
                    Some((idt73::VOLUME_KNOB, DIRECT_MAX_VOLUME))
                } else {
                    knob_capabilities.map(|_| (STAC922X_VOLUME_KNOB, DIRECT_MAX_VOLUME))
                },
                capture_output_amplifier: knob_capabilities
                    .map(|_| (STAC922X_CAPTURE_MUX, STAC922X_CAPTURE_AMP_CAPS)),
                idt83: idt83.as_ref().map(idt83::State::report).transpose()?,
                idt73: idt73.as_ref().map(idt73::State::report).transpose()?,
                idt95: idt95
                    .as_ref()
                    .map(|state| {
                        state.report().map(|report| Idt95PowerReport {
                            power_map: report.power_map,
                            ports: report.ports,
                        })
                    })
                    .transpose()?,
            })
        })();
        if result.is_ok() {
            self.sigmatel_codecs[index].active = true;
            self.sigmatel_codecs[index].idt83 = idt83;
            self.sigmatel_codecs[index].idt73 = idt73;
            self.sigmatel_codecs[index].idt95 = idt95;
        } else {
            self.routing_failed = true;
        }
        result
    }
    /// Program one explicit standard path after actual codec startup. Source
    /// own_eapd_ctl suppresses all per-pin EAPD edits, including generic calls.
    pub fn configure_sigmatel_route(
        &mut self,
        graph: &CodecGraph,
        route: &AnalogRoute,
        id: StreamId,
        channel: u8,
        options: PinOptions,
    ) -> Result<(), Error> {
        self.sigmatel_guard(graph)?;
        let policy = if profile(graph.vendor_id)? == SigmatelProfile::Stac922x {
            RoutePolicy::SigmatelStac922x
        } else {
            RoutePolicy::Standard
        };
        self.preflight_analog_route_policy(graph, route, id, channel, options, policy)?;
        let state = self.sigmatel_active(graph)?;
        if matches!(options, PinOptions::Playback { eapd: Some(_), .. }) {
            return Err(Error::InvalidPinControl);
        }
        if let Some(idt83) = state.idt83 {
            idt83.require_route_power(route.pin())?;
        }
        if let Some(idt73) = state.idt73 {
            idt73.require_route_power(route.pin())?;
        }
        if let Some(idt95) = state.idt95 {
            idt95.require_route_power(route.pin())?;
        }
        self.configure_analog_route_policy(graph, route, id, channel, options, policy)
    }
    /// STAC/IDT's no_trigger_sense applies through the canonical pin API too.
    /// IDT83xxx detectable ports also retain source jack-driven power control.
    pub fn poll_sigmatel_pin_sense(
        &mut self,
        graph: &CodecGraph,
        pin: u8,
    ) -> Result<PinSense, Error> {
        let mut state = self.sigmatel_active(graph)?;
        let result = self
            .poll_pin_sense_policy(graph, pin, false)
            .and_then(|sense| {
                if let Some(idt83) = &mut state.idt83 {
                    self.update_idt83_pin(graph.address, state.group, idt83, pin, sense)?;
                    if let Some(owned) = self
                        .sigmatel_codecs
                        .iter_mut()
                        .find(|owned| owned.address == graph.address)
                    {
                        owned.idt83 = state.idt83;
                    }
                }
                if let Some(idt73) = &mut state.idt73 {
                    self.update_idt73_pin(graph.address, state.group, idt73, pin, sense)?;
                    if let Some(owned) = self
                        .sigmatel_codecs
                        .iter_mut()
                        .find(|owned| owned.address == graph.address)
                    {
                        owned.idt73 = state.idt73;
                    }
                }
                if let Some(idt95) = &mut state.idt95 {
                    self.update_idt_port(graph.address, state.group, idt95, pin, sense)?;
                    if let Some(owned) = self
                        .sigmatel_codecs
                        .iter_mut()
                        .find(|owned| owned.address == graph.address)
                    {
                        owned.idt95 = state.idt95;
                    }
                }
                Ok(sense)
            });
        if result.as_ref().is_err_and(|error| {
            *error != Error::UnsupportedTopology && *error != Error::InvalidCodecGraph
        }) {
            self.routing_failed = true;
        }
        result
    }
    /// Refresh all seven source-defined IDT83xxx ports through explicit
    /// no-trigger polling and checked whole-map programming. PCM may continue.
    pub fn refresh_idt83_power_map(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<Idt83PowerReport, Error> {
        let mut state = self.sigmatel_active(graph)?;
        let idt83 = state.idt83.as_mut().ok_or(Error::UnsupportedTopology)?;
        if let Err(error) = self.refresh_idt83(graph, state.group, idt83) {
            self.routing_failed = true;
            return Err(error);
        }
        let report = idt83.report()?;
        self.sigmatel_codecs
            .iter_mut()
            .find(|owned| owned.address == graph.address)
            .ok_or(Error::NeedsReset)?
            .idt83 = state.idt83;
        Ok(report)
    }
    /// Refresh all eight IDT73xx source ports by explicit no-trigger polling.
    /// GPIO0 remains at the source startup EAPD level; automute is separate.
    pub fn refresh_idt73_power_map(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<Idt73PowerReport, Error> {
        let mut state = self.sigmatel_active(graph)?;
        let idt73 = state.idt73.as_mut().ok_or(Error::UnsupportedTopology)?;
        if let Err(error) = self.refresh_idt73(graph, state.group, idt73) {
            self.routing_failed = true;
            return Err(error);
        }
        let report = idt73.report()?;
        self.sigmatel_codecs
            .iter_mut()
            .find(|owned| owned.address == graph.address)
            .ok_or(Error::NeedsReset)?
            .idt73 = state.idt73;
        Ok(report)
    }
    /// Refresh the exact four IDT92HD95 ports through no-trigger actual jack
    /// sensing. Unlike IDT83xxx this profile has no mode788 startup effect.
    pub fn refresh_idt95_power_map(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<Idt95PowerReport, Error> {
        let mut state = self.sigmatel_active(graph)?;
        let ports = state.idt95.as_mut().ok_or(Error::UnsupportedTopology)?;
        if let Err(error) = self.refresh_idt_ports(graph, state.group, ports) {
            self.routing_failed = true;
            return Err(error);
        }
        let report = ports.report()?;
        self.sigmatel_codecs
            .iter_mut()
            .find(|owned| owned.address == graph.address)
            .ok_or(Error::NeedsReset)?
            .idt95 = state.idt95;
        Ok(Idt95PowerReport {
            power_map: report.power_map,
            ports: report.ports,
        })
    }

    pub(super) fn require_sigmatel_route_power(&self, id: StreamId) -> Result<(), Error> {
        for (_, route) in self.routes.iter().filter(|(stream, _)| *stream == id) {
            if let Some(idt83) = self
                .sigmatel_codecs
                .iter()
                .find(|state| state.address == route.codec_address())
                .and_then(|state| state.idt83.as_ref())
            {
                idt83.require_route_power(route.pin())?;
            }
            if let Some(idt73) = self
                .sigmatel_codecs
                .iter()
                .find(|state| state.address == route.codec_address())
                .and_then(|state| state.idt73.as_ref())
            {
                idt73.require_route_power(route.pin())?;
            }
            if let Some(idt95) = self
                .sigmatel_codecs
                .iter()
                .find(|state| state.address == route.codec_address())
                .and_then(|state| state.idt95.as_ref())
            {
                idt95.require_route_power(route.pin())?;
            }
        }
        Ok(())
    }
    /// Quiet the owned actual pin inventory after every stream stop has
    /// acknowledged. This is a native shutdown boundary, not S3/S4 support.
    pub(super) fn shutdown_sigmatel_codecs(&mut self) -> Result<(), Error> {
        for index in 0..self.sigmatel_codecs.len() {
            let state = self.sigmatel_codecs[index].clone();
            if state.quiet {
                continue;
            }
            if state.authority_lost || self.command_poisoned {
                return Err(Error::NeedsReset);
            }
            for (node, _) in state.pins {
                self.route_control(state.address, node, 0x707, 0xf07, 0)?;
            }
            if let Some(idt73) = &state.idt73 {
                self.quiet_idt73(state.address, state.group, idt73)?;
            }
            self.sigmatel_codecs[index].active = false;
            self.sigmatel_codecs[index].quiet = true;
        }
        Ok(())
    }
}
