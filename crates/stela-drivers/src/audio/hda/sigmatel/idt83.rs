// SPDX-License-Identifier: GPL-2.0-only
//! IDT MODEL_STAC92HD83XXX AFG amplifier mode and port power map adapted
//! from sound/hda/codecs/sigmatel.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright (c) 2005 Embedded Alley Solutions, Inc., Matt Porter.
//! Copyright (c) 2004 Takashi Iwai. See audio/THIRD_PARTY.md.
use super::super::{
    CodecGraph, Controller, PinConfiguration, PinConnection, PinSense, Registers, Verb, WidgetKind,
};
use crate::{audio::Error, bus::i2c::Timer};
use alloc::vec::Vec;

const PORTS: [u8; 7] = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
const PORT_MASK: u32 = 0x7f;
const SET_AMPLIFIER_MODE: u16 = 0x788;
const POWER_STATE_CONTROLS_AMPLIFIERS: u8 = 4;
const SET_POWER_MAP: u16 = 0x7ec;
const GET_POWER_MAP: u16 = 0xfec;
const PIN_PRESENCE: u32 = 1 << 2;
const PIN_INPUT_OUTPUT: u32 = (1 << 4) | (1 << 5);
const DIGITAL: u32 = 1 << 9;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Idt83PortPower {
    pub node: u8,
    pub configuration: PinConfiguration,
    pub sense: Option<PinSense>,
    pub powered: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Idt83PowerReport {
    /// Source mode4 was acknowledged. No source-defined getter or electrical
    /// observation is invented for this write-only vendor mode.
    pub amplifier_mode_acknowledged: u8,
    pub power_map: u8,
    pub ports: Vec<Idt83PortPower>,
}
#[derive(Clone)]
struct Port {
    node: u8,
    configuration: PinConfiguration,
    poll_presence: bool,
    sense: Option<PinSense>,
}
#[derive(Clone)]
pub(super) struct State {
    ports: Vec<Port>,
    power_map: Option<u8>,
}
impl State {
    pub(super) fn report(&self) -> Result<Idt83PowerReport, Error> {
        let power_map = self.power_map.ok_or(Error::NeedsReset)?;
        Ok(Idt83PowerReport {
            amplifier_mode_acknowledged: POWER_STATE_CONTROLS_AMPLIFIERS,
            power_map,
            ports: self
                .ports
                .iter()
                .enumerate()
                .map(|(index, port)| Idt83PortPower {
                    node: port.node,
                    configuration: port.configuration,
                    sense: port.sense,
                    powered: power_map & (1 << index) == 0,
                })
                .collect(),
        })
    }
    pub(super) fn require_route_power(&self, pin: u8) -> Result<(), Error> {
        let power_map = self.power_map.ok_or(Error::NeedsReset)?;
        if let Some(index) = PORTS.iter().position(|node| *node == pin)
            && power_map & (1 << index) != 0
        {
            return Err(Error::UnsupportedTopology);
        }
        Ok(())
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    fn read_idt83_power_map(&mut self, address: u8, group: u8) -> Result<u8, Error> {
        let map = self.verb(Verb::short(address, group, GET_POWER_MAP, 0)?)?;
        if map & !PORT_MASK != 0 {
            return Err(Error::RouteRejected);
        }
        Ok(map as u8)
    }
    pub(super) fn preflight_idt83(
        &mut self,
        graph: &CodecGraph,
        group: u8,
    ) -> Result<State, Error> {
        // The source fixed core verb addresses AFG1. Do not redirect that
        // vendor authority to a different function group by inference.
        if group != 1 {
            return Err(Error::UnsupportedTopology);
        }
        let mut ports = Vec::new();
        for node in PORTS {
            let widget = graph.widget(node).ok_or(Error::UnsupportedTopology)?;
            let caps = widget.pin_capabilities.ok_or(Error::UnsupportedTopology)?;
            let configuration = widget
                .pin_configuration()
                .ok_or(Error::UnsupportedTopology)?;
            if widget.kind != WidgetKind::Pin
                || widget.capabilities & DIGITAL != 0
                || caps == u32::MAX
                || caps & PIN_INPUT_OUTPUT == 0
                || configuration.raw == u32::MAX
            {
                return Err(Error::UnsupportedTopology);
            }
            if self.verb(Verb::short(graph.address, node, 0xf1c, 0)?)? != configuration.raw {
                return Err(Error::InvalidCodecGraph);
            }
            // This native API explicitly uses polling instead of the source's
            // unsolicited callback or jackpoll_interval event delivery.
            let poll_presence = configuration.connection() == PinConnection::Jack
                && caps & PIN_PRESENCE != 0
                && !configuration.no_presence_detection();
            ports.push(Port {
                node,
                configuration,
                poll_presence,
                sense: None,
            });
        }
        Ok(State {
            ports,
            power_map: None,
        })
    }
    pub(super) fn validate_idt83(
        &mut self,
        graph: &CodecGraph,
        group: u8,
        state: &State,
    ) -> Result<(), Error> {
        for port in &state.ports {
            if graph
                .widget(port.node)
                .and_then(|widget| widget.pin_configuration())
                != Some(port.configuration)
                || self.verb(Verb::short(graph.address, port.node, 0xf1c, 0)?)?
                    != port.configuration.raw
            {
                return Err(Error::InvalidCodecGraph);
            }
        }
        if self.read_idt83_power_map(graph.address, group)?
            != state.power_map.ok_or(Error::NeedsReset)?
        {
            return Err(Error::RouteRejected);
        }
        Ok(())
    }
    pub(super) fn initialize_idt83(
        &mut self,
        graph: &CodecGraph,
        group: u8,
        state: &mut State,
    ) -> Result<(), Error> {
        // Vendor registers may be inaccessible in D3. The caller already owns
        // the codec and has acknowledged D0 before this first map read.
        state.power_map = Some(self.read_idt83_power_map(graph.address, group)?);
        if self.verb(Verb::short(
            graph.address,
            group,
            SET_AMPLIFIER_MODE,
            POWER_STATE_CONTROLS_AMPLIFIERS,
        )?)? == u32::MAX
        {
            return Err(Error::RouteRejected);
        }
        self.refresh_idt83(graph, group, state)
    }
    pub(super) fn refresh_idt83(
        &mut self,
        graph: &CodecGraph,
        group: u8,
        state: &mut State,
    ) -> Result<(), Error> {
        let mut map = 0;
        for (index, port) in state.ports.iter_mut().enumerate() {
            let enabled = if port.poll_presence {
                let sense = self.poll_pin_sense_policy(graph, port.node, false)?;
                port.sense = Some(sense);
                sense.present
            } else {
                port.configuration.connection() != PinConnection::None
            };
            if !enabled {
                map |= 1 << index;
            }
        }
        // stac_init and jack_update_power(NULL) synchronize the entire map,
        // even if the source shadow value happens to be unchanged.
        self.route_control(graph.address, group, SET_POWER_MAP, GET_POWER_MAP, map)?;
        state.power_map = Some(map);
        Ok(())
    }
    pub(super) fn update_idt83_pin(
        &mut self,
        address: u8,
        group: u8,
        state: &mut State,
        pin: u8,
        sense: PinSense,
    ) -> Result<(), Error> {
        let Some(index) = state
            .ports
            .iter()
            .position(|port| port.node == pin && port.poll_presence)
        else {
            return Ok(());
        };
        let old = state.power_map.ok_or(Error::NeedsReset)?;
        let map = if sense.present {
            old & !(1 << index)
        } else {
            old | (1 << index)
        };
        if map != old {
            self.route_control(address, group, SET_POWER_MAP, GET_POWER_MAP, map)?;
            state.power_map = Some(map);
        }
        state.ports[index].sense = Some(sense);
        Ok(())
    }
}
