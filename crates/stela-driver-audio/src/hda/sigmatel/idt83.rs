// SPDX-License-Identifier: GPL-2.0-only
//! IDT MODEL_STAC92HD83XXX AFG amplifier mode and port power map adapted
//! from sound/hda/codecs/sigmatel.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright (c) 2005 Embedded Alley Solutions, Inc., Matt Porter.
//! Copyright (c) 2004 Takashi Iwai. See audio/THIRD_PARTY.md.
use super::super::{CodecGraph, Controller, Registers, Verb};
use super::port_power;
use crate::{Error, Timer};
use alloc::vec::Vec;
pub use port_power::IdtPortPower as Idt83PortPower;
const PORTS: [u8; 7] = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
const SET_AMPLIFIER_MODE: u16 = 0x788;
const POWER_STATE_CONTROLS_AMPLIFIERS: u8 = 4;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Idt83PowerReport {
    /// Source mode4 was acknowledged; no stable getter is invented.
    pub amplifier_mode_acknowledged: u8,
    pub power_map: u8,
    pub ports: Vec<Idt83PortPower>,
}
#[derive(Clone)]
pub(super) struct State {
    pub(super) ports: port_power::State,
}
impl State {
    pub(super) fn report(&self) -> Result<Idt83PowerReport, Error> {
        let report = self.ports.report()?;
        Ok(Idt83PowerReport {
            amplifier_mode_acknowledged: POWER_STATE_CONTROLS_AMPLIFIERS,
            power_map: report.power_map,
            ports: report.ports,
        })
    }
    pub(super) fn require_route_power(&self, pin: u8) -> Result<(), Error> {
        self.ports.require_route_power(pin)
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn preflight_idt83(
        &mut self,
        graph: &CodecGraph,
        group: u8,
    ) -> Result<State, Error> {
        self.minimum_guard()?;
        Ok(State {
            ports: self.preflight_idt_ports(graph, group, &PORTS)?,
        })
    }
    pub(super) fn validate_idt83(
        &mut self,
        graph: &CodecGraph,
        group: u8,
        state: &State,
    ) -> Result<(), Error> {
        self.minimum_guard()?;
        self.validate_idt_ports(graph, group, &state.ports)
    }
    pub(super) fn initialize_idt83(
        &mut self,
        graph: &CodecGraph,
        group: u8,
        state: &mut State,
    ) -> Result<(), Error> {
        self.minimum_guard()?;
        self.observe_idt_port_map(graph, group, &mut state.ports)?;
        if self.verb(Verb::short(
            graph.address,
            group,
            SET_AMPLIFIER_MODE,
            POWER_STATE_CONTROLS_AMPLIFIERS,
        )?)? == u32::MAX
        {
            return Err(Error::RouteRejected);
        }
        self.refresh_idt_ports(graph, group, &mut state.ports)
    }
}
