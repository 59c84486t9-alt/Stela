// SPDX-License-Identifier: GPL-2.0-only
//! MODEL_STAC92HD73XX source-default GPIO EAPD, direct volume and port map
//! adapted from Linux sound/hda/codecs/sigmatel.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright (c) 2005 Embedded Alley Solutions, Inc., Matt Porter.
//! Copyright (c) 2004 Takashi Iwai. See audio/THIRD_PARTY.md.
use super::super::{CodecGraph, Controller, Registers, Verb, WidgetKind};
use super::{SigmatelGpio, port_power};
use crate::{audio::Error, bus::i2c::Timer};
pub use port_power::IdtPowerMapReport as Idt73PowerReport;

const PORTS: [u8; 8] = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11];
pub(super) const VOLUME_KNOB: u8 = 0x1f;
pub(super) const EAPD: u8 = 1;
#[derive(Clone)]
pub(super) struct State {
    pub(super) ports: port_power::State,
    knob_caps: u32,
    gpio_caps: u32,
    gpio: Option<SigmatelGpio>,
}
impl State {
    pub(super) fn report(&self) -> Result<Idt73PowerReport, Error> {
        self.ports.report()
    }
    pub(super) fn require_route_power(&self, pin: u8) -> Result<(), Error> {
        self.ports.require_route_power(pin)
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn preflight_idt73(
        &mut self,
        graph: &CodecGraph,
        group: u8,
        gpio_caps: u32,
    ) -> Result<State, Error> {
        if gpio_caps & 255 == 0
            || graph
                .widget(VOLUME_KNOB)
                .is_none_or(|knob| knob.kind != WidgetKind::Volume)
        {
            return Err(Error::UnsupportedTopology);
        }
        Ok(State {
            ports: self.preflight_idt_ports(graph, group, &PORTS)?,
            knob_caps: self.sigmatel_knob_capabilities(graph.address, VOLUME_KNOB)?,
            gpio_caps,
            gpio: None,
        })
    }
    pub(super) fn initialize_idt73(
        &mut self,
        graph: &CodecGraph,
        group: u8,
        state: &mut State,
        gpio: SigmatelGpio,
    ) -> Result<(), Error> {
        // GPIO source default is already applied after actual D0. Generic init
        // runs the direct knob verb before synchronizing the port power map.
        state.gpio = Some(gpio);
        self.route_control(
            graph.address,
            VOLUME_KNOB,
            super::SET_VOLUME_KNOB,
            super::GET_VOLUME_KNOB,
            super::DIRECT_MAX_VOLUME,
        )?;
        self.observe_idt_port_map(graph, group, &mut state.ports)?;
        self.refresh_idt_ports(graph, group, &mut state.ports)
    }
    fn validate_idt73_gpio(
        &mut self,
        address: u8,
        group: u8,
        state: &State,
    ) -> Result<SigmatelGpio, Error> {
        if self.verb(Verb::short(address, group, 0xf00, 0x11)?)? != state.gpio_caps {
            return Err(Error::InvalidCodecGraph);
        }
        let allowed = ((1u16 << (state.gpio_caps & 255)) - 1) as u8;
        let actual = SigmatelGpio {
            data: self.sigmatel_gpio_read(address, group, super::GET_GPIO_DATA, allowed)?,
            mask: self.sigmatel_gpio_read(address, group, super::GET_GPIO_MASK, allowed)?,
            direction: self.sigmatel_gpio_read(
                address,
                group,
                super::GET_GPIO_DIRECTION,
                allowed,
            )?,
        };
        let expected = state.gpio.ok_or(Error::NeedsReset)?;
        // Only source-owned GPIO0 is an authority invariant. Other GPIO
        // inputs/owners may change; quiet must preserve their fresh values.
        if ((actual.data ^ expected.data)
            | (actual.mask ^ expected.mask)
            | (actual.direction ^ expected.direction))
            & EAPD
            != 0
        {
            return Err(Error::RouteRejected);
        }
        Ok(actual)
    }
    pub(super) fn validate_idt73(
        &mut self,
        graph: &CodecGraph,
        group: u8,
        state: &State,
    ) -> Result<(), Error> {
        self.validate_idt73_gpio(graph.address, group, state)?;
        if self.sigmatel_knob_capabilities(graph.address, VOLUME_KNOB)? != state.knob_caps
            || self.verb(Verb::short(
                graph.address,
                VOLUME_KNOB,
                super::GET_VOLUME_KNOB,
                0,
            )?)? != u32::from(super::DIRECT_MAX_VOLUME)
        {
            return Err(Error::InvalidCodecGraph);
        }
        self.validate_idt_ports(graph, group, &state.ports)
    }
    pub(super) fn quiet_idt73(
        &mut self,
        address: u8,
        group: u8,
        state: &State,
    ) -> Result<(), Error> {
        let actual = self.validate_idt73_gpio(address, group, state)?;
        // Source stac_suspend quietens pins first, then clears its EAPD mask
        // through the same preserving GPIO/CMOS/ordered DATA sequence.
        self.sigmatel_gpio_program(
            address,
            group,
            SigmatelGpio {
                data: actual.data & !EAPD,
                ..actual
            },
            ((1u16 << (state.gpio_caps & 255)) - 1) as u8,
            EAPD,
        )
        .map(|_| ())
    }
}
