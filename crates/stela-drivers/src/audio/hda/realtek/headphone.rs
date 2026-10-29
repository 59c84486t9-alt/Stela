// SPDX-License-Identifier: GPL-2.0-only
//! Timed Realtek headphone startup adapted from alc269.c::{alc_default_init,alc256_init} and
//! realtek.c::alc_fill_eapd_coef at
//! a804c5742bff224d4cb4d25dd383554d598be32b (GPL-2.0-or-later).
//! This is a selected standard headphone route; OEM GPIO/companion amplifiers,
//! presence inversion and headset CTIA/OMTP policies are not inferred.
use super::RealtekCommonReport;
use crate::{
    audio::hda::{
        AnalogRoute, CodecGraph, Controller, PinConnection, PinDevice, PinOptions, PinSense,
        Registers, StreamId, Verb, WidgetKind,
    },
    audio::{Direction, Error},
    bus::i2c::Timer,
};

/// Startup measurements and observed common controls after the explicit route
/// was configured and reserved. This is not an acoustic or OEM-readiness claim.
/// Common coefficient observations are ordered transactions; an index may
/// occur more than once. Fixed depop endpoints are verified during startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtekHeadphoneReport {
    pub common: RealtekCommonReport,
    pub headphone_pin: u8,
    pub initial_sense: PinSense,
}
// These are fixed endpoints in the ALC256/257 donor procedure, not selectable
// register banks or arbitrary graph NIDs. The public caller chooses only hp_pin.
#[derive(Clone, Copy)]
pub(super) enum DepopControl {
    HeadphonePower,
    AnalogReset,
}
#[derive(Clone, Copy)]
enum DepopProfile {
    Alc255,
    Alc256And257,
}

impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn headphone_preflight(
        &mut self,
        graph: &CodecGraph,
        route: &AnalogRoute,
        id: StreamId,
        channel: u8,
        options: PinOptions,
    ) -> Result<bool, Error> {
        self.realtek_common_guard(graph)?;
        self.preflight_analog_route(graph, route, id, channel, options)?;
        if route.direction() != Direction::Playback
            || route.group_node() != 1
            || channel != 0
            || self.stream_format(id)?.channels > 2
            || !matches!(
                options,
                PinOptions::Playback {
                    headphone: true,
                    ..
                }
            )
        {
            return Err(Error::UnsupportedTopology);
        }
        let pin = graph.widget(route.pin()).ok_or(Error::InvalidCodecGraph)?;
        let converter = graph
            .widget(route.converter())
            .ok_or(Error::InvalidCodecGraph)?;
        let configuration = pin.pin_configuration().ok_or(Error::InvalidCodecGraph)?;
        if pin.kind != WidgetKind::Pin
            || pin.channels() != 2
            || converter.channels() != 2
            || configuration.device() != PinDevice::Headphone
            || configuration.connection() == PinConnection::None
            || configuration.no_presence_detection()
            || pin
                .pin_capabilities
                .is_none_or(|value| value == u32::MAX || value & 0x1c != 0x1c)
            || pin
                .output_amplifier
                .is_none_or(|value| value == u32::MAX || value & (1 << 31) == 0)
        {
            return Err(Error::UnsupportedTopology);
        }
        // Graph fields are public metadata. Recheck the selected pin,
        // rather than authorizing pin/amp writes from edited cached fields.
        let nodes = self.realtek_parameter(graph.address, 1, 4)?;
        let first = (nodes >> 16) & 255;
        let count = nodes & 255;
        let end = first + count;
        if first < 2
            || count == 0
            || end > 128
            || !(first..end).contains(&u32::from(route.pin()))
            || !(first..end).contains(&u32::from(route.converter()))
        {
            return Err(Error::InvalidCodecGraph);
        }
        let caps = self.realtek_parameter(graph.address, route.pin(), 9)?;
        let pin_caps = self.realtek_parameter(graph.address, route.pin(), 0x0c)?;
        let defaults = self.verb(Verb::short(graph.address, route.pin(), 0xf1c, 0)?)?;
        let amp = self.realtek_parameter(
            graph.address,
            if caps & 8 != 0 { route.pin() } else { 1 },
            0x12,
        )?;
        if caps != pin.capabilities
            || pin.pin_capabilities != Some(pin_caps)
            || pin.pin_default != Some(defaults)
            || pin.output_amplifier != Some(amp)
        {
            return Err(Error::InvalidCodecGraph);
        }
        let pin_power = caps & (1 << 10) != 0;
        if pin_power {
            let raw = self.realtek_parameter(graph.address, route.pin(), 0x0f)?;
            let states = if raw == 0 {
                self.realtek_parameter(graph.address, 1, 0x0f)?
            } else {
                raw
            };
            if states == u32::MAX || states & 1 == 0 {
                return Err(Error::UnsupportedTopology);
            }
        }
        Ok(pin_power)
    }
    pub(super) fn headphone_unmute_zero(&mut self, codec: u8, pin: u8) -> Result<(), Error> {
        // Exact AMP_OUT_UNMUTE: both declared stereo channels, gain code zero.
        // Generic route programming subsequently chooses its advertised 0dB.
        self.verb(Verb::long(codec, pin, 3, 0xb000)?)?;
        for get in [0xa000, 0x8000] {
            if self.verb(Verb::long(codec, pin, 11, get)?)? != 0 {
                return Err(Error::RouteRejected);
            }
        }
        Ok(())
    }

    /// Exact ALC298 standard-power startup followed by one explicit headphone
    /// route. A real firmware-described headphone pin and PCM path are required;
    /// the Linux fallback pin is not substituted for an unknown board route.
    /// Presence uses only standard non-inverted polling. Initial 30ms, present-
    /// jack 2ms, pin-enable 75ms and unmute 75ms intervals use the same Timer.
    /// Any failure after power/programming begins quarantines typed route/start
    /// until controller reinitialization; a successful route reserves its path.
    pub fn configure_realtek_alc298_headphone(
        &mut self,
        graph: &CodecGraph,
        route: &AnalogRoute,
        id: StreamId,
        channel: u8,
        options: PinOptions,
    ) -> Result<RealtekHeadphoneReport, Error> {
        self.realtek_common_guard(graph)?;
        if graph.vendor_id != 0x10ec_0298 {
            return Err(Error::UnsupportedTopology);
        }
        let pin_power = self.headphone_preflight(graph, route, id, channel, options)?;
        let (codec_id, revision_id, subsystem_id, vendor_power) =
            self.realtek_common_identity(graph)?;
        // alc269_probe's ALC5505 hook replacement is outside this normal path.
        if self.realtek_parameter(graph.address, 0x51, 0)? != 0 {
            return Err(Error::UnsupportedTopology);
        }
        let result = (|| {
            self.power_d0(graph.address, 1)?;
            if vendor_power {
                self.power_d0(graph.address, 0x20)?;
            }
            if pin_power {
                self.power_d0(graph.address, route.pin())?;
            }
            let coefficients =
                alloc::vec![self.clear_coefficient_bits(graph.address, 0x10, 1 << 9)?];
            self.delay(30_000);
            let initial_sense = self.poll_pin_sense(graph, route.pin())?;
            if initial_sense.present {
                self.delay(2_000);
                self.route_control(graph.address, route.pin(), 0x707, 0xf07, 0x40)?;
                self.delay(75_000);
                self.headphone_unmute_zero(graph.address, route.pin())?;
                self.delay(75_000);
            }
            self.configure_analog_route(graph, route, id, channel, options)?;
            Ok(RealtekHeadphoneReport {
                common: RealtekCommonReport {
                    codec_id,
                    revision_id,
                    subsystem_id,
                    coefficients,
                },
                headphone_pin: route.pin(),
                initial_sense,
            })
        })();
        if result.is_err() {
            self.routing_failed = true;
        }
        result
    }
    pub(super) fn depop_control(
        &mut self,
        codec: u8,
        control: DepopControl,
        setting: u16,
    ) -> Result<(), Error> {
        let (node, index, mask) = match control {
            DepopControl::HeadphonePower => (0x57, 4, 7),
            DepopControl::AnalogReset => (0x53, 2, 0x8000),
        };
        let fault = Error::CoefficientRejected { node, index };
        if setting & !mask != 0 {
            return Err(Error::InvalidConfiguration);
        }
        // Exact family identity is checked before this helper. These hidden
        // vendor endpoints are not invented standard widget-capability nodes;
        // positive index and data readback are required for every transaction.
        self.verb(Verb::long(codec, node, 5, index)?)?;
        if self.verb(Verb::long(codec, node, 13, 0)?)? != u32::from(index) {
            return Err(fault);
        }
        let previous =
            u16::try_from(self.verb(Verb::long(codec, node, 12, 0)?)?).map_err(|_| fault)?;
        let current = (previous & !mask) | setting;
        self.verb(Verb::long(codec, node, 5, index)?)?;
        if self.verb(Verb::long(codec, node, 13, 0)?)? != u32::from(index) {
            return Err(fault);
        }
        // Keep the donor's write even when the value matches, notably the
        // ordered high/low analog-reset transactions.
        self.verb(Verb::long(codec, node, 4, current)?)?;
        self.verb(Verb::long(codec, node, 5, index)?)?;
        if self.verb(Verb::long(codec, node, 13, 0)?)? != u32::from(index)
            || self.verb(Verb::long(codec, node, 12, 0)?)? != u32::from(current)
        {
            return Err(fault);
        }
        Ok(())
    }

    /// Exact ALC256/257 held-D0 headphone depop/startup, then explicit route
    /// configuration/reservation. It uses alc256_init's fixed node57 power,
    /// node53 analog-reset pulse and node20 controls, including the literal
    /// 0x5757 PC-beep/1Ah routing choice. The same live pin/codec/format and
    /// presence checks as ALC298 apply. ULP, OEM headset/GPIO/amp and shutup
    /// policies are not selected; those need their own board ownership.
    pub fn configure_realtek_alc256_headphone(
        &mut self,
        graph: &CodecGraph,
        route: &AnalogRoute,
        id: StreamId,
        channel: u8,
        options: PinOptions,
    ) -> Result<RealtekHeadphoneReport, Error> {
        self.configure_realtek_depop_headphone(
            graph,
            route,
            id,
            channel,
            options,
            DepopProfile::Alc256And257,
        )
    }

    /// Exact ALC255 held-D0 headphone startup and explicit route reservation.
    /// Its fixed depop/reset sequence matches alc256_init, but its initial
    /// EAPD selection clears only node20/index10 bit9: index36 bit13 is left
    /// untouched until the donor's final unconditional 0x5757 write.
    /// The same live pin, presence, failure and OEM-policy bounds apply.
    pub fn configure_realtek_alc255_headphone(
        &mut self,
        graph: &CodecGraph,
        route: &AnalogRoute,
        id: StreamId,
        channel: u8,
        options: PinOptions,
    ) -> Result<RealtekHeadphoneReport, Error> {
        self.configure_realtek_depop_headphone(
            graph,
            route,
            id,
            channel,
            options,
            DepopProfile::Alc255,
        )
    }

    fn configure_realtek_depop_headphone(
        &mut self,
        graph: &CodecGraph,
        route: &AnalogRoute,
        id: StreamId,
        channel: u8,
        options: PinOptions,
        profile: DepopProfile,
    ) -> Result<RealtekHeadphoneReport, Error> {
        self.realtek_common_guard(graph)?;
        let accepts = match profile {
            DepopProfile::Alc255 => graph.vendor_id == 0x10ec_0255,
            DepopProfile::Alc256And257 => matches!(graph.vendor_id, 0x10ec_0256 | 0x10ec_0257),
        };
        if !accepts {
            return Err(Error::UnsupportedTopology);
        }
        let pin_power = self.headphone_preflight(graph, route, id, channel, options)?;
        let (codec_id, revision_id, subsystem_id, vendor_power) =
            self.realtek_common_identity(graph)?;
        if self.realtek_parameter(graph.address, 0x51, 0)? != 0 {
            return Err(Error::UnsupportedTopology);
        }
        let result = (|| {
            self.power_d0(graph.address, 1)?;
            if vendor_power {
                self.power_d0(graph.address, 0x20)?;
            }
            if pin_power {
                self.power_d0(graph.address, route.pin())?;
            }
            let mut coefficients = alloc::vec::Vec::new();
            if matches!(profile, DepopProfile::Alc256And257) {
                coefficients.push(self.clear_coefficient_bits(graph.address, 0x36, 1 << 13)?);
            }
            coefficients.push(self.clear_coefficient_bits(graph.address, 0x10, 1 << 9)?);
            self.delay(30_000);
            let initial_sense = self.poll_pin_sense(graph, route.pin())?;
            if initial_sense.present {
                self.delay(2_000);
                self.depop_control(graph.address, DepopControl::HeadphonePower, 1)?;
                self.route_control(graph.address, route.pin(), 0x707, 0xf07, 0x40)?;
                self.delay(75_000);
                self.headphone_unmute_zero(graph.address, route.pin())?;
                self.delay(75_000);
                self.depop_control(graph.address, DepopControl::HeadphonePower, 4)?;
            }
            coefficients.push(self.clear_coefficient_bits(graph.address, 0x46, 3 << 12)?);
            self.depop_control(graph.address, DepopControl::AnalogReset, 0x8000)?;
            self.depop_control(graph.address, DepopControl::AnalogReset, 0)?;
            let previous = self.read_coefficient(graph.address, 0x36)?;
            coefficients.push(self.write_coefficient_observed(
                graph.address,
                0x36,
                previous,
                0x5757,
            )?);
            self.configure_analog_route(graph, route, id, channel, options)?;
            Ok(RealtekHeadphoneReport {
                common: RealtekCommonReport {
                    codec_id,
                    revision_id,
                    subsystem_id,
                    coefficients,
                },
                headphone_pin: route.pin(),
                initial_sense,
            })
        })();
        if result.is_err() {
            self.routing_failed = true;
        }
        result
    }
}
