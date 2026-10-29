// SPDX-License-Identifier: GPL-2.0-only
//! CS4210 startup, DAC range and speaker boost adapted from Linux
//! sound/hda/codecs/cirrus/cs421x.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See audio/THIRD_PARTY.md.
//! GPL version2 combines the upstream GPL-2.0-or-later codec with native HDA.
use super::super::{CodecGraph, Controller, PinConnection, PinDevice, Registers, Verb, WidgetKind};
use super::{CirrusCoefficient, CirrusOutputAmplifier, CirrusProfile, GROUP};
use crate::{
    audio::{Direction, Error},
    bus::i2c::Timer,
};
use alloc::vec::Vec;

pub(super) const ERRATA_COEFFICIENT_WRITES: usize = 5;
const DAC: u8 = 2;
const ADC: u8 = 3;
const DEVICE_CONFIG: u16 = 1;
const SPEAKER_CONTROL: u16 = 4;
const GPIO_SENSE_MUX: u16 = 0x18;
const BOOST_MASK: u16 = 3;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CirrusSpeakerBoost {
    pub code: u8,
    pub gain_centibels: u16,
    pub coefficient: u16,
    pub changed: bool,
}
impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn cs4210_pin_defaults(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<Vec<(u8, u32)>, Error> {
        let mut defaults = Vec::new();
        for pin in graph
            .groups
            .iter()
            .flat_map(|group| &group.widgets)
            .filter(|widget| widget.kind == WidgetKind::Pin)
        {
            let cached = pin.pin_default.ok_or(Error::InvalidCodecGraph)?;
            let live = self.verb(Verb::short(graph.address, pin.node, 0xf1c, 0)?)?;
            if live == u32::MAX || live != cached {
                return Err(Error::InvalidCodecGraph);
            }
            defaults.push((pin.node, live));
        }
        Ok(defaults)
    }
    pub(super) fn cs4210_output_amplifiers(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<Vec<CirrusOutputAmplifier>, Error> {
        let dac = graph.widget(DAC).ok_or(Error::UnsupportedTopology)?;
        let adc = graph.widget(ADC).ok_or(Error::UnsupportedTopology)?;
        if dac.kind != WidgetKind::Output || adc.kind != WidgetKind::Input {
            return Err(Error::UnsupportedTopology);
        }
        let observed_caps = self.validate_live_output_amplifier(graph.address, GROUP, dac)?;
        Ok(alloc::vec![CirrusOutputAmplifier {
            node: DAC,
            observed_caps,
            effective_caps: (observed_caps & !0x7f00) | ((observed_caps & 0x7f) << 8),
        }])
    }
    fn cs4210_default_pinmux(&mut self, graph: &CodecGraph) -> Result<CirrusCoefficient, Error> {
        let vendor = CirrusProfile::Cs4210.vendor();
        let original = self.cirrus_read(graph.address, vendor, DEVICE_CONFIG)?;
        // Unselected source profile has gpio_mask=0 and sense_b=0. Preserve
        // every other bit and the unconditional write, even if unchanged.
        self.cirrus_write(
            graph.address,
            vendor,
            DEVICE_CONFIG,
            original & !GPIO_SENSE_MUX,
        )
    }
    pub(super) fn initialize_cs4210_coefficients(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<Vec<CirrusCoefficient>, Error> {
        let vendor = CirrusProfile::Cs4210.vendor();
        // Probe pinmux precedes processing enable and the source core recipe.
        self.cs4210_default_pinmux(graph)?;
        self.cirrus_processing(graph.address, vendor, 1)?;
        self.cirrus_write(graph.address, vendor, DEVICE_CONFIG, 1)?;
        let adc = self.cirrus_write(graph.address, vendor, 2, 2)?;
        let dac = self.cirrus_write(graph.address, vendor, 3, 0x000e)?;
        // Source calls this A1 recipe unconditionally, including the repeated
        // processing enable. It does not close the test key afterward.
        self.cirrus_processing(graph.address, vendor, 1)?;
        for (index, value) in [
            (6, 0x9999),
            (0x0a, 0x14cb),
            (0x11, 0xa2d0),
            (0x1a, 0x02a9),
            (0x1b, 0x1006),
        ] {
            self.cirrus_coefficient_ack(graph.address, vendor, index, value)?;
        }
        let device = self.cs4210_default_pinmux(graph)?;
        Ok(alloc::vec![device, adc, dac])
    }
    /// Change the CS4210 speaker amplifier through its source-defined four
    /// gain codes (9/12/15/18dB). Requires an owned speaker DAC route;
    /// PCM may continue while the two low coefficient bits are updated.
    pub fn set_cirrus_cs4210_speaker_boost(
        &mut self,
        graph: &CodecGraph,
        code: u8,
    ) -> Result<CirrusSpeakerBoost, Error> {
        if code > BOOST_MASK as u8 {
            return Err(Error::InvalidFormat);
        }
        self.cirrus_guard(graph)?;
        if super::profile(graph.vendor_id)? != CirrusProfile::Cs4210 {
            return Err(Error::UnsupportedTopology);
        }
        self.cirrus_active(graph)?;
        let speaker = self.routes.iter().any(|(_, route)| {
            route.codec_address() == graph.address
                && route.direction() == Direction::Playback
                && route.converter() == DAC
                && graph
                    .widget(route.pin())
                    .and_then(|pin| pin.pin_configuration())
                    .is_some_and(|pin| {
                        pin.connection() != PinConnection::None
                            && pin.device() == PinDevice::Speaker
                    })
        });
        if !speaker {
            return Err(Error::UnsupportedTopology);
        }
        let result = (|| {
            let vendor = CirrusProfile::Cs4210.vendor();
            let original = self.cirrus_read(graph.address, vendor, SPEAKER_CONTROL)?;
            let coefficient = (original & !BOOST_MASK) | u16::from(code);
            let changed = coefficient != original;
            if changed {
                self.cirrus_write(graph.address, vendor, SPEAKER_CONTROL, coefficient)?;
            }
            Ok(CirrusSpeakerBoost {
                code,
                gain_centibels: 900 + 300 * u16::from(code),
                coefficient,
                changed,
            })
        })();
        if result.is_err() {
            self.routing_failed = true;
        }
        result
    }
}
