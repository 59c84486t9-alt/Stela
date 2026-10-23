// SPDX-License-Identifier: GPL-2.0-only
//! CS4206/CS4207 fixed errata and shared-pin setup from the pinned cs420x.c.
//! Copyright (c) 2009 Takashi Iwai <tiwai@suse.de>. See audio/THIRD_PARTY.md.
use super::super::{CodecGraph, Controller, PinConnection, Registers, Verb, WidgetKind};
use super::{Authority, CirrusCoefficient, CirrusProfile, DIGITAL};
use crate::{audio::Error, bus::i2c::Timer};
use alloc::vec::Vec;

pub(super) const ERRATA_COEFFICIENT_WRITES: usize = 6;
const SHARED_PINS: [u8; 3] = [0x0e, 0x12, 0x15];
const DAC_CONFIG: u16 = 0x146a;
const ADC_CONFIG: u16 = 0x000a;
const BEEP_CONFIG: u16 = 0x0007;
const SPDIF_CONFIG: u16 = 0x000a;

impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn cs420x_shared_pins(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<Vec<(u8, u32)>, Error> {
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
        Ok(shared_pins)
    }
    pub(super) fn initialize_cs420x_coefficients(
        &mut self,
        graph: &CodecGraph,
        authority: &Authority,
    ) -> Result<Vec<CirrusCoefficient>, Error> {
        // AFG/vendor D0 already acknowledged; preserve all source errata writes.
        let vendor = CirrusProfile::Cs420x.vendor();
        self.cirrus_processing(graph.address, vendor, 1)?;
        for (index, value) in [(8, 0x9999), (0x17, 0xa412), (1, 9)] {
            self.cirrus_coefficient_ack(graph.address, vendor, index, value)?;
        }
        self.power_d0(graph.address, 7)?;
        self.power_d0(graph.address, 8)?;
        for (index, value) in [(0x17, 0x2412), (8, 0), (1, 8)] {
            self.cirrus_coefficient_ack(graph.address, vendor, index, value)?;
        }
        self.cirrus_processing(graph.address, vendor, 0)?;
        self.cirrus_processing(graph.address, vendor, 1)?;
        let mut coefficients = alloc::vec![
            self.cirrus_write(graph.address, vendor, 3, DAC_CONFIG)?,
            self.cirrus_write(graph.address, vendor, 2, ADC_CONFIG)?,
        ];
        self.cirrus_write(graph.address, vendor, 4, BEEP_CONFIG)?;
        let active = |node| {
            authority.shared_pins.iter().any(|(pin, raw)| {
                *pin == node
                    && (super::super::PinConfiguration { raw: *raw }).connection()
                        != PinConnection::None
            })
        };
        let mut beep = self.cirrus_read(graph.address, vendor, 4)?;
        if active(0x12) {
            beep |= 1 << 4;
        }
        if active(0x0e) {
            beep |= 1 << 3;
        }
        coefficients.push(self.cirrus_write(graph.address, vendor, 4, beep)?);
        let spdif = SPDIF_CONFIG | if active(0x15) { 0x4000 } else { 0 };
        coefficients.push(self.cirrus_write(graph.address, vendor, 1, spdif)?);
        Ok(coefficients)
    }
}
