// SPDX-License-Identifier: GPL-2.0-only
//! CS4208 input stereo/gain corrections and startup from the pinned cs420x.c.
//! Copyright (c) 2009 Takashi Iwai <tiwai@suse.de>. See audio/THIRD_PARTY.md.
use super::super::{CodecGraph, Controller, Registers, WidgetKind, codec::widget_channels};
use super::{CirrusCoefficient, CirrusInputAmplifier, CirrusProfile, GROUP};
use crate::{Error, Timer};
use alloc::vec::Vec;

const INPUT_AMPLIFIERS: [u8; 3] = [0x18, 0x1b, 0x1c];
impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn cs4208_input_amplifiers(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<Vec<CirrusInputAmplifier>, Error> {
        self.minimum_guard()?;
        let mut amplifiers = Vec::new();
        for node in INPUT_AMPLIFIERS {
            let widget = graph.widget(node).ok_or(Error::UnsupportedTopology)?;
            if !matches!(widget.kind, WidgetKind::Pin | WidgetKind::Input)
                || (widget.kind == WidgetKind::Pin
                    && widget
                        .pin_capabilities
                        .is_none_or(|caps| caps & (1 << 5) == 0))
            {
                return Err(Error::UnsupportedTopology);
            }
            let observed_caps = self.validate_live_input_amplifier(graph.address, GROUP, widget)?;
            let effective_caps = (observed_caps & !0x7f) | 2;
            if (effective_caps >> 8) & 0x7f < 2 {
                return Err(Error::UnsupportedTopology);
            }
            let capabilities = widget.capabilities | if node == 0x18 { 1 } else { 0 };
            amplifiers.push(CirrusInputAmplifier {
                node,
                observed_caps,
                effective_caps,
                effective_channels: widget_channels(capabilities),
            });
        }
        Ok(amplifiers)
    }
    pub(super) fn initialize_cs4208_coefficients(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<Vec<CirrusCoefficient>, Error> {
        self.minimum_guard()?;
        let vendor = CirrusProfile::Cs4208.vendor();
        self.cirrus_processing(graph.address, vendor, 1)?;
        Ok(alloc::vec![
            self.cirrus_write(graph.address, vendor, 0x33, 1)?,
            self.cirrus_write(graph.address, vendor, 0x34, 0x1c01)?
        ])
    }
}
