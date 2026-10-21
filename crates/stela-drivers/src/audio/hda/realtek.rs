// SPDX-License-Identifier: GPL-2.0-only
//! Codec-common Realtek desktop PLL/EAPD controls adapted from Linux
//! sound/hda/codecs/realtek/{realtek,alc882,alc662}.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b (GPL-2.0-or-later).
//! This explicitly scoped setup does not select OEM fixups or establish board,
//! GPIO, companion-amplifier, headset or speaker readiness. See THIRD_PARTY.md.
use super::{CodecGraph, Controller, Registers, Verb};
use crate::{audio::Error, bus::i2c::Timer};
use alloc::vec::Vec;

const PROCESSING: u8 = 0x20;
const GET_PARAMETER: u16 = 0xf00;
#[derive(Clone, Copy)]
struct Profile {
    pll: Option<(u16, u16)>,
    eapd: Option<(u16, u16)>,
}
fn profile(id: u32) -> Result<Profile, Error> {
    let (pll, eapd) = match id {
        0x10ec_0887 => (Some((0x0a, 1 << 10)), None),
        0x10ec_0892 | 0x10ec_0897 => (Some((0x04, 1 << 15)), Some((0x07, 1 << 5))),
        0x10ec_0900 | 0x10ec_1220 => (None, Some((0x07, 1 << 1))),
        // The donor's alc882_probe default includes this ALC1220 alias, unlike
        // 1220 itself: keep its PLL clear in addition to common EAPD control.
        0x10ec_1168 => (Some((0x0a, 1 << 10)), Some((0x07, 1 << 1))),
        _ => return Err(Error::UnsupportedTopology),
    };
    Ok(Profile { pll, eapd })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoefficientChange {
    pub index: u16,
    pub previous: u16,
    pub current: u16,
}
/// An observation of codec-common controls only, not a board-readiness token.
/// AFG subsystem ID is reported raw; no board identity is inferred from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtekCommonReport {
    pub codec_id: u32,
    pub revision_id: u32,
    pub subsystem_id: u32,
    pub coefficients: Vec<CoefficientChange>,
}
impl<R: Registers, T: Timer> Controller<R, T> {
    fn realtek_parameter(&mut self, codec: u8, node: u8, parameter: u8) -> Result<u32, Error> {
        self.verb(Verb::short(codec, node, GET_PARAMETER, parameter)?)
    }
    fn coefficient_index(&mut self, codec: u8, index: u16) -> Result<(), Error> {
        self.verb(Verb::long(codec, PROCESSING, 5, index)?)?;
        if self.verb(Verb::long(codec, PROCESSING, 13, 0)?)? != u32::from(index) {
            return Err(Error::CoefficientRejected {
                node: PROCESSING,
                index,
            });
        }
        Ok(())
    }
    fn clear_coefficient_bits(
        &mut self,
        codec: u8,
        index: u16,
        mask: u16,
    ) -> Result<CoefficientChange, Error> {
        let fault = Error::CoefficientRejected {
            node: PROCESSING,
            index,
        };
        self.coefficient_index(codec, index)?;
        let previous =
            u16::try_from(self.verb(Verb::long(codec, PROCESSING, 12, 0)?)?).map_err(|_| fault)?;
        let current = previous & !mask;
        if current != previous {
            // Explicitly reselect for the write/readback transaction, matching
            // Realtek's indexed helper. &mut Controller serializes the cursor.
            self.coefficient_index(codec, index)?;
            self.verb(Verb::long(codec, PROCESSING, 4, current)?)?;
            self.coefficient_index(codec, index)?;
            if self.verb(Verb::long(codec, PROCESSING, 12, 0)?)? != u32::from(current) {
                return Err(fault);
            }
        }
        Ok(CoefficientChange {
            index,
            previous,
            current,
        })
    }

    /// Apply only exact codec-common desktop PLL/EAPD coefficient masks.
    /// Live identity/revision/AFG/vendor-node bounds are checked again before
    /// writes, so editing public graph metadata cannot select a different chip.
    /// Every stream must be stopped, none poisoned, and this codec must have no
    /// reserved route. D0 and every written coefficient are read back. Failure
    /// after programming begins blocks typed routing/start until reinitialize.
    /// This does not enable EAPD pins, choose PinOptions or apply an OEM fixup.
    /// ALC2xx depop/headset/revision procedures are deliberately unsupported here.
    pub fn initialize_realtek_common(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<RealtekCommonReport, Error> {
        if graph.token != self.token {
            return Err(Error::InvalidCodecGraph);
        }
        if self.routing_failed {
            return Err(Error::NeedsReset);
        }
        self.require_routing_stopped()?;
        if self
            .routes
            .iter()
            .any(|(_, route)| route.codec_address() == graph.address)
        {
            return Err(Error::RouteInUse);
        }
        let selected = profile(graph.vendor_id)?;
        let group = graph
            .groups
            .iter()
            .find(|group| group.node == 1 && group.function_type & 255 == 1)
            .ok_or(Error::InvalidCodecGraph)?;
        if group
            .power_states
            .is_none_or(|value| value == u32::MAX || value & 1 == 0)
        {
            return Err(Error::UnsupportedTopology);
        }
        let codec_id = self.realtek_parameter(graph.address, 0, 0)?;
        let revision_id = self.realtek_parameter(graph.address, 0, 2)?;
        if codec_id != graph.vendor_id
            || revision_id != graph.revision_id
            || revision_id == u32::MAX
        {
            return Err(Error::InvalidCodecGraph);
        }
        // These profiles use their actual standard AFG1 processing node20.
        let function = self.realtek_parameter(graph.address, 1, 5)?;
        let power = self.realtek_parameter(graph.address, 1, 0x0f)?;
        let nodes = self.realtek_parameter(graph.address, 1, 4)?;
        let first = (nodes >> 16) & 255;
        let count = nodes & 255;
        if function == u32::MAX
            || function & 255 != 1
            || power == u32::MAX
            || power & 1 == 0
            || first < 2
            || first > u32::from(PROCESSING)
            || count == 0
            || first + count > 128
            || first + count <= u32::from(PROCESSING)
        {
            return Err(Error::InvalidCodecGraph);
        }
        let caps = self.realtek_parameter(graph.address, PROCESSING, 9)?;
        if caps == u32::MAX || (caps >> 20) & 15 != 15 || caps & (1 << 6) == 0 {
            return Err(Error::UnsupportedTopology);
        }
        let vendor_power = if caps & (1 << 10) != 0 {
            let value = self.realtek_parameter(graph.address, PROCESSING, 0x0f)?;
            let effective = if value == 0 { power } else { value };
            if effective == u32::MAX || effective & 1 == 0 {
                return Err(Error::UnsupportedTopology);
            }
            true
        } else {
            false
        };
        let subsystem_id = self.verb(Verb::short(graph.address, 1, 0xf20, 0)?)?;
        let result = (|| {
            self.power_d0(graph.address, 1)?;
            if vendor_power {
                self.power_d0(graph.address, PROCESSING)?;
            }
            let mut coefficients = Vec::new();
            for (index, mask) in [selected.pll, selected.eapd].into_iter().flatten() {
                coefficients.push(self.clear_coefficient_bits(graph.address, index, mask)?);
            }
            Ok(RealtekCommonReport {
                codec_id,
                revision_id,
                subsystem_id,
                coefficients,
            })
        })();
        if result.is_err() {
            self.routing_failed = true;
        }
        result
    }
}
