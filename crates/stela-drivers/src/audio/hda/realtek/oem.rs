// SPDX-License-Identifier: GPL-2.0-only
//! ALC1220 OEM analog wiring from alc882.c::{alc1220_fixup_gb_x570,
//! alc1220_fixup_clevo_p950,alc882_fixup_tbl} at Linux
//! a804c5742bff224d4cb4d25dd383554d598be32b (GPL-2.0-or-later).
//! PCI subsystem observations come from the retained controller, never AFG f20.
use super::CoefficientChange;
use crate::{
    audio::{
        Error,
        hda::{AnalogRoute, CodecGraph, Controller, Registers, Verb},
    },
    bus::i2c::Timer,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealtekOem {
    /// Firmware routing only; no assertion that an unknown OEM amplifier works.
    Firmware,
    GigabyteX570,
    ClevoP950,
}

pub(super) fn select(id: u32, subsystem: u32) -> Result<RealtekOem, Error> {
    if id != 0x10ec_1220 {
        return Err(Error::UnsupportedTopology);
    }
    let vendor = subsystem as u16;
    let device = (subsystem >> 16) as u16;
    match (vendor, device) {
        (0x1458, 0xa0cd | 0xa0ce | 0xa0d5) => Ok(RealtekOem::GigabyteX570),
        (0x1462, 0x11f7 | 0x1228 | 0x1229 | 0x1275 | 0x1276 | 0x1293)
        | (
            0x1558,
            0x9501 | 0x9506 | 0x950a | 0x95e1 | 0x95e2 | 0x95e3 | 0x95e4 | 0x95e5 | 0x95e6 | 0x96e1
            | 0x97e1 | 0x97e2,
        ) => Ok(RealtekOem::ClevoP950),
        _ => Err(Error::UnsupportedTopology),
    }
}

impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn realtek_oem_preflight(
        &mut self,
        graph: &CodecGraph,
        oem: RealtekOem,
    ) -> Result<(), Error> {
        if oem == RealtekOem::Firmware {
            return Ok(());
        }
        // Linux overrides these connections to {0x0c}. This native cut requires
        // that actual silicon advertises that same first selector entry; it
        // never forges graph metadata to claim an unobserved hardware route.
        for node in [0x14, 0x1b] {
            let pin = graph.widget(node).ok_or(Error::UnsupportedTopology)?;
            if pin.connections.first() != Some(&0x0c)
                || self.verb(Verb::short(graph.address, node, 0xf02, 0)?)? & 255 != 0x0c
            {
                return Err(Error::UnsupportedTopology);
            }
        }
        Ok(())
    }
    pub(super) fn realtek_oem_coefficients(
        &mut self,
        address: u8,
        oem: RealtekOem,
    ) -> Result<alloc::vec::Vec<CoefficientChange>, Error> {
        let mut changes = alloc::vec::Vec::new();
        match oem {
            RealtekOem::Firmware => {}
            RealtekOem::ClevoP950 => changes.push(self.update_coefficient(address, 7, 0, 0x03c3)?),
            RealtekOem::GigabyteX570 => {
                for (index, value) in [(7, 0x03c0), (0x1a, 0x01c1), (0x1b, 0x0202), (0x43, 0x3005)]
                {
                    let old = self.read_coefficient(address, index)?;
                    changes.push(self.write_coefficient_observed(address, index, old, value)?);
                }
            }
        }
        Ok(changes)
    }
}

pub(super) fn validate_route(oem: RealtekOem, route: &AnalogRoute) -> Result<(), Error> {
    if oem != RealtekOem::Firmware
        && matches!(route.pin(), 0x14 | 0x1b)
        && (route.converter() != 2 || route.nodes().get(1) != Some(&0x0c))
    {
        return Err(Error::UnsupportedTopology);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_pci_quirks_do_not_use_codec_subsystem_or_nearby_products() {
        assert_eq!(
            select(0x10ec_1220, 0xa0cd_1458),
            Ok(RealtekOem::GigabyteX570)
        );
        assert_eq!(select(0x10ec_1220, 0x9501_1558), Ok(RealtekOem::ClevoP950));
        for (id, subsystem) in [
            (0x10ec_1168, 0xa0cd_1458),
            (0x10ec_1220, 0xa0cc_1458),
            (0x10ec_1220, 0x65e1_1558),
            (0x10ec_1220, 0x1458_a0cd),
        ] {
            assert_eq!(select(id, subsystem), Err(Error::UnsupportedTopology));
        }
    }
}
