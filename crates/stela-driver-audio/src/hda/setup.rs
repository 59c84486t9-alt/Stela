// SPDX-License-Identifier: GPL-2.0-only
//! The vendor codec setup a codec's identity selects when it binds, as
//! Linux's codec patch table selects its patch driver.
use super::{
    Alc269CommonReport, CirrusReport, CodecGraph, ConexantHeadsetInitialization, ConexantReport,
    Controller, RealtekReport, Registers, SigmatelReport, cirrus, conexant, realtek, sigmatel,
};
use crate::{Error, bus::i2c::Timer};

/// What [`Controller::initialize_codec`] applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecSetup {
    /// Managed ALC882/ALC662-family setup, with any PCI-subsystem OEM procedure.
    Realtek(RealtekReport),
    Alc269(Alc269CommonReport),
    Cirrus(CirrusReport),
    Conexant(ConexantReport),
    ConexantHeadset(ConexantHeadsetInitialization),
    Sigmatel(SigmatelReport),
    /// No vendor table names the codec; its standard widgets need no setup,
    /// as Linux's generic parser drives them.
    Standard,
}

impl core::fmt::Display for CodecSetup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Realtek(report) => write!(f, "Realtek {:?} ({:?})", report.family, report.oem),
            Self::Alc269(report) => write!(f, "Realtek ALC269 {:?}", report.variant),
            Self::Cirrus(report) => write!(f, "Cirrus {:?}", report.profile),
            Self::Conexant(_) => f.write_str("Conexant"),
            Self::ConexantHeadset(_) => f.write_str("Conexant headset"),
            Self::Sigmatel(report) => write!(f, "Sigmatel {:?}", report.profile),
            Self::Standard => f.write_str("standard widgets"),
        }
    }
}

impl<R: Registers, T: Timer> Controller<R, T> {
    /// Apply the vendor setup `graph`'s identity selects. A codec outside
    /// every vendor table is left as discovered.
    pub fn initialize_codec(&mut self, graph: &CodecGraph) -> Result<CodecSetup, Error> {
        let id = graph.vendor_id;
        if id == 0x10ec_0269 {
            self.initialize_realtek_alc269_common(graph)
                .map(CodecSetup::Alc269)
        } else if realtek::managed(id, graph.revision_id) {
            let report = if self.realtek_oem_selected(graph)? {
                self.initialize_realtek_oem_codec(graph)
            } else {
                self.initialize_realtek_codec(graph)
            };
            report.map(CodecSetup::Realtek)
        } else if cirrus::profile(id).is_ok() {
            self.initialize_cirrus_codec(graph).map(CodecSetup::Cirrus)
        } else if conexant::headset::is_profile(id) {
            self.initialize_conexant_headset_codec(graph)
                .map(CodecSetup::ConexantHeadset)
        } else if conexant::profile(id).is_ok() {
            self.initialize_conexant_codec(graph)
                .map(CodecSetup::Conexant)
        } else if sigmatel::profile(id).is_ok() {
            self.initialize_sigmatel_codec(graph)
                .map(CodecSetup::Sigmatel)
        } else {
            Ok(CodecSetup::Standard)
        }
    }
}
