// SPDX-License-Identifier: GPL-2.0-or-later
//! UAC3 class discovery executes actual high-capability cluster transactions;
//! only the returned complete Binding may create a native PCM owner.
use super::descriptors::scope;
use super::{Binding, CLASS, CONTROL_SUBCLASS, Control, Error, STREAMING_SUBCLASS, UAC3};
use crate::usb::xhci::{INTERFACE_ASSOCIATION_DESCRIPTOR, Interface};
use alloc::vec::Vec;
mod cluster;
mod format;
mod graph;
use cluster::Reader;
pub use cluster::{ChannelInformation, Cluster};

pub struct Discovery {
    control: Interface,
    interfaces: Vec<Interface>,
    speed: u8,
    unsupported: Vec<(u8, u8, &'static str)>,
}

pub(super) fn full_function(
    control: &Interface,
    all: &[Interface],
    configuration: &[u8],
) -> Result<bool, Error> {
    if (
        control.class,
        control.subclass,
        control.protocol,
        control.alternate,
    ) != (CLASS, CONTROL_SUBCLASS, UAC3, 0)
    {
        return Err(Error::Unsupported("UAC3 control interface required"));
    }
    scope(configuration, control.number, all, UAC3)?;
    let mut at = 0;
    while at < configuration.len() {
        let d = &configuration[at..at + usize::from(configuration[at])];
        if d[1] == INTERFACE_ASSOCIATION_DESCRIPTOR && d[2] == control.number {
            return Ok(d[5] == 1);
        }
        at += d.len();
    }
    Err(Error::Descriptor("UAC3 requires an interface association"))
}
impl Discovery {
    pub(super) fn new(
        control: &Interface,
        all: &[Interface],
        configuration: &[u8],
        speed: u8,
    ) -> Result<Self, Error> {
        let range = scope(configuration, control.number, all, UAC3)?;
        let mut interfaces = Vec::new();
        let mut unsupported = Vec::new();
        for number in range.filter(|n| *n != u16::from(control.number)) {
            let settings: Vec<_> = all
                .iter()
                .filter(|i| u16::from(i.number) == number)
                .collect();
            if settings.is_empty()
                || settings
                    .iter()
                    .any(|i| (i.class, i.subclass, i.protocol) != (CLASS, STREAMING_SUBCLASS, UAC3))
            {
                return Err(Error::Descriptor(
                    "UAC3 function includes a foreign/missing interface",
                ));
            }
            if !settings
                .iter()
                .any(|i| i.alternate == 0 && i.endpoints.is_empty())
            {
                return Err(Error::Descriptor(
                    "UAC3 streaming interface lacks a zero-bandwidth alternate",
                ));
            }
            interfaces.extend(settings.into_iter().filter(|i| i.alternate != 0).cloned());
        }
        if interfaces.is_empty()
            || all
                .iter()
                .any(|i| i.number == control.number && i.alternate != 0)
        {
            return Err(Error::Descriptor(
                "UAC3 function control/stream interface extent",
            ));
        }
        for i in &interfaces {
            for other in all.iter().filter(|o| {
                o.number != i.number && !interfaces.iter().any(|s| s.number == o.number)
            }) {
                if other
                    .endpoints
                    .iter()
                    .any(|e| i.endpoints.iter().any(|ours| ours.dci() == e.dci()))
                {
                    return Err(Error::Descriptor(
                        "UAC3 endpoint aliases a foreign function",
                    ));
                }
            }
        }
        if !control.endpoints.is_empty() {
            unsupported.push((control.number, 0, "UAC3 interrupt/status delivery"));
        }
        Ok(Self {
            control: control.clone(),
            interfaces,
            speed,
            unsupported,
        })
    }
    pub(super) fn settings(&self) -> Vec<(u8, u8)> {
        let mut result = vec![(self.control.number, 0)];
        for i in &self.interfaces {
            if !result.iter().any(|(n, _)| *n == i.number) {
                result.push((i.number, 0));
            }
        }
        result
    }
    pub(super) fn discover<C: Control>(self, io: &mut C) -> Result<Binding, Error> {
        let mut reader = Reader {
            io,
            interface: self.control.number,
            clusters: Vec::new(),
        };
        let parsed = graph::parse(&self.control, &mut reader)?;
        let mut formats = Vec::new();
        let mut unsupported = self.unsupported;
        for interface in &self.interfaces {
            match format::parse(
                interface,
                &parsed,
                &mut reader,
                self.speed,
                &self.interfaces,
            ) {
                Ok(f) => formats.push(f),
                Err(Error::Unsupported(reason)) => {
                    unsupported.push((interface.number, interface.alternate, reason))
                }
                Err(e) => return Err(e),
            }
        }
        if formats.is_empty() {
            return Err(Error::Unsupported(
                "no usable discovered UAC3 PCM alternate",
            ));
        }
        Ok(Binding {
            clusters: reader.clusters,
            entity_clusters: parsed.clusters,
            basic_profile: None,
            graph: parsed.graph,
            formats,
            speed: self.speed,
            unsupported,
        })
    }
}
