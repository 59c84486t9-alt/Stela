// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2002 Takashi Iwai
//! UAC2 terminal connector status from actual descriptor access and GET_CUR.
//! Linux sound/usb/mixer.c::get_connector_value and audio-v2.h at
//! cc9de5d4b5ab6459f5774946aa3195ad51236fa8. See THIRD_PARTY.md.
use super::{Binding, Control, Entity, Error, UAC2, control};
use crate::usb::xhci;
use alloc::vec::Vec;

/// An actual terminal connector observation. Notifications invalidate this
/// historical value; they never replace it with an inferred plug or route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorStatus {
    pub terminal: u8,
    pub terminal_type: u16,
    pub channels: u8,
    pub channel_config: u32,
    pub channel_names: u8,
    pub raw: [u8; 6],
}
impl ConnectorStatus {
    pub fn connected(self) -> bool {
        self.channels != 0
    }
}

#[derive(Clone)]
pub(super) struct ConnectorPlan {
    protocol: u8,
    interface: u8,
    terminals: Vec<(u8, u16)>,
}
impl ConnectorPlan {
    pub(super) fn discover(binding: &Binding, configuration: &[u8]) -> Result<Self, Error> {
        let mut plan = Self {
            protocol: binding.graph.protocol,
            interface: binding.graph.control_interface,
            terminals: Vec::new(),
        };
        if plan.protocol != UAC2 {
            return Ok(plan);
        }
        let interfaces = xhci::interfaces(configuration);
        let interface = interfaces
            .iter()
            .find(|i| i.number == plan.interface && i.alternate == 0)
            .ok_or(Error::Descriptor("missing connector control interface"))?;
        if interface.class != super::CLASS
            || interface.subclass != super::CONTROL_SUBCLASS
            || interface.protocol != UAC2
        {
            return Err(Error::Descriptor("foreign connector control interface"));
        }
        for d in &interface.extra {
            if d.len() < 3 || d[1] != 0x24 {
                continue;
            }
            let (id, terminal_type, bits) = match d[2] {
                2 if d.len() == 17 => {
                    let Entity::Input { terminal_type, .. } = binding.graph.entity(d[3])? else {
                        return Err(Error::Descriptor("connector input terminal identity"));
                    };
                    (d[3], *terminal_type, u16::from_le_bytes([d[14], d[15]]))
                }
                3 if d.len() == 12 => {
                    let Entity::Output { terminal_type, .. } = binding.graph.entity(d[3])? else {
                        return Err(Error::Descriptor("connector output terminal identity"));
                    };
                    (d[3], *terminal_type, u16::from_le_bytes([d[9], d[10]]))
                }
                2 | 3 => return Err(Error::Descriptor("connector terminal descriptor length")),
                _ => continue,
            };
            if control::access(u32::from(bits), 2)?.0 {
                plan.terminals.push((id, terminal_type));
            }
        }
        Ok(plan)
    }
    pub(super) fn supports(&self, terminal: u8) -> bool {
        self.terminals.iter().any(|(id, _)| *id == terminal)
    }
    pub(super) fn read<C: Control>(
        &self,
        io: &mut C,
        terminal: u8,
    ) -> Result<ConnectorStatus, Error> {
        if self.protocol != UAC2 {
            return Err(Error::Unsupported("UAC2 terminal connector control"));
        }
        let (_, terminal_type) = self
            .terminals
            .iter()
            .find(|(id, _)| *id == terminal)
            .ok_or(Error::Unsupported(
                "no advertised readable terminal connector control",
            ))?;
        let raw: [u8; 6] = control::get(io, self.interface, terminal, 2, 0, 1, 6)?
            .try_into()
            .map_err(|_| Error::ControlLength)?;
        Ok(ConnectorStatus {
            terminal,
            terminal_type: *terminal_type,
            channels: raw[0],
            channel_config: u32::from_le_bytes(raw[1..5].try_into().unwrap()),
            channel_names: raw[5],
            raw,
        })
    }
}

#[cfg(test)]
mod tests;
