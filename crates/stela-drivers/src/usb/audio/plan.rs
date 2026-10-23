// SPDX-License-Identifier: GPL-2.0-or-later
//! Separate pure USB ownership plans from bindings requiring native observations.
use super::{Binding, Control, Error, UAC3, uac3};
use crate::usb::xhci::Interface;
use alloc::vec::Vec;

pub enum Plan {
    Ready(Binding),
    DiscoverUac3(uac3::Discovery),
}
impl Plan {
    pub fn parse(
        control: &Interface,
        all: &[Interface],
        configuration: &[u8],
        speed: u8,
    ) -> Result<Self, Error> {
        if control.protocol == UAC3 && uac3::full_function(control, all, configuration)? {
            return Ok(Self::DiscoverUac3(uac3::Discovery::new(
                control,
                all,
                configuration,
                speed,
            )?));
        }
        Binding::parse(control, all, configuration, speed).map(Self::Ready)
    }
    pub(crate) fn settings(&self) -> Vec<(u8, u8)> {
        match self {
            Self::Ready(b) => b.settings(),
            Self::DiscoverUac3(p) => p.settings(),
        }
    }
    /// Finish high-capability descriptor controls before any audio owner is
    /// published. Discovery performs no streaming alternate or DMA publication.
    pub fn discover<C: Control>(self, io: &mut C) -> Result<Binding, Error> {
        match self {
            Self::Ready(b) => Ok(b),
            Self::DiscoverUac3(p) => p.discover(io),
        }
    }
}
