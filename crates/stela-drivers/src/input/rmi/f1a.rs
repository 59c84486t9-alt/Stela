// SPDX-License-Identifier: GPL-2.0-only
//! Native F1A one-byte active-high button records.
//! Pinned source and kept copyright are in input/THIRD_PARTY.md.
use super::{Error, Function, transport::Transport};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub function: Function,
    /// Number of buttons independently supplied by the firmware/platform owner.
    /// The pinned F1A protocol does not discover this count from the device.
    pub buttons: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub capabilities: Capabilities,
    /// Complete data byte, including bits outside the declared buttons.
    pub raw: u8,
}
impl Frame {
    /// Hardware button index and its active-high pressed state. Logical key
    /// mappings and contact/trackstick associations belong to the shared frontend.
    pub fn buttons(&self) -> impl Iterator<Item = (u8, bool)> + '_ {
        (0..self.capabilities.buttons).map(|index| (index, self.raw & (1 << index) != 0))
    }
}
pub(super) struct Engine {
    pub(super) capabilities: Capabilities,
}
impl Engine {
    pub(super) fn configure(function: Function, buttons: u8) -> Result<Self, Error> {
        if !(1..=8).contains(&buttons) {
            return Err(Error::InvalidButtonCount(buttons));
        }
        if function.interrupt_count == 0 {
            return Err(Error::InterruptLimit);
        }
        Ok(Self {
            capabilities: Capabilities { function, buttons },
        })
    }
    pub(super) fn read<X: Transport>(&self, transport: &mut X) -> Result<Frame, Error> {
        let mut data = [0];
        transport.read(self.capabilities.function.data, &mut data)?;
        Ok(Frame {
            capabilities: self.capabilities,
            raw: data[0],
        })
    }
}
