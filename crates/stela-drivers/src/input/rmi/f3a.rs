// SPDX-License-Identifier: GPL-2.0-only
//! Native RMI F3A GPIO existence, direction and active-low input bitmaps.
//! Pinned source and retained copyright are in input/THIRD_PARTY.md.
use super::{
    Error, Function,
    transport::{Transport, buffer},
};
use alloc::vec::Vec;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub function: Function,
    pub query: u8,
    pub gpio_count: u8,
    pub exists: Vec<u8>,
    pub directions: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Button {
    pub gpio_index: u8,
    pub pressed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub function: Function,
    /// Complete actual data bitmap, including outputs and unused high bits.
    pub levels: Vec<u8>,
    pub buttons: Vec<Button>,
}
pub(super) struct Engine {
    pub(super) capabilities: Capabilities,
}
impl Engine {
    pub(super) fn configure<X: Transport>(
        transport: &mut X,
        function: Function,
    ) -> Result<Self, Error> {
        if function.interrupt_count == 0 {
            return Err(Error::InterruptLimit);
        }
        let mut query = [0];
        transport.read(function.query, &mut query)?;
        let count = query[0] & 0x7f;
        if count == 0 {
            return Err(Error::InvalidGpioCount(count));
        }
        let length = usize::from(count).div_ceil(8);
        let mut exists = buffer(length)?;
        let mut directions = buffer(length)?;
        transport.read(register1(function.query, length)?, &mut exists)?;
        transport.read(register1(function.control, length)?, &mut directions)?;
        Ok(Self {
            capabilities: Capabilities {
                function,
                query: query[0],
                gpio_count: count,
                exists,
                directions,
            },
        })
    }
    pub(super) fn read<X: Transport>(&self, transport: &mut X) -> Result<Frame, Error> {
        let c = &self.capabilities;
        let mut buttons = Vec::new();
        buttons
            .try_reserve_exact(usize::from(c.gpio_count))
            .map_err(|_| Error::Allocation)?;
        let mut levels = buffer(c.exists.len())?;
        transport.read(c.function.data, &mut levels)?;
        for index in 0..c.gpio_count {
            let byte = usize::from(index / 8);
            let bit = 1 << (index % 8);
            if c.exists[byte] & bit != 0 && c.directions[byte] & bit == 0 {
                buttons.push(Button {
                    gpio_index: index,
                    pressed: levels[byte] & bit == 0,
                });
            }
        }
        Ok(Frame {
            function: c.function,
            levels,
            buttons,
        })
    }
}
fn register1(base: u16, length: usize) -> Result<u16, Error> {
    base.checked_add(1).ok_or(Error::AddressRange {
        address: base,
        length: length + 1,
    })
}
