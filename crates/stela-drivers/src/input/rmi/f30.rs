// SPDX-License-Identifier: GPL-2.0-only
//! Native RMI F30 GPIO button controls and active-low data records.
//! Pinned source and kept copyright are in input/THIRD_PARTY.md.
use super::{
    Error, Function,
    transport::{Transport, buffer},
};
use alloc::vec::Vec;
const HAS_GPIO: u8 = 1 << 3;
const HAS_LED: u8 = 1 << 2;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    pub number: u8,
    pub address: u16,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub function: Function,
    pub query: [u8; 2],
    pub gpio_count: u8,
    pub controls: Vec<Control>,
    /// Hardware pins whose direction is input and whose button-data bit is set.
    pub input_buttons: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Button {
    pub gpio_index: u8,
    pub pressed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub function: Function,
    /// Complete data registers, including outputs and unused high bits.
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
        let mut query = [0; 2];
        transport.read(function.query, &mut query)?;
        let flags = query[0];
        let count = query[1] & 31;
        if flags & HAS_GPIO == 0 {
            return Err(Error::UnsupportedFormat {
                function: 0x30,
                format: flags,
            });
        }
        if count == 0 {
            return Err(Error::InvalidGpioCount(count));
        }
        let bytes = usize::from(count).div_ceil(8);
        let sizes = [
            if flags & HAS_LED != 0 { bytes } else { 0 },
            1,
            bytes,
            bytes,
            if flags & HAS_LED != 0 { bytes } else { 0 },
            if flags & HAS_LED != 0 {
                if flags & 1 != 0 { 6 } else { 2 }
            } else {
                0
            },
            if flags & (HAS_LED | 32) != 0 {
                usize::from(count)
            } else {
                0
            },
            if flags & 2 != 0 {
                usize::from(count)
            } else {
                0
            },
            if flags & 16 != 0 { bytes } else { 0 },
            usize::from(flags & 16 != 0),
            usize::from(flags & 64 != 0),
        ];
        let length = sizes.iter().sum();
        let mut raw = buffer(length)?;
        transport.read(function.control, &mut raw)?;
        let mut controls = Vec::new();
        controls
            .try_reserve_exact(11)
            .map_err(|_| Error::Allocation)?;
        let mut offset = 0;
        for (number, size) in sizes.into_iter().enumerate() {
            if size == 0 {
                continue;
            }
            let address = register(function.control, offset)?;
            let mut bytes = buffer(size)?;
            bytes.copy_from_slice(&raw[offset..offset + size]);
            controls.push(Control {
                number: number as u8,
                address,
                bytes,
            });
            offset += size;
        }
        let direction = controls
            .iter()
            .find(|control| control.number == 2)
            .ok_or(Error::MissingRegister(2))?;
        let data = controls
            .iter()
            .find(|control| control.number == 3)
            .ok_or(Error::MissingRegister(3))?;
        let mut input_buttons = 0;
        for index in 0..count {
            let byte = usize::from(index / 8);
            let bit = 1 << (index % 8);
            if direction.bytes[byte] & bit == 0 && data.bytes[byte] & bit != 0 {
                input_buttons |= 1 << index;
            }
        }
        // Reapply the complete hardware control image as the donor does.
        // No LED, haptic, output-direction or pin remapping policy is invented.
        transport.write(function.control, &raw)?;
        let mut actual = buffer(length)?;
        transport.read(function.control, &mut actual)?;
        if actual != raw {
            return Err(Error::ConfigurationRejected);
        }
        Ok(Self {
            capabilities: Capabilities {
                function,
                query,
                gpio_count: count,
                controls,
                input_buttons,
            },
        })
    }
    pub(super) fn read<X: Transport>(&self, transport: &mut X) -> Result<Frame, Error> {
        let capabilities = &self.capabilities;
        let mut buttons = Vec::new();
        buttons
            .try_reserve_exact(capabilities.input_buttons.count_ones() as usize)
            .map_err(|_| Error::Allocation)?;
        let mut levels = buffer(usize::from(capabilities.gpio_count).div_ceil(8))?;
        transport.read(capabilities.function.data, &mut levels)?;
        for index in 0..capabilities.gpio_count {
            if capabilities.input_buttons & (1 << index) != 0 {
                buttons.push(Button {
                    gpio_index: index,
                    pressed: levels[usize::from(index / 8)] & (1 << (index % 8)) == 0,
                });
            }
        }
        Ok(Frame {
            function: capabilities.function,
            levels,
            buttons,
        })
    }
}
fn register(base: u16, offset: usize) -> Result<u16, Error> {
    u16::try_from(usize::from(base) + offset).map_err(|_| Error::AddressRange {
        address: base,
        length: offset + 1,
    })
}
