// SPDX-License-Identifier: GPL-2.0-only
//! F12 descriptor-qualified contact input. Raw object/tool values and the
//! complete actual packet remain available to the native input consumer.
use super::{
    Error, Function,
    descriptor::Descriptor,
    transport::{Transport, buffer},
};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contact {
    /// Index in the hardware's object array, not a manufactured tracking ID.
    pub object_index: u8,
    /// Exact F12 tool/object code, including inactive/unknown classifications.
    pub object_type: u8,
    pub x: u16,
    pub y: u16,
    pub pressure: u8,
    pub width_x: u8,
    pub width_y: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub function: Function,
    /// Every advertised object slot is present, including inactive slots.
    pub contacts: Vec<Contact>,
    /// Includes auxiliary Data5/6/9/15 and unknown described packet bytes.
    pub raw_packet: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub function: Function,
    pub general_information: u8,
    pub query: Descriptor,
    pub control: Descriptor,
    pub data: Descriptor,
    pub raw_tuning: Vec<u8>,
    pub maximum: Option<(u16, u16)>,
    pub dimensions_mm: (Option<u16>, Option<u16>),
    pub objects: usize,
}
pub(super) struct Engine {
    pub(super) capabilities: Capabilities,
    object_offset: usize,
    packet_size: usize,
}
fn register(base: u16, offset: usize) -> Result<u16, Error> {
    u16::try_from(usize::from(base) + offset).map_err(|_| Error::RegisterDescriptor)
}
impl Engine {
    pub(super) fn configure<X: Transport>(
        transport: &mut X,
        function: Function,
        dribble: Option<bool>,
    ) -> Result<Self, Error> {
        let mut information = [0];
        transport.read(function.query, &mut information)?;
        if information[0] & 1 == 0 {
            return Err(Error::RegisterDescriptor);
        }
        let query = Descriptor::read(transport, register(function.query, 1)?)?;
        let control = Descriptor::read(transport, register(function.query, 4)?)?;
        let data = Descriptor::read(transport, register(function.query, 7)?)?;
        let packet_size = data.packet_size()?;
        if packet_size == 0 || packet_size > 1024 * 1024 {
            return Err(Error::RegisterDescriptor);
        }
        if packet_size > transport.maximum_read(function.data) {
            return Err(Error::AddressRange {
                address: function.data,
                length: packet_size,
            });
        }
        let (objects, object_offset) = {
            let (objects, _) = data.register(1).ok_or(Error::MissingRegister(1))?;
            let count = objects.subpacket_count();
            if count == 0 || count > 255 || (objects.byte_length as usize) < count * 8 {
                return Err(Error::RegisterDescriptor);
            }
            (
                count,
                data.packet_offset(1)?.ok_or(Error::MissingRegister(1))?,
            )
        };
        if object_offset > 65535 {
            return Err(Error::RegisterDescriptor);
        }
        // Tuning control8 uses a packet-register selector (count), not the sum
        // of byte lengths of previous controls.
        let (tuning, tuning_offset) = control.register(8).ok_or(Error::MissingRegister(8))?;
        if tuning.byte_length > 15 {
            return Err(Error::RegisterDescriptor);
        }
        let mut raw_tuning = buffer(tuning.byte_length as usize)?;
        transport.read(register(function.control, tuning_offset)?, &mut raw_tuning)?;
        let mut offset = 0;
        let mut maximum = None;
        let mut pitch = (0u16, 0u16);
        let mut receivers = (0u8, 0u8);
        for subpacket in 0..5 {
            if !tuning.has_subpacket(subpacket) {
                continue;
            }
            let length = [4, 4, 4, 2, 1][usize::from(subpacket)];
            let bytes = raw_tuning
                .get(offset..offset + length)
                .ok_or(Error::RegisterDescriptor)?;
            match subpacket {
                0 => {
                    maximum = Some((
                        u16::from_le_bytes([bytes[0], bytes[1]]),
                        u16::from_le_bytes([bytes[2], bytes[3]]),
                    ))
                }
                1 => {
                    pitch = (
                        u16::from_le_bytes([bytes[0], bytes[1]]),
                        u16::from_le_bytes([bytes[2], bytes[3]]),
                    )
                }
                3 => receivers = (bytes[0], bytes[1]),
                _ => {}
            }
            offset += length;
        }
        let dimensions_mm = if let Some((_, selector)) = query.register(29) {
            let mut resolution = [0];
            transport.read(register(function.query, selector)?, &mut resolution)?;
            if resolution[0] == 0 {
                return Err(Error::InvalidConfiguration);
            }
            if let Some((x, y)) = maximum {
                (
                    Some(x / u16::from(resolution[0])),
                    Some(y / u16::from(resolution[0])),
                )
            } else {
                (None, None)
            }
        } else {
            let x = ((u32::from(pitch.0) * u32::from(receivers.0)) >> 12) as u16;
            let y = ((u32::from(pitch.1) * u32::from(receivers.1)) >> 12) as u16;
            ((x != 0).then_some(x), (y != 0).then_some(y))
        };
        if let Some(enabled) = dribble {
            if information[0] & 8 == 0 {
                return Err(Error::UnsupportedControl(20));
            }
            let (dribble, selector) = control.register(20).ok_or(Error::MissingRegister(20))?;
            let mut bytes = buffer((dribble.byte_length as usize).min(3))?;
            let index = usize::from(dribble.has_subpacket(0));
            if index >= bytes.len() {
                return Err(Error::RegisterDescriptor);
            }
            let address = register(function.control, selector)?;
            transport.read(address, &mut bytes)?;
            bytes[index] = if enabled {
                bytes[index] | 4
            } else {
                bytes[index] & !4
            };
            transport.write(address, &bytes)?;
        }
        Ok(Self {
            capabilities: Capabilities {
                function,
                general_information: information[0],
                query,
                control,
                data,
                raw_tuning,
                maximum,
                dimensions_mm,
                objects,
            },
            object_offset,
            packet_size,
        })
    }
    pub(super) fn read<X: Transport>(&self, transport: &mut X) -> Result<Frame, Error> {
        let mut raw_packet = buffer(self.packet_size)?;
        transport.read(self.capabilities.function.data, &mut raw_packet)?;
        let mut contacts = Vec::new();
        contacts
            .try_reserve_exact(self.capabilities.objects)
            .map_err(|_| Error::Allocation)?;
        for index in 0..self.capabilities.objects {
            let offset = self.object_offset + index * 8;
            let bytes = raw_packet
                .get(offset..offset + 8)
                .ok_or(Error::RegisterDescriptor)?;
            contacts.push(Contact {
                object_index: index as u8,
                object_type: bytes[0],
                x: u16::from_le_bytes([bytes[1], bytes[2]]),
                y: u16::from_le_bytes([bytes[3], bytes[4]]),
                pressure: bytes[5],
                width_x: bytes[6],
                width_y: bytes[7],
            });
        }
        Ok(Frame {
            function: self.capabilities.function,
            contacts,
            raw_packet,
        })
    }
}
