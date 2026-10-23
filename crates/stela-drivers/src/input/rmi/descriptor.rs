// SPDX-License-Identifier: GPL-2.0-only
//! RMI packet-register descriptors, following rmi_driver.c. Packet-register
//! selectors count registers; byte offsets in attention reports sum their sizes.
use super::{
    Error,
    transport::{Transport, buffer},
};
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Register {
    pub number: u16,
    pub byte_length: u32,
    subpackets: [u8; 37],
}
impl Register {
    pub fn has_subpacket(&self, index: u16) -> bool {
        index < 296 && self.subpackets[usize::from(index / 8)] & (1 << (index % 8)) != 0
    }
    pub fn subpacket_count(&self) -> usize {
        self.subpackets
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub registers: Vec<Register>,
}
impl Descriptor {
    pub fn register(&self, number: u16) -> Option<(&Register, usize)> {
        self.registers
            .iter()
            .enumerate()
            .find(|(_, register)| register.number == number)
            .map(|(offset, register)| (register, offset))
    }
    pub fn packet_size(&self) -> Result<usize, Error> {
        self.registers.iter().try_fold(0usize, |total, register| {
            total
                .checked_add(register.byte_length as usize)
                .ok_or(Error::RegisterDescriptor)
        })
    }
    pub fn packet_offset(&self, number: u16) -> Result<Option<usize>, Error> {
        let mut offset = 0usize;
        for register in &self.registers {
            if register.number == number {
                return Ok(Some(offset));
            }
            offset = offset
                .checked_add(register.byte_length as usize)
                .ok_or(Error::RegisterDescriptor)?;
        }
        Ok(None)
    }
    pub(super) fn read<X: Transport>(transport: &mut X, address: u16) -> Result<Self, Error> {
        let mut length = [0];
        transport.read(address, &mut length)?;
        if !(1..=35).contains(&length[0]) {
            return Err(Error::RegisterDescriptor);
        }
        let presence_address = address.checked_add(1).ok_or(Error::RegisterDescriptor)?;
        let structure_address = address.checked_add(2).ok_or(Error::RegisterDescriptor)?;
        let mut presence = buffer(usize::from(length[0]))?;
        transport.read(presence_address, &mut presence)?;
        let (structure_length, map_start) = if presence[0] == 0 {
            if presence.len() < 3 {
                return Err(Error::RegisterDescriptor);
            }
            (
                usize::from(u16::from_le_bytes([presence[1], presence[2]])),
                3,
            )
        } else {
            (usize::from(presence[0]), 1)
        };
        if structure_length == 0 {
            return Err(Error::RegisterDescriptor);
        }
        let mut structure = buffer(structure_length)?;
        transport.read(structure_address, &mut structure)?;
        Self::parse(&presence[map_start..], &structure)
    }
    fn parse(presence: &[u8], structure: &[u8]) -> Result<Self, Error> {
        let mut registers = Vec::new();
        let mut offset = 0;
        for (byte_index, byte) in presence.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) == 0 {
                    continue;
                }
                let number = byte_index * 8 + bit;
                if number >= 256 {
                    return Err(Error::RegisterDescriptor);
                }
                let mut size = u32::from(*structure.get(offset).ok_or(Error::RegisterDescriptor)?);
                offset += 1;
                if size == 0 {
                    let bytes = structure
                        .get(offset..offset + 2)
                        .ok_or(Error::RegisterDescriptor)?;
                    size = u32::from(u16::from_le_bytes([bytes[0], bytes[1]]));
                    offset += 2;
                }
                if size == 0 {
                    let bytes = structure
                        .get(offset..offset + 4)
                        .ok_or(Error::RegisterDescriptor)?;
                    size = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    offset += 4;
                }
                let mut subpackets = [0u8; 37];
                let mut subpacket = 0;
                loop {
                    let map = *structure.get(offset).ok_or(Error::RegisterDescriptor)?;
                    offset += 1;
                    for bit in 0..7 {
                        if map & (1 << bit) != 0 {
                            if subpacket >= 296 {
                                return Err(Error::RegisterDescriptor);
                            }
                            subpackets[subpacket / 8] |= 1 << (subpacket % 8);
                        }
                        subpacket += 1;
                    }
                    if map & 0x80 == 0 {
                        break;
                    }
                }
                // Linux ignores explicit zero-size entries. Their selectors do
                // not appear in its retained register list; preserve that rule.
                if size != 0 {
                    registers.try_reserve(1).map_err(|_| Error::Allocation)?;
                    registers.push(Register {
                        number: number as u16,
                        byte_length: size,
                        subpackets,
                    });
                }
            }
        }
        Ok(Self { registers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_selectors_count_registers_while_report_offsets_count_bytes() {
        let descriptor = Descriptor::parse(&[0b10, 1], &[16, 3, 0, 0x34, 0x12, 1]).unwrap();
        let (second, selector) = descriptor.register(8).unwrap();
        assert_eq!(selector, 1);
        assert_eq!(second.byte_length, 0x1234);
        assert_eq!(descriptor.packet_offset(8).unwrap(), Some(16));
        assert_eq!(descriptor.packet_size().unwrap(), 16 + 0x1234);
        assert_eq!(descriptor.register(1).unwrap().0.subpacket_count(), 2);
    }
    #[test]
    fn extended_sizes_and_zero_sized_entries_preserve_source_selector_rules() {
        let descriptor = Descriptor::parse(&[1], &[0, 0, 0, 0, 0, 1, 0, 1]).unwrap();
        assert_eq!(descriptor.register(0).unwrap().0.byte_length, 65536);
        assert_eq!(descriptor.packet_size().unwrap(), 65536);
        let descriptor = Descriptor::parse(&[3], &[0, 0, 0, 0, 0, 0, 0, 0, 8, 1]).unwrap();
        assert!(descriptor.register(0).is_none());
        assert_eq!(descriptor.register(1).unwrap().1, 0);
    }
    #[test]
    fn truncated_sizes_maps_and_set_bits_beyond_caps_are_rejected() {
        for bytes in [
            &[][..],
            &[0][..],
            &[0, 0][..],
            &[0, 0, 0, 0][..],
            &[1][..],
            &[1, 0x80][..],
        ] {
            assert_eq!(
                Descriptor::parse(&[1], bytes),
                Err(Error::RegisterDescriptor)
            );
        }
        let mut presence = [0; 33];
        presence[32] = 1;
        assert_eq!(
            Descriptor::parse(&presence, &[1, 0]),
            Err(Error::RegisterDescriptor)
        );
        let mut map = alloc::vec![1];
        map.extend_from_slice(&[0x80; 42]);
        map.push(0x10);
        assert_eq!(
            Descriptor::parse(&[1], &map),
            Err(Error::RegisterDescriptor)
        );
    }
}
