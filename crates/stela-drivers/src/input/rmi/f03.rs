// SPDX-License-Identifier: GPL-2.0-only
//! Native RMI F03 single-device PS/2 passthrough register protocol.
//! Pinned source and retained copyrights are in input/THIRD_PARTY.md.
use super::{
    Error, Function,
    transport::{Transport, buffer},
};
use alloc::vec::Vec;
const RX_AVAILABLE: u8 = 1;
const RX_TIMEOUT: u8 = 1 << 6;
const RX_PARITY: u8 = 1 << 7;
const RX_OFFSET: u16 = 2;
const RECORD_BYTES: usize = 2;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub function: Function,
    pub queries: Vec<u8>,
    pub legacy: bool,
    pub receive_queue_length: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceivedByte {
    pub status: u8,
    pub data: u8,
}
impl ReceivedByte {
    pub fn available(self) -> bool {
        self.status & RX_AVAILABLE != 0
    }
    pub fn timeout(self) -> bool {
        self.status & RX_TIMEOUT != 0
    }
    pub fn parity_error(self) -> bool {
        self.status & RX_PARITY != 0
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub function: Function,
    /// Every actual output-buffer slot, including inactive and unknown status
    /// bits. Only available slots belong to the received PS/2 byte stream.
    pub slots: Vec<ReceivedByte>,
}
impl Frame {
    pub fn received(&self) -> impl Iterator<Item = ReceivedByte> + '_ {
        self.slots.iter().copied().filter(|slot| slot.available())
    }
}
pub(super) struct Engine {
    pub(super) capabilities: Capabilities,
    receive_address: u16,
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
        let device_count = query[0] & 7;
        let query_bytes = usize::from(device_count) * usize::from((query[0] >> 4) & 7);
        let legacy = query_bytes == 0;
        let mut queries = buffer(query_bytes + 1)?;
        queries[0] = query[0];
        let receive_queue_length = if legacy {
            7
        } else {
            let address = function.query.checked_add(1).ok_or(Error::AddressRange {
                address: function.query,
                length: query_bytes + 1,
            })?;
            transport.read(address, &mut queries[1..])?;
            if device_count != 1 {
                return Err(Error::UnsupportedPassthroughDevices(device_count));
            }
            queries[1] & 15
        };
        if receive_queue_length == 0 {
            return Err(Error::InvalidF03QueueLength);
        }
        let receive_address = function
            .data
            .checked_add(RX_OFFSET)
            .ok_or(Error::AddressRange {
                address: function.data,
                length: usize::from(RX_OFFSET) + 1,
            })?;
        let length = usize::from(receive_queue_length) * RECORD_BYTES;
        if length > transport.maximum_read(receive_address) {
            return Err(Error::AddressRange {
                address: receive_address,
                length,
            });
        }
        // Opening the port discards actual stale announcements before enabling
        // receive attention. A drain error cannot establish an open port.
        let mut stale = buffer(length)?;
        transport.read(receive_address, &mut stale)?;
        Ok(Self {
            capabilities: Capabilities {
                function,
                queries,
                legacy,
                receive_queue_length,
            },
            receive_address,
        })
    }
    pub(super) fn read<X: Transport>(&self, transport: &mut X) -> Result<Frame, Error> {
        let length = usize::from(self.capabilities.receive_queue_length);
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(length)
            .map_err(|_| Error::Allocation)?;
        let mut bytes = buffer(length * RECORD_BYTES)?;
        transport.read(self.receive_address, &mut bytes)?;
        for record in bytes.as_chunks::<RECORD_BYTES>().0 {
            slots.push(ReceivedByte {
                status: record[0],
                data: record[1],
            });
        }
        Ok(Frame {
            function: self.capabilities.function,
            slots,
        })
    }
    pub(super) fn write<X: Transport>(&self, transport: &mut X, byte: u8) -> Result<(), Error> {
        transport.write(self.capabilities.function.data, &[byte])
    }
}
