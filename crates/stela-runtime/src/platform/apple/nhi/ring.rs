//! NHI's sixteen-byte DMA descriptor and programmed ring state.
use super::{Frame, Options};
use alloc::vec::Vec;
use {stela_contracts::dma::DmaError, stela_contracts::dma::Port};

pub(super) const POSTED: u32 = 1 << 22;
pub(super) const COMPLETED: u32 = 1 << 21;
pub(super) const INTERRUPT: u32 = 1 << 23;
const ISOCH_OR_CRC: u32 = 1 << 20;
const MAX_FRAME: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Transmit,
    Receive,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Descriptor {
    pub address: u64,
    pub metadata: u32,
    pub time: u32,
}
impl Descriptor {
    pub fn read(port: &mut Port<'_, '_>, address: u64) -> Result<Self, DmaError> {
        let mut bytes = [0; 16];
        port.read(address, &mut bytes)?;
        Ok(Self {
            address: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            metadata: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            time: u32::from_le_bytes(bytes[12..].try_into().unwrap()),
        })
    }
    pub fn validate(self, direction: Direction) -> Result<(), &'static str> {
        let fields = match direction {
            Direction::Transmit => 0x000f_ffff | ISOCH_OR_CRC,
            Direction::Receive => 0,
        };
        if self.metadata & POSTED == 0 || self.metadata & COMPLETED != 0 {
            return Err("NHI descriptor is not owned by the device");
        }
        if self.metadata & !(fields | POSTED | INTERRUPT) != 0 {
            return Err("NHI posted descriptor field without a model");
        }
        Ok(())
    }
    pub fn length(self) -> usize {
        let bytes = (self.metadata & 0xfff) as usize;
        if bytes == 0 { MAX_FRAME } else { bytes }
    }
    pub fn sof(self) -> u8 {
        ((self.metadata >> 16) & 15) as u8
    }
    pub fn eof(self) -> u8 {
        ((self.metadata >> 12) & 15) as u8
    }
    pub fn isochronous(self) -> bool {
        self.metadata & ISOCH_OR_CRC != 0
    }
    pub fn tx_completion(self) -> u32 {
        (self.metadata & !POSTED) | COMPLETED
    }
    pub fn rx_completion(self, frame: &Frame, length: usize) -> u32 {
        self.metadata & INTERRUPT
            | COMPLETED
            | (u32::from(frame.crc_error) * ISOCH_OR_CRC)
            | (u32::from(length < frame.bytes.len()) * POSTED)
            | u32::from(frame.sof) << 16
            | u32::from(frame.eof) << 12
            | (length as u32 & 0xfff)
    }
}

/// An accepted frame must not be replayed if its completion DMA faults.
pub(super) struct Transfer {
    pub descriptor: u64,
    pub metadata: u32,
    pub timestamp: u32,
    pub payload: Option<(u64, Vec<u8>)>,
    pub payload_written: bool,
}
impl Transfer {
    pub fn publish(&mut self, port: &mut Port<'_, '_>) -> Result<(), DmaError> {
        if !self.payload_written {
            if let Some((address, bytes)) = &self.payload {
                port.write(*address, bytes)?;
            }
            self.payload_written = true;
        }
        // The ownership/completion word is last. Partial DMA never advertises
        // a completed packet whose payload or timestamp is still unavailable.
        port.write(self.descriptor + 12, &self.timestamp.to_le_bytes())?;
        port.write(self.descriptor + 8, &self.metadata.to_le_bytes())
    }
}

pub(super) struct Ring {
    pub base: u64,
    pub count: u16,
    pub posted: u16,
    pub consumed: u16,
    pub capacity: u16,
    pub flags: u32,
    pub parameter: u32,
    pub pdf: u32,
    pub active: Option<Options>,
    pub transfer: Option<Transfer>,
    pub incoming: alloc::collections::VecDeque<Frame>,
}
impl Ring {
    pub fn new() -> Self {
        Self {
            base: 0,
            count: 0,
            posted: 0,
            consumed: 0,
            capacity: 0,
            flags: 0,
            parameter: 0,
            pdf: 0,
            active: None,
            transfer: None,
            incoming: alloc::collections::VecDeque::new(),
        }
    }
    pub fn has_posted(&self) -> bool {
        self.active.is_some() && self.posted != self.consumed
    }
    pub fn address(&self) -> u64 {
        self.base + u64::from(self.consumed) * 16
    }
    pub fn advance(&mut self) {
        self.consumed = (self.consumed + 1) % self.count;
    }
    pub fn validate_configuration(&self) -> Result<(), &'static str> {
        if self.base & 15 != 0 || self.count < 2 {
            return Err("NHI ring needs aligned descriptors and at least two slots");
        }
        if self.base.checked_add(u64::from(self.count) * 16).is_none() {
            return Err("NHI descriptor ring overflows the I/O address space");
        }
        if self.posted >= self.count || self.consumed >= self.count {
            return Err("NHI descriptor index is outside the ring");
        }
        if self.capacity > MAX_FRAME as u16 {
            return Err("NHI receive buffer exceeds the maximum frame size");
        }
        Ok(())
    }
    pub fn capacity(&self) -> usize {
        if self.capacity == 0 {
            MAX_FRAME
        } else {
            usize::from(self.capacity)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direction_and_ownership_change_the_same_wire_bits() {
        let descriptor = Descriptor {
            address: 0x1000,
            metadata: POSTED | INTERRUPT | 0x100000 | 0x7a000 | 3,
            time: 9,
        };
        assert!(descriptor.validate(Direction::Transmit).is_ok());
        assert!(descriptor.validate(Direction::Receive).is_err());
        assert_eq!(
            (descriptor.length(), descriptor.sof(), descriptor.eof()),
            (3, 7, 10)
        );
        assert!(descriptor.isochronous());
        assert_eq!(descriptor.tx_completion(), 0xb7a003);
        let posted = Descriptor {
            metadata: POSTED | INTERRUPT,
            ..descriptor
        };
        assert!(posted.validate(Direction::Receive).is_ok());
        let frame = Frame::new(0, alloc::vec![1, 2, 3], 7, 10, 42, true).unwrap();
        assert_eq!(posted.rx_completion(&frame, 2), 0xf7a002);
        assert_eq!(posted.rx_completion(&frame, 3), 0xb7a003);
        assert_eq!(posted.length(), 4096);
        assert!(
            Descriptor {
                metadata: COMPLETED | POSTED,
                ..posted
            }
            .validate(Direction::Transmit)
            .is_err()
        );
    }
}
