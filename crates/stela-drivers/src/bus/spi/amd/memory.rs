// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2020, Advanced Micro Devices, Inc.
// Source author: Sanjay R Mehta <sanju.mehta@amd.com>
// SPI memory policy references: Copyright 2018 Exceet Electronics GmbH and
// Bootlin; author Boris Brezillon. See ../../THIRD_PARTY.md.
//! AMD V1/V2 index-mode memory operations, using the original controller owner.
//!
//! Address bytes are sent most significant first; read dummy bytes are 0xff.
//! The source index path programs no separate lane register; this API admits
//! the single/dual/quad read formats named by its recognized opcodes.
//! This interface cannot program arbitrary phased bus widths, DTR or HID2 DMA.
//! Every operation fits the original 70-byte FIFO and at most 64 data bytes.
//! Callers can query the payload limit and explicitly divide a memory request;
//! the controller never silently truncates, splits or replays an operation.
use super::*;

const ADDRESS32: usize = 0x50;
// The opcode register is separate from this indexed FIFO window. Ordinary
// command()'s MAX_MESSAGE additionally accounts for its opcode byte.
const FIFO_BYTES: usize = 70;
const DATA_LIMIT: usize = 64;

/// Maximum connected/owned lanes for this peripheral, including its pin mux.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lanes {
    Single = 1,
    Dual = 2,
    Quad = 4,
}

/// These describe the actual peripheral and board pins retained by Registers.
/// Values describe that ownership; constructing this value grants no pins.
#[derive(Clone, Copy, Debug)]
pub struct MemoryDevice {
    pub device: Device,
    pub transmit: Lanes,
    pub receive: Lanes,
}

pub enum Data<'a> {
    None,
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}
impl Data<'_> {
    fn len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Read(bytes) => bytes.len(),
            Self::Write(bytes) => bytes.len(),
        }
    }
}

/// One opcode, optional big-endian address/dummy phase and half-duplex payload.
pub struct Operation<'a> {
    pub opcode: u8,
    pub address: u64,
    pub address_bytes: u8,
    pub dummy_bytes: u8,
    /// Zero uses the actual device limit; a nonzero value is capped to it.
    pub max_hz: u32,
    pub data: Data<'a>,
}
impl Operation<'_> {
    /// Safe index-mode payload capacity, including the actual FIFO header.
    /// Returns zero when the header itself does not fit. This does not change
    /// the supplied operation or infer permission to split a device command.
    pub fn maximum_data_len(&self) -> usize {
        FIFO_BYTES
            .saturating_sub(usize::from(self.address_bytes) + usize::from(self.dummy_bytes))
            .min(DATA_LIMIT)
    }
}

// The named read command families in spi-amd.c define their hardware phases.
// Unknown commands retain ordinary single-line behavior; writes are single-line.
fn protocol(opcode: u8) -> (Lanes, Lanes, bool) {
    match opcode {
        0x3b => (Lanes::Single, Lanes::Dual, false),
        0xbb => (Lanes::Dual, Lanes::Dual, false),
        0x6b => (Lanes::Single, Lanes::Quad, false),
        0xeb => (Lanes::Quad, Lanes::Quad, false),
        0x0c => (Lanes::Single, Lanes::Single, true),
        0x3c => (Lanes::Single, Lanes::Dual, true),
        0xbc => (Lanes::Dual, Lanes::Dual, true),
        0x6c => (Lanes::Single, Lanes::Quad, true),
        0xec => (Lanes::Quad, Lanes::Quad, true),
        _ => (Lanes::Single, Lanes::Single, false),
    }
}

impl<R: Registers, T: Timer> Controller<R, T> {
    /// Execute one serialized memory operation. The returned rate is the
    /// configured source-table frequency, not a physical measurement. Reads
    /// are published only after completion, selector and address-mode cleanup.
    /// Unsupported requests have no hardware effects and preserve the owner.
    pub fn memory(
        &mut self,
        device: MemoryDevice,
        operation: &mut Operation<'_>,
    ) -> Result<u32, Error> {
        if self.failed.is_some() {
            return Err(self.error(ErrorKind::NeedsReset));
        }
        self.offset = None;
        self.triggered = false;
        self.last_status = None;
        if device.device.mode != Mode::Mode0 {
            return Err(self.error(ErrorKind::UnsupportedMode));
        }
        let max_hz = if operation.max_hz == 0 {
            device.device.max_hz
        } else {
            operation.max_hz.min(device.device.max_hz)
        };
        let frequency = FREQUENCIES
            .iter()
            .copied()
            .find(|entry| entry.0 <= max_hz)
            .ok_or_else(|| self.error(ErrorKind::Configuration))?;
        let (address_lanes, data_lanes, address32) = protocol(operation.opcode);
        let read = matches!(operation.data, Data::Read(_));
        if device.device.chip_select > 3
            || operation.address_bytes > 8
            || (operation.address_bytes < 8
                && operation.address >> (8 * u32::from(operation.address_bytes)) != 0)
            || ((operation.address_bytes != 0 || operation.dummy_bytes != 0)
                && device.transmit < address_lanes)
            || (read && device.receive < data_lanes)
            || (!read && data_lanes != Lanes::Single && operation.data.len() != 0)
            || (!read && operation.dummy_bytes != 0)
        {
            return Err(self.error(ErrorKind::Configuration));
        }
        let bytes = operation.data.len();
        if bytes > operation.maximum_data_len()
            || usize::from(operation.address_bytes) + usize::from(operation.dummy_bytes)
                > FIFO_BYTES
            || (bytes == 0 && !matches!(operation.data, Data::None))
        {
            return Err(self.error(ErrorKind::Length));
        }
        let mut transmit = [0u8; FIFO_BYTES];
        let address = usize::from(operation.address_bytes);
        for (index, byte) in transmit[..address].iter_mut().enumerate() {
            *byte = (operation.address >> (8 * (address - index - 1))) as u8;
        }
        let header = address + usize::from(operation.dummy_bytes);
        transmit[address..header].fill(0xff);
        let tx = if let Data::Write(data) = &operation.data {
            transmit[header..header + data.len()].copy_from_slice(data);
            header + data.len()
        } else {
            header
        };
        let mut received = [0u8; DATA_LIMIT];
        self.started = self.owners.as_ref().unwrap().1.start();
        let result = (|| {
            self.wait_idle()?;
            let saved = if self.owners.as_ref().unwrap().0.profile() == Profile::V2 {
                let previous = self.read32(ADDRESS32)? & 1;
                self.replace32(ADDRESS32, 1, u32::from(address32))?;
                Some(previous)
            } else {
                None
            };
            self.execute(
                device.device,
                frequency,
                operation.opcode,
                &transmit[..tx],
                if read {
                    &mut received[..bytes]
                } else {
                    &mut []
                },
            )?;
            // Ordinary commands share this same controller. Preserve its
            // original address-mode epoch rather than leaving a memory flag.
            if let Some(saved) = saved {
                self.replace32(ADDRESS32, 1, saved)?;
            }
            self.deadline()
        })();
        if let Err(error) = result {
            self.failed = Some(error);
            return Err(error);
        }
        if let Data::Read(output) = &mut operation.data {
            output.copy_from_slice(&received[..bytes]);
        }
        Ok(frequency.0)
    }
}

#[cfg(test)]
mod tests;
