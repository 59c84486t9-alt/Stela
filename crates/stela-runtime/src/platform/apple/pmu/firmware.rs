//! Source-bounded AP firmware-SRAM transport, separate from PMIC execution.
//!
//! J314s26A434 LLB file15940..15c1c uploads through C830/C831/C833 in
//! sixteen-byte logical windows. Its 16138 helper splits these into consecutive
//! eight-byte SPMI commands. mac13j `_readMem`/`_writeMem` (VA9d592f8..597b8)
//! use the same low/high address and repeated data-window sequence for reads
//! and writes. This owner implements those sequences over kept
//! bytes. It supplies no PMIC reset, execution, ID, status or Ready value.
use crate::Result;
use alloc::vec::Vec;
use core::ops::Range;
use stela_contracts::refuse;

const COMMAND_BYTES: usize = 8;

use stela_soc_data::pmu::FirmwareSram;
#[cfg(test)]
use stela_soc_data::pmu::FirmwareStartup;
use stela_soc_data::pmu::firmware::{FirmwareHistory, WINDOW_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy)]
enum Stream {
    Unaddressed,
    Low(u8),
    Window {
        cursor: usize,
        direction: Option<Direction>,
        tail: bool,
    },
    /// A source's short final window has completed. Its continuation/wrap is
    /// not specified by the AP consumer; require an explicit new address pair.
    Ended,
}

/// Private prepared effect. Never exposed as an external completion receipt.
pub(super) struct Transfer {
    pub(super) range: Range<usize>,
    next: Stream,
}

pub(super) struct FirmwareMemory {
    pub ports: FirmwareSram,
    bytes: Vec<u8>,
    stream: Stream,
}
impl From<FirmwareHistory> for FirmwareMemory {
    fn from(history: FirmwareHistory) -> Self {
        let (ports, initial) = history.into_parts();
        Self {
            ports,
            bytes: initial,
            stream: Stream::Unaddressed,
        }
    }
}
impl FirmwareMemory {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn forget_address(&mut self) {
        self.stream = Stream::Unaddressed;
    }

    pub fn claims(&self, address: u16, bytes: usize) -> bool {
        let end = u64::from(address).saturating_add(bytes.max(1) as u64);
        self.ports.windows().iter().any(|w| {
            u64::from(address) < u64::from(w.base) + u64::from(w.bytes) && u64::from(w.base) < end
        })
    }

    pub fn check_address(&self, address: u16, data: &[u8]) -> Result<Option<u8>> {
        if address != self.ports.address_low && address != self.ports.address_high {
            return Ok(None);
        }
        if data.len() != 1 {
            return Err(refuse!(
                "PMU firmware address ports require separate one-byte writes"
            ));
        }
        if address == self.ports.address_high {
            let Stream::Low(low) = self.stream else {
                return Err(refuse!(
                    "PMU firmware high address requires a fresh low address"
                ));
            };
            let cursor = usize::from(u16::from_le_bytes([low, data[0]]));
            if cursor >= self.bytes.len() {
                return Err(refuse!("PMU firmware address is outside retained SRAM"));
            }
        }
        Ok(Some(data[0]))
    }

    /// The complete logical window, or its exact eight-byte prefix/tail. A
    /// failed command keeps previous commands. A repeated partial prefix or
    /// a direction change without a new address pair refuses before effects.
    /// No lost-response retry semantics are inferred for completed windows.
    pub fn prepare(&self, address: u16, bytes: usize, direction: Direction) -> Result<Transfer> {
        let Stream::Window {
            cursor,
            direction: previous,
            tail,
        } = self.stream
        else {
            return Err(refuse!(
                "PMU firmware data requires a complete explicit address pair"
            ));
        };
        if previous.is_some_and(|previous| previous != direction) {
            return Err(refuse!(
                "PMU firmware data direction requires a new address pair"
            ));
        }
        let (offset, limit) = match tail {
            false if address == self.ports.data => (0, usize::from(WINDOW_BYTES)),
            true if address == self.ports.data + COMMAND_BYTES as u16 => {
                (COMMAND_BYTES, COMMAND_BYTES)
            }
            _ => return Err(refuse!("PMU firmware data command is out of order")),
        };
        if bytes == 0 || bytes > limit {
            return Err(refuse!(
                "PMU firmware data exceeds the qualified logical window"
            ));
        }
        let start = cursor + offset;
        let end = start + bytes;
        if end > self.bytes.len() {
            return Err(refuse!("PMU firmware transfer exceeds retained SRAM"));
        }
        let next = if offset == 0 && bytes == COMMAND_BYTES {
            Stream::Window {
                cursor,
                direction: Some(direction),
                tail: true,
            }
        } else if offset + bytes == usize::from(WINDOW_BYTES) {
            Stream::Window {
                cursor: end,
                direction: Some(direction),
                tail: false,
            }
        } else {
            Stream::Ended
        };
        Ok(Transfer {
            range: start..end,
            next,
        })
    }
    pub fn address(&mut self, address: u16, byte: u8) {
        self.stream = if address == self.ports.address_low {
            Stream::Low(byte)
        } else {
            let Stream::Low(low) = self.stream else {
                unreachable!("address preflight")
            };
            Stream::Window {
                cursor: usize::from(u16::from_le_bytes([low, byte])),
                direction: None,
                tail: false,
            }
        };
    }
    pub fn read(&mut self, transfer: Transfer, data: &mut [u8]) {
        data.copy_from_slice(&self.bytes[transfer.range]);
        self.stream = transfer.next;
    }
    pub fn write(&mut self, transfer: Transfer, data: &[u8]) {
        self.bytes[transfer.range].copy_from_slice(data);
        self.stream = transfer.next;
    }
}

#[cfg(test)]
mod tests;
