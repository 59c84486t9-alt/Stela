//! Ordered SIO firmware setup effects, without a synthetic setup ACK.
//!
//! Selected 26A434 firmware VA0x6898 consumes 24-byte tunable rows:
//! {u32 offset,u32 width,u64 mask,u64 value}. Width0 skips a row;
//! width4/8 perform a read, compare masked bits, then write only if changed.
//! Reads and writes are physical MMIO, distinct from DMA of the table.
//! The machine must route them through its normal checked device path.
pub mod control;

use super::Error;
use alloc::vec::Vec;
use stela_contracts::refuse;
use {stela_contracts::bus::Width, stela_contracts::dma::Port};

const ROW_BYTES: usize = 24;
/// Native resource bound, not a hardware table-length claim. Larger tables
/// remain an explicit requirement rather than causing unchecked allocation.
const MAX_TABLE_BYTES: u32 = 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct Row {
    address: u64,
    width: Width,
    mask: u64,
    value: u64,
}

/// One physical device access to perform outside the firmware borrow.
/// A mapped range does not check its hardware: the routed bank must
/// accept this access and its normal PMGR preflight/settle still applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Read {
        address: u64,
        width: Width,
    },
    Write {
        address: u64,
        width: Width,
        value: u64,
    },
}

/// One claimed operation. The private sequence prevents a stale completion
/// from retiring an identical later read/write in the same setup program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effect {
    sequence: u64,
    request: Request,
}
impl Effect {
    pub fn request(self) -> Request {
        self.request
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectResult {
    Read(u64),
    Written,
}

/// Routed access failures keep their original type and detail. Platform
/// code neither depends on the machine's error type nor replaces its reason.
#[derive(Debug, PartialEq, Eq)]
pub enum FinishError<E> {
    Ownership(&'static str),
    Access(E),
}

/// An acquired immutable tunable table and its partially committed effects.
/// Loading snapshots and validates all rows before the first MMIO access.
/// Completion only means these setup effects committed; it grants no SIO
/// protocol version, functional DMA, device ownership or PMGR sink credit.
pub struct TunableProgram {
    rows: Vec<Row>,
    row: usize,
    write: Option<u64>,
    sequence: u64,
    in_flight: Option<Effect>,
}

impl TunableProgram {
    pub fn load(
        port: &mut Port<'_, '_>,
        table_iova: u64,
        byte_len: u32,
        physical_base: u64,
        physical_span: u64,
    ) -> Result<Self, Error> {
        if byte_len > MAX_TABLE_BYTES || !byte_len.is_multiple_of(ROW_BYTES as u32) {
            return Err(Error::Unsupported(refuse!(
                "SIO tunable table length is not qualified"
            )));
        }
        table_iova
            .checked_add(u64::from(byte_len))
            .ok_or(Error::Unsupported(refuse!(
                "SIO tunable table exceeds I/O space"
            )))?;
        let end = physical_base
            .checked_add(physical_span)
            .ok_or(Error::Unsupported(refuse!(
                "SIO tunable physical range exceeds address space"
            )))?;
        let mut data = alloc::vec![0; byte_len as usize];
        // Port is RAM-only; it cannot silently convert a guest register
        // aperture into successful table data. No MMIO effect has started.
        port.read(table_iova, &mut data)?;
        let mut rows = Vec::with_capacity(data.len() / ROW_BYTES);
        for row in data.as_chunks::<ROW_BYTES>().0 {
            let offset = u32::from_le_bytes(row[..4].try_into().unwrap());
            let width = u32::from_le_bytes(row[4..8].try_into().unwrap());
            // Original firmware skips width0 before reading its offset,
            // mask or value. Do not invent an access for a disabled row.
            if width == 0 {
                continue;
            }
            let width = match width {
                4 => Width::Word,
                8 => Width::Double,
                _ => {
                    return Err(Error::Unsupported(refuse!(
                        "SIO tunable width is not qualified"
                    )));
                }
            };
            let address = physical_base
                .checked_add(u64::from(offset))
                .filter(|address| address.is_multiple_of(width.bytes()))
                .filter(|address| {
                    address
                        .checked_add(width.bytes())
                        .is_some_and(|last| last <= end)
                })
                .ok_or(Error::Unsupported(refuse!(
                    "SIO tunable exceeds its aligned physical range"
                )))?;
            rows.push(Row {
                address,
                width,
                mask: u64::from_le_bytes(row[8..16].try_into().unwrap()),
                value: u64::from_le_bytes(row[16..].try_into().unwrap()),
            });
        }
        Ok(Self {
            rows,
            row: 0,
            write: None,
            sequence: 0,
            in_flight: None,
        })
    }

    /// Claim one effect, then release all mutable firmware/bus borrows before
    /// routing it. Reentrant service cannot claim or execute it a second time.
    pub fn begin_effect(&mut self) -> Result<Option<Effect>, Error> {
        if self.in_flight.is_some() {
            return Err(Error::Unsupported(refuse!(
                "SIO setup effect is already in flight"
            )));
        }
        let Some(row) = self.rows.get(self.row) else {
            return Ok(None);
        };
        let request = match self.write {
            Some(value) => Request::Write {
                address: row.address,
                width: row.width,
                value,
            },
            None => Request::Read {
                address: row.address,
                width: row.width,
            },
        };
        let effect = Effect {
            sequence: self.sequence,
            request,
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::Unsupported(refuse!(
                "SIO setup effect sequence is exhausted"
            )))?;
        self.in_flight = Some(effect);
        Ok(Some(effect))
    }

    /// Retire only the claimed result. A failed routed access releases
    /// the claim for retry, keeping phase and any earlier read result.
    /// The caller propagates Access(E) intact; it must not substitute success.
    pub fn finish_effect<E>(
        &mut self,
        expected: Effect,
        result: Result<EffectResult, E>,
    ) -> Result<(), FinishError<E>> {
        if self.in_flight != Some(expected) {
            return Err(FinishError::Ownership(
                "SIO setup result has no matching in-flight owner",
            ));
        }
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                self.in_flight = None;
                return Err(FinishError::Access(error));
            }
        };
        let row = self.rows[self.row];
        match (expected.request, result) {
            (Request::Read { .. }, EffectResult::Read(value)) if value & !row.width.mask() == 0 => {
                let wanted = row.value & row.mask;
                if value & row.mask == wanted {
                    self.row += 1;
                } else {
                    // The original word path compares 64-bit masked bits,
                    // then stores only the low32 bits. Preserve that ordering
                    // even when a mask/value has bits outside a word access.
                    self.write = Some(((value & !row.mask) | wanted) & row.width.mask());
                }
            }
            (Request::Write { .. }, EffectResult::Written) => {
                self.write = None;
                self.row += 1;
            }
            _ => {
                return Err(FinishError::Ownership(
                    "SIO setup result does not match its access width or direction",
                ));
            }
        }
        self.in_flight = None;
        Ok(())
    }

    pub fn complete(&self) -> bool {
        self.row == self.rows.len() && self.in_flight.is_none()
    }
}

#[cfg(test)]
mod tests;
