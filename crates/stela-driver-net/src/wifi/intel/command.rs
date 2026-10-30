// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2003-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Gen2 host-command wire preparation from iwl-trans.c, fw/api/cmdhdr.h and
//! pcie/gen1_2/tx-gen2.c. Encoding is not publication or command completion.
use super::context::{Region, crosses_4g_boundary};
use alloc::vec::Vec;

pub const TFD_BYTES: usize = 256;
pub const FIRST_TB_BYTES: usize = 20;
/// One owned contiguous command body under the existing32KiB allocator profile.
pub const MAX_PAYLOAD_BYTES: usize = 32760;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Id {
    pub group: u8,
    pub opcode: u8,
    pub version: u8,
}
impl Id {
    /// Wide-header MVM translates legacy group0 to always-long group1, except
    /// REPLY_ERROR. Version bits remain unchanged, as DEF_ID(cmd->id) does.
    pub fn wire(self) -> Self {
        if self.group == 0 && !(self.opcode == 2 && self.version == 0) {
            Self { group: 1, ..self }
        } else {
            self
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    PayloadSize,
    Queue,
    BufferCount,
    BufferLength,
    Address,
    Boundary,
    Split,
}
#[derive(Debug)]
pub struct Command {
    id: Id,
    sequence: u16,
    bytes: Vec<u8>,
}
impl Command {
    /// Caller selects the negotiated command API. No missing command
    /// version is replaced with a guessed default here. queue/index are the
    /// source queue/host write pointer; only its low8 bits enter the sequence.
    pub fn encode(id: Id, queue: u8, index: u16, payload: &[u8]) -> Result<Self, Error> {
        if queue > 31 {
            return Err(Error::Queue);
        }
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::PayloadSize);
        }
        let id = id.wire();
        let sequence = (u16::from(queue) << 8) | (index & 0xff);
        let mut bytes = Vec::with_capacity(8 + payload.len());
        bytes.extend([id.opcode, id.group]);
        bytes.extend(sequence.to_le_bytes());
        bytes.extend((payload.len() as u16).to_le_bytes());
        bytes.extend([0, id.version]);
        bytes.extend(payload);
        Ok(Self {
            id,
            sequence,
            bytes,
        })
    }
    pub fn id(&self) -> Id {
        self.id
    }
    pub fn sequence(&self) -> u16 {
        self.sequence
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// TB0 is coherent bidirectional DMA, up to20 copied header/body
    /// bytes. The remaining command bytes use a separate ToDevice mapping.
    pub fn first_tb(&self) -> &[u8] {
        &self.bytes[..self.bytes.len().min(FIRST_TB_BYTES)]
    }
    pub fn remainder(&self) -> &[u8] {
        &self.bytes[self.bytes.len().min(FIRST_TB_BYTES)..]
    }
    /// Match exact lengths to this command, with no invented padding/TB.
    /// These Regions are serialization inputs, never mapping/visibility proof.
    pub fn tfd(&self, first: Region, remainder: Option<Region>) -> Result<Tfd, Error> {
        if first.bytes != self.first_tb().len() {
            return Err(Error::Split);
        }
        match (self.remainder().is_empty(), remainder) {
            (true, None) => Tfd::encode(&[first]),
            (false, Some(rest)) if rest.bytes == self.remainder().len() => {
                Tfd::encode(&[first, rest])
            }
            _ => Err(Error::Split),
        }
    }
}
#[derive(Debug)]
pub struct Tfd {
    bytes: [u8; TFD_BYTES],
}
impl Tfd {
    /// Exact iwl_tfh_tfd: LE16 count,25 packed {LE16 len,LE64 address}
    /// entries and the trailing reserved word. No alignment is invented for a
    /// TB address; streaming offsets need not be page aligned.
    pub fn encode(regions: &[Region]) -> Result<Self, Error> {
        if regions.is_empty() || regions.len() > 25 {
            return Err(Error::BufferCount);
        }
        let mut bytes = [0; TFD_BYTES];
        bytes[..2].copy_from_slice(&(regions.len() as u16).to_le_bytes());
        for (index, region) in regions.iter().enumerate() {
            if region.bytes == 0 || region.bytes > u16::MAX as usize {
                return Err(Error::BufferLength);
            }
            if region.address.checked_add(region.bytes as u64).is_none() {
                return Err(Error::Address);
            }
            if crosses_4g_boundary(region.address, region.bytes as u16) {
                return Err(Error::Boundary);
            }
            let at = 2 + index * 10;
            bytes[at..at + 2].copy_from_slice(&(region.bytes as u16).to_le_bytes());
            bytes[at + 2..at + 10].copy_from_slice(&region.address.to_le_bytes());
        }
        Ok(Self { bytes })
    }
    pub fn bytes(&self) -> &[u8; TFD_BYTES] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests;
