// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2018-2026 Intel Corporation
//! Native PNVM/reduced-power payload mappings from pcie/ctxt-info-v2.c.
//! These are prepared bytes, not an ALIVE-selected source receipt or
//! a firmware PNVM completion. The owning ROM epoch must bind source/SKU,
//! keep the requester/BAR, publish scratch then ring the doorbell.
//! Every payload/descriptor mapping survives PNVM notification until stop.
use super::{
    context::Region,
    dma::{self, Chunk},
    pnvm,
};
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError},
    memory::PageSource,
};
use alloc::{sync::Arc, vec::Vec};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    PayloadCount,
    PayloadSize,
    Dma(dma::Error),
    State,
}
impl From<dma::Error> for Error {
    fn from(value: dma::Error) -> Self {
        Self::Dma(value)
    }
}

/// Serialization data only; no DMA ownership, completion or source permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Configuration {
    pub address: u64,
    pub bytes: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Prepared,
    Exposed,
    Stopped,
}
pub struct MappedTable {
    payloads: Vec<Chunk>,
    descriptors: Option<Chunk>,
    configuration: Configuration,
    state: State,
}
impl MappedTable {
    /// Source-backed capability selection: fragmented is firmware capability
    /// bit 32. Without it, exactly two chunks are concatenated in source order.
    /// This allocator profile bounds each allocation to 32 KiB and 64 payloads.
    /// # Safety
    /// Source allocations are fresh exclusive real native RAM with no aliases.
    /// The domain is the isolated requester domain, not identity DMA.
    /// Until publication all returned bytes remain exclusively CPU-owned.
    pub unsafe fn prepare(
        chunks: &[pnvm::Chunk<'_>],
        fragmented: bool,
        source: &dyn PageSource,
        domain: Option<Arc<dyn DmaDomain>>,
    ) -> Result<Self, Error> {
        if chunks.is_empty() || chunks.len() > 64 || (!fragmented && chunks.len() != 2) {
            return Err(Error::PayloadCount);
        }
        let mut total = 0u32;
        for chunk in chunks {
            if chunk.data.is_empty() || chunk.data.len() > 32768 {
                return Err(Error::PayloadSize);
            }
            total = total
                .checked_add(chunk.data.len() as u32)
                .ok_or(Error::PayloadSize)?;
        }
        if !fragmented && total > 32768 {
            return Err(Error::PayloadSize);
        }
        let domain = domain.ok_or(Error::Dma(dma::Error::Dma(DmaError::IommuUnavailable)))?;
        let allocate =
            |bytes: &[u8]| Chunk::allocate(source, domain.clone(), bytes, Direction::Bidirectional);
        let (payloads, descriptors, address) = if fragmented {
            let descriptors = allocate(&[0; 512])?;
            let mut payloads = Vec::new();
            let mut addresses = [0; 512];
            for (index, chunk) in chunks.iter().enumerate() {
                let payload = allocate(chunk.data)?;
                addresses[index * 8..index * 8 + 8]
                    .copy_from_slice(&payload.region().address.to_le_bytes());
                payloads.push(payload);
            }
            // SAFETY: this private descriptor buffer has never been published.
            unsafe {
                descriptors.write_owned(0, &addresses)?;
            }
            let address = descriptors.region().address;
            (payloads, Some(descriptors), address)
        } else {
            let mut bytes = Vec::with_capacity(total as usize);
            for chunk in chunks {
                bytes.extend_from_slice(chunk.data);
            }
            let payload = allocate(&bytes)?;
            let address = payload.region().address;
            (alloc::vec![payload], None, address)
        };
        Ok(Self {
            payloads,
            descriptors,
            configuration: Configuration {
                address,
                bytes: total,
            },
            state: State::Prepared,
        })
    }
    /// Conservative lifetime transition before the first possible scratch
    /// pointer store. The owner must keep this table and its real PCI
    /// claim through uncertain publication. Calling this does not publish DMA.
    pub fn expose_for_scratch(&mut self) -> Result<Configuration, Error> {
        if self.state != State::Prepared {
            return Err(Error::State);
        }
        for chunk in &mut self.payloads {
            chunk.expose();
        }
        if let Some(descriptors) = self.descriptors.as_mut() {
            descriptors.expose();
        }
        self.state = State::Exposed;
        Ok(self.configuration)
    }
    /// # Safety
    /// Requester master-disable/reset or a stronger device fence proves
    /// no further table reads/writes; all submission/IRQ work has drained.
    /// PNVM notification/ALIVE/timeouts alone do not satisfy this contract.
    pub unsafe fn release_after_stop(&mut self) -> Result<(), Error> {
        if self.state != State::Exposed {
            return Err(Error::State);
        }
        for chunk in &mut self.payloads {
            // SAFETY: covered by this function's own safety contract.
            unsafe {
                chunk.release().map_err(dma::Error::Dma)?;
            }
        }
        if let Some(descriptors) = self.descriptors.as_mut() {
            // SAFETY: covered by this function's own safety contract.
            unsafe {
                descriptors.release().map_err(dma::Error::Dma)?;
            }
        }
        self.state = State::Stopped;
        Ok(())
    }
    pub fn payloads(&self) -> impl Iterator<Item = Region> + '_ {
        self.payloads.iter().map(Chunk::region)
    }
    pub fn fragmented(&self) -> bool {
        self.descriptors.is_some()
    }
}

#[cfg(test)]
mod tests;
