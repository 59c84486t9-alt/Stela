// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C single beacon TXBD for firmware reserved pages. Pinned rtw88
//! pci.c/tx.c are hardware references; allocations and IOVAs are native Stela.
//! Submission is not a DMA completion, radio transmission or firmware ALIVE.
use super::{
    io::{self, Bar},
    registers::*,
};
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DmaMapping},
    memory::{CpuMapping, MemoryError, PageSource},
};
use alloc::sync::Arc;
use core::sync::atomic::{Ordering, fence};

const PACKET_DESCRIPTOR: usize = 48;
const BUFFER_DESCRIPTOR: usize = 16;
const MAX_DATA: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Memory(MemoryError),
    Dma(DmaError),
    Register,
    InvalidLength,
    Address,
    Pending,
    NoPending,
    Quarantined,
}
impl From<MemoryError> for Error {
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}
impl From<DmaError> for Error {
    fn from(e: DmaError) -> Self {
        Self::Dma(e)
    }
}

/// Source management-rate configuration for the reserved-page descriptor.
/// This never tunes a radio; use the prior MAC configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareBand {
    Ghz2,
    Ghz5,
}

/// A specialized single beacon queue has no general TX ring read index.
///
/// # Safety
/// Implementations own the selected RTL8822C claim and UC BAR; reads
/// are volatile observations, writes ordered real MMIO. configure is
/// called only with acknowledged stopped DMA and no competing worker; kick
/// publishes BCN_WORK. Drop keeps the real claim/BAR reservation for
/// its full lifetime. Never infer completion from configure/kick readback.
pub unsafe trait Registers {
    fn configure(&mut self, iova: u32) -> Result<(), Error>;
    fn kick(&mut self) -> Result<(), Error>;
}

// SAFETY: `Bar::new` binds the exclusive requester BAR; only the beacon
// base and work registers are accessed, without completion claims.
unsafe impl Registers for Bar {
    fn configure(&mut self, iova: u32) -> Result<(), Error> {
        self.write32(RTK_PCI_TXBD_DESA_BCNQ, iova);
        if self.read32(RTK_PCI_TXBD_DESA_BCNQ) != iova {
            return Err(Error::Register);
        }
        Ok(())
    }
    fn kick(&mut self) -> Result<(), Error> {
        let work = self.read8(RTK_PCI_TXBD_BCN_WORK);
        if work == u8::MAX {
            return Err(Error::Register);
        }
        self.write8(RTK_PCI_TXBD_BCN_WORK, work | BIT_PCI_BCNQ_FLAG);
        Ok(())
    }
}

pub(super) struct Allocation {
    pub(super) cpu: CpuMapping,
    pub(super) dma: DmaMapping,
    pub(super) published: bool,
    pub(super) unmapped: bool,
}
impl Allocation {
    pub(super) fn new(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        direction: Direction,
    ) -> Result<Self, Error> {
        let (cpu, dma) =
            crate::wifi::allocation::allocate_32bit::<Error>(source, domain, bytes, direction)?;
        Ok(Self {
            cpu,
            dma,
            published: false,
            unmapped: false,
        })
    }
    pub(super) fn address(&self) -> Result<u32, Error> {
        u32::try_from(self.dma.address()?).map_err(|_| Error::Address)
    }
    pub(super) fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let ptr = self.cpu.address(offset, bytes.len())?;
        // SAFETY: bounded exclusive CPU-owned native WB RAM. Caller proves
        // prior device consumption before recycling any descriptor or payload.
        unsafe {
            ptr.as_ptr()
                .copy_from_nonoverlapping(bytes.as_ptr(), bytes.len())
        };
        Ok(())
    }
    pub(super) unsafe fn release(&mut self) -> Result<(), Error> {
        if !self.unmapped {
            // SAFETY: caller supplies acknowledged requester stop and drain.
            unsafe { self.dma.unmap()? };
            self.unmapped = true;
            self.published = false;
        }
        Ok(())
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.published && !self.unmapped {
            // SAFETY: no hardware was given this allocation; uncertain unmap
            // keeps pins/domain in canonical DmaMapping's quarantine Drop.
            let _ = unsafe { self.dma.unmap() };
        }
    }
}

/// Source reserved-page packet descriptor and two TXBD segments. The
/// final eight packet-descriptor bytes remain zero as in the donor's 48-byte
/// memset; ordinary radio TX/crypto fields are not exposed here.
pub fn descriptors(
    data: &[u8],
    address: u32,
    band: FirmwareBand,
) -> Result<([u8; 48], [u8; 16]), Error> {
    if !(1..=MAX_DATA).contains(&data.len()) {
        return Err(Error::InvalidLength);
    }
    address
        .checked_add((PACKET_DESCRIPTOR + data.len() - 1) as u32)
        .ok_or(Error::Address)?;
    let mut packet = [0u8; PACKET_DESCRIPTOR];
    let (rate_id, rate) = match band {
        FirmwareBand::Ghz2 => (8, 0),
        FirmwareBand::Ghz5 => (7, 4),
    };
    // Broadcast is also multicast, so source's broadcast || multicast is
    // exactly the low bit of addr1[0], including opaque firmware payloads.
    for (word, value) in [
        (
            0,
            data.len() as u32
                | 48 << 16
                | u32::from(data.get(4).is_some_and(|byte| byte & 1 != 0)) << 24
                | 1 << 26
                | 1 << 31,
        ),
        (1, 16 << 8 | rate_id << 16),
        (3, 1 << 8 | 1 << 10),
        (4, rate),
        (8, 1 << 15),
    ] {
        packet[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    let mut buffer = [0u8; BUFFER_DESCRIPTOR];
    buffer[0..2].copy_from_slice(&48u16.to_le_bytes());
    let psb = ((PACKET_DESCRIPTOR + data.len()).div_ceil(128) as u16) | 0x8000;
    buffer[2..4].copy_from_slice(&psb.to_le_bytes());
    buffer[4..8].copy_from_slice(&address.to_le_bytes());
    buffer[8..10].copy_from_slice(&(data.len() as u16).to_le_bytes());
    buffer[12..16].copy_from_slice(&(address + 48).to_le_bytes());
    Ok((packet, buffer))
}

/// Owned single firmware beacon slot. Queue base/pins survive successful
/// packet consumption: only explicit acknowledged requester stop permits unmap.
pub struct Beacon<R: Registers> {
    io: Option<R>,
    descriptor: Allocation,
    payload: Allocation,
    band: FirmwareBand,
    configured: bool,
    pending: bool,
    poisoned: bool,
    last_error: Option<Error>,
}
impl<R: Registers> Beacon<R> {
    /// # Safety
    /// The real RTL8822C requester is stopped/drained, attached to `domain`,
    /// and `io` keeps that exact PCI/BAR claim. Source allocations are real
    /// coherent WB DMA RAM on this requester, with NoSnoop/ATS disabled; WB
    /// alone is not coherence proof. No other engine/IRQ/reset worker touches
    /// this queue until acknowledged stop. `band` is prior MAC configuration.
    pub unsafe fn install(
        io: R,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        band: FirmwareBand,
    ) -> Result<Self, Error> {
        // Donor allocates coherent TXBD memory. Do not infer read-only DMA
        // from its lack of descriptor reads: the device may update OWN.
        let descriptor = Allocation::new(
            source,
            domain.clone(),
            BUFFER_DESCRIPTOR,
            Direction::Bidirectional,
        )?;
        let payload = Allocation::new(
            source,
            domain,
            PACKET_DESCRIPTOR + MAX_DATA,
            Direction::ToDevice,
        )?;
        let address = descriptor.address()?;
        let mut queue = Self {
            io: Some(io),
            descriptor,
            payload,
            band,
            configured: false,
            pending: false,
            poisoned: true,
            last_error: None,
        };
        queue.descriptor.write(0, &[0; BUFFER_DESCRIPTOR])?;
        queue.descriptor.dma.sync_for_device(0..BUFFER_DESCRIPTOR)?;
        fence(Ordering::Release);
        // Set before MMIO: a store/readback failure may already publish base.
        queue.descriptor.published = true;
        queue.configured = true;
        queue
            .io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .configure(address)?;
        queue.poisoned = false;
        Ok(queue)
    }
    pub fn pending(&self) -> bool {
        self.pending
    }
    pub fn quarantined(&self) -> bool {
        self.poisoned
    }
    pub fn last_error(&self) -> Option<Error> {
        self.last_error
    }
    pub fn enqueue(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.poisoned || !self.configured {
            return Err(Error::Quarantined);
        }
        if self.pending {
            return Err(Error::Pending);
        }
        let (packet, buffer) = descriptors(data, self.payload.address()?, self.band)?;
        self.poisoned = true;
        let result = (|| {
            self.payload.write(0, &packet)?;
            self.payload.write(PACKET_DESCRIPTOR, data)?;
            self.payload
                .dma
                .sync_for_device(0..PACKET_DESCRIPTOR + data.len())?;
            // The configured descriptor page is device-visible coherent RAM.
            // Keep payload before placing its IOVA there, including if the
            // subsequent descriptor visibility operation fails before kick.
            self.payload.published = true;
            self.descriptor.write(0, &buffer)?;
            self.descriptor.dma.sync_for_device(0..BUFFER_DESCRIPTOR)?;
            fence(Ordering::Release);
            self.pending = true;
            self.io.as_mut().ok_or(Error::Quarantined)?.kick()
        })();
        match result {
            Ok(()) => {
                self.poisoned = false;
                Ok(())
            }
            Err(error) => {
                self.last_error = Some(error);
                Err(error)
            }
        }
    }
    /// Prepare a live idle slot for post-power HCI rebinding.
    /// # Safety
    /// Independent real requester stop/drain and exclusive workers. A completed
    /// payload is still held; this does not authorize firmware retry/reset.
    pub(super) unsafe fn begin_hci_rebind(&mut self) -> Result<u32, Error> {
        if self.poisoned || self.pending || !self.configured {
            return Err(Error::Quarantined);
        }
        self.poisoned = true;
        // SAFETY: covered by this function's own safety contract.
        unsafe {
            self.descriptor.dma.sync_for_cpu(0..BUFFER_DESCRIPTOR)?;
        }
        self.descriptor.write(0, &[0; BUFFER_DESCRIPTOR])?;
        self.descriptor.dma.sync_for_device(0..BUFFER_DESCRIPTOR)?;
        self.descriptor.address()
    }
    pub(super) fn finish_hci_rebind(&mut self) {
        self.poisoned = false;
    }
    /// # Safety
    /// The requester is stopped and all DMA/IRQ/submission workers
    /// drained, with no new access possible throughout both unmaps. BCN_VALID
    /// alone is only payload consumption and does not satisfy this contract.
    pub unsafe fn release_after_stop(&mut self) -> Result<(), Error> {
        self.poisoned = true;
        // SAFETY: caller supplies complete requester stop and drained workers.
        unsafe {
            self.descriptor.release()?;
            self.payload.release()?;
        }
        self.pending = false;
        self.configured = false;
        self.poisoned = false;
        Ok(())
    }
}
// SAFETY: install binds real owned DMA pages/domain/registers; pending slot
// cannot be overwritten before source's new BCN_VALID proof. No Drop
// unmap exists for published buffers, and uncertain io ownership is held.
unsafe impl<R: Registers> io::BeaconQueue for Beacon<R> {
    fn submit(&mut self, data: &[u8]) -> Result<(), io::Error> {
        self.enqueue(data).map_err(|_| io::Error::Queue)
    }
    unsafe fn consumed(&mut self) -> Result<(), io::Error> {
        if self.poisoned || !self.pending {
            return Err(io::Error::Queue);
        }
        self.poisoned = true;
        // SAFETY: caller supplies source's fresh BCN_VALID consumption proof;
        // no device access to this TXBD remains until the next explicit kick.
        if let Err(error) = unsafe { self.descriptor.dma.sync_for_cpu(0..BUFFER_DESCRIPTOR) } {
            self.last_error = Some(Error::Dma(error));
            return Err(io::Error::Queue);
        }
        fence(Ordering::Acquire);
        self.pending = false;
        self.poisoned = false;
        Ok(())
    }
    fn quarantine(&mut self) {
        self.poisoned = true;
    }
}
impl<R: Registers> Drop for Beacon<R> {
    fn drop(&mut self) {
        if self.configured
            && let Some(io) = self.io.take()
        {
            core::mem::forget(io);
        }
    }
}

#[cfg(test)]
pub(super) mod tests;
