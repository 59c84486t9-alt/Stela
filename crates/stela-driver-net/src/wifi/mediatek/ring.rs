// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
// Copyright (C) 2020-2023 MediaTek Inc.
//! PCIe WFDMA raw-command TX rings from mt76 dma.c. Descriptor/payload RAM
//! uses canonical native pins and IOMMU leases; no CPU or physical address is
//! substituted for a device IOVA. Completion here releases DMA ownership,
//! never implies an over-the-air packet acknowledgement or a ready radio.
use crate::bus::{
    dma::{
        mapping::{Direction, DmaDomain, DmaError, DmaMapping},
        memory::{CpuMapping, MemoryError, PageSource},
    },
    mmio::Mmio,
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    ptr::NonNull,
    sync::atomic::{Ordering, fence},
};

pub mod data;
pub mod rx;

const DESC_BYTES: usize = 16;
const DONE: u32 = 1 << 31;
const LAST: u32 = 1 << 30;
const MAX_COUNT: usize = 256;
const MAX_PAYLOAD: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Memory(MemoryError),
    Dma(DmaError),
    InvalidSize,
    Full,
    EmptyPayload,
    Poisoned,
    RegisterFailure,
    InvalidDeviceIndex,
    OwnershipMismatch,
    InvalidDeviceLength,
    UnsupportedDescriptor,
    ReceiveChainLimit,
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
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek WFDMA TX: {self:?}")
    }
}
impl core::error::Error for Error {}

/// Exactly one owned queue register block. Queue installation requires a
/// quiescent WFDMA engine; an acknowledged engine stop/reset is also required
/// before unmapping a ring. Queue register readback alone is not that proof.
///
/// # Safety
/// Implementors must own the selected PCI requester and mapped queue
/// registers for this object's lifetime. `device_index` must be a
/// volatile hardware read and `publish` an ordered MMIO doorbell after prior
/// DMA visibility operations; successful writes are completed register stores.
/// Errors may be uncertain and must never manufacture a completion index.
/// No competing firmware, OS, IRQ worker or reset path may access this queue.
pub unsafe trait QueueIo: 'static {
    fn configure(&mut self, address: u32, count: u16) -> Result<(), Error>;
    fn device_index(&mut self) -> Result<u16, Error>;
    fn publish(&mut self, head: u16) -> Result<(), Error>;
}

/// Native queue MMIO, keeping the owned BAR/requester context.
/// Construct it only after PCI ownership, full BAR bounds and UC mapping are
/// established. This is not a PCI function claim or an interrupt allocation.
pub struct MmioQueue {
    registers: Mmio,
    _owner: Arc<dyn core::any::Any>,
}
impl MmioQueue {
    /// # Safety
    /// `window` names the four uncached queue registers of the claimed
    /// requester. `owner` must keep the real exclusive PCI function claim
    /// and BAR mapping/reservation through its final Drop; the window remains
    /// mapped and excludes competing accesses for that entire lifetime.
    /// No unrelated token or owner whose Drop releases another reservation
    /// meets this contract. Uncertain ring Drop keeps this Arc.
    pub unsafe fn from_window(window: NonNull<[u32; 4]>, owner: Arc<dyn core::any::Any>) -> Self {
        Self {
            // SAFETY: covered by this function's own safety contract.
            registers: unsafe { Mmio::new(window.as_ptr().cast::<u32>() as u64) },
            _owner: owner,
        }
    }
}
// SAFETY: construction requires the exclusive mapped queue window;
// volatile accesses use the donor's exact four-register offsets.
unsafe impl QueueIo for MmioQueue {
    fn configure(&mut self, address: u32, count: u16) -> Result<(), Error> {
        self.registers.write32(8, 0);
        self.registers.write32(12, 0);
        self.registers.write32(4, u32::from(count));
        self.registers.write32(0, address);
        if self.registers.read32(4) != u32::from(count) || self.registers.read32(0) != address {
            return Err(Error::RegisterFailure);
        }
        Ok(())
    }
    fn device_index(&mut self) -> Result<u16, Error> {
        let index = self.registers.read32(12);
        u16::try_from(index).map_err(|_| Error::InvalidDeviceIndex)
    }
    fn publish(&mut self, head: u16) -> Result<(), Error> {
        self.registers.write32(8, u32::from(head));
        Ok(())
    }
}

struct Allocation {
    cpu: CpuMapping,
    dma: DmaMapping,
    published: bool,
    unmapped: bool,
}
impl Allocation {
    fn new(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        direction: Direction,
    ) -> Result<Self, Error> {
        // The unsafe installer requires hardware-coherent WB DMA for
        // this requester, with NoSnoop/ATS disabled. WB alone proves nothing.
        let (cpu, dma) =
            crate::wifi::allocation::allocate_32bit::<Error>(source, domain, bytes, direction)?;
        Ok(Self {
            cpu,
            dma,
            published: false,
            unmapped: false,
        })
    }
    fn address(&self) -> Result<u32, Error> {
        u32::try_from(self.dma.address()?).map_err(|_| Error::OwnershipMismatch)
    }
    fn pointer(&self, at: usize, bytes: usize) -> Result<*mut u8, Error> {
        Ok(self.cpu.address(at, bytes)?.as_ptr())
    }
    fn write32(&self, at: usize, value: u32) -> Result<(), Error> {
        let ptr = self.pointer(at, 4)?.cast::<u32>();
        // SAFETY: bounded aligned checked-coherent WB allocation, serialized ring owner, descriptor
        // is CPU-owned when written; no Rust reference aliases a device access.
        unsafe { ptr.write_volatile(value.to_le()) };
        Ok(())
    }
    fn read32(&self, at: usize) -> Result<u32, Error> {
        let ptr = self.pointer(at, 4)?.cast::<u32>();
        // SAFETY: bounded aligned checked-coherent WB descriptor polling.
        Ok(u32::from_le(unsafe { ptr.read_volatile() }))
    }
    unsafe fn release(&mut self) -> Result<(), Error> {
        if self.unmapped {
            return Ok(());
        }
        // SAFETY: caller proves all queue access stopped and DMA completed/reset.
        unsafe { self.dma.unmap()? };
        self.published = false;
        self.unmapped = true;
        Ok(())
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.published && !self.unmapped {
            // SAFETY: unpublished allocations were never exposed to the requester;
            // unmap failures remain held by DmaMapping's quarantine Drop.
            let _ = unsafe { self.dma.unmap() };
        }
    }
}
struct Slot {
    data: Allocation,
    pending: Option<(u64, usize)>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    pub cookie: u64,
    pub bytes: usize,
}

/// One raw WFDMA TX queue. Payload buffers and descriptors remain pinned and
/// mapped across all submissions and are quarantined on Drop until explicit
/// acknowledged quiescence. This queue reserves two entries as donor raw TX.
pub struct TxRing<Q: QueueIo> {
    io: Option<Q>,
    descriptors: Allocation,
    slots: Vec<Slot>,
    head: usize,
    tail: usize,
    queued: usize,
    poisoned: bool,
    released: bool,
}
impl<Q: QueueIo> TxRing<Q> {
    /// # Safety
    /// The caller must hold exclusive PCI/WFDMA ownership, with the TX
    /// engine disabled and idle before queue register mutation, and keep it
    /// through this ring's destruction/quarantine. `domain` must belong to that
    /// same requester. Ordinary WB DMA must be cache coherent for
    /// volatile completion polling on this exact platform/requester, with PCIe
    /// NoSnoop and ATS disabled. A WB cache attribute or compiler fence alone
    /// is not that proof. This validation must remain true until acknowledged
    /// quiescence and final unmap, including every quarantined mapping.
    /// Polling mode must keep device IRQ sources masked and
    /// exclude every other submit/cleanup/reset owner.
    pub unsafe fn install(
        io: Q,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        count: usize,
    ) -> Result<Self, Error> {
        if !(4..=MAX_COUNT).contains(&count) || !count.is_power_of_two() {
            return Err(Error::InvalidSize);
        }
        let descriptors = Allocation::new(
            source,
            domain.clone(),
            count * DESC_BYTES,
            Direction::Bidirectional,
        )?;
        let mut slots = Vec::with_capacity(count);
        for i in 0..count {
            descriptors.write32(i * DESC_BYTES + 4, DONE)?;
            slots.push(Slot {
                data: Allocation::new(source, domain.clone(), MAX_PAYLOAD, Direction::ToDevice)?,
                pending: None,
            });
        }
        descriptors.dma.sync_for_device(0..count * DESC_BYTES)?;
        let base = descriptors.address()?;
        let mut ring = Self {
            io: Some(io),
            descriptors,
            slots,
            head: 0,
            tail: 0,
            queued: 0,
            poisoned: true,
            released: false,
        };
        // Construct the guard before the first potentially publishing store.
        // Any later error keeps both Q's requester/BAR owner and DMA.
        ring.descriptors.published = true;
        ring.io
            .as_mut()
            .expect("retained queue")
            .configure(base, count as u16)?;
        if ring.io.as_mut().expect("retained queue").device_index()? != 0 {
            return Err(Error::InvalidDeviceIndex);
        }
        ring.poisoned = false;
        Ok(ring)
    }

    pub fn pending(&self) -> usize {
        self.queued
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    /// Submit one complete MCU/headerless-scatter transfer. `Ok` means queued,
    /// not completed; the caller must keep its command epoch until completion.
    pub fn submit(&mut self, cookie: u64, payload: &[u8]) -> Result<(), Error> {
        if self.poisoned || self.released {
            return Err(Error::Poisoned);
        }
        if payload.is_empty() {
            return Err(Error::EmptyPayload);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::InvalidSize);
        }
        if self.queued + 1 >= self.slots.len() - 1 {
            return Err(Error::Full);
        }
        let result = self.submit_inner(cookie, payload);
        if result.is_err() {
            self.poisoned = true
        }
        result
    }
    fn submit_inner(&mut self, cookie: u64, payload: &[u8]) -> Result<(), Error> {
        let slot = &mut self.slots[self.head];
        if slot.pending.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        let pointer = slot.data.pointer(0, payload.len())?;
        // SAFETY: this slot is CPU-owned and contains distinct pinned RAM; the
        // borrowed caller bytes cannot alias this private allocation.
        unsafe { core::ptr::copy_nonoverlapping(payload.as_ptr(), pointer, payload.len()) };
        slot.data.dma.sync_for_device(0..payload.len())?;
        // The first descriptor store can expose a prefetchable payload address.
        slot.data.published = true;
        slot.pending = Some((cookie, payload.len()));
        let at = self.head * DESC_BYTES;
        self.descriptors.write32(at, slot.data.address()?)?;
        self.descriptors.write32(at + 8, 0)?;
        self.descriptors.write32(at + 12, 0)?;
        self.descriptors
            .write32(at + 4, LAST | ((payload.len() as u32) << 16))?;
        self.descriptors.dma.sync_for_device(at..at + DESC_BYTES)?;
        self.queued += 1;
        self.head = (self.head + 1) % self.slots.len();
        fence(Ordering::SeqCst);
        self.io
            .as_mut()
            .expect("retained queue")
            .publish(self.head as u16)
    }
    /// Read the hardware DMA index and release at most one completed
    /// transfer. Enqueue or software head progression never grants CPU ownership.
    pub fn poll(&mut self) -> Result<Option<Completion>, Error> {
        if self.poisoned || self.released {
            return Err(Error::Poisoned);
        }
        let result = self.poll_inner();
        if result.is_err() {
            self.poisoned = true
        }
        result
    }
    fn poll_inner(&mut self) -> Result<Option<Completion>, Error> {
        let count = self.slots.len();
        let actual = usize::from(self.io.as_mut().expect("retained queue").device_index()?);
        if actual >= count {
            return Err(Error::InvalidDeviceIndex);
        }
        let advanced = (actual + count - self.tail) % count;
        if advanced > self.queued {
            return Err(Error::InvalidDeviceIndex);
        }
        if advanced == 0 {
            return Ok(None);
        }
        fence(Ordering::SeqCst);
        let descriptor = self.tail * DESC_BYTES;
        // SAFETY: the observed hardware DMA index passed this entry,
        // completing descriptor fetch/writeback for this exact queue slot.
        unsafe {
            self.descriptors
                .dma
                .sync_for_cpu(descriptor..descriptor + DESC_BYTES)?
        };
        let slot = &mut self.slots[self.tail];
        let (cookie, bytes) = slot.pending.ok_or(Error::OwnershipMismatch)?;
        // SAFETY: DMA index passed this slot; the requester has completed reads.
        unsafe { slot.data.dma.sync_for_cpu(0..bytes)? };
        slot.pending = None;
        self.tail = (self.tail + 1) % count;
        self.queued -= 1;
        Ok(Some(Completion { cookie, bytes }))
    }
    /// # Safety
    /// The owning controller must have disabled submissions and IRQs,
    /// drained workers, and observed acknowledged WFDMA idle/reset such that no
    /// current or stale device access can touch any queue or payload mapping.
    /// Software timeout, disabled PCI command bit or a write without readback
    /// is not this proof. Failed unmaps keep/quarantine remaining mappings.
    pub unsafe fn release_after_quiesce(&mut self) -> Result<(), Error> {
        self.poisoned = true;
        for slot in &mut self.slots {
            // SAFETY: caller's full hardware/worker quiescence covers every slot.
            unsafe { slot.data.release()? };
            slot.pending = None;
        }
        // SAFETY: the same quiescence covers descriptor fetch/writeback.
        unsafe { self.descriptors.release()? };
        self.queued = 0;
        self.released = true;
        Ok(())
    }
}

/// Keep the queue/BAR/requester context of an uncertain publication or
/// Drop; this does not claim hardware reset or reclamation.
fn retain_queue<Q>(io: Option<Q>) {
    if let Some(io) = io {
        core::mem::forget(io);
    }
}
impl<Q: QueueIo> Drop for TxRing<Q> {
    fn drop(&mut self) {
        if self.descriptors.published && !self.released {
            retain_queue(self.io.take());
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
