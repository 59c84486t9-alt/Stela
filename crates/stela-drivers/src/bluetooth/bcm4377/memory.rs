// SPDX-License-Identifier: MIT
//! Coherent device IOVAs; CPU pointers never become device addresses.
use super::{Error, Result};
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaMapping},
    memory::{CacheAttribute, CpuMapping, PinnedPages},
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{Ordering, fence};

/// Source firmware's whole allowed DMA window, starting at IOVA zero.
pub const DMA_WINDOW_BYTES: u64 = 0xffff_fe00;

/// A kept CPU mapping, RAM pin and device-domain mapping.
/// An active Drop uses the common DMA quarantine; it never unmaps live DMA.
pub struct CoherentBuffer {
    cpu: CpuMapping,
    mapping: DmaMapping,
    address: u64,
    bytes: usize,
}
impl CoherentBuffer {
    /// # Safety
    /// These exclusive zeroed WB pages and domain belong to the same
    /// requester/reset epoch as the enclosing transport. The real platform
    /// guarantees native coherent scalar CPU/device accesses, including shared
    /// volatile ring indices. No noncoherent cache-maintenance substitute or
    /// numerical address grant is sufficient. The domain, pins and mapping must
    /// remain valid through device/posted/IRQ/CPU/deferred retirement.
    pub unsafe fn map(pages: PinnedPages, domain: Arc<dyn DmaDomain>) -> Result<Self> {
        let bytes = pages.logical_bytes();
        let cpu = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(Error::Memory)?;
        let mapping = DmaMapping::map(
            domain,
            pages,
            Direction::Bidirectional,
            DMA_WINDOW_BYTES - 1,
        )
        .map_err(Error::Dma)?;
        let address = mapping.address().map_err(Error::Dma)?;
        Ok(Self {
            cpu,
            mapping,
            address,
            bytes,
        })
    }
    pub(super) fn len(&self) -> usize {
        self.bytes
    }
    pub(super) fn address(&self) -> u64 {
        self.address
    }
    fn pointer(&self, at: usize, bytes: usize) -> *mut u8 {
        assert!(at <= self.bytes && bytes <= self.bytes - at);
        self.cpu
            .address(at, bytes)
            .expect("retained coherent CPU bounds")
            .as_ptr()
    }
    pub(super) fn read16(&self, at: usize) -> u16 {
        let pointer = self.pointer(at, 2).cast::<u16>();
        assert!((pointer as usize).is_multiple_of(2));
        // SAFETY: coherent aligned scalar; caller owns this range or is polling
        // the source's shared producer index. No Rust reference aliases DMA.
        u16::from_le(unsafe { pointer.read_volatile() })
    }
    pub(super) fn write16(&mut self, at: usize, value: u16) {
        let pointer = self.pointer(at, 2).cast::<u16>();
        assert!((pointer as usize).is_multiple_of(2));
        // SAFETY: checked coherent scalar; serialized host owns this index.
        unsafe { pointer.write_volatile(value.to_le()) };
    }
    pub(super) fn read(&self, at: usize, bytes: usize) -> Vec<u8> {
        let pointer = self.pointer(at, bytes);
        (0..bytes)
            .map(|offset| {
                // SAFETY: checked coherent range; completion gives CPU ownership.
                unsafe { pointer.add(offset).read_volatile() }
            })
            .collect()
    }
    pub(super) fn write(&mut self, at: usize, bytes: &[u8]) {
        let pointer = self.pointer(at, bytes.len());
        for (offset, byte) in bytes.iter().enumerate() {
            // SAFETY: checked coherent range; not device-owned when written.
            unsafe { pointer.add(offset).write_volatile(*byte) };
        }
    }
    pub(super) fn publish(&self) -> Result<()> {
        self.mapping
            .sync_for_device(0..self.bytes)
            .map_err(Error::Dma)?;
        fence(Ordering::Release);
        Ok(())
    }
    /// # Safety
    /// Device DMA and posted writes, CPU/IRQ callbacks and deferred
    /// submissions are stopped/drained; no new access can begin or resume.
    pub(super) unsafe fn release(&mut self) -> Result<()> {
        // SAFETY: caller provides retirement, not a mask/readiness token.
        unsafe { self.mapping.unmap() }.map_err(Error::Dma)
    }
}

/// The requester's coherent RAM/domain allocator, or an explicit model.
/// # Safety
/// Every returned allocation owns unique pins/CPU mappings and low IOVAs
/// in this transport's requester/reset epoch. Native coherency and
/// alignment are platform properties, never inferred from WB metadata.
/// Errors after effects keep uncertain backing/domain ownership. No identity
/// fallback or DMA address derived from a CPU pointer is allowed.
pub unsafe trait CoherentAllocator {
    fn allocate(&mut self, bytes: usize) -> Result<CoherentBuffer>;
}
