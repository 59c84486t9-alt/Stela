// SPDX-License-Identifier: GPL-2.0-only
//! Page source and write-trace assertions shared by the direct PDM family
//! fixtures. Each family keeps its own register model.
use crate::bus::dma::memory::{
    CacheAttribute, MemoryError, PageBacking, PageGeometry, PageSource, PinnedPages,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

#[repr(align(4096))]
struct Ram([u8; 32768]);
struct Backing {
    ram: Box<UnsafeCell<Ram>>,
    physical: Vec<u64>,
    drops: Arc<AtomicUsize>,
}

// SAFETY: uniquely owned aligned CPU storage with no exposed safe mutable
// references; the synchronous device model serializes every access.
unsafe impl Send for Backing {}

// SAFETY: same stable UnsafeCell storage, raw volatile access only.
unsafe impl Sync for Backing {}

// SAFETY: owned CPU RAM, immutable symbolic non-contiguous physical
// labels used only by the model domain, never dereferenced as CPU addresses.
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        // SAFETY: stable allocation, UnsafeCell permits DMA writes.
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.ram.get()).0).cast()) }
    }
    fn physical_pages(&self) -> &[u64] {
        &self.physical
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}

impl Drop for Backing {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

/// Write-back pages at symbolic, non-contiguous physical labels, counting
/// every backing dropped.
pub(crate) struct Source {
    pub(crate) drops: Arc<AtomicUsize>,
    pub(crate) geometry: u8,
}

impl Source {
    pub(crate) fn new() -> Self {
        Self {
            drops: Arc::new(AtomicUsize::new(0)),
            geometry: 12,
        }
    }
}

impl PageSource for Source {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        PageGeometry::base_only(self.geometry)
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert!(bytes <= 32768);
        assert_eq!(alignment, 4096);
        assert_eq!(attribute, CacheAttribute::WriteBack);
        PinnedPages::new(
            Box::new(Backing {
                ram: Box::new(UnsafeCell::new(Ram([0; 32768]))),
                physical: (0..bytes / 4096)
                    .map(|page| 0x5000_0000 + page as u64 * 0x3000)
                    .collect(),
                drops: self.drops.clone(),
            }),
            bytes,
            alignment,
        )
    }
}

/// Assert the exact PTE/ring programming in an independent model write
/// trace, not a translation-cache implementation or a cache-completion/ACK
/// model. Addresses and order come from the pinned YC/Renoir/PS DMA
/// configuration and ring helpers.
pub(crate) fn assert_ring_invalidation(
    writes: &[(usize, u32)],
    iova: u64,
    sram: u32,
    period_bytes: usize,
    started: bool,
) {
    let ring_bytes = period_bytes * 4;
    let pages = ring_bytes.div_ceil(4096);
    let mut expected = vec![(0xc04, sram | 0x8000_0000), (0xc00, 2)];
    for page in 0..pages {
        let address = iova + (page * 4096) as u64;
        expected.push((0x10000 + page * 8, address as u32));
        expected.push((0x10004 + page * 8, (address >> 32) as u32 | 0x8000_0000));
    }
    for page in pages..8 {
        expected.push((0x10004 + page * 8, 0));
    }
    expected.extend([
        (0x2c0c, 0x0400_0000),
        (0x2c10, ring_bytes as u32),
        (0x2c20, period_bytes as u32),
        (0xc40, 1),
    ]);
    let observed: Vec<_> = writes
        .iter()
        .copied()
        .filter(|(offset, value)| {
            (*offset == 0xc04 && *value != 0)
                || matches!(*offset, 0xc00 | 0xc40 | 0x2c0c | 0x2c10 | 0x2c20)
                || (0x10000..0x10040).contains(offset)
        })
        .collect();
    assert_eq!(
        observed, expected,
        "exact PTE/ring sequence must end with one required invalidate1 request"
    );
    let invalidations: Vec<_> = writes
        .iter()
        .enumerate()
        .filter(|(_, (offset, _))| *offset == 0xc40)
        .collect();
    assert_eq!(
        invalidations.len(),
        1,
        "required request cannot be absent or duplicated"
    );
    let invalidate = invalidations[0].0;
    for request in [(0x2c04, 1), (0x2c08, 1)] {
        let starts: Vec<_> = writes
            .iter()
            .enumerate()
            .filter(|(_, actual)| **actual == request)
            .collect();
        assert_eq!(starts.len(), usize::from(started));
        if started {
            assert!(
                invalidate < starts[0].0,
                "PDM/DMA cannot start before required cache request"
            );
        }
    }
}
