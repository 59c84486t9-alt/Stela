// SPDX-License-Identifier: GPL-2.0-only
//! Retained page backing and allocation for the synchronous model.
use super::*;

// SAFETY: uniquely owned aligned CPU storage with no exposed safe mutable
// references; the synchronous device model serializes every access.
unsafe impl Send for Backing {}

// SAFETY: same stable UnsafeCell storage, raw volatile access only.
unsafe impl Sync for Backing {}

// SAFETY: actual owned CPU RAM, immutable symbolic non-contiguous physical
// labels used only by the model domain, never dereferenced as CPU addresses.
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        // SAFETY: stable retained allocation, UnsafeCell permits DMA writes.
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
