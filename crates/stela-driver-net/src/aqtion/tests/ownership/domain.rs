// SPDX-License-Identifier: GPL-2.0-only
//! Current-epoch DMA adapter over the peer's distinct CPU/PA/IOVA memory model.
use super::*;
pub(super) struct NativeDomain(pub Arc<RootState>);
// SAFETY: all DMA resolves through the same owned model maps, never through
// numerical addresses cast to CPU pointers. The actual model config and queue
// state independently gate completion/unmap; no native provider is installed.
unsafe impl DmaDomain for NativeDomain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        limit: u64,
    ) -> core::result::Result<DomainMapping, DmaError> {
        self.0.current()?;
        assert_eq!(self.0.old_backing.load(Ordering::Relaxed), 0x55aa);
        let failed = self.0.record("map");
        let next = self.0.base.next.load(Ordering::Relaxed) + 1;
        if failed || self.0.fail_map_at.load(Ordering::Relaxed) == next {
            return Err(DmaError::MappingFailed);
        }
        // SAFETY: same isolated pinned pages, direction and original model map.
        unsafe { self.0.base.map(pages, direction, limit) }
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> core::result::Result<(), DmaError> {
        self.0.current()?;
        self.0.stopped();
        self.0.record("unmap");
        let base = &self.0.base;
        let call = base.unmap_calls.fetch_add(1, Ordering::Relaxed) + 1;
        if base.fail_unmap.load(Ordering::Relaxed)
            || base.fail_unmap_at.load(Ordering::Relaxed) == call
        {
            return Err(DmaError::InvalidationFailed);
        }
        assert!(base.drain_count.load(Ordering::Relaxed) > 0);
        assert_eq!(
            base.drained_epoch.load(Ordering::Relaxed),
            base.engine_epoch.load(Ordering::Relaxed)
        );
        assert_eq!(base.pending_dma.load(Ordering::Relaxed), 0);
        assert!(base.posted.lock().unwrap().is_empty());
        base.maps
            .lock()
            .unwrap()
            .remove(&mapping.address)
            .ok_or(DmaError::Unmapped)?;
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> core::result::Result<(), DmaError> {
        self.0.current()?;
        // SAFETY: same live symbolic mapping and checked coherent peer range.
        unsafe { self.0.base.sync_for_device(mapping, range, direction) }
    }
    unsafe fn sync_for_cpu(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> core::result::Result<(), DmaError> {
        self.0.current()?;
        // SAFETY: same live symbolic mapping and checked coherent peer range.
        unsafe { self.0.base.sync_for_cpu(mapping, range, direction) }
    }
    unsafe fn read_coherent_u32(
        &self,
        mapping: DomainMapping,
        offset: usize,
        direction: Direction,
    ) -> core::result::Result<u32, DmaError> {
        self.0.current()?;
        // SAFETY: same live aligned coherent descriptor observation.
        unsafe { self.0.base.read_coherent_u32(mapping, offset, direction) }
    }
    unsafe fn drain_posted_writes(&self) -> core::result::Result<(), DmaError> {
        self.0.current()?;
        self.0.stopped();
        if self.0.record("bound drain") || self.0.base.fail_drain.load(Ordering::Relaxed) {
            return Err(DmaError::DrainUnavailable);
        }
        self.0.base.complete_posted();
        self.0.base.pending_dma.store(0, Ordering::Relaxed);
        self.0.base.drained_epoch.store(
            self.0.base.engine_epoch.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.0.base.drain_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
