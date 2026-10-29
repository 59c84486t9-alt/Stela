//! Cold usable-page views share the firmware allocation and validated mappings.
use super::*;
use alloc::alloc::{Layout, alloc};
use core::ptr::NonNull;
use stela_drivers::bus::dma::memory::{CacheAttribute, PageBacking, PinnedPages};

struct View {
    _reservation: Arc<Reservation>,
    cpu: usize,
    physical: Vec<u64>,
}
// SAFETY: construction accepts only one zeroed, never-entered usable slot in
// Preparing. The shared Reservation retains the firmware-created allocation
// claim and all qualified root mappings. Its immutable page list excludes raw
// padding and guard holes. Pages remain Stela-owned for the whole boot.
unsafe impl PageBacking for View {
    fn cpu_base(&self) -> NonNull<u8> {
        // SAFETY: export checked the nonzero usable mapping; it is retained
        // with this view and its page list is immutable.
        unsafe { NonNull::new_unchecked(self.cpu as *mut u8) }
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

fn boxed(view: View) -> Result<Box<View>, MemoryError> {
    // SAFETY: nonzero View layout; allocation occurs outside IRQ-save/queue
    // locks and NULL is reported without relinquishing its retained inputs.
    let raw = unsafe { alloc(Layout::new::<View>()) }.cast::<View>();
    let Some(raw) = NonNull::new(raw) else {
        return Err(MemoryError::OutOfMemory);
    };
    // SAFETY: fresh aligned allocation for exactly one View. Box becomes the
    // sole initialized owner and will use the same allocator/layout on Drop.
    unsafe {
        raw.as_ptr().write(view);
        Ok(Box::from_raw(raw.as_ptr()))
    }
}

/// # Safety
/// Called only after the work frame owner excludes this never-entered backing
/// in Preparing and zeros its entire usable range. No callback, byte user,
/// DMA producer, root/cache mutation or stack loan overlaps the export.
pub(super) unsafe fn export(backing: &Backing) -> Result<PinnedPages, MemoryError> {
    backing
        ._reservation
        .identity
        .check_current()
        .map_err(|_| MemoryError::Unavailable)?;
    if backing._reservation.identity.in_interrupt() {
        return Err(MemoryError::Unavailable);
    }
    let bytes = backing
        .bounds
        .end
        .checked_sub(backing.bounds.start)
        .filter(|bytes| *bytes != 0 && bytes.is_multiple_of(4096))
        .ok_or(MemoryError::InvalidSize)?;
    if backing.bounds.start == 0
        || !backing.bounds.start.is_multiple_of(4096)
        || !backing.physical.is_multiple_of(4096)
        || !backing
            ._reservation
            .allocation
            .contains(backing.physical, bytes as u64)
    {
        return Err(MemoryError::OutsideReservation);
    }
    let mut physical = Vec::new();
    physical
        .try_reserve_exact(bytes / 4096)
        .map_err(|_| MemoryError::OutOfMemory)?;
    for offset in (0..bytes).step_by(4096) {
        physical.push(
            backing
                .physical
                .checked_add(offset as u64)
                .ok_or(MemoryError::InvalidPageList)?,
        );
    }
    let view = boxed(View {
        _reservation: backing._reservation.clone(),
        cpu: backing.bounds.start,
        physical,
    })?;
    PinnedPages::new(view, bytes, 4096)
}
