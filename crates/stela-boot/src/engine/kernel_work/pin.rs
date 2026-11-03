//! Prepared usable-page views share the firmware allocation and validated mappings.
use super::*;
use alloc::alloc::{Layout, alloc};
use core::{ptr::NonNull, sync::atomic::AtomicU64};
use stela_drivers::bus::dma::memory::{CacheAttribute, PageBacking, PinnedPages};

pub(super) struct Epoch {
    last: AtomicU64,
    active: AtomicBool,
}

impl Epoch {
    pub(super) const fn new() -> Self {
        Self {
            last: AtomicU64::new(0),
            active: AtomicBool::new(false),
        }
    }
}

struct Lease {
    reservation: Arc<Reservation>,
    slot: usize,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.reservation.pin_epochs[self.slot]
            .active
            .store(false, Ordering::Release);
    }
}

struct View {
    _lease: Lease,
    cpu: usize,
    physical: Vec<u64>,
}
// SAFETY: construction accepts only one zeroed usable slot in Preparing
// and keeps its exact epoch exclusion until the last pin drops. The shared
// Reservation keeps the firmware allocation and all checked root mappings.
// The immutable page list excludes raw padding and guard holes.
unsafe impl PageBacking for View {
    fn cpu_base(&self) -> NonNull<u8> {
        // SAFETY: export checked the nonzero usable mapping; it is held
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
    // locks and NULL is reported without relinquishing its inputs.
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
/// Called only after the work frame owner excludes this exact epoch in
/// Preparing and zeros its entire usable range. No callback, byte user,
/// DMA producer, root/cache mutation or stack loan overlaps the export.
pub(super) unsafe fn export(backing: &Backing, epoch: u64) -> Result<PinnedPages, MemoryError> {
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
    let state = &backing._reservation.pin_epochs[backing.slot];
    if state
        .active
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(MemoryError::Unavailable);
    }
    let lease = Lease {
        reservation: backing._reservation.clone(),
        slot: backing.slot,
    };
    if epoch <= state.last.load(Ordering::Relaxed) {
        return Err(MemoryError::Unavailable);
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
        _lease: lease,
        cpu: backing.bounds.start,
        physical,
    })?;
    let pages = PinnedPages::new(view, bytes, 4096)?;
    state.last.store(epoch, Ordering::Relaxed);
    Ok(pages)
}
