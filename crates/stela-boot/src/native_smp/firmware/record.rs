//! Immutable pre-EBS observation layout, separate from firmware operations.
//! The processor inventory is a trailing array sized by the firmware's
//! processor count, so the record has no fixed logical-processor ceiling.
#[cfg(test)]
extern crate alloc;
#[cfg(test)]
use crate::boot_native_topology as topology;
#[cfg(not(test))]
use crate::native_smp::topology;
use core::{alloc::Layout, ptr};
use topology::{Processor, Snapshot};

#[repr(C)]
pub(crate) struct Capture {
    pub magic: u64,
    pub version: u32,
    pub processor_count: u32,
    /// Physical cores with source observations: the assignable roster,
    /// `min(physical_count, MAX_CORES)`.
    pub core_count: u32,
    pub enabled_count: u32,
    /// Every physical core the firmware inventory identifies. Cores past
    /// `core_count` are retired at EBS with the unassigned SMT siblings.
    pub physical_count: u32,
    pub selected: [u32; topology::MAX_CORES],
    pub snapshots: [Snapshot; topology::MAX_CORES],
    pub processors: [Processor],
}

impl Capture {
    /// Layout of a record holding `processors` inventory entries.
    pub(crate) fn layout(processors: usize) -> Option<Layout> {
        let header = Layout::new::<Header>();
        let (layout, _) = header
            .extend(Layout::array::<Processor>(processors).ok()?)
            .ok()?;
        Some(layout.pad_to_align())
    }

    /// # Safety
    /// `base` addresses at least `layout(processors)` bytes, suitably aligned,
    /// that stay valid and unaliased by writers for `'a`.
    pub(crate) unsafe fn from_raw<'a>(base: *const u8, processors: usize) -> &'a Self {
        // SAFETY: forwarded caller contract; the slice metadata is the tail length.
        unsafe {
            &*(ptr::slice_from_raw_parts(base.cast::<Processor>(), processors) as *const Self)
        }
    }

    /// The record at `base`, with the tail length its header records.
    ///
    /// # Safety
    /// As `from_raw`, for the header's `processor_count`.
    pub(crate) unsafe fn read<'a>(base: *const u8) -> &'a Self {
        // SAFETY: the header-only view lies within the caller's record.
        let count = unsafe { Self::from_raw(base, 0) }.processor_count as usize;
        // SAFETY: forwarded caller contract.
        unsafe { Self::from_raw(base, count) }
    }

    /// # Safety
    /// As `from_raw`, with exclusive access for `'a`.
    pub(crate) unsafe fn from_raw_mut<'a>(base: *mut u8, processors: usize) -> &'a mut Self {
        // SAFETY: forwarded caller contract; the slice metadata is the tail length.
        unsafe {
            &mut *(ptr::slice_from_raw_parts_mut(base.cast::<Processor>(), processors) as *mut Self)
        }
    }

    /// A zeroed record with `processors` inventory entries.
    #[cfg(test)]
    pub(crate) fn boxed(processors: usize) -> alloc::boxed::Box<Self> {
        let layout = Self::layout(processors).unwrap();
        // SAFETY: nonzero layout; all-zero is valid for this record of
        // integers, booleans and arrays. Box frees with `Layout::for_value`,
        // which equals `layout` for this tail length.
        unsafe {
            let base = alloc::alloc::alloc_zeroed(layout);
            assert!(!base.is_null());
            let record = Self::from_raw_mut(base, processors);
            assert_eq!(Layout::for_value(record), layout);
            alloc::boxed::Box::from_raw(record)
        }
    }
}

/// The fixed prefix of `Capture`, for layout arithmetic.
#[repr(C)]
struct Header {
    magic: u64,
    version: u32,
    processor_count: u32,
    core_count: u32,
    enabled_count: u32,
    physical_count: u32,
    selected: [u32; topology::MAX_CORES],
    snapshots: [Snapshot; topology::MAX_CORES],
    processors: [Processor; 0],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_takes_the_inventory_length_from_the_header() {
        for count in [1, 256, 640] {
            let mut record = Capture::boxed(count);
            record.processor_count = count as u32;
            record.processors[count - 1].apic_id = 77;
            let base = (&raw const *record).cast::<u8>();
            // SAFETY: the boxed record holds `count` entries and outlives the view.
            let view = unsafe { Capture::read(base) };
            assert_eq!(view.processors.len(), count);
            assert_eq!(view.processors[count - 1].apic_id, 77);
            assert_eq!(
                Capture::layout(count).unwrap().size(),
                size_of_val::<Capture>(view)
            );
        }
    }
}
