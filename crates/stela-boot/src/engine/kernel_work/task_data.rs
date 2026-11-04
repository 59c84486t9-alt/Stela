//! Storage lifetime for original task accounting fields.
use super::*;
use crate::native_memory::{self, HeapPin};
use stela_boot_core::native_memory::PAGE;
use stela_linux::threads::{TaskDataBacking, TaskDataStorage};

struct Backing {
    _root: Arc<Reservation>,
    _heap_pin: HeapPin,
    heap: Range<usize>,
    image: Vec<Range<usize>>,
}

// SAFETY: Reservation keeps the actual relocated code/DATA and original
// loader table backing; HeapPin keeps that same boot's allocator generation.
// The loader allocation is kept through the engine lifetime. Neither owner
// has a Queue, Runtime, KernelOwner, binding or execution-borrow edge. This
// validates membership only; the original C task reference is independent.
unsafe impl TaskDataBacking for Backing {
    fn contains(&self, storage: TaskDataStorage, span: Range<usize>) -> bool {
        if span.is_empty() {
            return false;
        }
        let inside = |range: &Range<usize>| range.start <= span.start && span.end <= range.end;
        match storage {
            TaskDataStorage::InitialImage => self.image.iter().any(inside),
            TaskDataStorage::AllocatedTask => inside(&self.heap),
        }
    }
}

impl KernelWork {
    pub(in crate::engine) fn task_data(&self) -> Result<Arc<dyn TaskDataBacking>, Error> {
        self.dispatch(|_| {
            let root = &self.reservation;
            let loader = &root._handoff.native_loader_tables;
            let scope = root.identity.process_root().map_err(Error::Work)?;
            scope.entered_original(loader).map_err(Error::Work)?;
            // SAFETY: this checked root is the original live heap owner, with
            // same-BSP IRQ and registration replacement excluded by dispatch.
            let heap_pin = unsafe { native_memory::pin_heap() }.map_err(Error::Cache)?;
            let heap = heap_pin.registration();
            let owned = root._handoff.heap;
            if heap.cpu as u64 != layout::physical(owned.physical)
                || heap.physical != owned.physical
                || heap.bytes as u64 != owned.bytes
                || !root._wire.loader_ram(owned.physical, owned.bytes)
            {
                return Err(Error::Inventory);
            }
            let heap_end = heap.cpu.checked_add(heap.bytes).ok_or(Error::Geometry)?;
            native_memory::cache::verify_writeback(
                heap.cpu as u64,
                heap.physical,
                heap.bytes,
                layout::physical(0),
            )
            .map_err(Error::Cache)?;
            // SAFETY: same entered loader root, kept immutable image headers.
            let ranges = unsafe { root._image.writable_data_ranges() }.map_err(Error::Image)?;
            let mut image = Vec::new();
            image
                .try_reserve_exact(ranges.len())
                .map_err(|_| Error::Allocation)?;
            for (span, physical) in ranges {
                for address in span.clone().step_by(PAGE) {
                    let page = scope
                        .observe_original(address as u64)
                        .map_err(Error::Work)?
                        .ok_or(Error::Qualification)?;
                    if page.physical != physical + (address - span.start) as u64
                        || page.user
                        || !page.writable
                        || !page.nx
                    {
                        return Err(Error::Qualification);
                    }
                }
                native_memory::cache::verify_writeback(
                    span.start as u64,
                    physical,
                    span.len(),
                    layout::physical(0),
                )
                .map_err(Error::Cache)?;
                image.push(span);
            }
            if image.is_empty() {
                return Err(Error::Inventory);
            }
            scope.entered_original(loader).map_err(Error::Work)?;
            let backing: Arc<dyn TaskDataBacking> = Arc::new(Backing {
                _root: root.clone(),
                _heap_pin: heap_pin,
                heap: heap.cpu..heap_end,
                image,
            });
            Ok(backing)
        })?
    }
}
