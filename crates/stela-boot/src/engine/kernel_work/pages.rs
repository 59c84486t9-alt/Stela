//! Task-slot coverage in the one Linux page descriptor owner.
use super::*;
use crate::native_memory::LinuxPages as HeapPages;
use core::ptr::NonNull;
use stela_drivers::{
    bus::dma::memory::PinnedPages,
    gpu::linux::pages::{
        Catalog, Extent, PinRetirement, Provider, Request, Reservation as PageReservation,
    },
};

#[derive(Clone, Copy)]
struct Coverage {
    cpu: usize,
    physical: u64,
    pages: usize,
}
/// Immutable coverage holds the original allocation claim and checked roots.
/// It contains neither Runtime nor a worker/frame execution permission.
pub(super) struct TaskPageInventory {
    owner: Arc<Reservation>,
    rows: Vec<Coverage>,
}
pub(super) struct KernelPages {
    heap: HeapPages,
    stacks: TaskPageInventory,
}
impl TaskPageInventory {
    pub(super) fn from_spans(
        owner: Arc<Reservation>,
        spans: &[(Range<usize>, Range<usize>, u64)],
    ) -> Result<Self, Error> {
        let required = stela_drivers::gpu::linux::task::stack_requirement().map_err(Error::Work)?;
        let mut rows = Vec::new();
        for (bounds, guard, physical) in spans {
            if bounds.len() != required.usable_bytes()
                || !bounds.start.is_multiple_of(required.alignment())
                || !physical.is_multiple_of(required.usable_bytes() as u64)
                || guard.len() < required.minimum_guard_bytes()
            {
                continue;
            }
            if !owner.allocation.contains(*physical, bounds.len() as u64) {
                return Err(Error::Inventory);
            }
            rows.try_reserve(1).map_err(|_| Error::Allocation)?;
            rows.push(Coverage {
                cpu: bounds.start,
                physical: *physical,
                pages: bounds.len() / 4096,
            });
        }
        Ok(Self { owner, rows })
    }
    fn check(&self) -> Result<(), WorkError> {
        self.owner.identity.check_irq_cpu()?;
        if self.owner.identity.in_interrupt() {
            return Err(WorkError::InterruptContext);
        }
        Ok(())
    }
    pub(super) fn count(&self) -> usize {
        self.rows.len()
    }
    fn retained_copy(&self) -> Result<Self, Error> {
        self.check().map_err(Error::Work)?;
        if self.rows.is_empty() {
            return Err(Error::NoKernelStacks);
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.rows.len())
            .map_err(|_| Error::Allocation)?;
        rows.extend_from_slice(&self.rows);
        Ok(Self {
            owner: self.owner.clone(),
            rows,
        })
    }
    /// # Safety
    /// Serialized native process/deferred context excludes C reentry, migration,
    /// root/cache mutation and source retargeting through catalog retirement.
    /// This is taskless metadata entry; a taskful C caller must use its
    /// entered-owner boundary rather than reentering this leaf constructor.
    pub(super) unsafe fn register(self) -> Result<Catalog<KernelPages>, Error> {
        self.check().map_err(Error::Work)?;
        if self.rows.is_empty() {
            return Err(Error::NoKernelStacks);
        }
        // SAFETY: native heap generation is initialized and remains
        // excluded from retargeting through its returned provider guard.
        let (heap, ordinary) =
            unsafe { crate::native_memory::linux_page_source() }.map_err(Error::Pages)?;
        let capacity = self.rows.len().checked_add(1).ok_or(Error::Allocation)?;
        let mut extents = Vec::new();
        extents
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Allocation)?;
        extents.push(Extent::ordinary(ordinary));
        for row in &self.rows {
            let cpu = NonNull::new(row.cpu as *mut u8).ok_or(Error::Inventory)?;
            // SAFETY: these exact bounds/PA pairs came from prepare_plan's
            // all-root/WB/guard checks. The same original allocation claim and
            // RootIdentity stay held in this inventory through quarantine.
            let reservation = unsafe { PageReservation::new(row.physical, cpu, row.pages) }
                .map_err(Error::Pages)?;
            extents.push(Extent::runtime_stack(reservation));
        }
        let provider = KernelPages { heap, stacks: self };
        // SAFETY: provider owns both heap-generation and task allocation/
        // mapping lifetimes. Ordinary allocation delegates only to heap pages;
        // RuntimeStack coverage stays reserved and supplies no payload loan.
        unsafe { Catalog::register_annotated(provider, extents) }.map_err(Error::Pages)
    }
}
// SAFETY: NativeMemory heap pins keep its generation and WB mappings.
// Stack coverage independently keeps the original firmware allocation claim
// and all checked roots. Only the heap provides ordinary allocations, with
// its original flag/context checks. Final release remains serialized; unknown
// CPU/IRQ/root context keeps pins instead of acknowledging their release.
unsafe impl Provider for KernelPages {
    fn validate(&self, request: Request) -> Result<(), MemoryError> {
        self.stacks.check().map_err(|_| MemoryError::Unavailable)?;
        self.heap.validate(request)
    }
    fn allocate(&self, request: Request) -> Result<PinnedPages, MemoryError> {
        self.validate(request)?;
        self.heap.allocate(request)
    }
    fn retirement(&self, pin: &PinnedPages) -> PinRetirement {
        if self.stacks.check().is_err() {
            PinRetirement::Retain
        } else {
            self.heap.retirement(pin)
        }
    }
}
impl KernelWork {
    /// Keep only C-compatible slot coverage. Uniform128K-only pools
    /// report NoKernelStacks. This supplies descriptors, not cold-worker access;
    /// the work owner's entered history still rejects hot-frame preparation.
    pub(super) fn task_pages(&self) -> Result<TaskPageInventory, Error> {
        self.stack_pages.retained_copy()
    }
}
