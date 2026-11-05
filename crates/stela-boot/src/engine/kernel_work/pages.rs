//! Task-slot coverage in the one Linux page descriptor owner.
use super::*;
use crate::native_memory::LinuxPages as HeapPages;
use core::ptr::NonNull;
use stela_drivers::bus::dma::memory::PinnedPages;
use stela_linux::pages::{
    Catalog, Extent, PinRetirement, Provider, Request, Reservation as PageReservation,
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
pub(in crate::engine) struct KernelPages {
    heap: HeapPages,
    stacks: TaskPageInventory,
}
impl TaskPageInventory {
    pub(super) fn from_spans(
        owner: Arc<Reservation>,
        spans: &[(Range<usize>, Range<usize>, u64)],
    ) -> Result<Self, Error> {
        let required = stela_linux::task::stack_requirement().map_err(Error::Work)?;
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
        self.owner.identity.check_clock_root()?;
        if self.owner.identity.in_interrupt() {
            return Err(WorkError::InterruptContext);
        }
        Ok(())
    }
    #[cfg(feature = "diagnostics")]
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
    /// Actual loader-root BSP owns these allocations through retirement.
    #[cfg(feature = "diagnostics")]
    pub(super) unsafe fn register(self) -> Result<Catalog<KernelPages>, Error> {
        // SAFETY: original task and heap allocations are retained.
        let (provider, extents) = unsafe { self.into_inventory() }?;
        // SAFETY: diagnostic owns the taskless legacy entry for this boot.
        unsafe { Catalog::register_annotated(provider, extents) }.map_err(Error::Pages)
    }

    /// # Safety
    /// Serialized native process/deferred context excludes C reentry, migration,
    /// root/cache mutation and source retargeting through catalog retirement.
    /// This is taskless metadata entry; a taskful C caller must use its
    /// entered-owner boundary rather than reentering this leaf constructor.
    unsafe fn into_inventory(self) -> Result<(KernelPages, Vec<Extent>), Error> {
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
        Ok((KernelPages { heap, stacks: self }, extents))
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
    /// Keep only C-compatible slot coverage. Generic-only pools
    /// report NoKernelStacks. This supplies descriptors, not cold-worker access;
    /// the work owner's entered history still rejects hot-frame preparation.
    pub(super) fn task_pages(&self) -> Result<TaskPageInventory, Error> {
        self.stack_pages
            .as_ref()
            .ok_or(Error::NoKernelStacks)?
            .retained_copy()
    }

    /// Publish the original heap and guarded runtime-stack descriptors under
    /// the already claimed kernel before its first source task is published.
    ///
    /// # Safety
    /// Inside this work owner's admitted native Linux dispatcher segment,
    /// with this exact kernel and no active source entry or task.
    pub(in crate::engine) unsafe fn register_linux_pages<K: stela_linux::owner::Platform>(
        &self,
        kernel: &stela_linux::kernel::KernelOwner<K, SLOTS>,
    ) -> Result<&'static Catalog<KernelPages>, Error> {
        let pages = self.task_pages()?;
        // SAFETY: exact retained heap and slot allocations on the loader root.
        let (provider, extents) = unsafe { pages.into_inventory() }?;
        // SAFETY: exact claimed owner on this taskless dispatcher before
        // Initial. Provider keeps the actual backing through publication.
        let catalog = unsafe { Catalog::register_annotated_bootstrap(kernel, provider, extents) }
            .map_err(Error::Pages)?;
        Ok(&*Box::leak(Box::new(catalog)))
    }
}
