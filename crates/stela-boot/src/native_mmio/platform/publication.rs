//! RAM-only publication capability shared with the actual MMIO root authority.
//! Candidate child module of native_mmio::platform; not admitted boot source.
//! It owns no second root catalog and never interprets UC device permissions
//! as RAM ownership. Callers supply genuine PageSource pins and retain every
//! referenced data/table pin through quiescence, unmap and TLB acknowledgement.
use super::*;
use core::{mem::ManuallyDrop, ops::Range, sync::atomic::AtomicUsize};
use stela_drivers::bus::dma::memory::{CpuMapping, PinnedPages};

const STACK_OFFSET: u64 = 0x6_0000_0000;
const STACK_BYTES: u64 = 1 << 30;
const ACCESSED: u64 = 1 << 5;
static QUARANTINED_PUBLICATIONS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Eq, PartialEq)]
struct Parent {
    table: u64,
    index: usize,
}
struct ParentPin {
    physical: u64,
    pages: PinnedPages,
}
#[derive(Default)]
struct ParentPins {
    published: Option<ParentPin>,
    retiring: Option<PinnedPages>,
}
struct Inner {
    platform: ManuallyDrop<Arc<Platform>>,
    scope: ManuallyDrop<Arc<RootProcessScope>>,
    authority: ManuallyDrop<Authority>,
    parent: Parent,
    window: Range<u64>,
    armed: AtomicBool,
    pins: ManuallyDrop<UnsafeCell<ParentPins>>,
}
// SAFETY: immutable source/scope metadata can be retained on any CPU. Every
// effect rejects foreign contexts before accessing the owner-local tables.
// Parent pin state is touched only with the SAME Platform::held lock and IRQs
// disabled. Neither capability moves the original !Send HostOwner.
unsafe impl Send for Inner {}
// SAFETY: the same immutable metadata and held/IRQ exclusion protect sharing.
unsafe impl Sync for Inner {}

fn quarantine() {
    let _ = QUARANTINED_PUBLICATIONS.try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(1))
    });
}
fn shared_parent(platform: &Platform, first: u64) -> Result<Parent, Error> {
    let mut common = None;
    for root in platform.resources._roots.roots() {
        let mut table = *root;
        for level in (3..platform.resources.wire.levels).rev() {
            let index = ((first >> (12 + 9 * level)) & 511) as usize;
            // SAFETY: actual retained LOADER_DATA table; index is bounded.
            let value = unsafe { platform.table(table)?.add(index).read_volatile() };
            if value & (PRESENT | WRITABLE | HUGE | (1 << 3) | (1 << 4)) != (PRESENT | WRITABLE) {
                return Err(Error::Unavailable);
            }
            table = value & ADDRESS;
        }
        let parent = Parent {
            table,
            index: ((first >> 30) & 511) as usize,
        };
        if common
            .replace(parent)
            .is_some_and(|previous| previous != parent)
        {
            return Err(Error::Unavailable);
        }
    }
    common.ok_or(Error::Unavailable)
}
impl Inner {
    fn check_current(&self) -> Result<(), Error> {
        self.platform.check_context(self.platform.space)?;
        self.scope.check().map_err(failed)
    }
    fn parent_slot(&self) -> Result<*mut u64, Error> {
        if shared_parent(&self.platform, self.window.start)? != self.parent {
            return Err(Error::Unavailable);
        }
        Ok(self
            .platform
            .table(self.parent.table)?
            .wrapping_add(self.parent.index))
    }
}

/// Unique source-qualified RAM page-table publisher for one reserved one-GiB
/// stack window. A live capability or QualifiedRam prevents Source::Session closing.
pub(crate) struct RootPublication {
    inner: Arc<Inner>,
}
/// Genuine original WB RAM and CPU mapping, qualified in this exact root epoch.
/// This grants no device, DMA, IOVA, VRAM or WC authority. Safe Drop alone does
/// not remove page-table references: the actual RAM mapper owns that unsafe
/// publication/retirement obligation and keeps these pins until acknowledged.
pub(crate) struct QualifiedRam {
    pages: ManuallyDrop<PinnedPages>,
    mapping: ManuallyDrop<CpuMapping>,
    cpu: usize,
    bytes: usize,
    physical: ManuallyDrop<Vec<u64>>,
    owner: ManuallyDrop<Arc<Inner>>,
}
impl QualifiedRam {
    /// Original pin for outside-guard ownership/alias operations only.
    pub(crate) fn pages(&self) -> &PinnedPages {
        &self.pages
    }
    /// Cached immutable metadata: no PageBacking callback.
    pub(crate) fn physical_pages(&self) -> &[u64] {
        &self.physical
    }
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
    pub(crate) fn cpu_address(&self, offset: usize, bytes: usize) -> Result<NonNull<u8>, Error> {
        self.owner.check_current()?;
        if bytes == 0 || offset.checked_add(bytes).is_none_or(|end| end > self.bytes) {
            return Err(Error::InvalidRange);
        }
        let cpu = self.cpu.checked_add(offset).ok_or(Error::InvalidRange)?;
        NonNull::new(cpu as *mut u8).ok_or(Error::InvalidPlatformReply)
    }
}
impl Drop for QualifiedRam {
    fn drop(&mut self) {
        if self.owner.check_current().is_err() {
            // Retain original physical/CPU pins AND the publication/scope;
            // no affine or allocator release occurs on a foreign CPU/ISR.
            quarantine();
            return;
        }
        // SAFETY: qualified process context. The actual RAM mapper's unsafe
        // publication contract requires all references/TLBs to be retired
        // before it releases its last QualifiedRam, including error paths.
        unsafe {
            ManuallyDrop::drop(&mut self.mapping);
            ManuallyDrop::drop(&mut self.pages);
            ManuallyDrop::drop(&mut self.physical);
            ManuallyDrop::drop(&mut self.owner);
        }
    }
}
impl RootPublication {
    pub(crate) fn window(&self) -> Range<u64> {
        self.inner.window.clone()
    }
    /// Cache encoding for NEW WB RAM leaves. Source activation observes PAT0
    /// as architectural WB, and every check preserves that exact actual PAT.
    pub(crate) fn writeback_leaf_bits(&self) -> Result<u64, Error> {
        self.check_current()?;
        if self.inner.platform.snapshot.pat as u8 != 6 {
            return Err(Error::UnsupportedCache);
        }
        Ok(0)
    }
    pub(crate) fn authority(&self) -> &Authority {
        &self.inner.authority
    }
    pub(crate) fn check_current(&self) -> Result<(), Error> {
        self.inner.check_current()
    }

    /// Qualify before acquiring a publication guard: the existing cache
    /// decoder may allocate bounded observation metadata. The caller supplies
    /// real native PageSource pins, never an address tuple or synthetic backing.
    pub(crate) fn qualify(&self, pages: &PinnedPages) -> Result<QualifiedRam, Error> {
        self.check_current()?;
        if pages.cache_attribute() != CacheAttribute::WriteBack || pages.page_shift() != 12 {
            return Err(Error::UnsupportedCache);
        }
        let bytes = pages.bytes();
        let mut physical = Vec::new();
        let observed = pages.physical_pages();
        physical.try_reserve_exact(observed.len()).map_err(failed)?;
        physical.extend_from_slice(observed);
        let mapping = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(failed)?;
        let cpu = mapping.address(0, bytes).map_err(failed)?.as_ptr() as usize;
        for (index, physical) in physical.iter().copied().enumerate() {
            if !self.inner.platform.resources.wire.table_owned(physical) {
                return Err(Error::OutsideResource);
            }
            let address = cpu
                .checked_add(
                    index
                        .checked_mul(PAGE as usize)
                        .ok_or(Error::InvalidRange)?,
                )
                .ok_or(Error::InvalidRange)?;
            crate::native_memory::cache::verify_writeback(
                address as u64,
                physical,
                PAGE as usize,
                crate::layout::physical(0),
            )
            .map_err(failed)?;
        }
        self.check_current()?;
        Ok(QualifiedRam {
            pages: ManuallyDrop::new(pages.clone()),
            mapping: ManuallyDrop::new(mapping),
            cpu,
            bytes,
            physical: ManuallyDrop::new(physical),
            owner: ManuallyDrop::new(self.inner.clone()),
        })
    }
    pub(crate) fn acquire(&self) -> Result<PublicationGuard<'_>, Error> {
        self.check_current()?;
        let flags = self.inner.platform.context.save_disable().map_err(failed)?;
        let lock = match self.inner.platform.lock() {
            Ok(lock) => lock,
            Err(error) => {
                // SAFETY: exact enclosing same-CPU save, no publication.
                unsafe { self.inner.platform.context.restore(flags) };
                return Err(error);
            }
        };
        Ok(PublicationGuard {
            inner: &self.inner,
            lock: Some(lock),
            flags,
            retired: None,
            _local: PhantomData,
        })
    }
}

/// Same physical CPU, actual process scope and the MMIO authority's single
/// publication lock. No allocation, waiting, callback or switch while retained.
#[must_use]
pub(crate) struct PublicationGuard<'a> {
    inner: &'a Inner,
    lock: Option<super::Guard<'a>>,
    flags: u64,
    retired: Option<PinnedPages>,
    _local: PhantomData<*mut ()>,
}
impl PublicationGuard<'_> {
    pub(crate) fn parent_value(&self) -> Result<u64, Error> {
        self.inner.check_current()?;
        // SAFETY: exact retained shared parent and bounded slot, under held.
        Ok(unsafe { self.inner.parent_slot()?.read_volatile() })
    }
    pub(crate) fn table(&self, pages: &QualifiedRam) -> Result<NonNull<u64>, Error> {
        self.inner.check_current()?;
        if !ptr::eq(self.inner, &**pages.owner) || pages.bytes != PAGE as usize {
            return Err(Error::OutsideResource);
        }
        pages.cpu_address(0, PAGE as usize).map(NonNull::cast)
    }
    /// Publish/clear only the fixed shared parent. Returns the NEW canonical
    /// value written; hardware A is ignored only when comparing expectations.
    /// A removed table pin remains owned until flush_root succeeds.
    ///
    /// # Safety
    /// No old/new stack or table user can race this parent transition. New
    /// child entries reference only caller-retained QualifiedRam WB pages,
    /// with supervisor RW+NX leaves and an actually absent stack guard. All
    /// pins remain retained through unmap and actual TLB acknowledgement.
    pub(crate) unsafe fn replace_parent(
        &mut self,
        expected: u64,
        table: Option<&QualifiedRam>,
    ) -> Result<u64, Error> {
        self.inner.check_current()?;
        if self.retired.is_some() {
            return Err(Error::Busy);
        }
        let slot = self.inner.parent_slot()?;
        // SAFETY: the same concrete root/slot under exclusive held and IRQ-save.
        let observed = unsafe { slot.read_volatile() };
        if observed & !ACCESSED != expected & !ACCESSED {
            return Err(Error::Busy);
        }
        let next_pin = if let Some(table) = table {
            self.table(table)?;
            if observed != 0 {
                return Err(Error::ResourceConflict);
            }
            Some(ParentPin {
                physical: table.physical[0],
                pages: table.pages().clone(),
            })
        } else {
            None
        };
        let next = next_pin
            .as_ref()
            .map_or(0, |pin| pin.physical | PRESENT | WRITABLE);
        // SAFETY: ParentPins is accessed only through this same held guard;
        // no reference crosses a callback/switch or another method borrow.
        let pins = unsafe { &mut *self.inner.pins.get() };
        if pins.retiring.is_some() {
            return Err(Error::Busy);
        }
        let owned = pins
            .published
            .as_ref()
            .map_or(0, |pin| pin.physical | PRESENT | WRITABLE);
        if observed & !ACCESSED != owned {
            return Err(Error::Unavailable);
        }
        pins.retiring = pins.published.take().map(|pin| pin.pages);
        pins.published = next_pin;
        // SAFETY: all checks and pin retention precede this primitive store;
        // the exact WB shared parent is owned and no fallible work intervenes.
        unsafe { slot.write_volatile(next) };
        Ok(next)
    }
    /// # Safety
    /// Caller published/cleared only its retained WB stack mappings. Every
    /// user is excluded until this actual acknowledgement completes.
    pub(crate) unsafe fn invalidate(&mut self, first: u64, bytes: u64) -> Result<(), Error> {
        self.inner.check_current()?;
        let end = first.checked_add(bytes).ok_or(Error::InvalidRange)?;
        if bytes == 0
            || !first.is_multiple_of(PAGE)
            || !bytes.is_multiple_of(PAGE)
            || first < self.inner.window.start
            || end > self.inner.window.end
        {
            return Err(Error::InvalidRange);
        }
        // SAFETY: qualified one-CPU CPL0, complete range preflighted, PGE/PCID
        // remain disabled. Inactive roots flush before their next CR3 entry.
        unsafe {
            asm!("mfence", options(nostack, preserves_flags));
            for address in (first..end).step_by(PAGE as usize) {
                asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags));
            }
            asm!("mfence", options(nostack, preserves_flags));
        }
        self.inner.check_current()
    }
    /// # Safety
    /// Actual consumers are stopped; cleared parent/child entries cannot be
    /// republished concurrently. All pins remain retained until success.
    pub(crate) unsafe fn flush_root(&mut self) -> Result<(), Error> {
        self.inner.check_current()?;
        if self.retired.is_some() {
            return Err(Error::Busy);
        }
        // SAFETY: actual captured current root, one CPU and PGE/PCID clear;
        // reload invalidates paging-structure caches as well as leaf TLBs.
        unsafe {
            asm!("mfence", "mov cr3, {}", in(reg) self.inner.platform.snapshot.cr3,
                options(nostack, preserves_flags));
        }
        self.inner.check_current()?;
        // SAFETY: same held guard, and full-root acknowledgement succeeded.
        self.retired = unsafe { &mut *self.inner.pins.get() }.retiring.take();
        Ok(())
    }
}
impl Drop for PublicationGuard<'_> {
    fn drop(&mut self) {
        if self.inner.check_current().is_err() {
            self.inner
                .platform
                .context
                .fatal(stela_drivers::platform::work::WorkError::CorruptContext);
        }
        drop(self.lock.take());
        // SAFETY: exact enclosing save on the same actual physical CPU.
        unsafe { self.inner.platform.context.restore(self.flags) };
        // Final backing release follows unlock and exact original IRQ restoration.
        drop(self.retired.take());
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if !self.armed.load(Ordering::Acquire) {
            // SAFETY: never published; construction retained no PTE pin.
            unsafe {
                ManuallyDrop::drop(&mut self.pins);
                ManuallyDrop::drop(&mut self.authority);
                ManuallyDrop::drop(&mut self.scope);
                ManuallyDrop::drop(&mut self.platform);
            }
            return;
        }
        if self.check_current().is_err() {
            quarantine();
            return;
        }
        let flags = match self.platform.context.save_disable() {
            Ok(flags) => flags,
            Err(_) => {
                quarantine();
                return;
            }
        };
        let lock = match self.platform.lock() {
            Ok(lock) => lock,
            Err(_) => {
                // SAFETY: exact same-CPU save, no source change.
                unsafe { self.platform.context.restore(flags) };
                quarantine();
                return;
            }
        };
        // SAFETY: final owner and the same publication lock. All child pins
        // also retain Inner, so final Drop cannot precede their final release.
        let pins = unsafe { &*self.pins.get() };
        let empty = self.parent_slot().is_ok_and(|slot| {
            // SAFETY: actual retained shared-parent slot, under held.
            unsafe { slot.read_volatile() == 0 }
        }) && pins.published.is_none()
            && pins.retiring.is_none();
        if empty {
            self.platform.ram_publisher.store(false, Ordering::Release);
        }
        drop(lock);
        // SAFETY: exact enclosing physical-CPU save.
        unsafe { self.platform.context.restore(flags) };
        if !empty {
            quarantine();
            return;
        }
        // SAFETY: qualified final context, actual parent empty and all table
        // retirement acknowledgements complete. No resource release under held.
        unsafe {
            ManuallyDrop::drop(&mut self.pins);
            ManuallyDrop::drop(&mut self.authority);
            ManuallyDrop::drop(&mut self.scope);
            ManuallyDrop::drop(&mut self.platform);
        }
    }
}

impl Source {
    /// Bind the SAME actual root catalog and publication lock to a RAM-only
    /// provider. This is not a new host owner, device grant or root activation.
    pub(crate) fn root_publication(
        &self,
        execution: &RootExecution,
    ) -> Result<RootPublication, Error> {
        self.platform.check_context(self.platform.space)?;
        if self.platform.ram_publisher.load(Ordering::Acquire) {
            return Err(Error::Busy);
        }
        let scope = execution.process_scope().map_err(failed)?;
        let context = scope.context();
        if !Arc::ptr_eq(context, &self.platform.context) {
            return Err(Error::Unavailable);
        }
        let first = crate::layout::window()
            .checked_add(STACK_OFFSET)
            .ok_or(Error::InvalidRange)?;
        let end = first.checked_add(STACK_BYTES).ok_or(Error::InvalidRange)?;
        let parent = shared_parent(&self.platform, first)?;
        crate::native_memory::cache::verify_writeback(
            crate::layout::physical(parent.table),
            parent.table,
            PAGE as usize,
            crate::layout::physical(0),
        )
        .map_err(failed)?;
        // Required join changes inventory to accept an extra privately derived
        // write-table PA. It audits the same real roots, not another catalog.
        let _aliases = inventory(&self.platform, Some(parent.table))?;
        let inner = Arc::new(Inner {
            platform: ManuallyDrop::new(self.platform.clone()),
            scope: ManuallyDrop::new(scope),
            authority: ManuallyDrop::new(self.authority.clone()),
            parent,
            window: first..end,
            armed: AtomicBool::new(false),
            pins: ManuallyDrop::new(UnsafeCell::new(ParentPins::default())),
        });
        let publication = RootPublication { inner };
        {
            let guard = publication.acquire()?;
            if guard.parent_value()? != 0 {
                return Err(Error::ResourceConflict);
            }
            publication
                .inner
                .platform
                .ram_publisher
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| Error::Busy)?;
            publication.inner.armed.store(true, Ordering::Release);
        }
        Ok(publication)
    }
}
