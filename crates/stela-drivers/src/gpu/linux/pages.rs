//! Owned platform pins behind Linux's actual PFN-indexed page descriptors.
//! The catalog supplies no DMA mapping or GPU attachment. Its provider and
//! reservation survive until explicit retirement, or observable quarantine.
use crate::bus::dma::memory::{CacheAttribute, MemoryError, PinnedPages};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::{
    alloc::Layout,
    ffi::{c_int, c_void},
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::{self, NonNull},
    sync::atomic::{AtomicU64, Ordering},
};

const PAGE_SHIFT: u32 = 12;
const PAGE_BYTES: usize = 1 << PAGE_SHIFT;
// Linux's asm-generic errno ABI, independent of the hosted C library's errno.
const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;
const EOPNOTSUPP: c_int = 95;

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static QUARANTINED_CATALOGS: AtomicU64 = AtomicU64::new(0);

/// Catalogs whose Drop could not establish exclusive, fully retired ownership.
/// Their provider and descriptor storage remain retained; this is not a count
/// of reclaimed or reset resources.
pub fn quarantined_catalogs() -> u64 {
    QUARANTINED_CATALOGS.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidReservation,
    OutOfMemory,
    Busy,
    GenerationExhausted,
    Native(c_int),
}

/// The immutable physical and CPU span covered by a descriptor catalog.
/// Coverage grants no payload access; each allocation must supply a real pin.
#[derive(Clone, Copy)]
pub struct Reservation {
    physical_base: u64,
    cpu_base: NonNull<u8>,
    page_count: usize,
}

impl Reservation {
    /// # Safety
    /// This exact page-aligned RAM extent is exclusively reserved, excluded
    /// from guest/free inventories, and mapped linearly writable WB at cpu_base.
    /// The provider retains that reservation and mapping through catalog
    /// retirement or quarantine. It may allocate only from this generation;
    /// root changes cannot invalidate the mapping or retarget the provider.
    /// Ordinary heap/metadata addresses gain no Linux page ownership.
    pub unsafe fn new(
        physical_base: u64,
        cpu_base: NonNull<u8>,
        page_count: usize,
    ) -> Result<Self, Error> {
        let bytes = page_count
            .checked_mul(PAGE_BYTES)
            .filter(|bytes| *bytes != 0 && *bytes <= isize::MAX as usize)
            .ok_or(Error::InvalidReservation)?;
        if !physical_base.is_multiple_of(PAGE_BYTES as u64)
            || !(cpu_base.as_ptr() as usize).is_multiple_of(PAGE_BYTES)
            || physical_base.checked_add(bytes as u64).is_none()
            || (cpu_base.as_ptr() as usize).checked_add(bytes).is_none()
        {
            return Err(Error::InvalidReservation);
        }
        Ok(Self {
            physical_base,
            cpu_base,
            page_count,
        })
    }
}

/// A request made by unchanged Linux code. Flags keep Linux's exact bits.
#[derive(Clone, Copy, Debug)]
pub struct Request {
    pub gfp: u32,
    pub order: u32,
    pub atomic: bool,
}

impl Request {
    pub fn bytes(self) -> Option<usize> {
        1usize
            .checked_shl(PAGE_SHIFT.checked_add(self.order)?)
            .filter(|bytes| *bytes <= isize::MAX as usize)
    }

    /// The ordinary base-RAM policy defined with the pinned Linux GFP names.
    /// Zones, mobility/reclaimable pools, emergency reserves, no-fail and
    /// unknown flags are outside this policy. This is not an atomic grant.
    pub fn basic_ram(self) -> bool {
        // SAFETY: pure classification of a value using Linux's own constants.
        unsafe { stela_linux_page_request_basic(self.gfp) }
    }

    /// Reclaimable-class RAM with the otherwise ordinary flag policy.
    /// A provider must explicitly supply Linux's permitted unmovable fallback
    /// from its actual retained RAM. This grants no migration, background
    /// reclaim, atomic context or physical/DMA authority by itself.
    pub fn reclaimable_ram(self) -> bool {
        // SAFETY: pure classification using the pinned Linux GFP constants.
        unsafe { stela_linux_page_request_reclaimable(self.gfp) }
    }

    pub fn may_block(self) -> bool {
        // SAFETY: pure GFP classification; no platform or owner is accessed.
        unsafe { stela_linux_page_request_blocking(self.gfp) }
    }
}

/// Observation of the exact pin's final platform ownership fences.
/// Retain keeps the mapping, allocation markers and provider alive; it is not
/// a native stack/terminal acknowledgment or a permission token by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinRetirement {
    Ready,
    Retain,
}

/// A retained platform source, not an allocator that invents physical labels.
///
/// # Safety
/// Successful allocations meet PageBacking's real reservation/mapping contract
/// inside the registered generation. They are contiguous, zeroed WB base RAM,
/// aligned to their order-sized extent, with immutable metadata. The provider
/// enforces every request flag/context or returns Unavailable for an explicit
/// unsupported report. OutOfMemory means ordinary exhaustion, not unsupported
/// semantics. No callback reenters Linux, unwinds or migrates the execution
/// context. Allocation can run in the indicated atomic context; unsupported
/// contexts must be refused before any platform operation. Final pin release
/// occurs only at checked serialized quiescence. The owned provider retains
/// its source generation even if a busy catalog is quarantined. Pins with
/// additional native/task/RCU lifetimes override `retirement` and retain until
/// those actual owners acknowledge; C logical free alone is insufficient.
/// Another
/// serialized native owner may invoke it; no creator-thread affinity is assumed.
pub unsafe trait Provider: Send + Sync + 'static {
    /// Pure preflight before metadata/backing allocation. Success also attests
    /// the canonical global metadata heap for this exact request/context.
    fn validate(&self, request: Request) -> Result<(), MemoryError>;

    fn allocate(&self, request: Request) -> Result<PinnedPages, MemoryError>;

    /// Observe final ownership after C's logical page references have ended.
    /// This callback must not allocate, block, reenter Linux or change its
    /// execution state. The default applies to ordinary pins whose final
    /// PageBacking release is valid at that point. A future external Runtime
    /// stack provider must retain until its genuine native/stackref/task/RCU
    /// fences acknowledge; C free alone cannot establish that observation.
    fn retirement(&self, _pages: &PinnedPages) -> PinRetirement {
        PinRetirement::Ready
    }
}

#[repr(C)]
struct NativeReservation {
    generation: u64,
    physical_base: u64,
    cpu_base: *mut c_void,
    page_count: usize,
}

#[repr(C)]
struct NativeAllocation {
    pin: *mut c_void,
    cpu_base: *mut c_void,
    physical_pages: *const u64,
    page_count: usize,
}

#[repr(C)]
struct Operations {
    validate: unsafe extern "C" fn(*mut c_void, u32, u32, bool) -> c_int,
    allocate: unsafe extern "C" fn(*mut c_void, u32, u32, bool, *mut NativeAllocation) -> c_int,
    release: unsafe extern "C" fn(*mut c_void, *mut c_void),
}

#[repr(C)]
struct OperationsV2 {
    version: u32,
    bytes: u32,
    ordinary: Operations,
    release_ready: unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool,
}

unsafe extern "C" {
    static stela_linux_bare: u8;
    fn stela_linux_try_enter(owner: *const c_void) -> bool;
    fn stela_linux_exit();
    fn stela_linux_page_catalog_register_extents_v2(
        reservations: *const NativeReservation,
        reservation_count: usize,
        operations: *const OperationsV2,
        context: *mut c_void,
    ) -> c_int;
    fn stela_linux_page_catalog_unregister(generation: u64) -> c_int;
    fn stela_linux_page_catalog_verify(generation: u64) -> c_int;
    fn stela_linux_page_request_basic(gfp: u32) -> bool;
    fn stela_linux_page_request_reclaimable(gfp: u32) -> bool;
    fn stela_linux_page_request_blocking(gfp: u32) -> bool;
}

struct Entered;
impl Entered {
    fn try_new() -> Result<Self, Error> {
        // SAFETY: only the address of the original C owner is used. A failed
        // try-enter touches no borrowed owner and never waits recursively.
        if unsafe { stela_linux_try_enter(ptr::addr_of!(stela_linux_bare).cast()) } {
            Ok(Self)
        } else {
            Err(Error::Busy)
        }
    }
}
impl Drop for Entered {
    fn drop(&mut self) {
        // SAFETY: this guard owns the successful nonreentrant entry; all local
        // C operations ended before exit settles RCU and retired backing pins.
        unsafe { stela_linux_exit() };
    }
}

struct Context<P> {
    provider: P,
    reservations: Vec<Reservation>,
}

struct Pin {
    pages: PinnedPages,
}

fn try_box<T>(value: T) -> Result<Box<T>, Error> {
    let layout = Layout::new::<T>();
    let pointer = if layout.size() == 0 {
        NonNull::<T>::dangling()
    } else {
        // SAFETY: a checked nonzero layout for T, with ordinary global ownership.
        NonNull::new(unsafe { alloc::alloc::alloc(layout) })
            .ok_or(Error::OutOfMemory)?
            .cast::<T>()
    };
    // SAFETY: fresh aligned storage (or the standard ZST dangling allocation),
    // initialized exactly once. Box owns the exact original global layout.
    Ok(unsafe {
        pointer.as_ptr().write(value);
        Box::from_raw(pointer.as_ptr())
    })
}

fn allocation_error(error: MemoryError) -> c_int {
    -match error {
        MemoryError::OutOfMemory => ENOMEM,
        MemoryError::Unavailable | MemoryError::CacheAttributeUnavailable => EOPNOTSUPP,
        _ => EINVAL,
    }
}

unsafe extern "C" fn allocate<P: Provider>(
    context: *mut c_void,
    gfp: u32,
    order: u32,
    atomic: bool,
    output: *mut NativeAllocation,
) -> c_int {
    // SAFETY: the catalog retains this exact typed provider through callbacks.
    let context = unsafe { &*context.cast::<Context<P>>() };
    let request = Request { gfp, order, atomic };
    if let Err(error) = context.provider.validate(request) {
        return allocation_error(error);
    }
    let Some(bytes) = request.bytes() else {
        return -EINVAL;
    };
    // Reserve the token before asking the platform for RAM. An error transfers
    // nothing and drops this uninitialized metadata without touching a Pin.
    let mut storage = match try_box(MaybeUninit::<Pin>::uninit()) {
        Ok(storage) => storage,
        Err(_) => return -ENOMEM,
    };
    let pages = match context.provider.allocate(request) {
        Ok(pages) => pages,
        Err(error) => return allocation_error(error),
    };
    if pages.page_shift() != PAGE_SHIFT as u8
        || pages.bytes() != bytes
        || pages.logical_bytes() != bytes
        || pages.cache_attribute() != CacheAttribute::WriteBack
    {
        return -EINVAL;
    }
    let cpu = match pages
        .cpu_mapping(CacheAttribute::WriteBack)
        .and_then(|mapping| mapping.address(0, bytes))
    {
        Ok(cpu) => cpu,
        Err(error) => return allocation_error(error),
    };
    // Validate every actual retained page against the immutable inventory.
    // Adjacent physical extents may have different CPU mappings: only the
    // real mapping for each page establishes its relation, never a direct-map
    // assumption or an inferred address in an unmapped guard gap.
    for (index, physical) in pages.physical_pages().iter().enumerate() {
        let Some(address) = (cpu.as_ptr() as usize).checked_add(index * PAGE_BYTES) else {
            return -EINVAL;
        };
        if !context.reservations.iter().any(|reservation| {
            address
                .checked_sub(reservation.cpu_base.as_ptr() as usize)
                .filter(|offset| *offset < reservation.page_count * PAGE_BYTES)
                .is_some_and(|offset| *physical == reservation.physical_base + offset as u64)
        }) {
            return -EINVAL;
        }
    }
    let pin = storage.write(Pin { pages });
    let allocation = NativeAllocation {
        pin: (pin as *mut Pin).cast(),
        cpu_base: cpu.as_ptr().cast(),
        physical_pages: pin.pages.physical_pages().as_ptr(),
        page_count: pin.pages.physical_pages().len(),
    };
    // SAFETY: C receives the unique initialized token only on successful
    // return. Its rollback/deferred-release path returns it exactly once.
    unsafe { output.write(allocation) };
    let _ = Box::into_raw(storage);
    0
}

unsafe extern "C" fn validate<P: Provider>(
    context: *mut c_void,
    gfp: u32,
    order: u32,
    atomic: bool,
) -> c_int {
    // SAFETY: C retains the exact registered Context and invokes callbacks only
    // in its serialized execution. Validation borrows no backing allocation.
    let context = unsafe { &*context.cast::<Context<P>>() };
    match context.provider.validate(Request { gfp, order, atomic }) {
        Ok(()) => 0,
        Err(error) => allocation_error(error),
    }
}

unsafe extern "C" fn release_ready<P: Provider>(context: *mut c_void, pin: *mut c_void) -> bool {
    // SAFETY: the same registered Context and exact transferred Pin remain
    // retained by C; this serialized observation neither takes nor drops them.
    let (context, pin) = unsafe { (&*context.cast::<Context<P>>(), &*pin.cast::<Pin>()) };
    context.provider.retirement(&pin.pages) == PinRetirement::Ready
}

unsafe extern "C" fn release(_context: *mut c_void, pin: *mut c_void) {
    // SAFETY: the C catalog returns this unique initialized token once, only
    // after all logical page refs end and checked quiescence permits release.
    drop(unsafe { Box::from_raw(pin.cast::<Pin>()) });
}

/// Owns the platform provider while C retains its descriptor catalog.
/// This handle is affine to its creating native context, including retirement.
pub struct Catalog<P: Provider> {
    context: Option<Box<Context<P>>>,
    generation: u64,
    same_context: PhantomData<Rc<()>>,
}

impl<P: Provider> Catalog<P> {
    /// # Safety
    /// Call in process/deferred context with native IRQ/reentry, migration and
    /// reservation/root changes excluded. The provider and Reservation satisfy
    /// their retained authority contracts. Retirement and final Drop must obey
    /// the same context rules; a busy drop quarantines, never frees live pages.
    pub unsafe fn register(provider: P, reservation: Reservation) -> Result<Self, Error> {
        let mut reservations = Vec::new();
        reservations
            .try_reserve_exact(1)
            .map_err(|_| Error::OutOfMemory)?;
        reservations.push(reservation);
        // SAFETY: the same retained provider/reservation and caller context
        // contract is forwarded; a one-extent inventory adds no authority.
        unsafe { Self::register_extents(provider, reservations) }
    }

    /// Register the complete immutable actual reservation inventory.
    ///
    /// Every extent is copied into the one canonical C descriptor owner.
    /// Physical gaps and guard mappings are absent. Descriptor addresses stay
    /// stable until full retirement; admission cannot grow a live catalog.
    /// This does not qualify dynamic sparse-memory or native stack ownership.
    ///
    /// # Safety
    /// Each reservation satisfies its actual retained mapping/physical contract
    /// under this provider. No physical or writable CPU extent aliases another;
    /// the provider may allocate only exact pinned pages in this inventory.
    /// The process/IRQ/root/retirement requirements of `register` also apply.
    pub unsafe fn register_extents(
        provider: P,
        mut reservations: Vec<Reservation>,
    ) -> Result<Self, Error> {
        if reservations.is_empty() {
            return Err(Error::InvalidReservation);
        }
        reservations.sort_unstable_by_key(|reservation| reservation.physical_base);
        let generation = NEXT_GENERATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| Error::GenerationExhausted)?;
        let mut native = Vec::new();
        native
            .try_reserve_exact(reservations.len())
            .map_err(|_| Error::OutOfMemory)?;
        for reservation in &reservations {
            native.push(NativeReservation {
                generation,
                physical_base: reservation.physical_base,
                cpu_base: reservation.cpu_base.as_ptr().cast(),
                page_count: reservation.page_count,
            });
        }
        let mut context = try_box(Context {
            provider,
            reservations,
        })?;
        let operations = OperationsV2 {
            version: 2,
            bytes: u32::try_from(size_of::<OperationsV2>())
                .map_err(|_| Error::InvalidReservation)?,
            ordinary: Operations {
                validate: validate::<P>,
                allocate: allocate::<P>,
                release,
            },
            release_ready: release_ready::<P>,
        };
        let result = {
            let _entered = Entered::try_new()?;
            // SAFETY: native contains exactly its declared number of original
            // ABI records, each derived from a retained actual reservation.
            // C copies them before return and borrows only stable Context.
            unsafe {
                stela_linux_page_catalog_register_extents_v2(
                    native.as_ptr(),
                    native.len(),
                    &operations,
                    (&mut *context as *mut Context<P>).cast(),
                )
            }
        };
        if result != 0 {
            return Err(Error::Native(result));
        }
        Ok(Self {
            context: Some(context),
            generation,
            same_context: PhantomData,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Authored service diagnostic over the actual provider and Linux page API.
    /// This neither attaches hardware nor qualifies a GPU or DMA mapping.
    pub fn verify(&self) -> Result<(), Error> {
        if self.context.is_none() {
            return Err(Error::InvalidReservation);
        }
        let _entered = Entered::try_new()?;
        // SAFETY: the retained generation/provider remain registered; the
        // diagnostic owns and retires its temporary page references.
        let result = unsafe { stela_linux_page_catalog_verify(self.generation) };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::Native(result))
        }
    }

    /// Retire only after every Linux page reference and external lease ends.
    /// A refusal leaves the same catalog/provider intact for a later retry.
    pub fn try_retire(&mut self) -> Result<(), Error> {
        if self.context.is_none() {
            return Ok(());
        }
        let result = {
            let _entered = Entered::try_new()?;
            // SAFETY: the handle supplies its unique registered generation.
            // C refuses live pages and drains retired pins before success.
            unsafe { stela_linux_page_catalog_unregister(self.generation) }
        };
        if result != 0 {
            return Err(Error::Native(result));
        }
        // Drop the platform provider only after leaving the C owner.
        self.context.take();
        Ok(())
    }
}

impl<P: Provider> Drop for Catalog<P> {
    fn drop(&mut self) {
        if self.try_retire().is_err() {
            // The C catalog may retain callbacks and page descriptors. Keep
            // their actual provider stable even after losing the Rust handle.
            if let Some(context) = self.context.take() {
                core::mem::forget(context);
                let _ = QUARANTINED_CATALOGS.try_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |count| Some(count.saturating_add(1)),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
