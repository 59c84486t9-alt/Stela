//! Owned platform pins behind Linux's actual PFN-indexed page descriptors.
//! The catalog supplies no DMA mapping or GPU attachment. Its provider and
//! reservation survive until explicit retirement, or observable quarantine.
use crate::bus::dma::memory::{CacheAttribute, MemoryError, PinnedPages};
use alloc::{boxed::Box, rc::Rc};
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

    pub fn may_block(self) -> bool {
        // SAFETY: pure GFP classification; no platform or owner is accessed.
        unsafe { stela_linux_page_request_blocking(self.gfp) }
    }
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
/// its source generation even if a busy catalog is quarantined. Another
/// serialized native owner may invoke it; no creator-thread affinity is assumed.
pub unsafe trait Provider: Send + Sync + 'static {
    /// Pure preflight before metadata/backing allocation. Success also attests
    /// the canonical global metadata heap for this exact request/context.
    fn validate(&self, request: Request) -> Result<(), MemoryError>;

    fn allocate(&self, request: Request) -> Result<PinnedPages, MemoryError>;
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

unsafe extern "C" {
    static stela_linux_bare: u8;
    fn stela_linux_try_enter(owner: *const c_void) -> bool;
    fn stela_linux_exit();
    fn stela_linux_page_catalog_register(
        reservation: *const NativeReservation,
        operations: *const Operations,
        context: *mut c_void,
    ) -> c_int;
    fn stela_linux_page_catalog_unregister(generation: u64) -> c_int;
    fn stela_linux_page_catalog_verify(generation: u64) -> c_int;
    fn stela_linux_page_request_basic(gfp: u32) -> bool;
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
    reservation: Reservation,
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
    // Check the provider's registered CPU/PA relation before publishing even
    // an opaque token. C independently checks its complete physical page list.
    let Some(offset) = (cpu.as_ptr() as usize)
        .checked_sub(context.reservation.cpu_base.as_ptr() as usize)
        .filter(|offset| {
            offset
                .checked_add(bytes)
                .is_some_and(|end| end <= context.reservation.page_count * PAGE_BYTES)
        })
    else {
        return -EINVAL;
    };
    if pages.physical_pages()[0] != context.reservation.physical_base + offset as u64 {
        return -EINVAL;
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
        let generation = NEXT_GENERATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| Error::GenerationExhausted)?;
        let mut context = try_box(Context {
            provider,
            reservation,
        })?;
        let operations = Operations {
            validate: validate::<P>,
            allocate: allocate::<P>,
            release,
        };
        let native = NativeReservation {
            generation,
            physical_base: reservation.physical_base,
            cpu_base: reservation.cpu_base.as_ptr().cast(),
            page_count: reservation.page_count,
        };
        let result = {
            let _entered = Entered::try_new()?;
            // SAFETY: C copies the two temporary records and retains only the
            // stable Context pointer. It publishes nothing on a failed result.
            unsafe {
                stela_linux_page_catalog_register(
                    &native,
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
mod tests {
    extern crate std;
    use super::*;
    use crate::bus::dma::memory::PageBacking;
    use core::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};

    // CPU-only ownership model. Physical labels deliberately differ from CPU
    // addresses and are never passed to hardware or treated as native evidence.
    const PHYSICAL: u64 = 0x1_0000_0000;
    #[repr(align(4096))]
    struct Buffer([u8; PAGE_BYTES]);
    struct Backing {
        buffer: Box<Buffer>,
        physical: [u64; 1],
        drops: Arc<AtomicUsize>,
    }
    impl Drop for Backing {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    // SAFETY: aligned zeroed owned model memory, immutable symbolic page list,
    // and no DMA or shared data references. Drop ends the actual CPU storage.
    unsafe impl PageBacking for Backing {
        fn cpu_base(&self) -> NonNull<u8> {
            NonNull::from(&self.buffer.0[0])
        }
        fn physical_pages(&self) -> &[u64] {
            &self.physical
        }
        fn page_shift(&self) -> u8 {
            PAGE_SHIFT as u8
        }
        fn cache_attribute(&self) -> CacheAttribute {
            CacheAttribute::WriteBack
        }
    }

    struct Model {
        pin: Mutex<Option<PinnedPages>>,
        refused: bool,
        allocations: Arc<AtomicUsize>,
    }
    // SAFETY: serialized CPU model only. Validation never allocates or enters
    // Linux; successful allocation transfers one previously prepared real CPU
    // pin. No test establishes native physical addresses or atomic allocation.
    unsafe impl Provider for Model {
        fn validate(&self, request: Request) -> Result<(), MemoryError> {
            if self.refused || request.atomic {
                Err(MemoryError::Unavailable)
            } else {
                Ok(())
            }
        }
        fn allocate(&self, _: Request) -> Result<PinnedPages, MemoryError> {
            self.allocations.fetch_add(1, Ordering::Relaxed);
            self.pin
                .lock()
                .unwrap()
                .take()
                .ok_or(MemoryError::OutOfMemory)
        }
    }

    fn model(refused: bool) -> (Model, Reservation, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let drops = Arc::new(AtomicUsize::new(0));
        let allocations = Arc::new(AtomicUsize::new(0));
        let backing = Box::new(Backing {
            buffer: Box::new(Buffer([0; PAGE_BYTES])),
            physical: [PHYSICAL],
            drops: drops.clone(),
        });
        let cpu = backing.cpu_base();
        let pin = PinnedPages::new(backing, PAGE_BYTES, PAGE_BYTES).unwrap();
        // SAFETY: explicit CPU-only model with the exact retained CPU extent;
        // no conversion or callback grants hardware access to its PA labels.
        let reservation = unsafe { Reservation::new(PHYSICAL, cpu, 1) }.unwrap();
        (
            Model {
                pin: Mutex::new(Some(pin)),
                refused,
                allocations: allocations.clone(),
            },
            reservation,
            drops,
            allocations,
        )
    }

    #[test]
    fn request_extent_arithmetic_never_truncates_large_orders_to_zero() {
        for order in (0..=255).chain([u32::MAX]) {
            let expected = u32::checked_add(order, PAGE_SHIFT)
                .and_then(|shift| 1u128.checked_shl(shift))
                .filter(|bytes| *bytes <= isize::MAX as u128)
                .map(|bytes| bytes as usize);
            assert_eq!(
                Request {
                    gfp: 0,
                    order,
                    atomic: false
                }
                .bytes(),
                expected
            );
        }
    }

    #[test]
    fn callback_transfers_only_valid_pins_and_refuses_before_provider_allocation() {
        for (refused, invalid_relation) in [(true, false), (false, true), (false, false)] {
            let (provider, mut reservation, drops, allocations) = model(refused);
            if invalid_relation {
                reservation.physical_base += PAGE_BYTES as u64;
            }
            let mut context = Context {
                provider,
                reservation,
            };
            let mut output = NativeAllocation {
                pin: ptr::null_mut(),
                cpu_base: ptr::null_mut(),
                physical_pages: ptr::null(),
                page_count: 0,
            };
            // SAFETY: actual typed stable context and native writable output;
            // this directly tests the production ownership callback.
            let result = unsafe {
                allocate::<Model>(
                    (&mut context as *mut Context<Model>).cast(),
                    0,
                    0,
                    false,
                    &mut output,
                )
            };
            if refused {
                assert_eq!(result, -EOPNOTSUPP);
                assert_eq!(allocations.load(Ordering::Relaxed), 0);
                assert_eq!(drops.load(Ordering::Relaxed), 0);
            } else if invalid_relation {
                assert_eq!(result, -EINVAL);
                assert_eq!(allocations.load(Ordering::Relaxed), 1);
                assert_eq!(drops.load(Ordering::Relaxed), 1);
            } else {
                assert_eq!(result, 0);
                assert!(!output.pin.is_null());
                assert_eq!(output.page_count, 1);
                assert_eq!(drops.load(Ordering::Relaxed), 0);
                // SAFETY: successful callback retains its actual CPU mapping
                // and physical-list storage until the unique release below.
                unsafe {
                    assert_eq!(output.physical_pages.read(), PHYSICAL);
                    assert_eq!(output.cpu_base.cast::<u8>().read(), 0);
                    output.cpu_base.cast::<u8>().add(PAGE_BYTES - 1).write(0x5a);
                    release(ptr::null_mut(), output.pin);
                }
                assert_eq!(drops.load(Ordering::Relaxed), 1);
            }
            if result != 0 {
                assert!(output.pin.is_null() && output.cpu_base.is_null());
                assert!(output.physical_pages.is_null() && output.page_count == 0);
            }
            drop(context);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn catalog_retirement_and_nested_drop_preserve_provider_lifetime() {
        // Other unit tests enter the same serialized C adapter. Isolate this
        // catalog's lifetime in a child rather than weakening try-enter's Busy
        // behavior or imposing a new global lock on production callers.
        if std::env::var_os("STELA_LINUX_CATALOG_LIFETIME_CHILD").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "gpu::linux::pages::tests::catalog_retirement_and_nested_drop_preserve_provider_lifetime",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env("STELA_LINUX_CATALOG_LIFETIME_CHILD", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "catalog lifetime child failed: {}\n{}",
                std::string::String::from_utf8_lossy(&output.stdout),
                std::string::String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let (provider, reservation, drops, _) = model(false);
        // SAFETY: isolated CPU model in the ordinary test thread, with a
        // retained reservation/provider and no native IRQ or root writers.
        let mut catalog = unsafe { Catalog::register(provider, reservation) }.unwrap();
        catalog.try_retire().unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        catalog.try_retire().unwrap();
        drop(catalog);
        assert_eq!(drops.load(Ordering::Relaxed), 1);

        let (provider, reservation, drops, _) = model(false);
        // SAFETY: same isolated ordinary-context ownership contract.
        let catalog = unsafe { Catalog::register(provider, reservation) }.unwrap();
        let generation = catalog.generation;
        let context = &**catalog.context.as_ref().unwrap() as *const Context<Model>;
        let before = quarantined_catalogs();
        let entered = Entered::try_new().unwrap();
        // A nested final Drop must return immediately and retain the C callback
        // context. It cannot wait for its own borrowed Linux execution owner.
        drop(catalog);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(quarantined_catalogs(), before + 1);
        // Test-only cleanup of this known quiescent catalog. Production Drop
        // supplies no fabricated drain/reset witness or automatic reclamation.
        // SAFETY: no page was allocated through this catalog; the current
        // entered owner is quiescent and supplies the exact generation.
        assert_eq!(
            unsafe { stela_linux_page_catalog_unregister(generation) },
            0
        );
        drop(entered);
        // SAFETY: successful unregister ended all C borrows of the unique
        // Context retained by the production busy-drop path above.
        drop(unsafe { Box::from_raw(context.cast_mut()) });
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
