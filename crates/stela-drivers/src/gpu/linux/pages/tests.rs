//! CPU-owned page catalog and C ABI lifetime fixtures.
extern crate std;
use super::*;
use crate::bus::dma::memory::PageBacking;
use core::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex};

// CPU-only ownership model. Physical labels differ from CPU
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
// and no DMA or shared data references. Drop ends the CPU storage.
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
    model_at(refused, PHYSICAL)
}

fn model_at(
    refused: bool,
    physical: u64,
) -> (Model, Reservation, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    let allocations = Arc::new(AtomicUsize::new(0));
    let backing = Box::new(Backing {
        buffer: Box::new(Buffer([0; PAGE_BYTES])),
        physical: [physical],
        drops: drops.clone(),
    });
    let cpu = backing.cpu_base();
    let pin = PinnedPages::new(backing, PAGE_BYTES, PAGE_BYTES).unwrap();
    // SAFETY: explicit CPU-only model with the exact CPU extent;
    // no conversion or callback grants hardware access to its PA labels.
    let reservation = unsafe { Reservation::new(physical, cpu, 1) }.unwrap();
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

struct PairModel([Model; 2]);
// SAFETY: each component keeps its separate model CPU pin; the
// symbolic physical inventories do not grant any native hardware access.
// Validation and transfer obey the same serialized nonreentrant contract
// as Model; only ordinary exhaustion falls through to the second owner.
unsafe impl Provider for PairModel {
    fn validate(&self, request: Request) -> Result<(), MemoryError> {
        self.0[0].validate(request)?;
        self.0[1].validate(request)
    }
    fn allocate(&self, request: Request) -> Result<PinnedPages, MemoryError> {
        match self.0[0].allocate(request) {
            Err(MemoryError::OutOfMemory) => self.0[1].allocate(request),
            result => result,
        }
    }
}

#[test]
fn multiple_actual_mapping_pins_keep_their_distinct_cpu_and_physical_relations() {
    if std::env::var_os("STELA_LINUX_EXTENTS_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "gpu::linux::pages::tests::multiple_actual_mapping_pins_keep_their_distinct_cpu_and_physical_relations",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("STELA_LINUX_EXTENTS_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            std::string::String::from_utf8_lossy(&output.stdout),
            std::string::String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    unsafe extern "C" {
        fn __alloc_pages_noprof(gfp: u32, order: u32, nid: i32, nodes: *mut c_void) -> *mut c_void;
        fn __free_pages(page: *mut c_void, order: u32);
        fn page_to_pfn(page: *const c_void) -> usize;
        fn __phys_to_virt(physical: u64) -> *mut c_void;
    }
    let (left, left_extent, left_drops, _) = model_at(false, PHYSICAL);
    let right_physical = PHYSICAL + 17 * PAGE_BYTES as u64;
    let (right, right_extent, right_drops, _) = model_at(false, right_physical);
    let expected_cpu = [left_extent.cpu_base, right_extent.cpu_base];
    assert_ne!(expected_cpu[0], expected_cpu[1]);
    // SAFETY: both separate CPU grants are held by PairModel;
    // only isolated symbolic physical labels are used and IRQ/root writers
    // are absent. Reversed input proves ordering is not caller permission.
    let mut catalog = unsafe {
        Catalog::register_extents(
            PairModel([left, right]),
            alloc::vec![right_extent, left_extent],
        )
    }
    .unwrap();
    let entered = Entered::try_new().unwrap();
    // SAFETY: the isolated C owner is entered at quiescence; the
    // registered provider transfers its two real CPU pins through the
    // normal Linux page API. Null nodemask and node -1 permit node0.
    let pages = unsafe {
        [
            __alloc_pages_noprof(0, 0, -1, ptr::null_mut()),
            __alloc_pages_noprof(0, 0, -1, ptr::null_mut()),
        ]
    };
    assert!(!pages[0].is_null() && !pages[1].is_null());
    for (index, physical) in [PHYSICAL, right_physical].into_iter().enumerate() {
        // SAFETY: each page is live in this exact generation, and these
        // queries operate on its metadata and CPU mapping.
        unsafe {
            assert_eq!(page_to_pfn(pages[index]) as u64, physical >> PAGE_SHIFT);
            assert_eq!(
                __phys_to_virt(physical).cast::<u8>(),
                expected_cpu[index].as_ptr()
            );
        }
    }
    drop(entered);
    assert_eq!(catalog.try_retire(), Err(Error::Native(-16)));
    assert_eq!(left_drops.load(Ordering::Relaxed), 0);
    assert_eq!(right_drops.load(Ordering::Relaxed), 0);
    let entered = Entered::try_new().unwrap();
    // SAFETY: both original order0 live references are uniquely held
    // by this test; no device, IRQ, RCU or concurrent consumer exists.
    unsafe {
        __free_pages(pages[0], 0);
        __free_pages(pages[1], 0);
    }
    drop(entered);
    assert_eq!(left_drops.load(Ordering::Relaxed), 1);
    assert_eq!(right_drops.load(Ordering::Relaxed), 1);
    catalog.try_retire().unwrap();
}

struct DeferredModel {
    ordinary: Model,
    ready: Arc<AtomicBool>,
}
// SAFETY: this keeps the exact ordinary model pin. The test-only flag
// models an extra owner acknowledgment; it checks no native stack,
// terminal, RCU or platform permission. Until set, no pin may be dropped.
unsafe impl Provider for DeferredModel {
    fn validate(&self, request: Request) -> Result<(), MemoryError> {
        self.ordinary.validate(request)
    }
    fn allocate(&self, request: Request) -> Result<PinnedPages, MemoryError> {
        self.ordinary.allocate(request)
    }
    fn retirement(&self, _: &PinnedPages) -> PinRetirement {
        if self.ready.load(Ordering::Acquire) {
            PinRetirement::Ready
        } else {
            PinRetirement::Retain
        }
    }
}

#[test]
fn logical_c_free_and_busy_drop_retain_the_pin_until_its_owner_acknowledges() {
    if std::env::var_os("STELA_LINUX_RETAINED_PAGE_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "gpu::linux::pages::tests::logical_c_free_and_busy_drop_retain_the_pin_until_its_owner_acknowledges",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("STELA_LINUX_RETAINED_PAGE_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            std::string::String::from_utf8_lossy(&output.stdout),
            std::string::String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    unsafe extern "C" {
        fn __alloc_pages_noprof(gfp: u32, order: u32, nid: i32, nodes: *mut c_void) -> *mut c_void;
        fn __free_pages(page: *mut c_void, order: u32);
    }
    for quarantine in [false, true] {
        let (ordinary, extent, drops, _) = model(false);
        let ready = Arc::new(AtomicBool::new(false));
        let provider = DeferredModel {
            ordinary,
            ready: ready.clone(),
        };
        // SAFETY: isolated CPU backing/mapping model with kept
        // provider ownership and no native IRQ, root or resource producers.
        let mut catalog = unsafe { Catalog::register(provider, extent) }.unwrap();
        let entered = Entered::try_new().unwrap();
        // SAFETY: C owner at quiescence; the unique live order0
        // reference is allocated/freed through its original ordinary API.
        // Its backing remains held by the provider's extra fence.
        unsafe {
            let page = __alloc_pages_noprof(0, 0, -1, ptr::null_mut());
            assert!(!page.is_null());
            __free_pages(page, 0);
        }
        drop(entered);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(catalog.try_retire(), Err(Error::Native(-16)));
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        if quarantine {
            let generation = catalog.generation;
            let context = &**catalog.context.as_ref().unwrap() as *const Context<DeferredModel>;
            let before = quarantined_catalogs();
            drop(catalog);
            assert_eq!(quarantined_catalogs(), before + 1);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            ready.store(true, Ordering::Release);
            let entered = Entered::try_new().unwrap();
            assert_eq!(
                // SAFETY: fixture-only recovery of this exact isolated known
                // catalog after its modeled fence; no caller, callback
                // or page reference survives. Production Drop never does this.
                unsafe { stela_linux_page_catalog_unregister(generation) },
                0
            );
            drop(entered);
            // SAFETY: successful exact unregister ended all C borrows of
            // the unique Context kept by the production busy Drop.
            drop(unsafe { Box::from_raw(context.cast_mut()) });
        } else {
            ready.store(true, Ordering::Release);
            catalog.try_retire().unwrap();
            catalog.try_retire().unwrap();
        }
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn original_reservation_and_operations_abi_has_no_unread_tail() {
    assert_eq!(size_of::<NativeReservation>(), 32);
    assert_eq!(core::mem::offset_of!(NativeReservation, generation), 0);
    assert_eq!(core::mem::offset_of!(NativeReservation, physical_base), 8);
    assert_eq!(core::mem::offset_of!(NativeReservation, cpu_base), 16);
    assert_eq!(core::mem::offset_of!(NativeReservation, page_count), 24);
    assert_eq!(size_of::<Operations>(), 3 * size_of::<usize>());
    assert_eq!(size_of::<OperationsV2>(), 40);
    assert_eq!(core::mem::offset_of!(OperationsV2, ordinary), 8);
    assert_eq!(core::mem::offset_of!(OperationsV2, release_ready), 32);
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
            reservations: alloc::vec![Extent::ordinary(reservation)],
        };
        let mut output = NativeAllocation {
            pin: ptr::null_mut(),
            cpu_base: ptr::null_mut(),
            physical_pages: ptr::null(),
            page_count: 0,
        };
        // SAFETY: typed stable context and native writable output;
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
            // SAFETY: successful callback keeps its CPU mapping
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
    // reservation/provider and no native IRQ or root writers.
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
    // A nested final Drop must return immediately and keep the C callback
    // context. It cannot wait for its own borrowed Linux execution owner.
    drop(catalog);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(quarantined_catalogs(), before + 1);
    // Test-only cleanup of this known quiescent catalog. Production Drop
    // supplies no invented drain/reset witness or automatic reclamation.
    assert_eq!(
        // SAFETY: no page was allocated through this catalog; the current
        // entered owner is quiescent and supplies the exact generation.
        unsafe { stela_linux_page_catalog_unregister(generation) },
        0
    );
    drop(entered);
    // SAFETY: successful unregister ended all C borrows of the unique
    // Context kept by the production busy-drop path above.
    drop(unsafe { Box::from_raw(context.cast_mut()) });
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}
