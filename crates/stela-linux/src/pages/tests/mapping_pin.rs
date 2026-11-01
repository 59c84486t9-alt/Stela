//! Real Rust provider Pin/PinnedPages behind the C allocation-ref bridge.
//! CPU-only existing catalogue models: no fake KernelOwner/code permission,
//! native physical address, cache change or VMA/root admission is established.
use super::*;
use crate::owner::RawOwner;
#[repr(C)]
struct Raw {
    record: *mut c_void,
    provider_pin: *mut c_void,
    cpu_page: *mut c_void,
}
unsafe extern "C" {
    fn __alloc_pages_noprof(gfp: u32, order: u32, nid: i32, nodes: *mut c_void) -> *mut c_void;
    fn __free_pages(page: *mut c_void, order: u32);
    fn stela_linux_pages_finish();
    fn stela_linux_page_mapping_pin(
        generation: u64,
        context: *const c_void,
        owner: *const RawOwner,
        physical: u64,
        out: *mut Raw,
    ) -> c_int;
    fn stela_linux_page_mapping_unpin(
        generation: u64,
        context: *const c_void,
        owner: *const RawOwner,
        record: *mut c_void,
    ) -> c_int;
}
fn isolated(name: &str) -> bool {
    if std::env::var_os("STELA_MAPPING_REF_CHILD").is_some() {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env("STELA_MAPPING_REF_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        std::string::String::from_utf8_lossy(&output.stdout),
        std::string::String::from_utf8_lossy(&output.stderr)
    );
    false
}
#[test]
fn bridge_clones_original_backing_and_blocks_catalogue_reuse() {
    if !isolated(
        "pages::tests::mapping_pin::bridge_clones_original_backing_and_blocks_catalogue_reuse",
    ) {
        return;
    }
    let (provider, reservation, drops, _) = model(false);
    let expected_cpu = reservation.cpu_base;
    // SAFETY: actual owned aligned model CPU buffer; symbolic PA never gains
    // native/hardware permission. Existing provider/reservation own it fully.
    let mut catalog = unsafe { Catalog::register(provider, reservation) }.unwrap();
    let context = ptr::from_ref(&**catalog.context.as_ref().unwrap()).cast::<c_void>();
    let generation = catalog.generation;
    let entered = Entered::try_new().unwrap();
    let owner = ptr::addr_of!(stela_linux_bare).cast::<RawOwner>();
    // SAFETY: isolated entered C model, exact registered provider and page API.
    let page = unsafe { __alloc_pages_noprof(0, 0, -1, ptr::null_mut()) };
    assert!(!page.is_null());
    let mut raw = Raw {
        record: ptr::null_mut(),
        provider_pin: ptr::null_mut(),
        cpu_page: ptr::null_mut(),
    };
    assert_eq!(
        // SAFETY: retained registered Context and exact generation, entered bare
        // owner, live original C page allocation and writable Raw output.
        unsafe { stela_linux_page_mapping_pin(generation, context, owner, PHYSICAL, &raw mut raw) },
        0
    );
    assert!(!raw.record.is_null() && !raw.provider_pin.is_null());
    assert_eq!(raw.cpu_page.cast::<u8>(), expected_cpu.as_ptr());
    // SAFETY: C ref keeps this actual Rust-created provider Pin alive. Clone
    // shares its real CPU allocation, not an unrelated Arc or PA descriptor.
    let backing = unsafe { &*raw.provider_pin.cast::<Pin>() }.pages.clone();
    assert_eq!(backing.physical_pages(), [PHYSICAL]);
    assert_eq!(
        backing
            .cpu_mapping(CacheAttribute::WriteBack)
            .unwrap()
            .address(0, PAGE_BYTES)
            .unwrap(),
        expected_cpu
    );
    // SAFETY: end logical original C page ownership, keep the C allocation ref.
    unsafe {
        __free_pages(page, 0);
    }
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(
        // SAFETY: same entered owner and live registered generation; the actual
        // outstanding C ref must refuse retirement before Context teardown.
        unsafe { stela_linux_page_catalog_unregister(generation) },
        -16
    );
    assert_eq!(
        // SAFETY: exact live record from this Context/generation, released once
        // under its entered owner; no mapping was exposed through this ref.
        unsafe { stela_linux_page_mapping_unpin(generation, context, owner, raw.record) },
        0
    );
    // SAFETY: original logical references and external C ref ended at quiescence.
    unsafe {
        stela_linux_pages_finish();
    }
    assert_eq!(drops.load(Ordering::Relaxed), 0); // Real cloned backing still owns RAM.
    drop(backing);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    drop(entered);
    catalog.try_retire().unwrap();
}
#[test]
fn outstanding_c_ref_keeps_original_provider_context_after_drop() {
    if !isolated(
        "pages::tests::mapping_pin::outstanding_c_ref_keeps_original_provider_context_after_drop",
    ) {
        return;
    }
    let (provider, reservation, drops, _) = model(false);
    // SAFETY: isolated owned CPU model, no actual native root/cache operation.
    let catalog = unsafe { Catalog::register(provider, reservation) }.unwrap();
    let context = ptr::from_ref(&**catalog.context.as_ref().unwrap());
    let generation = catalog.generation;
    let entered = Entered::try_new().unwrap();
    let owner = ptr::addr_of!(stela_linux_bare).cast::<RawOwner>();
    // SAFETY: actual registered model provider receives ordinary page allocation.
    let page = unsafe { __alloc_pages_noprof(0, 0, -1, ptr::null_mut()) };
    assert!(!page.is_null());
    let mut raw = Raw {
        record: ptr::null_mut(),
        provider_pin: ptr::null_mut(),
        cpu_page: ptr::null_mut(),
    };
    assert_eq!(
        // SAFETY: live owned provider Context and original registered generation
        // match the entered owner and allocated C page; Raw output is writable.
        unsafe {
            stela_linux_page_mapping_pin(generation, context.cast(), owner, PHYSICAL, &raw mut raw)
        },
        0
    );
    // SAFETY: release only the logical Linux page reference.
    unsafe {
        __free_pages(page, 0);
    }
    drop(entered);
    let before = quarantined_catalogs();
    drop(catalog);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(quarantined_catalogs(), before + 1);
    let entered = Entered::try_new().unwrap();
    assert_eq!(
        // SAFETY: refused Catalog Drop retained this exact Context/generation
        // and still-live C record; the same entered owner ends that ref once.
        unsafe { stela_linux_page_mapping_unpin(generation, context.cast(), owner, raw.record) },
        0
    );
    // SAFETY: actual logical and external references now ended; drain/unregister.
    unsafe {
        stela_linux_pages_finish();
    }
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(
        // SAFETY: same original generation after logical/external refs ended
        // and pages_finish drained their records under the retained owner.
        unsafe { stela_linux_page_catalog_unregister(generation) },
        0
    );
    drop(entered);
    // SAFETY: same original Box quarantined by Drop, no C borrow survives the
    // successful unregister. This is not a production reset/reclaim pathway.
    drop(unsafe { Box::from_raw(context.cast_mut()) });
}
