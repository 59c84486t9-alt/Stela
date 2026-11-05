//! Kernel-lifetime catalogs and original per-task cleanup on real CPU memory.
extern crate std;
use super::*;
use crate::{
    pages::{Request as PageRequest, Reservation},
    task::TaskBinding,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    pin::Pin,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize},
};
use std::{sync::Mutex, thread};
use stela_driver_base::bus::dma::memory::{CacheAttribute, MemoryError, PageBacking, PinnedPages};
use stela_driver_base::platform::work::{
    Executor, Queue, Runtime, Stack,
    test_support::{CpuModel, backing},
};
const PAGE: usize = 4096;
const PAGES: usize = 16;
const PHYSICAL: u64 = 0x2_0000_0000;
#[repr(align(65536))]
struct Bytes(UnsafeCell<[u8; PAGE * PAGES]>);
struct Memory {
    bytes: Box<Bytes>,
    used: Mutex<[bool; PAGES]>,
    exhausted: AtomicBool,
    allocations: AtomicUsize,
    provider_drops: AtomicUsize,
}
// SAFETY: only disjoint claimed page ranges are exposed; the mutex serializes
// claims/releases, and each live pin exclusively owns its mutable model bytes.
unsafe impl Sync for Memory {}
struct View {
    memory: Arc<Memory>,
    first: usize,
    pages: Vec<u64>,
}
impl Drop for View {
    fn drop(&mut self) {
        let mut used = self.memory.used.lock().unwrap();
        for item in &mut used[self.first..self.first + self.pages.len()] {
            assert!(*item);
            *item = false;
        }
    }
}
// SAFETY: the same Arc owns aligned private CPU memory throughout every pin;
// symbolic PA labels are never presented as native physical ownership. Each
// view uniquely reserves its full range until Drop releases those exact pages.
unsafe impl PageBacking for View {
    fn cpu_base(&self) -> NonNull<u8> {
        // SAFETY: first is a checked page index in this aligned allocation.
        unsafe {
            NonNull::new_unchecked(
                self.memory
                    .bytes
                    .0
                    .get()
                    .cast::<u8>()
                    .add(self.first * PAGE),
            )
        }
    }
    fn physical_pages(&self) -> &[u64] {
        &self.pages
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
struct Model(Arc<Memory>);
impl Drop for Model {
    fn drop(&mut self) {
        self.0.provider_drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: isolated same-process CPU model over aligned owned bytes.
// Allocation claims disjoint ranges and transfers real pins, with no Linux
// reentry; it refuses atomic/unavailable requests and has no hardware permission.
unsafe impl Provider for Model {
    fn validate(&self, request: PageRequest) -> Result<(), MemoryError> {
        if request.atomic {
            Err(MemoryError::Unavailable)
        } else {
            Ok(())
        }
    }
    fn allocate(&self, request: PageRequest) -> Result<PinnedPages, MemoryError> {
        self.validate(request)?;
        if self.0.exhausted.load(Ordering::Acquire) {
            return Err(MemoryError::OutOfMemory);
        }
        let count = 1usize
            .checked_shl(request.order)
            .filter(|n| *n <= PAGES)
            .ok_or(MemoryError::OutOfMemory)?;
        let mut used = self.0.used.lock().unwrap();
        let first = (0..=PAGES - count)
            .step_by(count)
            .find(|i| used[*i..*i + count].iter().all(|v| !v))
            .ok_or(MemoryError::OutOfMemory)?;
        used[first..first + count].fill(true);
        drop(used);
        self.0.allocations.fetch_add(1, Ordering::Relaxed);
        let pages = (first..first + count)
            .map(|i| PHYSICAL + i as u64 * PAGE as u64)
            .collect();
        PinnedPages::new(
            Box::new(View {
                memory: self.0.clone(),
                first,
                pages,
            }),
            count * PAGE,
            count * PAGE,
        )
    }
}
fn catalog() -> (Catalog<Model>, Arc<Memory>) {
    let memory = Arc::new(Memory {
        bytes: Box::new(Bytes(UnsafeCell::new([0; PAGE * PAGES]))),
        used: Mutex::new([false; PAGES]),
        exhausted: AtomicBool::new(false),
        allocations: AtomicUsize::new(0),
        provider_drops: AtomicUsize::new(0),
    });
    let cpu = NonNull::new(memory.bytes.0.get().cast::<u8>()).unwrap();
    // SAFETY: one isolated child process owns these exact aligned CPU bytes;
    // Model keeps the allocation and symbolic PA inventory through retirement.
    let reservation = unsafe { Reservation::new(PHYSICAL, cpu, PAGES) }.unwrap();
    // SAFETY: isolated child has no other C caller/IRQ/root writer. This is a CPU
    // model, with backing lifetime and no native physical validation.
    let catalog = unsafe { Catalog::register(Model(memory.clone()), reservation) }.unwrap();
    (catalog, memory)
}
struct EnteredModel {
    thread: thread::ThreadId,
    allowed: AtomicBool,
}
// SAFETY: explicit hosted permission model checks the real OS thread and live
// test-owned entered flag. It never attests a CPL0 native DriverExecution guard.
unsafe impl EnteredProcess for EnteredModel {
    fn check(&self) -> Result<(), WorkError> {
        if self.thread != thread::current().id() {
            Err(WorkError::WrongCpu)
        } else if !self.allowed.load(Ordering::Acquire) {
            Err(WorkError::Closed)
        } else {
            Ok(())
        }
    }
}
#[repr(C)]
struct Control {
    context: *mut c_void,
    exhaust: unsafe extern "C" fn(*mut c_void, bool),
    heap_bytes: usize,
}
unsafe extern "C" {
    fn stela_linux_resource_fixture(context: *mut c_void);
    fn stela_linux_page_catalog_unregister(generation: u64) -> c_int;
}
unsafe extern "C" fn exhaust(context: *mut c_void, enabled: bool) {
    // SAFETY: immutable Memory Arc is held by the fixture throughout the
    // synchronous C body. This modifies only the model allocation-refusal flag.
    unsafe { &*context.cast::<Memory>() }
        .exhausted
        .store(enabled, Ordering::Release);
}
struct Fixture {
    runtime: AtomicPtr<Runtime<16>>,
    binding: Mutex<Option<Arc<TaskBinding<16>>>>,
    memory: Arc<Memory>,
}
unsafe extern "C" fn body(context: *mut c_void) {
    // SAFETY: the Queue keeps this stable fixture through every callback.
    let f = unsafe { &*context.cast::<Fixture>() };
    // SAFETY: pinned executor is held by the test through retirement;
    // no cross-thread dispatch or native execution permission is inferred.
    let runtime = unsafe { Pin::new_unchecked(&*f.runtime.load(Ordering::Acquire)) };
    // SAFETY: model's real same-thread process context before C entry; no binding
    // or metadata is published until bind_current validates the stack.
    let binding = unsafe { TaskBinding::new() }.unwrap();
    binding.bind_current(runtime).unwrap();
    *f.binding.lock().unwrap() = Some(binding.clone());
    let control = Control {
        context: Arc::as_ptr(&f.memory).cast_mut().cast(),
        exhaust,
        heap_bytes: PAGE * PAGES,
    };
    // SAFETY: attached task/stack and scoped Control/Memory stay held
    // until the finite original-C fixture returns with no owner or refs escaped.
    unsafe {
        binding.run_scoped(
            runtime,
            stela_linux_resource_fixture,
            core::ptr::from_ref(&control).cast_mut().cast(),
        )
    }
    .unwrap();
}
fn isolated(selector: &str) -> bool {
    if std::env::var_os("STELA_KERNEL_RESOURCE_CHILD").is_some() {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", selector, "--test-threads=1", "--nocapture"])
        .env("STELA_KERNEL_RESOURCE_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        std::string::String::from_utf8_lossy(&output.stdout),
        std::string::String::from_utf8_lossy(&output.stderr)
    );
    true
}
fn run(forget: bool) {
    let entered = EnteredModel {
        thread: thread::current().id(),
        allowed: AtomicBool::new(false),
    };
    let (first, first_memory) = catalog();
    let mut unused = KernelResources::new(first);
    assert_eq!(
        // SAFETY: isolated model context, same registered catalog; denied guard
        // refuses before C initialization and leaves this owner cancellable.
        unsafe { unused.initialize(&entered) },
        Err(Error::Work(WorkError::Closed))
    );
    entered.allowed.store(true, Ordering::Release);
    let mut returned = unused.cancel(&entered).ok().unwrap();
    returned.try_retire().unwrap();
    drop(returned);
    assert_eq!(first_memory.provider_drops.load(Ordering::Relaxed), 1);
    let (pages, memory) = catalog();
    let generation = pages.generation();
    let mut resources = KernelResources::new(pages);
    assert_eq!(size_of::<Request>(), 16);
    assert_eq!(core::mem::offset_of!(Request, page_generation), 8);
    {
        let _owner = Entered::try_new().unwrap();
        let short = [99u32, 8];
        assert_eq!(
            // SAFETY: C may read only this fixed8-byte header before
            // rejecting version/bytes; its generation tail is inaccessible.
            unsafe { stela_linux_resources_initialize(short.as_ptr().cast()) },
            -22
        );
        let stale = Request {
            version: 1,
            bytes: 16,
            page_generation: generation - 1,
        };
        // SAFETY: complete fixed ABI record, stale catalog generation.
        assert_eq!(unsafe { stela_linux_resources_initialize(&stale) }, -22);
    }
    // SAFETY: isolated process owns real model catalog and entered flag, with no
    // C/IRQ/producer overlap. This checks no native task or hardware service.
    unsafe { resources.initialize(&entered) }.unwrap();
    assert_eq!(memory.allocations.load(Ordering::Relaxed), 0);
    {
        let _owner = Entered::try_new().unwrap();
        assert_eq!(
            // SAFETY: same entered generation; permanent root hold must refuse
            // retirement before any per-task/slab page allocation exists.
            unsafe { stela_linux_page_catalog_unregister(generation) },
            -16
        );
    }
    assert_eq!(
        // SAFETY: same original context; second attempt rejects before effects.
        unsafe { resources.initialize(&entered) },
        Err(Error::AlreadyAttempted)
    );
    let cpu = CpuModel::new();
    let f = Arc::new(Fixture {
        runtime: AtomicPtr::new(ptr::null_mut()),
        binding: Mutex::new(None),
        memory: memory.clone(),
    });
    // SAFETY: real same-thread model and kept fixture, before any producer.
    let queue = unsafe { Queue::<16>::new(cpu, f.clone()) }.unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let required = super::super::task::stack_requirement().unwrap();
    let stacks = (0..4)
        .map(|_| Stack::new(backing(required, 0, &drops)).unwrap())
        .collect();
    let executor = Executor::new_hosted_for_test(queue, stacks).unwrap();
    let runtime = executor.runtime();
    f.runtime
        .store(runtime.get_ref() as *const _ as *mut _, Ordering::Release);
    // SAFETY: finite callback/fixture/code and all real guarded stack owners remain
    // through completion; no external/IRQ caller exists.
    unsafe { runtime.call_foreground(body, Arc::as_ptr(&f).cast_mut().cast(), u64::MAX - 1) }
        .unwrap();
    runtime.queue().close().unwrap();
    let binding = f.binding.lock().unwrap().take().unwrap();
    // SAFETY: callback and C scope returned, all test producers stopped. Exact
    // attached binding remains held through detachment and explicit release.
    let retained = unsafe { runtime.detach_binding(binding.context_id().unwrap()) }.unwrap();
    drop(retained);
    // SAFETY: same model process and unique detached metadata owner, after
    // the original resource fixture restored the bare task's exact quiet state.
    assert!(unsafe { binding.release_quiescent() }.is_ok());
    // SAFETY: all finite work returned and detached, no producer can enqueue/wake;
    // live executor keeps CPU/code/stack backing through proven retirement.
    unsafe { runtime.retire() }.unwrap();
    drop(executor);
    assert_eq!(drops.load(Ordering::Relaxed), 4);
    let (resources, error) = resources.cancel(&entered).err().unwrap();
    assert_eq!(error, Error::AlreadyAttempted);
    let before = retained_owners();
    if forget {
        core::mem::forget(resources);
        assert_eq!(retained_owners(), before);
    } else {
        drop(resources);
        assert_eq!(retained_owners(), before + 1);
    }
    assert_eq!(memory.provider_drops.load(Ordering::Relaxed), 0);
    {
        let _owner = Entered::try_new().unwrap();
        let request = Request {
            version: 1,
            bytes: 16,
            page_generation: generation,
        };
        // SAFETY: C roots/catalog must refuse reinitialization and
        // unregister independently of the lost/forgotten Rust owner handle.
        unsafe {
            assert_eq!(stela_linux_resources_initialize(&request), -16);
            assert_eq!(stela_linux_page_catalog_unregister(generation), -16);
        }
    }
    assert_eq!(memory.provider_drops.load(Ordering::Relaxed), 0);
}
#[test]
fn original_resources_release_per_task_state_and_keep_kernel_after_drop() {
    if !isolated(
        "resources::tests::original_resources_release_per_task_state_and_keep_kernel_after_drop",
    ) {
        run(false);
    }
}
#[test]
fn forgotten_kernel_owner_cannot_unregister_or_reinitialize_original_roots() {
    if !isolated(
        "resources::tests::forgotten_kernel_owner_cannot_unregister_or_reinitialize_original_roots",
    ) {
        run(true);
    }
}
