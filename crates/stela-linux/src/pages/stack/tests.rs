//! Guarded mmap owners and real Runtime/C-catalog lifetime controls.
//! PFNs/cache labels are CPU models; no native physical or IRQ grant is tested.
extern crate std;
use super::*;
use alloc::{format, sync::Arc};
use core::{ops::Range, pin::Pin};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize},
};
use stela_driver_base::bus::dma::memory::PageBacking;
use stela_driver_base::platform::work::{
    self, Cpu, Executor, Queue, Runtime, Stack, StackBacking, StackProfile, StackRequirement,
    test_support,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Case {
    Good,
    Missing,
    WrongClass,
    Busy,
    Denied,
    Postcheck,
    Drop,
    Forget,
    Stale,
    UnadmittedDrop,
}
fn kernel() -> StackRequirement {
    crate::task::stack_requirement().unwrap()
}
fn ordinary() -> StackRequirement {
    StackRequirement::at_least(128 * 1024, 4096, 4096).unwrap()
}
struct Slot {
    map: Arc<Box<dyn StackBacking>>,
    physical: u64,
    kernel: bool,
}
struct Hooks {
    active: AtomicBool,
    entered: AtomicUsize,
    ready: AtomicBool,
    revoke: AtomicBool,
}
struct Pool {
    slots: Vec<Slot>,
    heap: Arc<Box<dyn StackBacking>>,
    mapped_drops: Arc<AtomicUsize>,
    native_pin_drops: Arc<AtomicUsize>,
    heap_pin_drops: Arc<AtomicUsize>,
    provider_drops: AtomicUsize,
    hooks: Hooks,
}
impl Pool {
    fn new() -> Arc<Self> {
        let mapped_drops = Arc::new(AtomicUsize::new(0));
        let mut requirements = alloc::vec![ordinary(); 8];
        requirements[2] = kernel();
        requirements.extend(core::iter::repeat_n(ordinary(), 4));
        requirements.extend(core::iter::repeat_n(kernel(), 20));
        let slots = requirements
            .into_iter()
            .enumerate()
            .map(|(index, required)| Slot {
                map: Arc::new(test_support::backing(required, 0, &mapped_drops)),
                physical: 0x4000_0000 + index as u64 * 0x10_0000,
                kernel: required == kernel(),
            })
            .collect();
        Arc::new(Self {
            slots,
            heap: Arc::new(test_support::backing(kernel(), 0, &mapped_drops)),
            mapped_drops,
            native_pin_drops: Arc::new(AtomicUsize::new(0)),
            heap_pin_drops: Arc::new(AtomicUsize::new(0)),
            provider_drops: AtomicUsize::new(0),
            hooks: Hooks {
                active: AtomicBool::new(false),
                entered: AtomicUsize::new(0),
                ready: AtomicBool::new(false),
                revoke: AtomicBool::new(false),
            },
        })
    }
}
struct View {
    map: Arc<Box<dyn StackBacking>>,
    physical: Vec<u64>,
    dropped: Arc<AtomicUsize>,
}
impl Drop for View {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: CPU-only view holds the mmap object, including its guards.
// Usable bytes start zeroed, metadata is immutable and the symbolic page list
// is never used for hardware. Runtime keeps the same owner during execution.
unsafe impl PageBacking for View {
    fn cpu_base(&self) -> NonNull<u8> {
        NonNull::new(self.map.bounds().start as *mut u8).unwrap()
    }
    fn physical_pages(&self) -> &[u64] {
        &self.physical
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
fn view(
    map: &Arc<Box<dyn StackBacking>>,
    physical: u64,
    count: usize,
    dropped: &Arc<AtomicUsize>,
) -> PinnedPages {
    PinnedPages::new(
        Box::new(View {
            map: map.clone(),
            physical: (0..count)
                .map(|index| physical + index as u64 * 4096)
                .collect(),
            dropped: dropped.clone(),
        }),
        count * 4096,
        4096,
    )
    .unwrap()
}
struct Source {
    map: Arc<Box<dyn StackBacking>>,
    physical: u64,
    pin_drops: Arc<AtomicUsize>,
}
// SAFETY: source owns its guarded mapping object. Export is called only for
// Preparing's zeroed, never-entered usable range and shares that same owner.
unsafe impl StackBacking for Source {
    fn bounds(&self) -> Range<usize> {
        self.map.bounds()
    }
    fn guard(&self) -> Range<usize> {
        self.map.guard()
    }
    unsafe fn pin_prepared_pages(&self, epoch: u64) -> Result<PinnedPages, MemoryError> {
        Ok(view(
            &self.map,
            self.physical,
            self.map.bounds().len() / 4096,
            &self.pin_drops,
        ))
    }
}
struct Model {
    pool: Arc<Pool>,
    pin: Mutex<Option<PinnedPages>>,
}
impl Drop for Model {
    fn drop(&mut self) {
        self.pool.provider_drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: isolated CPU model keeps all registered mmap owners. It transfers
// one preallocated ordinary heap page, refuses atomic/other orders and never
// supplies Runtime stack RAM through ordinary allocation. Callbacks do not
// reenter Linux, change its borrowed owner, or invoke/switch Runtime callbacks.
unsafe impl Provider for Model {
    fn validate(&self, request: Request) -> Result<(), MemoryError> {
        if request.atomic {
            Err(MemoryError::Unavailable)
        } else {
            Ok(())
        }
    }
    fn allocate(&self, request: Request) -> Result<PinnedPages, MemoryError> {
        if request.order != 0 {
            return Err(MemoryError::OutOfMemory);
        }
        self.pin
            .lock()
            .unwrap()
            .take()
            .ok_or(MemoryError::OutOfMemory)
    }
    fn retirement(&self, _: &PinnedPages) -> PinRetirement {
        if self.pool.hooks.revoke.swap(false, Ordering::AcqRel) {
            self.pool.hooks.active.store(false, Ordering::Release);
        }
        if self.pool.hooks.ready.load(Ordering::Acquire) {
            PinRetirement::Ready
        } else {
            PinRetirement::Retain
        }
    }
}
struct ModelCpu {
    cpu: Arc<test_support::CpuModel>,
    pool: Arc<Pool>,
    unadmitted: bool,
}
// SAFETY: same-OS-thread CPU/flags model, delegating checks to CpuModel.
// No callback runs inside a metadata lock. All frames use real mmap owners.
unsafe impl Cpu for ModelCpu {
    fn check_cpu(&self) -> Result<(), WorkError> {
        self.cpu.check_cpu()
    }
    fn in_interrupt(&self) -> bool {
        self.cpu.in_interrupt()
    }
    fn save_disable(&self) -> Result<u64, WorkError> {
        self.cpu.save_disable()
    }
    unsafe fn restore(&self, flags: u64) {
        // SAFETY: enclosing same-thread model flags from this CPU.
        unsafe { self.cpu.restore(flags) }
    }
    fn ticks(&self) -> u64 {
        self.cpu.ticks()
    }
    fn fatal(&self, error: WorkError) -> ! {
        assert!(matches!(error, WorkError::Closed | WorkError::Pending));
        assert_eq!(self.pool.mapped_drops.load(Ordering::Relaxed), 0);
        assert_eq!(self.pool.native_pin_drops.load(Ordering::Relaxed), 0);
        assert_eq!(
            self.pool.provider_drops.load(Ordering::Relaxed),
            usize::from(self.unadmitted)
        );
        std::println!("OWNED_STACK_CREATOR_STOP {error:?}");
        std::process::exit(93)
    }
}
struct Scene {
    runtime: *const Runtime<64>,
    cpu: Arc<ModelCpu>,
    pool: Arc<Pool>,
    case: Case,
    marked: AtomicUsize,
}
impl Scene {
    fn runtime(&self) -> Pin<&Runtime<64>> {
        self.cpu.check_cpu().unwrap();
        // SAFETY: the pinned Executor remains alive until every accepted
        // callback joins, or fatal keeps it and ends this isolated process.
        unsafe { Pin::new_unchecked(&*self.runtime) }
    }
    fn guard(&self) -> Guard<'_> {
        assert_eq!(self.pool.hooks.entered.fetch_add(1, Ordering::AcqRel), 0);
        self.pool.hooks.active.store(true, Ordering::Release);
        Guard(self)
    }
}
struct Guard<'a>(&'a Scene);
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        assert_eq!(self.0.pool.hooks.entered.fetch_sub(1, Ordering::AcqRel), 1);
        self.0.pool.hooks.active.store(false, Ordering::Release);
    }
}
// SAFETY: same-thread borrowed entered-segment model only. Checks are
// nonblocking/nonallocating at IF0 and require this one live guard plus CPU.
unsafe impl EnteredProcess for Guard<'_> {
    fn check(&self) -> Result<(), WorkError> {
        self.0.cpu.check_cpu()?;
        if self.0.pool.hooks.entered.load(Ordering::Acquire) == 1
            && self.0.pool.hooks.active.load(Ordering::Acquire)
        {
            Ok(())
        } else {
            Err(WorkError::Unavailable)
        }
    }
}
fn catalog(scene: &Scene) -> Catalog<Model> {
    let heap = view(&scene.pool.heap, 0x2000_0000, 1, &scene.pool.heap_pin_drops);
    let mut extents = Vec::new();
    let heap_base = NonNull::new(scene.pool.heap.bounds().start as *mut u8).unwrap();
    // SAFETY: real mmap heap coverage in this isolated CPU
    // model; its symbolic PFNs are not a native physical-memory assertion.
    extents.push(Extent::ordinary(
        unsafe {
            Reservation::new(
                0x2000_0000,
                heap_base,
                scene.pool.heap.bounds().len() / 4096,
            )
        }
        .unwrap(),
    ));
    for (index, slot) in scene
        .pool
        .slots
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.kernel)
    {
        if scene.case == Case::Missing && index >= 12 {
            continue;
        }
        // SAFETY: this provider owns the same guarded slot mapping as
        // Runtime; immutable symbolic PA/CPU coverage excludes every guard.
        let reservation = unsafe {
            Reservation::new(
                slot.physical,
                NonNull::new(slot.map.bounds().start as *mut u8).unwrap(),
                slot.map.bounds().len() / 4096,
            )
        }
        .unwrap();
        extents.push(if scene.case == Case::WrongClass {
            Extent::ordinary(reservation)
        } else {
            Extent::runtime_stack(reservation)
        });
    }
    // SAFETY: real kept mmap owners back the whole immutable CPU-model
    // inventory. Root/cache/IRQ/native producers do not exist in this fixture;
    // same-thread construction and all later entry/retirement are serialized.
    unsafe {
        Catalog::register_annotated(
            Model {
                pool: scene.pool.clone(),
                pin: Mutex::new(Some(heap)),
            },
            extents,
        )
    }
    .unwrap()
}
unsafe extern "C" fn marker(pointer: *mut c_void) {
    // SAFETY: the caller keeps this exact Scene through the completed ticket.
    let scene = unsafe { &*pointer.cast::<Scene>() };
    scene.marked.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "C" fn creator(pointer: *mut c_void) {
    // SAFETY: run keeps this owned Scene until all callbacks join or fatal
    // terminates the process without releasing reachable data/frames.
    let scene = unsafe { &*pointer.cast::<Scene>() };
    let runtime = scene.runtime();
    let mut catalog = catalog(scene);
    let guard = scene.guard();
    if scene.case == Case::Postcheck {
        assert_eq!(catalog.verify(), Err(Error::Native(-ENOMEM)));
        assert_eq!(scene.pool.heap_pin_drops.load(Ordering::Relaxed), 0);
        assert_eq!(catalog.try_retire(), Err(Error::Native(-16)));
        scene.pool.hooks.ready.store(true, Ordering::Release);
        scene.pool.hooks.revoke.store(true, Ordering::Release);
    }
    let reserved = runtime.reserve_unstarted_general(&guard, kernel()).unwrap();
    let owned = reserved.into_owned().unwrap();
    let cold = match unsafe { owned.prepare_stack(&guard) } {
        Ok(cold) => cold,
        Err((_, error)) => panic!("cold prepare: {error:?}"),
    };
    let pin = match cold.pin(&guard) {
        Ok(pin) => pin,
        Err((_, error)) => panic!("cold pin: {error:?}"),
    };
    let mut admission = catalog.prepare_stack(pin);
    if scene.case == Case::UnadmittedDrop {
        drop(admission);
        let before = quarantined_catalogs();
        drop(catalog);
        assert_eq!(quarantined_catalogs(), before);
        assert_eq!(scene.pool.provider_drops.load(Ordering::Relaxed), 1);
        std::println!("CATALOG_AND_NATIVE_STACK_RETAINED unadmitted");
        return;
    }
    if scene.case == Case::Denied {
        scene.pool.hooks.active.store(false, Ordering::Release);
    }
    let busy = (scene.case == Case::Busy).then(|| Entered::try_new().unwrap());
    if let Err(error) = admission.admit(&guard) {
        let expected = match scene.case {
            Case::Missing | Case::WrongClass => AdmissionError::Catalog(Error::Native(-EINVAL)),
            Case::Busy => AdmissionError::Catalog(Error::Busy),
            Case::Denied | Case::Postcheck => AdmissionError::Work(WorkError::Unavailable),
            _ => panic!("unexpected refusal {error:?}"),
        };
        assert_eq!(error, expected);
        assert_eq!(admission.ticket.is_some(), scene.case == Case::Postcheck);
        assert_eq!(scene.pool.native_pin_drops.load(Ordering::Relaxed), 0);
        drop(busy);
        drop(guard);
        let fresh = scene.guard();
        unsafe { admission.cancel(&fresh) }.unwrap();
        catalog.try_retire().unwrap();
        assert_eq!(scene.pool.native_pin_drops.load(Ordering::Relaxed), 1);
        return;
    }
    drop(busy);
    let ticket = admission.ticket.unwrap();
    assert_eq!(
        admission.admit(&guard),
        Err(AdmissionError::AlreadyAdmitted)
    );
    assert_eq!(admission.ticket.unwrap().nonce, ticket.nonce);
    assert_eq!(admission.ticket.unwrap().record, ticket.record);
    let before = quarantined_catalogs();
    if matches!(scene.case, Case::Drop | Case::Forget | Case::Stale) {
        match scene.case {
            Case::Drop => drop(admission),
            Case::Forget => core::mem::forget(admission),
            Case::Stale => {
                scene.pool.hooks.active.store(false, Ordering::Release);
                assert_eq!(
                    cancellation_error(unsafe { admission.cancel(&guard) }),
                    AdmissionError::Work(WorkError::Unavailable)
                );
            }
            _ => unreachable!(),
        }
        drop(catalog);
        assert_eq!(quarantined_catalogs(), before + 1);
        assert_eq!(scene.pool.provider_drops.load(Ordering::Relaxed), 0);
        assert_eq!(scene.pool.native_pin_drops.load(Ordering::Relaxed), 0);
        std::println!("CATALOG_AND_NATIVE_STACK_RETAINED admitted");
        return;
    }
    let owner = Entered::try_new().unwrap();
    assert_eq!(
        // SAFETY: isolated real C metadata owner; this exact catalog's
        // native admission count must refuse retirement without freeing context.
        unsafe { stela_linux_page_catalog_unregister(catalog.generation()) },
        -16
    );
    drop(owner);
    unsafe { admission.cancel(&guard) }.unwrap();
    assert_eq!(scene.pool.native_pin_drops.load(Ordering::Relaxed), 1);
    catalog.try_retire().unwrap();
    assert_eq!(scene.pool.provider_drops.load(Ordering::Relaxed), 1);
    // SAFETY: cold cancellation reconstructed the same real frame; this finite
    // marker fits its kernel geometry and Scene remains held through drain.
    unsafe {
        runtime
            .queue()
            .execute_general_with_requirement(kernel(), marker, pointer)
    }
    .unwrap();
}
fn run(case: Case) {
    let pool = Pool::new();
    let cpu = Arc::new(ModelCpu {
        cpu: test_support::CpuModel::new(),
        pool: pool.clone(),
        unadmitted: case == Case::UnadmittedDrop,
    });
    // SAFETY: same constructing OS thread, kept pool/code/mappings, no IRQ
    // or external producers. Contexts keep owners through retirement.
    let queue = unsafe { Queue::<64>::new(cpu.clone(), pool.clone()) }.unwrap();
    let stacks = pool
        .slots
        .iter()
        .map(|slot| {
            Stack::new(Box::new(Source {
                map: slot.map.clone(),
                physical: slot.physical,
                pin_drops: pool.native_pin_drops.clone(),
            }))
            .unwrap()
        })
        .collect();
    let executor = Executor::new_hosted_profile_for_test(
        queue,
        stacks,
        work::ReservationPolicy::NativeFirmware32Protected {
            gpe: work::GpeQueueBudget::QUALIFICATION,
        },
        StackProfile::new(kernel(), ordinary(), 20, 4).unwrap(),
    )
    .unwrap();
    let runtime = executor.runtime();
    let scene = Box::into_raw(Box::new(Scene {
        runtime: runtime.get_ref(),
        cpu: cpu.clone(),
        pool: pool.clone(),
        case,
        marked: AtomicUsize::new(0),
    }));
    // SAFETY: this owned Scene remains until exact callback completion. Fatal
    // uncertainty ends the child without freeing the Scene or reachable owners.
    unsafe { runtime.call_foreground(creator, scene.cast(), cpu.ticks() + 1_000_000_000) }.unwrap();
    runtime.drain(cpu.ticks() + 1_000_000_000).unwrap();
    // SAFETY: the creator and every accepted marker callback joined; no producer
    // survives, so this unique owned fixture metadata is no longer borrowed.
    let scene = unsafe { Box::from_raw(scene) };
    assert_eq!(
        scene.marked.load(Ordering::Relaxed),
        usize::from(case == Case::Good)
    );
    assert_eq!(pool.hooks.entered.load(Ordering::Acquire), 0);
    runtime.queue().close().unwrap();
    // SAFETY: all external producers are absent, callbacks joined and every
    // owned marker/frame cancelled. Mmap owners remain held here.
    unsafe { runtime.retire() }.unwrap();
    assert_eq!(pool.mapped_drops.load(Ordering::Relaxed), 0);
    let dropped = pool.mapped_drops.clone();
    drop(scene);
    drop(executor);
    drop(cpu);
    drop(pool);
    assert_eq!(dropped.load(Ordering::Relaxed), 33);
}

fn selected() -> Option<Case> {
    std::env::var("STELA_STACK_ADMISSION_CASE")
        .ok()
        .map(|name| match name.as_str() {
            "good" => Case::Good,
            "missing" => Case::Missing,
            "class" => Case::WrongClass,
            "busy" => Case::Busy,
            "denied" => Case::Denied,
            "postcheck" => Case::Postcheck,
            "drop" => Case::Drop,
            "forget" => Case::Forget,
            "stale" => Case::Stale,
            "unadmitted" => Case::UnadmittedDrop,
            _ => panic!("unknown stack admission child"),
        })
}
fn isolate(name: &str, cases: &[(&str, bool)]) {
    if let Some(case) = selected() {
        run(case);
        return;
    }
    let selector = format!("{}::{name}", module_path!().split_once("::").unwrap().1);
    for (case, fatal) in cases {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &selector, "--test-threads=1", "--nocapture"])
            .env("STELA_STACK_ADMISSION_CASE", case)
            .output()
            .unwrap();
        let stdout = std::string::String::from_utf8_lossy(&output.stdout);
        let stderr = std::string::String::from_utf8_lossy(&output.stderr);
        if *fatal {
            assert_eq!(
                output.status.code(),
                Some(93),
                "{case}
{stdout}
{stderr}"
            );
            assert!(
                stdout.contains("CATALOG_AND_NATIVE_STACK_RETAINED"),
                "{stdout}"
            );
            assert!(stdout.contains("OWNED_STACK_CREATOR_STOP"), "{stdout}");
        } else {
            assert!(
                output.status.success(),
                "{case}
{stdout}
{stderr}"
            );
            assert!(stdout.contains("1 passed; 0 failed"), "{stdout}");
        }
    }
}
#[test]
fn admission_cancel_restores_stack() {
    isolate("admission_cancel_restores_stack", &[("good", false)]);
}
#[test]
fn admission_refusals_return_owner() {
    isolate(
        "admission_refusals_return_owner",
        &[
            ("missing", false),
            ("class", false),
            ("busy", false),
            ("denied", false),
        ],
    );
}
#[test]
fn admission_postcheck_keeps_marker() {
    isolate("admission_postcheck_keeps_marker", &[("postcheck", false)]);
}
#[test]
fn forgotten_admission_keeps_both_owners() {
    isolate(
        "forgotten_admission_keeps_both_owners",
        &[
            ("drop", true),
            ("forget", true),
            ("stale", true),
            ("unadmitted", true),
        ],
    );
}
#[test]
fn annotated_record_layout() {
    assert_eq!(size_of::<NativeExtentV3>(), 40);
    assert_eq!(core::mem::offset_of!(NativeExtentV3, kind), 32);
    assert_eq!(core::mem::offset_of!(NativeExtentV3, reserved), 36);
    assert_eq!(size_of::<NativeInventoryV3>(), 24);
    assert_eq!(core::mem::offset_of!(NativeInventoryV3, extents), 8);
    assert_eq!(core::mem::offset_of!(NativeInventoryV3, count), 16);
    assert_eq!(size_of::<NativeAdmission>(), 40);
    assert_eq!(core::mem::offset_of!(NativeAdmission, cpu_base), 16);
    assert_eq!(core::mem::offset_of!(NativeAdmission, physical_pages), 24);
    assert_eq!(size_of::<NativeTicket>(), 32);
    assert_eq!(core::mem::offset_of!(NativeTicket, generation), 8);
    assert_eq!(core::mem::offset_of!(NativeTicket, record), 16);
    assert_eq!(core::mem::offset_of!(NativeTicket, nonce), 24);
}

fn cancellation_error<T>(result: Result<(), (T, AdmissionError)>) -> AdmissionError {
    match result {
        Err((owner, error)) => {
            drop(owner);
            error
        }
        Ok(()) => panic!("expected exact catalogue/native cancellation refusal"),
    }
}
