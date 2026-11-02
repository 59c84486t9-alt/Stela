//! Actual stack, publication-tail and backing-destructor refusal controls.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
#[derive(Clone, Copy, Eq, PartialEq)]
enum Fault {
    Metadata,
    PublicationUnwind,
    DestructorUnwind,
    Postcheck,
}
struct Signals {
    fault: Fault,
    denied: AtomicBool,
    restore_armed: AtomicBool,
    published: AtomicBool,
    observed_context: AtomicU64,
    destructor_armed: AtomicBool,
    destructors: AtomicUsize,
}
struct FaultCpu {
    inner: Arc<ModelCpu>,
    runtime: Arc<AtomicU64>,
    signals: Arc<Signals>,
}
// SAFETY: existing checked OS-thread/IF model, with explicit hosted failures.
// This supplies no native RootExecution/DriverExecution or hardware evidence.
unsafe impl Cpu for FaultCpu {
    fn check_cpu(&self) -> Result<(), WorkError> {
        self.inner.check_cpu()?;
        if self.signals.denied.load(Ordering::Acquire) {
            Err(WorkError::Unavailable)
        } else {
            Ok(())
        }
    }
    fn in_interrupt(&self) -> bool {
        self.inner.in_interrupt()
    }
    fn save_disable(&self) -> Result<u64, WorkError> {
        self.check_cpu()?;
        self.inner.save_disable()
    }
    unsafe fn restore(&self, flags: u64) {
        // SAFETY: enclosing same-model flags; restore them before observation.
        unsafe { self.inner.restore(flags) };
        if flags & 512 == 0 || !self.signals.restore_armed.swap(false, Ordering::AcqRel) {
            return;
        }
        // SAFETY: armed only after this exact executor is pinned and retained.
        // Disarming excludes recursive observation of the diagnostic queue lock.
        let r = unsafe { &*(self.runtime.load(Ordering::Acquire) as *const Runtime<64>) };
        let mut guard = r.queue.lock().unwrap();
        let job = guard
            .state()
            .jobs
            .iter()
            .flatten()
            .any(|job| core::ptr::fn_addr_eq(job.callback, fault_child as Callback));
        // SAFETY: this same fixture CPU owns constructor state at IF0; only
        // copy actual private worker/assignment metadata before dropping guard.
        let context = unsafe {
            (&*r.tasks.get())
                .iter()
                .find(|task| task.stack_pin_nonce != 0 && task.state == TaskState::Ready)
                .map(|task| task.id.get())
        };
        let published =
            job && context.is_some() && r.queue.published_stack_pins.load(Ordering::Acquire) == 1;
        drop(guard);
        if published {
            self.signals
                .observed_context
                .store(context.unwrap(), Ordering::Release);
            self.signals.published.store(true, Ordering::Release);
            panic!("actual child published before outer restore returned");
        }
        self.signals.restore_armed.store(true, Ordering::Release);
    }
    fn ticks(&self) -> u64 {
        self.inner.ticks()
    }
    fn fatal(&self, error: WorkError) -> ! {
        self.inner.fatal(error)
    }
}
struct FaultSource {
    actual: Box<dyn StackBacking>,
    signals: Arc<Signals>,
}
// SAFETY: owns the existing mmap backing and forwards its original qualified
// pin. Neither CPU storage nor symbolic PA metadata is replaced.
unsafe impl StackBacking for FaultSource {
    fn bounds(&self) -> Range<usize> {
        self.actual.bounds()
    }
    fn guard(&self) -> Range<usize> {
        self.actual.guard()
    }
    unsafe fn pin_prepared_pages(&self, epoch: u64) -> Result<PinnedPages, MemoryError> {
        assert!(epoch != 0);
        // SAFETY: forwards the same exclusive cold/zeroed backing contract.
        let pin = unsafe { self.actual.pin_prepared_pages(epoch) }?;
        let bytes = pin.logical_bytes();
        PinnedPages::new(
            Box::new(FaultPin {
                pin,
                signals: self.signals.clone(),
            }),
            bytes,
            4096,
        )
    }
}
struct FaultPin {
    pin: PinnedPages,
    signals: Arc<Signals>,
}
impl Drop for FaultPin {
    fn drop(&mut self) {
        self.signals.destructors.fetch_add(1, Ordering::Release);
        if self.signals.destructor_armed.swap(false, Ordering::AcqRel) {
            if self.signals.fault == Fault::DestructorUnwind {
                panic!("actual backing destructor unwind");
            }
            if self.signals.fault == Fault::Postcheck {
                self.signals.denied.store(true, Ordering::Release);
            }
        }
    }
}
// SAFETY: retains and forwards the exact original pin/mmap/cache/page relation.
unsafe impl PageBacking for FaultPin {
    fn cpu_base(&self) -> NonNull<u8> {
        self.pin
            .cpu_mapping(CacheAttribute::WriteBack)
            .unwrap()
            .address(0, self.pin.bytes())
            .unwrap()
    }
    fn physical_pages(&self) -> &[u64] {
        self.pin.physical_pages()
    }
    fn page_shift(&self) -> u8 {
        self.pin.page_shift()
    }
    fn cache_attribute(&self) -> CacheAttribute {
        self.pin.cache_attribute()
    }
}
struct FaultScene {
    base: Arc<PinScene>,
    cpu: Arc<FaultCpu>,
    signals: Arc<Signals>,
    published: UnsafeCell<Option<PublishedGeneralStack<'static, 64>>>,
    children: AtomicUsize,
}
// SAFETY: passive Queue retention only. Affine fields are touched solely on
// this fixture's checked callback CPU/successor, never another OS thread.
unsafe impl Send for FaultScene {}
// SAFETY: the same single checked thread serializes every UnsafeCell access.
unsafe impl Sync for FaultScene {}
unsafe extern "C" fn fault_child(pointer: *mut c_void) {
    // SAFETY: queue keeps this exact fixture/code through real child completion.
    let f = unsafe { &*pointer.cast::<FaultScene>() };
    assert_eq!(f.base.entered.load(Ordering::Acquire), 0);
    assert_eq!(f.signals.destructors.load(Ordering::Acquire), 0);
    let current = f.base.runtime().current_context().unwrap();
    if f.signals.fault == Fault::PublicationUnwind {
        assert_eq!(
            current.context_id,
            f.signals.observed_context.load(Ordering::Acquire)
        );
    }
    f.children.fetch_add(1, Ordering::Release);
}
unsafe extern "C" fn creator(pointer: *mut c_void) {
    // SAFETY: exact Queue-owned scene plus actual executor survives all joins.
    let f = unsafe { &*pointer.cast::<FaultScene>() };
    // SAFETY: fixture keeps this Runtime until exact release or permanent
    // quarantine; the stored owner is taken before any successful retirement.
    let r: Pin<&'static Runtime<64>> = unsafe {
        Pin::new_unchecked(&*(f.cpu.runtime.load(Ordering::Acquire) as *const Runtime<64>))
    };
    let permission = f.base.authority();
    let owner = r
        .reserve_unstarted_general(&permission, kernel())
        .unwrap()
        .into_owned()
        .unwrap();
    let pinned = match take_prepared(owner, &permission).pin(&permission) {
        Ok(pin) => pin,
        Err(_) => panic!("valid pin refused"),
    };
    let ready = match pinned.reconstruct(&permission) {
        Ok(pin) => pin,
        Err(_) => panic!("valid reconstruction refused"),
    };
    if f.signals.fault == Fault::PublicationUnwind {
        f.signals.restore_armed.store(true, Ordering::Release);
        // SAFETY: complete actual context/code/pin roots precede publication;
        // catch stays INSIDE this Rust callback, crossing no C frame.
        let caught = catch_unwind(AssertUnwindSafe(|| unsafe {
            ready.commit(&permission, fault_child, pointer)
        }));
        assert!(caught.is_err());
        assert!(f.signals.published.load(Ordering::Acquire));
        assert_eq!(f.children.load(Ordering::Acquire), 0);
        assert_eq!(r.owned_escrows.get(), 0);
        assert_eq!(r.queue.published_stack_pins.load(Ordering::Acquire), 1);
        assert_eq!(f.base.cpu.model.flags(), 0x202);
        return;
    }
    // SAFETY: same kept callback/context/code and exact reconstructed backing.
    let published = match unsafe { ready.commit(&permission, fault_child, pointer) } {
        Ok(job) => job,
        Err(_) => panic!("valid publication refused"),
    };
    // SAFETY: checked same-CPU callback, with no concurrent affine slot reader.
    unsafe { *f.published.get() = Some(published) };
}
unsafe extern "C" fn misleading_metadata(pointer: *mut c_void) {
    // SAFETY: this real Foreground continuation borrows the kept fixture.
    let f = unsafe { &*pointer.cast::<FaultScene>() };
    let r = f.base.runtime();
    let view = r.current_context().unwrap();
    let current = r.current.get();
    // SAFETY: exact child joined; same CPU owns this affine slot.
    let published = unsafe { (*f.published.get()).take() }.unwrap();
    let flags = f.cpu.save_disable().unwrap();
    r.current.set(NONE);
    r.queue.active.clear();
    // SAFETY: intentionally false taskless metadata, actual saved flags first.
    unsafe { f.cpu.restore(flags) };
    // SAFETY: deliberate negative successor call; no foreign C users exist.
    // Actual RSP remains on this OTHER owned Runtime stack and must refuse.
    let result = unsafe { published.release() };
    let flags = f.cpu.save_disable().unwrap();
    r.current.set(current);
    r.queue.active.publish(
        ContextId(view.context_id),
        &(view.stack_start..view.stack_end),
    );
    // SAFETY: exact native current/active and flags restored before assertions.
    unsafe { f.cpu.restore(flags) };
    let published = match result {
        Err((job, WorkError::Busy)) => job,
        _ => panic!("owned RSP spoofed successor"),
    };
    assert_eq!(f.signals.destructors.load(Ordering::Acquire), 0);
    // SAFETY: same checked continuation, no concurrent slot user.
    unsafe { *f.published.get() = Some(published) };
}
fn metadata_fences(
    r: Pin<&Runtime<64>>,
    f: &FaultScene,
    published: PublishedGeneralStack<'static, 64>,
) -> PublishedGeneralStack<'static, 64> {
    r.queue.completing.store(true, Ordering::Release);
    // SAFETY: no foreign users; injected live-completion metadata must refuse.
    let result = unsafe { published.release() };
    r.queue.completing.store(false, Ordering::Release);
    let published = match result {
        Err((job, WorkError::Busy)) => job,
        _ => panic!("completing fence omitted"),
    };
    let flags = f.cpu.save_disable().unwrap();
    // SAFETY: same checked dispatcher at IF0, immutable kept constructor ranges.
    let bounds = unsafe {
        (&*r.tasks.get())
            .iter()
            .find(|task| task.id == published.assigned().context_id())
            .unwrap()
            .stack
            .bounds
            .clone()
    };
    r.queue
        .active
        .publish(published.assigned().context_id(), &bounds);
    // SAFETY: exact flags; no task borrow survives this negative publication.
    unsafe { f.cpu.restore(flags) };
    // SAFETY: no foreign users; injected active identity must independently refuse.
    let result = unsafe { published.release() };
    let flags = f.cpu.save_disable().unwrap();
    r.queue.active.clear();
    // SAFETY: exact flags after restoring actual taskless dispatcher metadata.
    unsafe { f.cpu.restore(flags) };
    match result {
        Err((job, WorkError::Busy)) => job,
        _ => panic!("active fence omitted"),
    }
}
fn run(fault: Fault) {
    let dropped = Arc::new(AtomicUsize::new(0));
    let inner = Arc::new(ModelCpu {
        model: test_support::CpuModel::new(),
        dropped: dropped.clone(),
        mode: Mode::Bytes,
        watch: AtomicU64::new(0),
        watch_state: AtomicU64::new(0),
        restored: AtomicBool::new(false),
    });
    let base = Arc::new(PinScene {
        runtime: AtomicU64::new(0),
        cpu: inner.clone(),
        case: Case::Good,
        active: AtomicBool::new(true),
        entered: AtomicUsize::new(0),
        exports: AtomicUsize::new(0),
        pins_dropped: Arc::new(AtomicUsize::new(0)),
        marked: AtomicUsize::new(0),
        binding: Mutex::new(None),
        held_view: Mutex::new(None),
    });
    let signals = Arc::new(Signals {
        fault,
        denied: AtomicBool::new(false),
        restore_armed: AtomicBool::new(false),
        published: AtomicBool::new(false),
        observed_context: AtomicU64::new(0),
        destructor_armed: AtomicBool::new(false),
        destructors: AtomicUsize::new(0),
    });
    let cpu = Arc::new(FaultCpu {
        inner,
        runtime: Arc::new(AtomicU64::new(0)),
        signals: signals.clone(),
    });
    let f = Arc::new(FaultScene {
        base: base.clone(),
        cpu: cpu.clone(),
        signals: signals.clone(),
        published: UnsafeCell::new(None),
        children: AtomicUsize::new(0),
    });
    let stacks = mappings(&base, &dropped)
        .into_iter()
        .map(|stack| {
            let Stack { backing, .. } = stack;
            Stack::new(Box::new(FaultSource {
                actual: backing,
                signals: signals.clone(),
            }))
            .unwrap()
        })
        .collect();
    // SAFETY: exact Queue-owned fixture/code and original mapped backing roots.
    let queue = unsafe { Queue::<64>::new(cpu.clone(), f.clone()) }.unwrap();
    let executor =
        Executor::new_hosted_profile_for_test(queue, stacks, policy(), profile()).unwrap();
    let r = executor.runtime();
    cpu.runtime
        .store(r.get_ref() as *const Runtime<64> as u64, Ordering::Release);
    base.runtime
        .store(r.get_ref() as *const Runtime<64> as u64, Ordering::Release);
    let pointer = Arc::as_ptr(&f) as *mut c_void;
    // SAFETY: fixture remains kept until creator/child join and explicit release.
    unsafe { r.call_foreground(creator, pointer, cpu.ticks() + 1_000_000_000) }.unwrap();
    r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    assert_eq!(f.children.load(Ordering::Acquire), 1);
    if fault == Fault::PublicationUnwind {
        assert!(signals.published.load(Ordering::Acquire));
        assert_eq!(signals.destructors.load(Ordering::Acquire), 0);
        assert_eq!(base.pins_dropped.load(Ordering::Acquire), 0);
        // SAFETY: real callbacks joined; missing handle must still retain the
        // complete Runtime/code/root owner and physical worker/pin allocation.
        r.queue.close().unwrap();
        // SAFETY: the same stopped, joined graph now also has closed admission.
        assert_eq!(unsafe { r.retire() }, Err(WorkError::Pending));
        // SAFETY: every native callback/producers joined and admission closed;
        // only the actual retained publication/pin blocks independent Queue retirement.
        assert_eq!(unsafe { r.queue.retire() }, Err(WorkError::Pending));
        drop(executor);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        return;
    }
    if fault == Fault::Metadata {
        // SAFETY: slot keeps the joined child owner while a real different
        // Runtime stack supplies the misleading-taskless-metadata control.
        unsafe { r.call_foreground(misleading_metadata, pointer, cpu.ticks() + 1_000_000_000) }
            .unwrap();
    }
    // SAFETY: actual dispatcher owns the affine slot, with every native job joined.
    let published = unsafe { (*f.published.get()).take() }.unwrap();
    let published = if fault == Fault::Metadata {
        metadata_fences(r, &f, published)
    } else {
        published
    };
    signals.destructor_armed.store(
        matches!(fault, Fault::DestructorUnwind | Fault::Postcheck),
        Ordering::Release,
    );
    if fault == Fault::DestructorUnwind {
        // SAFETY: no foreign C resources exist, real native child has joined.
        let caught = catch_unwind(AssertUnwindSafe(|| unsafe { published.release() }));
        assert!(caught.is_err());
        assert_eq!(signals.destructors.load(Ordering::Acquire), 1);
        assert_eq!(r.queue.published_stack_pins.load(Ordering::Acquire), 1);
        // SAFETY: callbacks/producers stopped; uncertain destructor must retain
        // actual worker/root ownership despite every native ticket completing.
        r.queue.close().unwrap();
        // SAFETY: the same stopped, joined graph now also has closed admission.
        assert_eq!(unsafe { r.retire() }, Err(WorkError::Pending));
        // SAFETY: every native callback/producers joined and admission closed;
        // only the actual retained publication/pin blocks independent Queue retirement.
        assert_eq!(unsafe { r.queue.retire() }, Err(WorkError::Pending));
        drop(executor);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        return;
    }
    let published = if fault == Fault::Postcheck {
        // SAFETY: no C users exist, child joined; destructor revokes the actual
        // model CPU admission only after the pre-destructor successor check.
        let published = match unsafe { published.release() } {
            Err((job, WorkError::Unavailable)) => job,
            _ => panic!("postcheck revocation lost owner"),
        };
        assert_eq!(signals.destructors.load(Ordering::Acquire), 1);
        assert_eq!(r.queue.published_stack_pins.load(Ordering::Acquire), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        signals.denied.store(false, Ordering::Release); // fresh model segment
        published
    } else {
        published
    };
    // SAFETY: fresh actual successor and no foreign users; previous successful
    // pin destruction is represented in the retained owner, never replayed.
    assert!(unsafe { published.release() }.is_ok());
    assert_eq!(signals.destructors.load(Ordering::Acquire), 1);
    assert_eq!(base.pins_dropped.load(Ordering::Acquire), 1);
    assert_eq!(r.queue.published_stack_pins.load(Ordering::Acquire), 0);
    r.queue.close().unwrap();
    // SAFETY: every job joined and pin/native worker ownership explicitly released.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
}
#[test]
fn actual_owned_stack_refuses_misleading_taskless_metadata() {
    run(Fault::Metadata);
}
#[test]
fn real_child_publication_survives_outer_restore_unwind_without_handle() {
    run(Fault::PublicationUnwind);
}
#[test]
fn actual_pin_destructor_unwind_keeps_runtime_and_worker_excluded() {
    run(Fault::DestructorUnwind);
}
#[test]
fn post_destructor_refusal_retries_without_dropping_pin_twice() {
    run(Fault::Postcheck);
}
