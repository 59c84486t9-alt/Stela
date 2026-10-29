use super::*;
extern crate std;

struct Model {
    ticks: AtomicU64,
    pending: AtomicBool,
    fail_pending: AtomicBool,
    fail_mask: AtomicBool,
    wrong_cpu: AtomicBool,
    fail_target: AtomicBool,
    invalid_target: AtomicBool,
    migrate_on_sync: AtomicBool,
    admit_irq: AtomicBool,
    callbacks: AtomicUsize,
    eois: AtomicUsize,
    quiesces: AtomicUsize,
    source_drops: AtomicUsize,
    handler_drops: AtomicUsize,
    registry: AtomicPtr<Registry<ModelPlatform>>,
    vector: AtomicU8,
}
impl Model {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            ticks: AtomicU64::new(0),
            pending: AtomicBool::new(false),
            fail_pending: AtomicBool::new(false),
            fail_mask: AtomicBool::new(false),
            wrong_cpu: AtomicBool::new(false),
            fail_target: AtomicBool::new(false),
            invalid_target: AtomicBool::new(false),
            migrate_on_sync: AtomicBool::new(false),
            admit_irq: AtomicBool::new(true),
            callbacks: AtomicUsize::new(0),
            eois: AtomicUsize::new(0),
            quiesces: AtomicUsize::new(0),
            source_drops: AtomicUsize::new(0),
            handler_drops: AtomicUsize::new(0),
            registry: AtomicPtr::new(core::ptr::null_mut()),
            vector: AtomicU8::new(0),
        })
    }
}
struct ModelPlatform(Arc<Model>, Option<std::thread::ThreadId>);
// SAFETY: synchronous explicit IRQ/controller model; no physical accesses.
unsafe impl Platform for ModelPlatform {
    fn check_cpu(&self) -> Result<(), IrqError> {
        if self.0.wrong_cpu.load(Ordering::Relaxed)
            || self.1.is_some_and(|id| id != std::thread::current().id())
        {
            Err(IrqError::WrongCpu)
        } else {
            Ok(())
        }
    }
    fn save_and_disable(&self) -> u64 {
        0
    }
    unsafe fn restore(&self, saved: u64) {
        assert_eq!(saved, 0);
    }
    fn target(&self, vector: u8) -> Result<Target, IrqError> {
        if self.0.fail_target.load(Ordering::Relaxed) {
            return Err(IrqError::Route);
        }
        self.0.vector.store(vector, Ordering::Relaxed);
        Ok(Target {
            destination: if self.0.invalid_target.load(Ordering::Relaxed) {
                255
            } else {
                0
            },
            vector,
        })
    }
    fn pending(&self, _: u8) -> Result<bool, IrqError> {
        if self.0.fail_pending.load(Ordering::Relaxed) {
            Err(IrqError::FailedRead)
        } else {
            Ok(self.0.pending.load(Ordering::Relaxed))
        }
    }
    fn eoi(&self) {
        self.0.eois.fetch_add(1, Ordering::Relaxed);
        self.0.pending.store(false, Ordering::Relaxed);
    }
    fn ticks(&self) -> u64 {
        self.0.ticks.fetch_add(1, Ordering::Relaxed)
    }
    fn timeout_ticks(&self) -> u64 {
        8
    }
    unsafe fn interrupt_window(&self) {
        if self.0.admit_irq.load(Ordering::Relaxed) && self.0.pending.load(Ordering::Relaxed) {
            // SAFETY: the model registry is leaked/stable, and closing
            // keeps its source/context for this pending delivery.
            let registry = unsafe { &*self.0.registry.load(Ordering::Relaxed) };
            assert!(registry.dispatch(self.0.vector.load(Ordering::Relaxed)));
        }
    }
}
struct ModelSource(Arc<Model>);
// SAFETY: explicit stopped-source model with injected mask failures and
// controller delivery. Quiesce represents device/work completion.
unsafe impl Source for ModelSource {
    fn mask(&mut self) -> Result<(), IrqError> {
        if self.0.fail_mask.load(Ordering::Relaxed) {
            Err(IrqError::Mask)
        } else {
            Ok(())
        }
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        self.0.quiesces.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn route(&self) -> RouteRequest {
        RouteRequest::Msi
    }
    unsafe fn program(&mut self, route: Route) -> Result<(), IrqError> {
        let Route::Msi(message) = route else {
            return Err(IrqError::Route);
        };
        assert_eq!(message.address, 0xfee00000);
        assert_eq!(
            message.data,
            u32::from(self.0.vector.load(Ordering::Relaxed))
        );
        Ok(())
    }
    unsafe fn unmask(&mut self) -> Result<(), IrqError> {
        Ok(())
    }
    unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
        self.synchronized()
    }
}
impl ModelSource {
    fn synchronized(&mut self) -> Result<(), IrqError> {
        self.quiesce()
    }
}
impl Drop for ModelSource {
    fn drop(&mut self) {
        self.0.source_drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct ModelHandler(Arc<Model>);
impl Handler for ModelHandler {
    fn handle(&self) -> Disposition {
        self.0.callbacks.fetch_add(1, Ordering::Relaxed);
        Disposition::Handled
    }
}
impl Drop for ModelHandler {
    fn drop(&mut self) {
        self.0.handler_drops.fetch_add(1, Ordering::Relaxed);
    }
}
fn registry(model: Arc<Model>) -> &'static Registry<ModelPlatform> {
    let registry = Box::leak(Box::new(Registry::new(ModelPlatform(model.clone(), None))));
    model.registry.store(registry, Ordering::Relaxed);
    registry
}
fn request(
    registry: &'static Registry<ModelPlatform>,
    model: &Arc<Model>,
) -> Registration<'static, ModelPlatform> {
    registry
        .request(
            Box::new(ModelSource(model.clone())),
            Arc::new(ModelHandler(model.clone())),
        )
        .unwrap()
}

// Rc/Cell plus a real creating thread identity make this owner
// !Send; no unsafe Send/Sync implementation or integer ownership erasure.
struct LocalSource {
    inner: ModelSource,
    token: std::rc::Rc<core::cell::Cell<usize>>,
    owner: std::thread::ThreadId,
}
// SAFETY: explicit same-CPU source model; the registry is the only owner
// and must keep it on every unchecked admission/retirement path.
unsafe impl Source for LocalSource {
    fn mask(&mut self) -> Result<(), IrqError> {
        self.inner.mask()
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        self.inner.quiesce()
    }
    fn route(&self) -> RouteRequest {
        self.inner.route()
    }
    unsafe fn program(&mut self, route: Route) -> Result<(), IrqError> {
        // SAFETY: forwards the wrapped source's own call under the same contract.
        unsafe { self.inner.program(route) }
    }
    unsafe fn unmask(&mut self) -> Result<(), IrqError> {
        // SAFETY: forwards the wrapped source's own call under the same contract.
        unsafe { self.inner.unmask() }
    }
    unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
        // SAFETY: forwards the wrapped source's own call under the same contract.
        unsafe { self.inner.synchronize() }?;
        if self.inner.0.migrate_on_sync.load(Ordering::Relaxed) {
            self.inner.0.wrong_cpu.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}
impl Drop for LocalSource {
    fn drop(&mut self) {
        assert_eq!(self.owner, std::thread::current().id());
        assert!(!self.inner.0.wrong_cpu.load(Ordering::Relaxed));
        assert_eq!(
            self.inner.0.handler_drops.load(Ordering::Relaxed),
            0,
            "source must release while its callback owner remains retained"
        );
        self.token.set(self.token.get() + 1);
    }
}
fn local_source(
    model: &Arc<Model>,
    token: std::rc::Rc<core::cell::Cell<usize>>,
) -> Box<dyn Source> {
    Box::new(LocalSource {
        inner: ModelSource(model.clone()),
        token,
        owner: std::thread::current().id(),
    })
}
#[test]
fn local_source_releases_before_handler_only_on_checked_cpu() {
    let model = Model::new();
    let registry = registry(model.clone());
    let token = std::rc::Rc::new(core::cell::Cell::new(0));
    let mut registration = registry
        .request(
            local_source(&model, token.clone()),
            Arc::new(ModelHandler(model.clone())),
        )
        .unwrap();
    model.migrate_on_sync.store(true, Ordering::Relaxed);
    assert_eq!(registration.retire(), Err(IrqError::WrongCpu));
    assert_eq!(token.get(), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    model.migrate_on_sync.store(false, Ordering::Relaxed);
    model.wrong_cpu.store(false, Ordering::Relaxed);
    registration.retire().unwrap();
    assert_eq!(token.get(), 1);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
}
#[test]
fn returned_local_source_keeps_callback_context_through_its_final_release() {
    let model = Model::new();
    let registry = registry(model.clone());
    let token = std::rc::Rc::new(core::cell::Cell::new(0));
    let mut registration = registry
        .request(
            local_source(&model, token.clone()),
            Arc::new(ModelHandler(model.clone())),
        )
        .unwrap();
    let retired = registration.retire_source().unwrap();
    assert_eq!(token.get(), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    drop(retired);
    assert_eq!(token.get(), 1);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
}
#[test]
fn untouched_typed_refusal_keeps_affine_source_and_callback_bound_for_default_drop() {
    let model = Model::new();
    let registry = registry(model.clone());
    let token = std::rc::Rc::new(core::cell::Cell::new(0));
    model.fail_target.store(true, Ordering::Relaxed);
    let Err(refusal) = registry.request_owned(
        LocalSource {
            inner: ModelSource(model.clone()),
            token: token.clone(),
            owner: std::thread::current().id(),
        },
        Arc::new(ModelHandler(model.clone())),
    ) else {
        panic!("failed target registered")
    };
    assert!(refusal.returned.is_some());
    assert_eq!(token.get(), 0);
    drop(refusal);
    assert_eq!(token.get(), 1);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
}
#[test]
fn all_early_admission_errors_keep_affine_source_and_callback_owner() {
    for case in 0..4 {
        let model = Model::new();
        let registry = registry(model.clone());
        let mut occupied = alloc::vec::Vec::new();
        if case == 3 {
            for _ in 0..VECTOR_COUNT {
                occupied.push(request(registry, &model));
            }
        }
        model.wrong_cpu.store(case == 0, Ordering::Relaxed);
        model.fail_target.store(case == 1, Ordering::Relaxed);
        model.invalid_target.store(case == 2, Ordering::Relaxed);
        let token = std::rc::Rc::new(core::cell::Cell::new(0));
        let result = registry.request(
            local_source(&model, token.clone()),
            Arc::new(ModelHandler(model.clone())),
        );
        let Err(refusal) = result else {
            panic!("an inadmissible request registered");
        };
        assert_eq!(
            refusal.error,
            [
                IrqError::WrongCpu,
                IrqError::Route,
                IrqError::Route,
                IrqError::Exhausted
            ][case]
        );
        assert_eq!(token.get(), 0);
        assert_eq!(std::rc::Rc::strong_count(&token), 2);
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
        // Only a wrong-CPU refusal keeps the owners; the others return
        // them untouched for the driver to keep polling with.
        assert_eq!(refusal.returned.is_some(), case != 0);
        assert_eq!(registry.quarantine_count(), u64::from(case == 0));
        drop(refusal);
        model.wrong_cpu.store(false, Ordering::Relaxed);
        for mut registered in occupied {
            registered.retire().unwrap();
        }
    }
}
#[test]
fn foreign_thread_admission_and_abandoned_migration_never_drop_local_owner() {
    let model = Model::new();
    let registry = Box::leak(Box::new(Registry::new(ModelPlatform(
        model.clone(),
        Some(std::thread::current().id()),
    ))));
    let registry: &'static Registry<ModelPlatform> = registry;
    let other = model.clone();
    std::thread::spawn(move || {
        let token = std::rc::Rc::new(core::cell::Cell::new(0));
        let result = registry.request(
            local_source(&other, token.clone()),
            Arc::new(ModelHandler(other.clone())),
        );
        assert!(matches!(
            result,
            Err(RequestError {
                error: IrqError::WrongCpu,
                returned: None
            })
        ));
        assert_eq!(token.get(), 0);
        assert_eq!(std::rc::Rc::strong_count(&token), 2);
    })
    .join()
    .unwrap();
    assert_eq!(registry.quarantine_count(), 1);
    let token = std::rc::Rc::new(core::cell::Cell::new(0));
    let registration = registry
        .request(
            local_source(&model, token.clone()),
            Arc::new(ModelHandler(model.clone())),
        )
        .unwrap();
    model.wrong_cpu.store(true, Ordering::Relaxed);
    drop(registration);
    assert_eq!(registry.quarantine_count(), 2);
    assert_eq!(token.get(), 0);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn immutable_sharing_invokes_all_members_and_preserves_unclaimed_status() {
    struct Member(Arc<AtomicUsize>, Disposition);
    impl Handler for Member {
        fn handle(&self) -> Disposition {
            self.0.fetch_add(1, Ordering::Relaxed);
            self.1
        }
    }
    let count = Arc::new(AtomicUsize::new(0));
    let a: Arc<dyn Handler> = Arc::new(Member(count.clone(), Disposition::NotMine));
    let b: Arc<dyn Handler> = Arc::new(Member(count.clone(), Disposition::Handled));
    assert!(matches!(
        SharedHandlers::new(alloc::vec![]),
        Err(IrqError::Unsupported)
    ));
    assert!(matches!(
        SharedHandlers::new(alloc::vec![a.clone(), a.clone()]),
        Err(IrqError::Unsupported)
    ));
    let group = SharedHandlers::new(alloc::vec![a.clone(), b.clone()]).unwrap();
    assert_eq!(group.handle(), Disposition::Handled);
    assert_eq!(count.load(Ordering::Relaxed), 2);
    assert_eq!(Arc::strong_count(&a), 2);
    let model = Model::new();
    let r = registry(model.clone());
    let mut registration = r.request(Box::new(ModelSource(model.clone())), a).unwrap();
    assert!(r.dispatch(registration.vector()));
    assert_eq!(registration.handled(), Ok(0));
    assert_eq!(model.eois.load(Ordering::Relaxed), 1);
    registration.retire().unwrap();
}

#[test]
fn real_registration_lifetime_drains_pending_delivery_before_final_release_and_reuse() {
    let model = Model::new();
    let registry = registry(model.clone());
    let mut registration = request(registry, &model);
    let vector = registration.vector();
    assert!(!registry.dispatch(FIRST_VECTOR - 1));
    assert!(registry.dispatch(vector));
    assert_eq!(registration.handled(), Ok(1));
    assert_eq!(model.callbacks.load(Ordering::Relaxed), 1);
    assert_eq!(model.eois.load(Ordering::Relaxed), 1);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    model.pending.store(true, Ordering::Relaxed);
    registration.retire().unwrap();
    assert!(!registry.dispatch(vector));
    assert_eq!(
        model.callbacks.load(Ordering::Relaxed),
        1,
        "closing IRQ must not enter the detached device callback"
    );
    assert_eq!(model.eois.load(Ordering::Relaxed), 2);
    assert_eq!(
        model.quiesces.load(Ordering::Relaxed),
        3,
        "work created by a formerly in-flight callback is drained after ISR completion"
    );
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
    let mut reused = request(registry, &model);
    assert_eq!(reused.vector(), vector);
    reused.retire().unwrap();
}

#[test]
fn concrete_source_handoff_returns_original_owner_only_after_acknowledged_drain() {
    let model = Model::new();
    let registry = registry(model.clone());
    let mut registration = registry
        .request_owned(
            ModelSource(model.clone()),
            Arc::new(ModelHandler(model.clone())),
        )
        .unwrap();
    let vector = registration.vector();
    model.pending.store(true, Ordering::Relaxed);
    model.fail_mask.store(true, Ordering::Relaxed);
    assert!(matches!(registration.retire(), Err(IrqError::Mask)));
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    model.fail_mask.store(false, Ordering::Relaxed);
    let retired = registration.retire().unwrap();
    assert_eq!(retired.route().vector(), vector);
    // SAFETY: this concrete modeled source has no release dependency;
    // keep its callback until after explicit source destruction.
    let (source, handler, route) = unsafe { retired.into_parts() };
    assert!(Arc::ptr_eq(&source.0, &model));
    assert_eq!(route.vector(), vector);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.eois.load(Ordering::Relaxed), 1);
    assert!(!registry.dispatch(vector));
    assert!(matches!(registration.retire(), Err(IrqError::Unregistered)));
    drop(source);
    drop(handler);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
    let mut reused = request(registry, &model);
    assert_eq!(reused.vector(), vector);
    reused.retire().unwrap();
}

#[test]
fn typed_early_refusal_preserves_original_source_for_untouched_retry() {
    let model = Model::new();
    let registry = registry(model.clone());
    model.fail_target.store(true, Ordering::Relaxed);
    let Err(refusal) = registry.request_owned(
        ModelSource(model.clone()),
        Arc::new(ModelHandler(model.clone())),
    ) else {
        panic!("failed target registered")
    };
    assert_eq!(refusal.error, IrqError::Route);
    // SAFETY: preserve the original CPU and callback through source
    // retry below; the refused request has not changed either owner.
    let (source, handler) = unsafe { refusal.returned.unwrap().into_parts() };
    assert!(Arc::ptr_eq(&source.0, &model));
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    model.fail_target.store(false, Ordering::Relaxed);
    let mut registration = registry.request_owned(*source, handler).unwrap();
    assert_eq!(registry.quarantine_count(), 0);
    drop(registration.retire().unwrap());
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn failed_pending_read_and_timeout_keep_for_retry_without_vector_reuse() {
    let model = Model::new();
    let registry = registry(model.clone());
    let mut registration = request(registry, &model);
    model.fail_pending.store(true, Ordering::Relaxed);
    assert_eq!(registration.retire(), Err(IrqError::FailedRead));
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    model.fail_pending.store(false, Ordering::Relaxed);
    model.pending.store(true, Ordering::Relaxed);
    model.admit_irq.store(false, Ordering::Relaxed);
    assert_eq!(registration.retire(), Err(IrqError::Drain));
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    model.admit_irq.store(true, Ordering::Relaxed);
    registration.retire().unwrap();
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn failed_teardown_or_arming_quarantines_the_source() {
    let model = Model::new();
    let registry = registry(model.clone());
    let registration = request(registry, &model);
    let vector = registration.vector();
    model.fail_mask.store(true, Ordering::Relaxed);
    drop(registration);
    assert_eq!(registry.quarantine_count(), 1);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    assert!(registry.dispatch(vector));
    assert_eq!(model.callbacks.load(Ordering::Relaxed), 0);
    assert!(matches!(
        registry.request(
            Box::new(ModelSource(model.clone())),
            Arc::new(ModelHandler(model.clone()))
        ),
        Err(RequestError {
            error: IrqError::Mask,
            returned: None
        })
    ));
    assert_eq!(registry.quarantine_count(), 2);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn callback_borrow_outlives_failed_removal_without_arc_clone_or_early_release() {
    struct BlockedHandler {
        entered: std::sync::Barrier,
        release: std::sync::Barrier,
        model: Arc<Model>,
    }
    impl Handler for BlockedHandler {
        fn handle(&self) -> Disposition {
            self.entered.wait();
            self.release.wait();
            Disposition::Handled
        }
    }
    impl Drop for BlockedHandler {
        fn drop(&mut self) {
            self.model.handler_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    let model = Model::new();
    let registry = registry(model.clone());
    let handler = Arc::new(BlockedHandler {
        entered: std::sync::Barrier::new(2),
        release: std::sync::Barrier::new(2),
        model: model.clone(),
    });
    let mut registration = registry
        .request(Box::new(ModelSource(model.clone())), handler.clone())
        .unwrap();
    let vector = registration.vector();
    // Concurrent model interleaving stresses the reader/remove lifetime;
    // the native adapter remains confined to its one owning BSP.
    let irq = std::thread::spawn(move || assert!(registry.dispatch(vector)));
    handler.entered.wait();
    assert_eq!(registration.retire(), Err(IrqError::Drain));
    assert_eq!(
        Arc::strong_count(&handler),
        2,
        "dispatch must not clone the handler Arc"
    );
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    handler.release.wait();
    irq.join().unwrap();
    registration.retire().unwrap();
    assert_eq!(Arc::strong_count(&handler), 1);
    assert_eq!(model.eois.load(Ordering::Relaxed), 1);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
    drop(handler);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
}
