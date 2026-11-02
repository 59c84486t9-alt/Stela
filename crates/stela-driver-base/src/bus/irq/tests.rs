use super::*;
use posted_msi::RouteOwner;
extern crate std;

struct Model {
    ticks: AtomicU64,
    pending: AtomicBool,
    fail_pending: AtomicBool,
    fail_eoi: AtomicBool,
    config_failures: AtomicU8,
    controller_on_unmask: AtomicU8,
    mask_calls: AtomicUsize,
    dispatch_on_program: AtomicBool,
    dispatch_on_unmask: AtomicBool,
    panic_unmask: AtomicBool,
    panic_pending: AtomicBool,
    panic_window: AtomicBool,
    irq_enabled: AtomicBool,
    root_epoch: AtomicU64,
    fail_mask: AtomicBool,
    panic_mask: AtomicBool,
    panic_sync: AtomicBool,
    root_pending: AtomicBool,
    root_checks: AtomicUsize,
    root_fences: AtomicUsize,
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
            fail_eoi: AtomicBool::new(false),
            config_failures: AtomicU8::new(0),
            controller_on_unmask: AtomicU8::new(0),
            mask_calls: AtomicUsize::new(0),
            dispatch_on_program: AtomicBool::new(false),
            dispatch_on_unmask: AtomicBool::new(false),
            panic_unmask: AtomicBool::new(false),
            panic_pending: AtomicBool::new(false),
            panic_window: AtomicBool::new(false),
            irq_enabled: AtomicBool::new(true),
            root_epoch: AtomicU64::new(1),
            fail_mask: AtomicBool::new(false),
            panic_mask: AtomicBool::new(false),
            panic_sync: AtomicBool::new(false),
            root_pending: AtomicBool::new(false),
            root_checks: AtomicUsize::new(0),
            root_fences: AtomicUsize::new(0),
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
    fn check_process(&self) -> Result<(), crate::bus::irq::IrqError> {
        self.check_cpu()
    }
    fn save_and_disable(&self) -> u64 {
        u64::from(self.0.irq_enabled.swap(false, Ordering::AcqRel))
    }
    unsafe fn restore(&self, saved: u64) {
        assert!(saved <= 1);
        self.0.irq_enabled.store(saved != 0, Ordering::Release);
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
        assert!(
            !self.0.panic_pending.load(Ordering::Relaxed),
            "injected pending unwind"
        );
        if self.0.fail_pending.load(Ordering::Relaxed) {
            Err(IrqError::FailedRead)
        } else {
            Ok(self.0.pending.load(Ordering::Relaxed))
        }
    }
    fn eoi(&self, _vector: u8) -> Result<crate::bus::irq::Trigger, crate::bus::irq::IrqError> {
        self.0.eois.fetch_add(1, Ordering::Relaxed);
        if self.0.config_failures.load(Ordering::Acquire) & 1 != 0 {
            return Err(config_fault(0x54));
        }
        if self.0.fail_eoi.load(Ordering::Acquire) {
            return Err(IrqError::FailedRead);
        }
        self.0.pending.store(false, Ordering::Relaxed);
        Ok(crate::bus::irq::Trigger::Edge)
    }
    fn ticks(&self) -> u64 {
        self.0.ticks.fetch_add(1, Ordering::Relaxed)
    }
    fn timeout_ticks(&self) -> u64 {
        8
    }
    unsafe fn interrupt_window(&self) {
        assert!(
            !self.0.panic_window.load(Ordering::Relaxed),
            "injected window unwind"
        );
        if self.0.admit_irq.load(Ordering::Relaxed) && self.0.pending.load(Ordering::Relaxed) {
            // SAFETY: the model registry is leaked/stable, and closing
            // keeps its source/context for this pending delivery.
            let registry = unsafe { &*self.0.registry.load(Ordering::Relaxed) };
            assert!(registry.dispatch(self.0.vector.load(Ordering::Relaxed)));
        }
    }
}

struct ModelDomain {
    model: Arc<Model>,
    epoch: u64,
}
// SAFETY: same explicit controller/source model and its actual epoch/CPU state;
// no native permission or physical source is fabricated by this fixture.
unsafe impl posted_msi::NotificationDomain for ModelDomain {
    fn check(&self) -> Result<(), posted_msi::Error> {
        if self.model.wrong_cpu.load(Ordering::Acquire) {
            return Err(posted_msi::Error::Context);
        }
        if self.model.root_epoch.load(Ordering::Acquire) != self.epoch {
            return Err(posted_msi::Error::RootFailed);
        }
        Ok(())
    }
}
struct DeliveryPeer {
    model: Arc<Model>,
    allocated: bool,
    epoch: u64,
}
// SAFETY: explicit isolated no-native-pin route peer. Its independent pending
// state is not source stop, payload, CPU IRR/ISR or a native delivery receipt.
unsafe impl posted_msi::RouteOwner for DeliveryPeer {
    fn allocate(
        &mut self,
        target: &CpuTarget<'_>,
    ) -> Result<MsiMessage, posted_msi::AllocationError> {
        target
            .check_current()
            .map_err(|_| posted_msi::AllocationError::Unexposed(posted_msi::Error::Context))?;
        if self.allocated {
            return Err(posted_msi::AllocationError::Unexposed(
                posted_msi::Error::AlreadyBound,
            ));
        }
        self.allocated = true;
        let target = target.descriptor();
        Ok(MsiMessage {
            address: 0xfee0_0000 | u64::from(target.destination) << 12,
            data: u32::from(target.vector),
        })
    }
    fn validate(&self) -> Result<(), posted_msi::Error> {
        self.model.root_checks.fetch_add(1, Ordering::Relaxed);
        if self.model.root_epoch.load(Ordering::Acquire) != self.epoch {
            return Err(posted_msi::Error::RootFailed);
        }
        if self.model.wrong_cpu.load(Ordering::Relaxed) {
            Err(posted_msi::Error::Context)
        } else {
            Ok(())
        }
    }
    fn notification_domain(
        &self,
    ) -> Result<Arc<dyn posted_msi::NotificationDomain>, posted_msi::Error> {
        self.validate()?;
        Ok(Arc::new(ModelDomain {
            model: self.model.clone(),
            epoch: self.epoch,
        }))
    }
    unsafe fn strong_fence(&mut self) -> Result<(), posted_msi::Error> {
        self.validate()?;
        if self.model.root_pending.load(Ordering::Relaxed) {
            return Err(posted_msi::Error::RootFailed);
        }
        self.model.root_fences.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    unsafe fn release_endpoint(
        &mut self,
        proof: &posted_msi::EndpointRetirement<'_>,
    ) -> Result<(), posted_msi::Error> {
        self.validate()?;
        assert!(proof.requester().is_none());
        Ok(())
    }
}
fn fixture_route(model: &Arc<Model>) -> RouteRequest {
    // SAFETY: this original synchronous model carries no native config pin;
    // private Registry target joins it, and its independent root state fences.
    RouteRequest::Msi(unsafe {
        posted_msi::MsiRoute::bounded_fixture(Box::new(DeliveryPeer {
            model: model.clone(),
            allocated: false,
            epoch: model.root_epoch.load(Ordering::Acquire),
        }))
    })
}
fn finish<S: Source + ?Sized>(retired: RetiredSource<S>) {
    // SAFETY: these fixture sources have no DMA-dependent release users; keep
    // the original callback through explicit source release on the checked CPU.
    let (source, handler, mut route) =
        unsafe { retired.into_parts() }.unwrap_or_else(|_| panic!("checked retired fixture"));
    route.release_unattached_fixture().unwrap();
    drop(source);
    drop(handler);
}

struct ModelSource(Arc<Model>);
// SAFETY: explicit stopped-source model with injected mask failures and
// controller delivery. Quiesce represents device/work completion.
unsafe impl Source for ModelSource {
    fn mask(&mut self) -> Result<(), IrqError> {
        self.0.mask_calls.fetch_add(1, Ordering::Relaxed);
        if self.0.config_failures.load(Ordering::Acquire) & 2 != 0 {
            return Err(config_fault(0x54));
        }
        assert!(
            !self.0.panic_mask.load(Ordering::Relaxed),
            "injected source unwind"
        );
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
    fn route_kind(&self) -> crate::bus::irq::RouteKind {
        crate::bus::irq::RouteKind::Msi
    }
    fn requester(&self) -> Option<&crate::bus::pci::requester::RequesterId> {
        None
    }
    unsafe fn program(
        &mut self,
        route: &crate::bus::irq::AllocatedRoute<'_>,
    ) -> Result<(), IrqError> {
        let Route::Msi(message) = route.programming() else {
            return Err(IrqError::Route);
        };
        assert_eq!(message.address, 0xfee00000);
        assert_eq!(
            message.data,
            u32::from(self.0.vector.load(Ordering::Relaxed))
        );
        if self.0.dispatch_on_program.swap(false, Ordering::AcqRel) {
            // SAFETY: exact permanently retained model Registry; this models
            // an old ordinary packet during masked new source programming.
            let registry = unsafe { &*self.0.registry.load(Ordering::Acquire) };
            assert!(registry.dispatch(self.0.vector.load(Ordering::Acquire)));
        }
        Ok(())
    }
    unsafe fn unmask(&mut self) -> Result<(), IrqError> {
        if self.0.dispatch_on_unmask.swap(false, Ordering::AcqRel) {
            // SAFETY: exact retained synchronous model original controller.
            let registry = unsafe { &*self.0.registry.load(Ordering::Acquire) };
            assert!(registry.dispatch(self.0.vector.load(Ordering::Acquire)));
        }
        assert!(
            !self.0.panic_unmask.load(Ordering::Acquire),
            "post-LIVE enable panic"
        );
        if self.0.config_failures.load(Ordering::Acquire) & 4 != 0 {
            return Err(config_fault(0x54));
        }
        let mode = self.0.controller_on_unmask.load(Ordering::Acquire);
        if mode != 0 {
            // SAFETY: this model's actual leaked Registry is retained by the
            // active constructor; no native source or foreign epoch is used.
            let registry = unsafe { &*self.0.registry.load(Ordering::Acquire) };
            if mode == 1 {
                registry.controller_fault.latch(config_fault(0x68));
            } else {
                claim_fault_writer(&registry.controller_fault);
            }
        }
        Ok(())
    }
    unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
        self.synchronized()
    }
}
impl ModelSource {
    fn synchronized(&mut self) -> Result<(), IrqError> {
        assert!(
            !self.0.panic_sync.load(Ordering::Relaxed),
            "injected work unwind"
        );
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
        .request(Request {
            source: Box::new(ModelSource(model.clone())),
            handler: Arc::new(ModelHandler(model.clone())),
            routing: fixture_route(model),
        })
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
    fn route_kind(&self) -> crate::bus::irq::RouteKind {
        self.inner.route_kind()
    }
    fn requester(&self) -> Option<&crate::bus::pci::requester::RequesterId> {
        self.inner.requester()
    }
    unsafe fn program(
        &mut self,
        route: &crate::bus::irq::AllocatedRoute<'_>,
    ) -> Result<(), IrqError> {
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
        .request(Request {
            source: local_source(&model, token.clone()),
            handler: Arc::new(ModelHandler(model.clone())),
            routing: fixture_route(&model),
        })
        .unwrap();
    model.migrate_on_sync.store(true, Ordering::Relaxed);
    assert!(matches!(registration.retire(), Err(IrqError::WrongCpu)));
    assert_eq!(token.get(), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    model.migrate_on_sync.store(false, Ordering::Relaxed);
    model.wrong_cpu.store(false, Ordering::Relaxed);
    finish(registration.retire().unwrap());
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
        .request(Request {
            source: local_source(&model, token.clone()),
            handler: Arc::new(ModelHandler(model.clone())),
            routing: fixture_route(&model),
        })
        .unwrap();
    let retired = registration.retire().unwrap();
    assert_eq!(token.get(), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    finish(retired);
    assert_eq!(token.get(), 1);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
}
#[test]
fn untouched_typed_refusal_retains_affine_source_and_callback_on_abandonment() {
    let model = Model::new();
    let registry = registry(model.clone());
    let token = std::rc::Rc::new(core::cell::Cell::new(0));
    model.fail_target.store(true, Ordering::Relaxed);
    {
        let Err(refusal) = registry.request_owned(Request {
            source: LocalSource {
                inner: ModelSource(model.clone()),
                token: token.clone(),
                owner: std::thread::current().id(),
            },
            handler: Arc::new(ModelHandler(model.clone())),
            routing: fixture_route(&model),
        }) else {
            panic!("failed target registered")
        };
        assert!(refusal.returned.is_some());
        assert_eq!(token.get(), 0);
    }
    assert_eq!(token.get(), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
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
        {
            let result = registry.request(Request {
                source: local_source(&model, token.clone()),
                handler: Arc::new(ModelHandler(model.clone())),
                routing: fixture_route(&model),
            });
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
        }
        model.wrong_cpu.store(false, Ordering::Relaxed);
        for mut registered in occupied {
            finish(registered.retire().unwrap());
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
        let result = registry.request(Request {
            source: local_source(&other, token.clone()),
            handler: Arc::new(ModelHandler(other.clone())),
            routing: fixture_route(&other),
        });
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
        .request(Request {
            source: local_source(&model, token.clone()),
            handler: Arc::new(ModelHandler(model.clone())),
            routing: fixture_route(&model),
        })
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
    let mut registration = r
        .request(Request {
            source: Box::new(ModelSource(model.clone())),
            handler: a,
            routing: fixture_route(&model),
        })
        .unwrap();
    assert!(r.dispatch(registration.vector()));
    assert_eq!(registration.handled(), Ok(0));
    assert_eq!(model.eois.load(Ordering::Relaxed), 1);
    finish(registration.retire().unwrap());
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
    finish(registration.retire().unwrap());
    assert!(registry.dispatch(vector));
    assert_eq!(
        model.callbacks.load(Ordering::Relaxed),
        1,
        "closing IRQ must not enter the detached device callback"
    );
    assert_eq!(model.eois.load(Ordering::Relaxed), 3);
    assert_eq!(
        model.quiesces.load(Ordering::Relaxed),
        3,
        "work created by a formerly in-flight callback is drained after ISR completion"
    );
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
    let mut reused = request(registry, &model);
    assert_eq!(reused.vector(), vector);
    finish(reused.retire().unwrap());
}

#[test]
fn concrete_source_handoff_returns_original_owner_only_after_acknowledged_drain() {
    let model = Model::new();
    let registry = registry(model.clone());
    let mut registration = registry
        .request_owned(Request {
            source: ModelSource(model.clone()),
            handler: Arc::new(ModelHandler(model.clone())),
            routing: fixture_route(&model),
        })
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
    let (source, handler, mut route) =
        unsafe { retired.into_parts() }.unwrap_or_else(|_| panic!("checked retired owner"));
    assert!(Arc::ptr_eq(&source.0, &model));
    assert_eq!(route.vector(), vector);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.eois.load(Ordering::Relaxed), 1);
    assert!(registry.dispatch(vector));
    assert!(matches!(registration.retire(), Err(IrqError::Unregistered)));
    route.release_unattached_fixture().unwrap();
    drop(source);
    drop(handler);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
    let mut reused = request(registry, &model);
    assert_eq!(reused.vector(), vector);
    finish(reused.retire().unwrap());
}

#[test]
fn typed_early_refusal_preserves_original_source_for_untouched_retry() {
    let model = Model::new();
    let registry = registry(model.clone());
    model.fail_target.store(true, Ordering::Relaxed);
    let Err(refusal) = registry.request_owned(Request {
        source: ModelSource(model.clone()),
        handler: Arc::new(ModelHandler(model.clone())),
        routing: fixture_route(&model),
    }) else {
        panic!("failed target registered")
    };
    assert_eq!(refusal.error, IrqError::Route);
    // SAFETY: preserve the original CPU and callback through source
    // retry below; the refused request has not changed either owner.
    let (source, handler, routing) = unsafe { refusal.returned.unwrap().into_parts() }
        .unwrap_or_else(|_| panic!("checked untouched owner"));
    assert!(Arc::ptr_eq(&source.0, &model));
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    model.fail_target.store(false, Ordering::Relaxed);
    let mut registration = registry
        .request_owned(Request {
            source: *source,
            handler,
            routing,
        })
        .unwrap();
    assert_eq!(registry.quarantine_count(), 0);
    finish(registration.retire().unwrap());
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn failed_pending_read_and_timeout_keep_for_retry_without_vector_reuse() {
    let model = Model::new();
    let registry = registry(model.clone());
    let mut registration = request(registry, &model);
    model.fail_pending.store(true, Ordering::Relaxed);
    assert!(matches!(registration.retire(), Err(IrqError::FailedRead)));
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    model.fail_pending.store(false, Ordering::Relaxed);
    model.pending.store(true, Ordering::Relaxed);
    model.admit_irq.store(false, Ordering::Relaxed);
    assert!(matches!(registration.retire(), Err(IrqError::Drain)));
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    model.admit_irq.store(true, Ordering::Relaxed);
    finish(registration.retire().unwrap());
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
        registry.request(Request {
            source: Box::new(ModelSource(model.clone())),
            handler: Arc::new(ModelHandler(model.clone())),
            routing: fixture_route(&model)
        }),
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
        .request(Request {
            source: Box::new(ModelSource(model.clone())),
            handler: handler.clone(),
            routing: fixture_route(&model),
        })
        .unwrap();
    let vector = registration.vector();
    // Concurrent model interleaving stresses the reader/remove lifetime;
    // the native adapter remains confined to its one owning BSP.
    let irq = std::thread::spawn(move || assert!(registry.dispatch(vector)));
    handler.entered.wait();
    assert!(matches!(registration.retire(), Err(IrqError::Drain)));
    assert_eq!(
        Arc::strong_count(&handler),
        2,
        "dispatch must not clone the handler Arc"
    );
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    handler.release.wait();
    irq.join().unwrap();
    finish(registration.retire().unwrap());
    assert_eq!(Arc::strong_count(&handler), 1);
    assert_eq!(model.eois.load(Ordering::Relaxed), 1);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
    drop(handler);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn notification_action_join_does_not_claim_optional_fabric_completion() {
    let model = Model::new();
    let registry = registry(model.clone());
    let mut registration = request(registry, &model);
    model.root_pending.store(true, Ordering::Relaxed);
    let mut stronger = DeliveryPeer {
        model: model.clone(),
        allocated: true,
        epoch: 1,
    };
    assert_eq!(
        // SAFETY: independent explicit model source is masked; this optional peer
        // refuses its stronger proof while notification/action retirement can join.
        unsafe { stronger.strong_fence() },
        Err(posted_msi::Error::RootFailed)
    );
    let retired = registration.retire().unwrap();
    assert_eq!(model.root_fences.load(Ordering::Relaxed), 0);
    model.wrong_cpu.store(true, Ordering::Relaxed);
    assert_eq!(retired.route().validate(), Err(IrqError::WrongCpu));
    model.wrong_cpu.store(false, Ordering::Relaxed);
    finish(retired);
}
#[test]
fn domain_loss_and_eoi_failure_preserve_exact_error_and_old_owners() {
    for root_loss in [false, true] {
        let model = Model::new();
        let registry = registry(model.clone());
        let mut registration = request(registry, &model);
        if root_loss {
            model.root_epoch.store(2, Ordering::Release);
        } else {
            model.fail_eoi.store(true, Ordering::Release);
        }
        assert!(registry.dispatch(registration.vector()));
        assert_eq!(
            model.callbacks.load(Ordering::Relaxed),
            usize::from(!root_loss)
        );
        let expected = if root_loss {
            IrqError::Delivery(posted_msi::Error::RootFailed)
        } else {
            IrqError::FailedRead
        };
        assert!(matches!(registration.retire(),Err(error) if error==expected));
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn delayed_ordinary_notification_enters_only_current_valid_status_handler() {
    struct StatusHandler {
        cause: AtomicBool,
        completions: AtomicUsize,
        entries: AtomicUsize,
    }
    impl Handler for StatusHandler {
        fn handle(&self) -> Disposition {
            self.entries.fetch_add(1, Ordering::Relaxed);
            if self.cause.swap(false, Ordering::AcqRel) {
                self.completions.fetch_add(1, Ordering::Relaxed);
                Disposition::Handled
            } else {
                Disposition::NotMine
            }
        }
    }
    let model = Model::new();
    let registry = registry(model.clone());
    let mut old = request(registry, &model);
    let vector = old.vector();
    model.root_pending.store(true, Ordering::Release); // unrelated old ordinary packet
    finish(old.retire().unwrap());
    let current = Arc::new(StatusHandler {
        cause: AtomicBool::new(false),
        completions: AtomicUsize::new(0),
        entries: AtomicUsize::new(0),
    });
    let mut new = registry
        .request(Request {
            source: Box::new(ModelSource(model.clone())),
            handler: current.clone(),
            routing: fixture_route(&model),
        })
        .unwrap();
    assert_eq!(new.vector(), vector);
    assert!(registry.dispatch(vector)); // late old packet: no current cause
    assert_eq!(current.completions.load(Ordering::Relaxed), 0);
    assert_eq!(model.callbacks.load(Ordering::Relaxed), 0);
    current.cause.store(true, Ordering::Release);
    assert!(registry.dispatch(vector));
    assert_eq!(current.completions.load(Ordering::Relaxed), 1);
    assert_eq!(current.entries.load(Ordering::Relaxed), 2);
    finish(new.retire().unwrap());
}
#[test]
fn abandoned_successful_retirement_does_not_drop_original_source_or_handler() {
    let model = Model::new();
    let registry = registry(model.clone());
    let mut registration = request(registry, &model);
    drop(registration.retire().unwrap());
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn exact_route_identity_rejects_a_later_registration_reusing_the_same_vector() {
    let model = Model::new();
    let registry = registry(model.clone());
    let mut first = request(registry, &model);
    let old = first.retire().unwrap();
    let mut second = request(registry, &model);
    let replacement = second.retire().unwrap();
    assert_eq!(old.route().vector(), replacement.route().vector());
    assert!(!old.route().id().same(replacement.route().id()));
    finish(old);
    finish(replacement);
}

#[test]
fn unavailable_notification_refuses_before_programming_and_returns_exact_grant() {
    struct AttachedModel(ModelSource, RequesterId);
    // SAFETY: this isolated source peer contains no native owner; only the
    // actual symbolic Registry route can reach its programming callbacks.
    unsafe impl Source for AttachedModel {
        fn route_kind(&self) -> RouteKind {
            RouteKind::Msi
        }
        fn requester(&self) -> Option<&RequesterId> {
            Some(&self.1)
        }
        fn mask(&mut self) -> Result<(), IrqError> {
            self.0.mask()
        }
        fn quiesce(&mut self) -> Result<(), IrqError> {
            self.0.quiesce()
        }
        unsafe fn program(&mut self, route: &AllocatedRoute<'_>) -> Result<(), IrqError> {
            assert!(route.matches_requester(&self.1));
            // SAFETY: forwards the same symbolic Registry programming view.
            unsafe { self.0.program(route) }
        }
        unsafe fn unmask(&mut self) -> Result<(), IrqError> {
            // SAFETY: forwards the same retained model callback obligation.
            unsafe { self.0.unmask() }
        }
        unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
            // SAFETY: Registry must establish exact model retirement first.
            unsafe { self.0.synchronize() }
        }
    }
    let model = Model::new();
    let registry = registry(model.clone());
    let requester = RequesterId::new();
    let grant = posted_msi::MsiRoute::attached(requester.clone(), None)
        .unwrap_or_else(|_| panic!("idle model key"));
    let refusal = registry
        .request(Request {
            source: Box::new(AttachedModel(ModelSource(model.clone()), requester.clone())),
            handler: Arc::new(ModelHandler(model.clone())),
            routing: RouteRequest::Msi(grant),
        })
        .err()
        .expect("unavailable notification cannot arm");
    assert_eq!(
        refusal.error,
        IrqError::Delivery(posted_msi::Error::RootUnavailable)
    );
    assert!(
        requester.check_detach().is_err(),
        "issuance stays outstanding until exact cancellation"
    );
    assert_eq!(model.quiesces.load(Ordering::Relaxed), 0);
    // SAFETY: exact original untouched model owner and current context.
    let (source, handler, routing) = unsafe { refusal.returned.unwrap().into_parts() }
        .unwrap_or_else(|_| panic!("untouched exact owners"));
    let RouteRequest::Msi(grant) = routing else {
        panic!("MSI grant")
    };
    grant
        .cancel(&requester)
        .unwrap_or_else(|_| panic!("exact unpublished cancellation"));
    assert!(requester.check_detach().is_ok());
    drop(source);
    drop(handler);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn source_callback_unwind_poison_retains_without_hardware_retry_on_drop() {
    let model = Model::new();
    let registry = registry(model.clone());
    model.panic_mask.store(true, Ordering::Relaxed);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| request(registry, &model)))
            .is_err()
    );
    assert_eq!(registry.quarantine_count(), 1);
    assert!(registry.dispatch(FIRST_VECTOR));
    assert_eq!(model.callbacks.load(Ordering::Relaxed), 0);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    model.panic_mask.store(false, Ordering::Relaxed);
    let mut registration = request(registry, &model);
    model.panic_sync.store(true, Ordering::Relaxed);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| registration.retire())).is_err()
    );
    let fences = model.root_fences.load(Ordering::Relaxed);
    model.panic_sync.store(false, Ordering::Relaxed);
    assert!(matches!(registration.retire(), Err(IrqError::Interrupted)));
    drop(registration);
    assert_eq!(model.root_fences.load(Ordering::Relaxed), fences);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(registry.quarantine_count(), 2);
}

#[test]
fn pending_and_delivery_window_unwind_restore_the_exact_original_irq_state() {
    for window in [false, true] {
        let model = Model::new();
        let registry = registry(model.clone());
        let mut registration = request(registry, &model);
        model.pending.store(true, Ordering::Release);
        if window {
            model.panic_window.store(true, Ordering::Release);
        } else {
            model.panic_pending.store(true, Ordering::Release);
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| registration.retire()))
                .is_err()
        );
        assert!(model.irq_enabled.load(Ordering::Acquire));
        assert_eq!(registry.quarantine_count(), 1);
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
        let fences = model.root_fences.load(Ordering::Relaxed);
        drop(registration);
        assert_eq!(model.root_fences.load(Ordering::Relaxed), fences);
    }
}
#[test]
fn extraction_preserves_exact_root_epoch_error_and_retains_original_owners() {
    let model = Model::new();
    let registry = registry(model.clone());
    let mut registration = request(registry, &model);
    let retired = registration.retire().unwrap();
    model.root_epoch.fetch_add(1, Ordering::AcqRel);
    {
        // SAFETY: this negative test attempts extraction through the actual
        // original receipt; epoch mismatch must refuse before moving any owner.
        let refusal = match unsafe { retired.into_parts() } {
            Ok(_) => panic!("stale root extracted"),
            Err(refusal) => refusal,
        };
        assert_eq!(
            refusal.error,
            IrqError::Delivery(posted_msi::Error::RootFailed)
        );
    }
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn unbound_delayed_eoi_failure_poison_is_not_lost_before_replacement_admission() {
    let model = Model::new();
    let registry = registry(model.clone());
    let mut old = request(registry, &model);
    let vector = old.vector();
    finish(old.retire().unwrap());
    model.fail_eoi.store(true, Ordering::Release);
    assert!(registry.dispatch(vector)); // owns vector, not successful EOI
    assert_eq!(registry.controller_failure(), Some(IrqError::FailedRead));
    model.fail_eoi.store(false, Ordering::Release); // cannot erase uncertain effect
    let quiesces = model.quiesces.load(Ordering::Relaxed);
    let refusal = registry
        .request(Request {
            source: Box::new(ModelSource(model.clone())),
            handler: Arc::new(ModelHandler(model.clone())),
            routing: fixture_route(&model),
        })
        .err()
        .unwrap();
    assert_eq!(refusal.error, IrqError::FailedRead);
    assert!(refusal.returned.is_some());
    assert_eq!(model.quiesces.load(Ordering::Relaxed), quiesces);
    assert_eq!(model.callbacks.load(Ordering::Relaxed), 0);
}

#[test]
fn arming_notification_never_enters_new_handler_or_overwrites_eoi_quarantine() {
    for failed_eoi in [false, true] {
        let model = Model::new();
        let registry = registry(model.clone());
        model.dispatch_on_program.store(true, Ordering::Release);
        model.fail_eoi.store(failed_eoi, Ordering::Release);
        let result = registry.request(Request {
            source: Box::new(ModelSource(model.clone())),
            handler: Arc::new(ModelHandler(model.clone())),
            routing: fixture_route(&model),
        });
        assert_eq!(model.callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(model.eois.load(Ordering::Relaxed), 1);
        if failed_eoi {
            let refusal = result.err().unwrap();
            assert_eq!(refusal.error, IrqError::FailedRead);
            assert!(refusal.returned.is_none());
            assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
            assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
        } else {
            let mut registration = result.unwrap();
            assert!(registry.dispatch(registration.vector()));
            assert_eq!(model.callbacks.load(Ordering::Relaxed), 1);
            finish(registration.retire().unwrap());
        }
    }
}

#[test]
fn post_live_delivery_then_enable_panic_never_returns_unexposed_owners() {
    let model = Model::new();
    let registry = registry(model.clone());
    model.dispatch_on_unmask.store(true, Ordering::Release);
    model.panic_unmask.store(true, Ordering::Release);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| request(registry, &model)))
            .is_err()
    );
    assert_eq!(model.callbacks.load(Ordering::Relaxed), 1);
    assert_eq!(registry.quarantine_count(), 1);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    let old = model.vector.load(Ordering::Acquire);
    assert!(registry.dispatch(old));
    assert_eq!(model.callbacks.load(Ordering::Relaxed), 1);
    model.panic_unmask.store(false, Ordering::Release);
    let mut next = request(registry, &model);
    assert_ne!(next.vector(), old);
    finish(next.retire().unwrap());
}

#[test]
fn handler_unwind_poison_retains_inflight_owners_and_never_reenters_callback() {
    struct PanicHandler(Arc<Model>);
    impl Handler for PanicHandler {
        fn handle(&self) -> Disposition {
            self.0.callbacks.fetch_add(1, Ordering::Relaxed);
            panic!("actual handler unwind");
        }
    }
    impl Drop for PanicHandler {
        fn drop(&mut self) {
            self.0.handler_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    let model = Model::new();
    let registry = registry(model.clone());
    let mut registration = registry
        .request(Request {
            source: Box::new(ModelSource(model.clone())),
            handler: Arc::new(PanicHandler(model.clone())),
            routing: fixture_route(&model),
        })
        .unwrap();
    let vector = registration.vector();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| registry.dispatch(vector)))
            .is_err()
    );
    assert_eq!(registry.controller_failure(), Some(IrqError::Interrupted));
    assert!(registry.dispatch(vector));
    assert_eq!(model.callbacks.load(Ordering::Relaxed), 1);
    assert!(matches!(registration.retire(), Err(IrqError::Interrupted)));
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
}

fn config_fault(offset: u16) -> IrqError {
    use crate::bus::pci::{ConfigError, ConfigFailure};
    IrqError::Config(ConfigError::write_may_have_applied(
        offset,
        4,
        ConfigFailure::Readback {
            offset,
            width: 4,
            expected: 0xfee0_0010,
            observed: 0xffff_ffff,
        },
    ))
}
/// Simulate an IRQ interrupting the only writer immediately after its CAS.
fn claim_fault_writer(cell: &FirstFault) {
    assert!(
        cell.phase
            .compare_exchange(
                FAULT_CLEAR,
                FAULT_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    );
}
/// # Safety
/// This test holds the only successful writer claim for this still-WRITING cell.
unsafe fn finish_fault_writer(cell: &FirstFault, cause: IrqError) {
    assert_eq!(cell.phase.load(Ordering::Acquire), FAULT_WRITING);
    // SAFETY: the test's actual successful CAS owns the unique payload write;
    // readers stay pending until the following release, exactly as latch does.
    unsafe { (*cell.cause.get()).write(cause) };
    cell.phase.store(FAULT_READY, Ordering::Release);
}
#[test]
fn first_fault_retains_full_config_effect_and_never_records_pending_observations() {
    let cell = FirstFault::new();
    assert!(!cell.latch(IrqError::FaultPublishing));
    assert_eq!(cell.failure(), None);
    let first = config_fault(0x54);
    assert!(cell.latch(first));
    assert!(!cell.latch(config_fault(0x64)));
    assert!(!cell.latch(IrqError::Interrupted));
    assert!(!cell.latch(IrqError::FaultPublishing));
    assert_eq!(cell.failure(), Some(first));
}
#[test]
fn pending_controller_and_slot_publications_preserve_their_original_cause_scope() {
    for controller in [true, false] {
        let model = Model::new();
        let registry = registry(model.clone());
        let mut registration = request(registry, &model);
        // SAFETY: active original registration retains this allocation; every
        // following retirement is refused, so this test never frees the slot.
        let slot = unsafe { registration.slot.as_ref() };
        let original = if controller {
            &registry.controller_fault
        } else {
            &slot.fault
        };
        claim_fault_writer(original);
        assert!(registry.dispatch(registration.vector()));
        assert_eq!(model.callbacks.load(Ordering::Relaxed), 0);
        assert!(matches!(
            registration.retire(),
            Err(IrqError::FaultPublishing)
        ));
        if controller {
            assert_eq!(
                slot.fault.failure(),
                None,
                "pending is not a new local cause"
            );
            assert_eq!(
                registry.identity().fault.failure(),
                Some(IrqError::FaultPublishing)
            );
        } else {
            assert_eq!(
                registry.controller_failure(),
                None,
                "source fault is not a global controller failure"
            );
        }
        let exact = config_fault(0x54);
        // SAFETY: claim_fault_writer established this test's only writer;
        // nested dispatch could neither overwrite it nor read its payload.
        unsafe { finish_fault_writer(original, exact) };
        assert!(matches!(registration.retire(), Err(error) if error == exact));
        if controller {
            assert_eq!(registry.identity().fault.failure(), Some(exact));
        } else {
            assert_eq!(slot.fault.failure(), Some(exact));
        }
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn interrupted_writer_stays_closed_without_reading_or_replacing_uninitialized_payload() {
    let model = Model::new();
    let registry = registry(model.clone());
    let mut registration = request(registry, &model);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            claim_fault_writer(&registry.controller_fault);
            panic!("writer never reached its plain Copy publication");
        }))
        .is_err()
    );
    for _ in 0..3 {
        assert!(registry.dispatch(registration.vector()));
        assert!(matches!(
            registration.retire(),
            Err(IrqError::FaultPublishing)
        ));
    }
    assert!(!registry.controller_fault.latch(config_fault(0x64)));
    assert_eq!(
        registry.controller_failure(),
        Some(IrqError::FaultPublishing)
    );
    assert_eq!(model.callbacks.load(Ordering::Relaxed), 0);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
}
#[test]
fn concurrent_first_fault_writers_publish_exactly_one_complete_payload() {
    let cell = Arc::new(FirstFault::new());
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut threads = alloc::vec::Vec::new();
    for index in 0u16..8 {
        let cell = cell.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let exact = config_fault(0x40 + index * 4);
            barrier.wait();
            (cell.latch(exact), exact)
        }));
    }
    let winners = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter_map(|(won, exact)| won.then_some(exact))
        .collect::<alloc::vec::Vec<_>>();
    assert_eq!(winners.len(), 1);
    for _ in 0..64 {
        assert_eq!(cell.failure(), Some(winners[0]));
    }
}
#[test]
fn controller_config_readback_retains_exact_payload_after_later_notifications() {
    let model = Model::new();
    let registry = registry(model.clone());
    let mut registration = request(registry, &model);
    model.config_failures.store(1, Ordering::Release);
    assert!(registry.dispatch(registration.vector()));
    assert_eq!(registry.controller_failure(), Some(config_fault(0x54)));
    assert_eq!(model.callbacks.load(Ordering::Relaxed), 1);
    model.config_failures.store(0, Ordering::Release);
    assert!(registry.dispatch(registration.vector()));
    assert_eq!(model.callbacks.load(Ordering::Relaxed), 1);
    assert_eq!(
        registry.identity().fault.failure(),
        Some(config_fault(0x54))
    );
    assert!(matches!(registration.retire(), Err(error) if error == config_fault(0x54)));
}
#[test]
fn post_live_config_failure_keeps_original_source_without_another_effect_attempt() {
    let model = Model::new();
    let registry = registry(model.clone());
    model.config_failures.store(4, Ordering::Release);
    {
        let Err(refusal) = registry.request(Request {
            source: Box::new(ModelSource(model.clone())),
            handler: Arc::new(ModelHandler(model.clone())),
            routing: fixture_route(&model),
        }) else {
            panic!("uncertain post-LIVE write registered")
        };
        assert_eq!(refusal.error, config_fault(0x54));
        assert!(refusal.returned.is_none());
    }
    assert_eq!(
        model.mask_calls.load(Ordering::Relaxed),
        1,
        "constructor must not call mask again after an uncertain unmask write"
    );
    let attempts = model.mask_calls.load(Ordering::Relaxed);
    model.config_failures.store(0, Ordering::Release);
    assert!(registry.dispatch(FIRST_VECTOR));
    assert_eq!(model.mask_calls.load(Ordering::Relaxed), attempts);
    assert_eq!(model.callbacks.load(Ordering::Relaxed), 0);
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
}
#[test]
fn reversible_or_closing_config_refusals_keep_first_effect_and_never_retry_source() {
    for operation in [0, 1, 2] {
        let model = Model::new();
        let registry = registry(model.clone());
        let mut registration = request(registry, &model);
        model
            .config_failures
            .store(if operation == 1 { 4 } else { 2 }, Ordering::Release);
        let error = match operation {
            0 => registration.mask(),
            1 => registration.unmask(),
            _ => registration.retire().map(|_| ()),
        };
        assert_eq!(error, Err(config_fault(0x54)));
        let attempts = model.mask_calls.load(Ordering::Relaxed);
        model.config_failures.store(0, Ordering::Release);
        assert!(matches!(registration.retire(), Err(error) if error == config_fault(0x54)));
        assert_eq!(registration.mask(), Err(config_fault(0x54)));
        assert_eq!(registration.unmask(), Err(config_fault(0x54)));
        assert_eq!(model.mask_calls.load(Ordering::Relaxed), attempts);
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn controller_failure_during_unmask_survives_pending_return_and_registration_drop() {
    for pending in [false, true] {
        let model = Model::new();
        let registry = registry(model.clone());
        model
            .controller_on_unmask
            .store(if pending { 2 } else { 1 }, Ordering::Release);
        {
            let Err(refusal) = registry.request(Request {
                source: Box::new(ModelSource(model.clone())),
                handler: Arc::new(ModelHandler(model.clone())),
                routing: fixture_route(&model),
            }) else {
                panic!("failed controller constructor published a registration")
            };
            assert_eq!(
                refusal.error,
                if pending {
                    IrqError::FaultPublishing
                } else {
                    config_fault(0x68)
                }
            );
            assert!(refusal.returned.is_none());
        }
        assert_eq!(model.mask_calls.load(Ordering::Relaxed), 1);
        // SAFETY: constructor refusal permanently retained this actual
        // quarantined Slot; no successful retirement/free occurred.
        let slot = unsafe { &*registry.slots[0].load(Ordering::Acquire) };
        if pending {
            assert_eq!(
                slot.fault.failure(),
                None,
                "Drop must not relatch a pending origin as Interrupted"
            );
            assert_eq!(registry.slot_failure(slot), IrqError::FaultPublishing);
            // SAFETY: the model's unmask callback owns the only original
            // controller writer claim; constructor/Drop could not replace it.
            unsafe { finish_fault_writer(&registry.controller_fault, config_fault(0x68)) };
        }
        assert_eq!(registry.slot_failure(slot), config_fault(0x68));
        assert_eq!(
            registry.identity().fault.failure(),
            Some(config_fault(0x68))
        );
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn an_earlier_drop_diagnostic_cannot_hide_later_original_controller_publication() {
    let model = Model::new();
    let registry = registry(model.clone());
    let registration = request(registry, &model);
    drop(registration);
    // SAFETY: default active Drop quarantined, retained, and never reclaimed
    // this exact original Slot, as asserted by its source retention counter.
    let slot = unsafe { &*registry.slots[0].load(Ordering::Acquire) };
    assert_eq!(slot.fault.failure(), Some(IrqError::Interrupted));
    claim_fault_writer(&registry.controller_fault);
    assert_eq!(registry.slot_failure(slot), IrqError::FaultPublishing);
    // SAFETY: this test owns the only successful controller writer claim;
    // no nested reader or earlier Drop diagnostic can write that payload.
    unsafe { finish_fault_writer(&registry.controller_fault, config_fault(0x68)) };
    assert_eq!(registry.slot_failure(slot), config_fault(0x68));
    assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
}
