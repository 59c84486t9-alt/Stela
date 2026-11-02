//! Hosted-only same-thread counter/entry/data model on actual guarded stacks.
use super::*;
use std::sync::Mutex;
pub(super) struct Clock {
    pub(super) cpu: Arc<dyn Cpu>,
    pub(super) now: AtomicU64,
}
// SAFETY: explicit deterministic nominal counter model, same hosted CPU only.
unsafe impl service::Clock for Clock {
    fn cpu(&self) -> &Arc<dyn Cpu> {
        &self.cpu
    }
    fn now_ns(&self) -> Result<u64, WorkError> {
        self.cpu.check_cpu()?;
        Ok(self.now.load(Ordering::Acquire))
    }
}
struct Idle {
    clock: Arc<dyn service::Clock>,
}
// SAFETY: never called to block by this tickless, explicitly driven fixture.
unsafe impl service::Idle for Idle {
    fn clock(&self) -> &Arc<dyn service::Clock> {
        &self.clock
    }
    fn notify(&self) -> Result<(), WorkError> {
        Ok(())
    }
    fn wait_until_ns(&self, _: Option<u64>) -> Result<(), WorkError> {
        Err(WorkError::Unavailable)
    }
}
pub(super) struct Entry {
    pub(super) cpu: Arc<CpuModel>,
    pub(super) clock: Arc<Clock>,
    pub(super) rsp: usize,
}
// SAFETY: bounded HOSTED test observation only. Actual CPU/thread, model entry,
// exact kept clock and real captured worker RSP; no native/root qualification.
unsafe impl InterruptedExecution for Entry {
    fn verify(
        &self,
        cpu: &Arc<dyn Cpu>,
        clock: &Arc<dyn service::Clock>,
    ) -> Result<usize, WorkError> {
        self.cpu.check_cpu()?;
        let actual_cpu: Arc<dyn Cpu> = self.cpu.clone();
        let actual_clock: Arc<dyn service::Clock> = self.clock.clone();
        if !Arc::ptr_eq(cpu, &actual_cpu)
            || !Arc::ptr_eq(clock, &actual_clock)
            || !self.cpu.in_interrupt()
        {
            return Err(WorkError::Unavailable);
        }
        Ok(self.rsp)
    }
}
pub(super) struct Fields {
    pub(super) total: AtomicU64,
    pub(super) through: AtomicU64,
}
// SAFETY: actual Arc-allocated aligned RAM kept by the fixture/registered target.
// Only two atomic stores, no C/task ref/synthetic Linux readiness exists here.
unsafe impl ExecutionPublication for Fields {
    unsafe fn publish(&self, sample: &ExecutionSample) {
        self.total.store(sample.total_ns(), Ordering::Release);
        self.through
            .store(sample.accounted_through_ns(), Ordering::Release);
    }
    unsafe fn publish_irq(
        &self,
        _: &dyn InterruptedExecution,
        sample: &ExecutionSample,
    ) -> Result<(), WorkError> {
        // SAFETY: this fixture uses one unchanged host data mapping; the tap has
        // checked the private Entry model. This is not a native data-root permit.
        unsafe { self.publish(sample) };
        Ok(())
    }
}
pub(super) struct Binding {
    pub(super) fields: Arc<Fields>,
    pub(super) blocked: AtomicBool,
    pub(super) measured: bool,
}
// SAFETY: real host continuation/binding lifetime, metadata-only model hooks.
unsafe impl SwitchBinding for Binding {
    fn execution_publication(
        &self,
        _: &TaskContext,
    ) -> Result<Option<Arc<dyn ExecutionPublication>>, WorkError> {
        Ok(self
            .measured
            .then(|| self.fields.clone() as Arc<dyn ExecutionPublication>))
    }
    unsafe fn attach(&self, _: &TaskContext) -> Result<(), WorkError> {
        Ok(())
    }
    unsafe fn still_blocked(&self, _: &TaskContext) -> Result<bool, WorkError> {
        Ok(self.blocked.load(Ordering::Acquire))
    }
    unsafe fn leave(&self, _: &TaskContext, _: LeaveReason) -> Result<(), WorkError> {
        Ok(())
    }
    unsafe fn arrive(&self, _: &TaskContext, _: bool) -> Result<(), WorkError> {
        Ok(())
    }
    unsafe fn complete(&self, _: &TaskContext) -> Result<(), WorkError> {
        Ok(())
    }
    unsafe fn detach(&self, _: &TaskContext) -> Result<(), WorkError> {
        Ok(())
    }
}
pub(super) struct Authority(pub(super) Arc<CpuModel>);
// SAFETY: explicit hosted process-scope model; not a native root/driver permit.
unsafe impl EnteredProcess for Authority {
    fn check(&self) -> Result<(), WorkError> {
        self.0.check_cpu()?;
        if self.0.in_interrupt() {
            Err(WorkError::InterruptContext)
        } else {
            Ok(())
        }
    }
}
pub(super) struct Scene {
    pub(super) cpu: Arc<CpuModel>,
    pub(super) clock: Arc<Clock>,
    pub(super) runtime: AtomicU64,
    pub(super) binding: Arc<Binding>,
    pub(super) service: Arc<Binding>,
    pub(super) domain: Mutex<Option<Arc<service::Domain<16>>>>,
    pub(super) wake: Mutex<Option<WakeHandle<16>>>,
    pub(super) service_wake: Mutex<Option<WakeHandle<16>>>,
    pub(super) tap: Mutex<Option<ExecutionTap>>,
}
impl Scene {
    pub(super) fn runtime(&self) -> Pin<&Runtime<16>> {
        // SAFETY: fixture queue keeps Scene, Executor remains pinned during all uses.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<16>))
        }
    }
}
pub(super) fn setup() -> (
    Executor<16>,
    Arc<Scene>,
    Arc<core::sync::atomic::AtomicUsize>,
) {
    let cpu = CpuModel::new();
    let clock = Arc::new(Clock {
        cpu: cpu.clone(),
        now: AtomicU64::new(0),
    });
    let binding = |measured| {
        Arc::new(Binding {
            fields: Arc::new(Fields {
                total: AtomicU64::new(0),
                through: AtomicU64::new(0),
            }),
            blocked: AtomicBool::new(true),
            measured,
        })
    };
    let s = Arc::new(Scene {
        cpu: cpu.clone(),
        clock: clock.clone(),
        runtime: AtomicU64::new(0),
        binding: binding(true),
        service: binding(false),
        domain: Mutex::new(None),
        wake: Mutex::new(None),
        service_wake: Mutex::new(None),
        tap: Mutex::new(None),
    });
    // SAFETY: actual same-thread model plus retained fixture/code/contexts.
    let queue = unsafe { Queue::new(cpu.clone(), s.clone()) }.unwrap();
    let dropped = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    // SAFETY: unprivileged snapshot only; fixture reserves actual Service lane.
    let controls = unsafe { context::read_controls() };
    let executor = Executor {
        runtime: ManuallyDrop::new(
            Runtime::with_service_controls(
                queue,
                test_support::stacks_count(&dropped, 4),
                controls,
                true,
            )
            .unwrap(),
        ),
    };
    let r = executor.runtime();
    s.runtime
        .store(r.get_ref() as *const Runtime<16> as u64, Ordering::Release);
    let domain = service::Domain::tickless(clock.clone(), Arc::new(Idle { clock })).unwrap();
    r.attach_service_domain(domain.clone()).unwrap();
    s.domain.lock().unwrap().replace(domain);
    s.tap
        .lock()
        .unwrap()
        .replace(r.execution_tap(&Authority(cpu)).unwrap());
    (executor, s, dropped)
}
