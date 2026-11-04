//! Pair the installed native clock with a real reserved service continuation.
use super::*;
use crate::native_clock::Installed;
use core::sync::atomic::{AtomicU8, AtomicU64};
use stela_drivers::platform::work::{
    ContextId, LeaveReason, ParkOutcome, SwitchBinding, TaskContext, service::Domain,
};
use stela_linux::threads::TaskDataStorage;

#[derive(Default)]
struct OneShotBinding {
    context: AtomicU64,
    sequence: AtomicU64,
    phase: AtomicU8,
}

const NEW: u8 = 0;
const RUNNING: u8 = 1;
const PARKED: u8 = 2;
const COMPLETED: u8 = 3;

impl OneShotBinding {
    fn same_job(&self, task: &TaskContext) -> bool {
        self.context.load(Ordering::Acquire) == task.context_id
            && self.sequence.load(Ordering::Acquire) == task.sequence
            && (task.stack_start..task.stack_end).contains(&task.stack_pointer)
    }

    fn transition(&self, from: u8, to: u8) -> Result<(), WorkError> {
        self.phase
            .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| WorkError::CorruptContext)
    }
}

// SAFETY: this one native service records only its attached job identity.
// Hooks allocate nothing, switch no frames and admit no foreign state.
unsafe impl SwitchBinding for OneShotBinding {
    unsafe fn attach(&self, task: &TaskContext) -> Result<(), WorkError> {
        if task.context_id == 0
            || task.sequence == 0
            || !(task.stack_start..task.stack_end).contains(&task.stack_pointer)
        {
            return Err(WorkError::CorruptContext);
        }
        self.context
            .compare_exchange(0, task.context_id, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| WorkError::Busy)?;
        self.sequence.store(task.sequence, Ordering::Release);
        self.transition(NEW, RUNNING)
    }

    unsafe fn still_blocked(&self, task: &TaskContext) -> Result<bool, WorkError> {
        if !self.same_job(task) || self.phase.load(Ordering::Acquire) != RUNNING {
            return Err(WorkError::CorruptContext);
        }
        // The service made one prepare after observing no due batch. A
        // producer only publishes a WakeHandle signal; Runtime checks it
        // under this same IF exclusion before committing the blocked switch.
        Ok(true)
    }

    unsafe fn leave(&self, task: &TaskContext, reason: LeaveReason) -> Result<(), WorkError> {
        if !self.same_job(task) || reason != LeaveReason::Blocked {
            return Err(WorkError::CorruptContext);
        }
        self.transition(RUNNING, PARKED)
    }

    unsafe fn arrive(&self, task: &TaskContext, new_job: bool) -> Result<(), WorkError> {
        if !self.same_job(task) || new_job {
            return Err(WorkError::CorruptContext);
        }
        self.transition(PARKED, RUNNING)
    }

    unsafe fn complete(&self, task: &TaskContext) -> Result<(), WorkError> {
        if !self.same_job(task) {
            return Err(WorkError::CorruptContext);
        }
        self.transition(RUNNING, COMPLETED)
    }

    unsafe fn detach(&self, task: &TaskContext) -> Result<(), WorkError> {
        if self.context.load(Ordering::Acquire) != task.context_id
            || task.sequence != 0
            || self.phase.load(Ordering::Acquire) != COMPLETED
        {
            return Err(WorkError::CorruptContext);
        }
        Ok(())
    }
}

struct Service {
    runtime: *const work::Runtime<SLOTS>,
    domain: Arc<Domain<SLOTS>>,
    binding: Arc<OneShotBinding>,
    context: Cell<Option<ContextId>>,
    result: Cell<Option<Result<(), WorkError>>>,
}

unsafe extern "C" fn deliver(context: *mut c_void) {
    // SAFETY: the dispatcher keeps this same owned box and the pinned Runtime
    // until this one callback has returned, including on uncertain errors.
    let service = unsafe { &*context.cast::<Service>() };
    // SAFETY: same owner and actual admitted service frame.
    let runtime = unsafe { Pin::new_unchecked(&*service.runtime) };
    let result = (|| {
        let wake = stage(
            "stack binding",
            runtime.bind_current(service.binding.clone()),
        )?;
        service.context.set(Some(wake.context_id()));
        stage("service binding", service.domain.bind_current(runtime))?;
        if service.domain.begin(runtime)?.is_some()
            || runtime.park_if_blocked()? != ParkOutcome::Resumed
        {
            return Err(WorkError::CorruptContext);
        }
        let batch = service
            .domain
            .begin(runtime)?
            .ok_or(WorkError::CorruptContext)?;
        if !batch.timer() || batch.tick() || batch.raised() {
            return Err(WorkError::CorruptContext);
        }
        // SAFETY: this is the fixture's sole timed effect, observed and
        // consumed on the current service frame. No C callback is involved.
        unsafe { service.domain.finish(runtime, batch, None) }
    })();
    service.result.set(Some(result));
}

/// # Safety
/// Same exclusive boot CPU, installed clock and untouched original stack pool
/// for the complete diagnostic. No other dispatcher, driver or service runs.
pub(crate) unsafe fn check_native_clock_domain(
    handoff: &'static Handoff,
    owner: &mut HostOwner,
    installed: &Installed,
    clock: &ClockServices,
) -> Result<(), WorkError> {
    fn failed(error: Error) -> WorkError {
        crate::output::arguments(format_args!("CHECK native-clock-domain FAIL {error}\n"));
        match error {
            Error::Work(error) => error,
            _ => WorkError::Unavailable,
        }
    }

    let plan = Plan::new(handoff).map_err(failed)?;
    // SAFETY: this diagnostic consumes the original stack pool once, with the
    // same BSP and real installed source. It joins before clock retirement.
    let work =
        unsafe { KernelWork::prepare_plan(handoff, owner, plan, Some(clock)) }.map_err(failed)?;
    let backing = work.task_data().map_err(failed)?;
    static IMAGE_DATA: AtomicU64 = AtomicU64::new(0);
    let heap_data = Box::new(0u64);
    let bytes = core::mem::size_of::<u64>();
    let data = (&raw const IMAGE_DATA).addr();
    let heap = core::ptr::from_ref(heap_data.as_ref()).addr();
    let code = check_native_clock_domain as *const () as usize;
    if !backing.contains(TaskDataStorage::InitialImage, data..data + bytes)
        || !backing.contains(TaskDataStorage::AllocatedTask, heap..heap + bytes)
        || backing.contains(TaskDataStorage::InitialImage, heap..heap + bytes)
        || backing.contains(TaskDataStorage::AllocatedTask, data..data + bytes)
        || backing.contains(TaskDataStorage::InitialImage, code..code + bytes)
        || backing.contains(TaskDataStorage::InitialImage, data..data)
    {
        return Err(WorkError::CorruptContext);
    }
    drop(backing);
    crate::output::arguments(format_args!(
        "CHECK native-task-data-backing PASS image=original-writable-data heap=registered-owner cross-kind+executable+empty=refused\n"
    ));
    let clock = work
        .native_clock
        .as_ref()
        .ok_or(WorkError::CorruptContext)?;
    let epoch = stage("epoch", clock.epoch())?;
    let root: Arc<dyn stela_linux::threads::OriginalKernelRoot> = work.reservation.clone();
    // The real Host-root entry must refuse to lend the loader PGD.
    {
        // SAFETY: same BSP and original HPET, before service publication.
        let host = stage("host-root admission", unsafe {
            clock.enter_dispatch(installed)
        })?;
        // SAFETY: immutable root observation only. The loan ends on return.
        let wrong_root = unsafe { host.with_process(|process| root.pgd(process)) }?;
        if wrong_root != Err(WorkError::CorruptContext) {
            return Err(WorkError::CorruptContext);
        }
    }

    work.dispatch(|runtime| {
        // SAFETY: the original loader root is entered. The clock supplies its
        // exact interrupt owner, and the service and timer join before return.
        let execution = stage("dispatch admission", unsafe {
            clock.enter_dispatch(installed)
        })?;
        // SAFETY: validate the borrowed loader root and test nested refusal.
        // Neither operation switches or retains the loan.
        let pgd = stage("initial PGD", unsafe {
            execution.with_process(|process| {
                if execution.with_process(|_| ()).is_ok() {
                    return Err(WorkError::CorruptContext);
                }
                root.pgd(process)
            })?
        })?;
        let expected = layout::physical(handoff.native_loader_tables.root());
        if pgd.as_ptr().addr() as u64 != expected {
            return Err(WorkError::CorruptContext);
        }
        let flags: u64;
        // SAFETY: read-only check before Runtime runs under the live guard.
        unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags)) };
        if flags & (1 << 9) == 0 {
            return Err(WorkError::CorruptContext);
        }
        let result = dispatch_timer(runtime, clock, &epoch);
        if let Err(error) = result {
            // A failing fixture may have retained a suspended frame. Stop
            // while the original root and interrupt owner are still held.
            crate::output::arguments(format_args!(
                "CHECK native-clock-domain FAIL timed dispatch {error:?}\n"
            ));
            crate::output::fatal("native clock domain did not join");
        }
        drop(execution);
        stage(
            "dispatcher restoration",
            work.reservation.identity.check_dispatch(),
        )
    })
    .map_err(failed)??;
    crate::output::arguments(format_args!(
        "CHECK native-clock-domain PASS cpu=installed clock=HPET service=park+timer+resume loader_irq=elapsed dispatcher_if=restored pgd=owned+WB wrong_root=refused retired=joined\n"
    ));
    Ok(())
}

fn dispatch_timer(
    runtime: Pin<&work::Runtime<SLOTS>>,
    clock: &ClockServices,
    epoch: &crate::native_clock::CounterEpoch,
) -> Result<(), WorkError> {
    let domain = stage("domain", Domain::tickless(clock.clock(), clock.idle()))?;
    stage("attach", runtime.attach_service_domain(domain.clone()))?;
    let service = Box::new(Service {
        runtime: core::ptr::from_ref(runtime.get_ref()),
        domain: domain.clone(),
        binding: Arc::new(OneShotBinding::default()),
        context: Cell::new(None),
        result: Cell::new(None),
    });
    let binding = service.binding.clone();
    let service = Box::into_raw(service);
    // SAFETY: exact callback and stable allocation, kept on all errors.
    let ticket = stage("start", unsafe {
        runtime.start_service(deliver, service.cast())
    })?;
    if !stage("initial dispatch", runtime.step())?
        || binding.phase.load(Ordering::Acquire) != PARKED
    {
        return Err(WorkError::CorruptContext);
    }
    let heartbeat = clock.heartbeat();
    let target = epoch
        .now_ns()?
        .checked_add(5_000_000)
        .ok_or(WorkError::Exhausted)?;
    stage("arm", domain.set_timer(Some(target)))?;
    for _ in 0..32 {
        if runtime.queue().completed(ticket)? {
            break;
        }
        stage("idle dispatch", runtime.step_or_idle())?;
    }
    if !runtime.queue().completed(ticket)? {
        return Err(WorkError::TimedOut);
    }
    if clock.heartbeat() <= heartbeat || epoch.now_ns()? < target {
        return Err(WorkError::CorruptContext);
    }
    // SAFETY: the ticket joined the only callback and all its users.
    let service = unsafe { Box::from_raw(service) };
    stage(
        "delivery",
        service.result.get().ok_or(WorkError::CorruptContext)?,
    )?;
    let context = service.context.get().ok_or(WorkError::CorruptContext)?;
    // SAFETY: the completed one-shot job has no foreign binding users.
    stage("detach", unsafe { runtime.detach_binding(context) })?;
    drop(service);
    stage("stop", domain.stop_producers())?;
    // SAFETY: sole consumer joined, timer finished, no other producer.
    unsafe {
        stage("domain retirement", domain.retire())?;
        stage("runtime retirement", runtime.retire())
    }
}

fn stage<T>(name: &str, result: Result<T, WorkError>) -> Result<T, WorkError> {
    result.inspect_err(|error| {
        crate::output::arguments(format_args!(
            "CHECK native-clock-domain FAIL {name} {error:?}\n"
        ));
    })
}
