//! Pair the installed native clock with a real reserved service continuation.
use super::*;
use core::sync::atomic::AtomicU64;
use stela_drivers::platform::work::{
    ContextId, LeaveReason, SwitchBinding, TaskContext, service::Domain,
};

#[derive(Default)]
struct OneShotBinding {
    context: AtomicU64,
    sequence: AtomicU64,
    completed: AtomicBool,
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
        Ok(())
    }

    unsafe fn still_blocked(&self, _: &TaskContext) -> Result<bool, WorkError> {
        Err(WorkError::Unavailable)
    }

    unsafe fn leave(&self, _: &TaskContext, _: LeaveReason) -> Result<(), WorkError> {
        Err(WorkError::Unavailable)
    }

    unsafe fn arrive(&self, _: &TaskContext, _: bool) -> Result<(), WorkError> {
        Err(WorkError::Unavailable)
    }

    unsafe fn complete(&self, task: &TaskContext) -> Result<(), WorkError> {
        if self.context.load(Ordering::Acquire) != task.context_id
            || self.sequence.load(Ordering::Acquire) != task.sequence
            || self.completed.swap(true, Ordering::AcqRel)
        {
            return Err(WorkError::CorruptContext);
        }
        Ok(())
    }

    unsafe fn detach(&self, task: &TaskContext) -> Result<(), WorkError> {
        if self.context.load(Ordering::Acquire) != task.context_id
            || task.sequence != 0
            || !self.completed.load(Ordering::Acquire)
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
    let clock = work
        .native_clock
        .as_ref()
        .ok_or(WorkError::CorruptContext)?;
    let epoch = stage("epoch", clock.epoch())?;
    work.dispatch(|runtime| {
        let domain = stage("domain", Domain::tickless(clock.clock(), clock.idle()))?;
        stage("attach", runtime.attach_service_domain(domain.clone()))?;
        let target = epoch
            .now_ns()?
            .checked_add(100_000)
            .ok_or(WorkError::Exhausted)?;
        stage("arm", domain.set_timer(Some(target)))?;
        // This phase runs with the original loader root held and IF clear.
        // The companion clock control exercises hardware IRQ and HLT wake.
        while stage("wait", epoch.now_ns())? < target {
            core::hint::spin_loop();
        }
        let service = Box::new(Service {
            runtime: core::ptr::from_ref(runtime.get_ref()),
            domain: domain.clone(),
            binding: Arc::new(OneShotBinding::default()),
            context: Cell::new(None),
            result: Cell::new(None),
        });
        let service = Box::into_raw(service);
        // SAFETY: exact callback and stable allocation, kept on all errors.
        let ticket = stage("start", unsafe {
            runtime.start_service(deliver, service.cast())
        })?;
        for _ in 0..8 {
            if runtime.queue().completed(ticket)? {
                break;
            }
            stage("dispatch", runtime.step())?;
        }
        if !runtime.queue().completed(ticket)? {
            return Err(WorkError::TimedOut);
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
    })
    .map_err(failed)??;
    crate::output::arguments(format_args!(
        "CHECK native-clock-domain PASS cpu=installed clock=HPET service=timed retired=joined; no Linux current grant\n"
    ));
    Ok(())
}

fn stage<T>(name: &str, result: Result<T, WorkError>) -> Result<T, WorkError> {
    result.inspect_err(|error| {
        crate::output::arguments(format_args!(
            "CHECK native-clock-domain FAIL {name} {error:?}\n"
        ));
    })
}
