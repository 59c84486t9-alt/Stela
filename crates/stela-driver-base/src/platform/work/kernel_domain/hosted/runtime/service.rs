//! Hosted deadline delivery through a reserved continuation.
use super::*;
use crate::platform::work::{
    Callback, ParkOutcome,
    kernel_domain::{DomainRaised, HostedBatch, HostedDomain, HostedTicket},
};
use core::cell::RefCell;

pub type HostedServiceCallback = unsafe fn(*mut c_void, &HostedBatch) -> Option<u64>;

pub(super) struct Service {
    deadlines: RefCell<HostedDeadlines>,
    mode: Mode,
    pub(super) retired: Cell<bool>,
}

enum Mode {
    Bounded {
        callback: HostedServiceCallback,
        context: *mut c_void,
    },
    Persistent {
        started: Cell<bool>,
        waiting_for_batch: Cell<bool>,
    },
}

impl Service {
    pub(super) fn bounded(
        deadlines: HostedDeadlines,
        callback: HostedServiceCallback,
        context: *mut c_void,
    ) -> Self {
        Self {
            deadlines: RefCell::new(deadlines),
            mode: Mode::Bounded { callback, context },
            retired: Cell::new(false),
        }
    }

    pub(super) fn persistent(deadlines: HostedDeadlines) -> Self {
        Self {
            deadlines: RefCell::new(deadlines),
            mode: Mode::Persistent {
                started: Cell::new(false),
                waiting_for_batch: Cell::new(false),
            },
            retired: Cell::new(false),
        }
    }

    pub(super) fn same_execution(&self, execution: &super::super::HostedExecution) -> bool {
        self.deadlines.borrow().execution().same_owner(execution)
    }

    fn can_deliver(&self) -> bool {
        !self.retired.get()
            && match &self.mode {
                Mode::Bounded { .. } => true,
                Mode::Persistent {
                    waiting_for_batch, ..
                } => waiting_for_batch.get(),
            }
    }
}

impl<const N: usize> HostedRuntime<N> {
    fn service(&self) -> Result<&Service, WorkError> {
        self.check()?;
        self.service.as_ref().ok_or(WorkError::Unavailable)
    }

    /// Verify the constructor-owned persistent service lane before a source
    /// claims its permanent C record.
    pub fn preflight_service(&self, required: StackRequirement) -> Result<(), WorkError> {
        self.dispatcher_successor()?;
        let service = self.service()?;
        let Mode::Persistent { started, .. } = &service.mode else {
            return Err(WorkError::Unavailable);
        };
        if service.retired.get() || self.queue.lock()?.state().closed {
            return Err(WorkError::Closed);
        }
        if started.get() {
            return Err(WorkError::Busy);
        }
        // SAFETY: immutable constructor-owned stack geometry, on the
        // original dispatcher with every hosted continuation stopped.
        let task = unsafe { &*self.task(self.count - 1) };
        if !required.accepts(task.stack.geometry) {
            return Err(WorkError::InvalidStack);
        }
        Ok(())
    }

    /// Check that this exact capture is live on its reserved service stack.
    pub fn validate_service_batch(&self, batch: &HostedBatch) -> Result<(), WorkError> {
        self.current_context()?;
        if self.current.get() != self.count - 1 || self.service.is_none() {
            return Err(WorkError::Unavailable);
        }
        self.service()?.deadlines.borrow().validate_batch(batch)
    }

    /// Start the reserved persistent service once on its exact hosted stack.
    /// Deadline reasons can accumulate before start and during source startup.
    ///
    /// # Safety
    /// Keep the callback, context and all reachable code and data until the
    /// service joins or through retained abandonment. The callback cannot
    /// unwind or return while a source scope or deadline capture is live.
    pub unsafe fn start_service(
        self: Pin<&Self>,
        callback: Callback,
        context: *mut c_void,
    ) -> Result<HostedTicket, WorkError> {
        self.dispatcher_successor()?;
        let service = self.service()?;
        let Mode::Persistent { started, .. } = &service.mode else {
            return Err(WorkError::Unavailable);
        };
        if service.retired.get() {
            return Err(WorkError::Closed);
        }
        if started.get() {
            return Err(WorkError::Busy);
        }
        let ticket = self.queue.enqueue_lane(Lane::Service, callback, context)?;
        started.set(true);
        Ok(ticket)
    }

    fn current_persistent_service(&self) -> Result<(&Service, &Cell<bool>), WorkError> {
        let service = self.service()?;
        if self.service_current()?
            && let Mode::Persistent {
                waiting_for_batch, ..
            } = &service.mode
        {
            return Ok((service, waiting_for_batch));
        }
        Err(WorkError::Unavailable)
    }

    /// Capture the current persistent service's due reasons. The capture is
    /// separate from any source's permission to deliver original callbacks.
    pub fn begin_service_batch(&self) -> Result<Option<HostedBatch>, WorkError> {
        let (service, _) = self.current_persistent_service()?;
        service.deadlines.borrow_mut().begin()
    }

    /// # Safety
    /// All consumers of this exact capture have returned on the original
    /// service, and next_timer is their actual remaining deadline.
    pub unsafe fn finish_service_batch(
        &self,
        batch: HostedBatch,
        next_timer: Option<u64>,
    ) -> Result<(), WorkError> {
        let (service, _) = self.current_persistent_service()?;
        // SAFETY: the caller joins the actual consumers of this capture.
        unsafe { service.deadlines.borrow_mut().finish(batch, next_timer) }
    }

    /// Park an original service wait after its binding prepares to suspend.
    /// Only this wait is woken by deadline reasons. A source bootstrap wait
    /// uses `park_if_blocked` and resumes through its own exact wake handle.
    pub fn park_service_if_idle(self: Pin<&Self>) -> Result<ParkOutcome, WorkError> {
        let (service, waiting) = self.current_persistent_service()?;
        {
            let mut deadlines = service.deadlines.borrow_mut();
            if deadlines.running() {
                return Err(WorkError::Busy);
            }
            if deadlines.due()? {
                return Ok(ParkOutcome::Skipped);
            }
        }
        waiting.set(true);
        let result = self.park_if_blocked();
        waiting.set(false);
        result
    }

    pub fn reschedule_requested(&self) -> Result<bool, WorkError> {
        if self.service_current()? {
            return Ok(false);
        }
        match &self.service {
            Some(service) if service.can_deliver() => service.deadlines.borrow_mut().due(),
            _ => Ok(false),
        }
    }

    pub fn service_raised_work(&self) -> Result<DomainRaised<HostedDomain>, WorkError> {
        self.service()?.deadlines.borrow().raised_work()
    }

    pub fn start_service_ticks(&self) -> Result<(), WorkError> {
        self.dispatcher_successor()?;
        self.service()?.deadlines.borrow_mut().start_ticks()
    }

    pub fn set_service_timer(&self, deadline: Option<u64>) -> Result<(), WorkError> {
        self.dispatcher_successor()?;
        let service = self.service()?;
        let mut deadlines = service.deadlines.borrow_mut();
        if deadlines.running() {
            return Err(WorkError::Busy);
        }
        deadlines.set_timer(deadline)
    }

    pub fn stop_service_producers(&self) -> Result<(), WorkError> {
        self.dispatcher_successor()?;
        self.service()?.deadlines.borrow_mut().stop_producers()
    }

    /// # Safety
    /// All source producers, waiter and callback/storage users are joined.
    /// Call before closing the queue, after dispatching pending service work.
    pub unsafe fn retire_service(&self) -> Result<(), WorkError> {
        self.dispatcher_successor()?;
        let service = self.service()?;
        if service.retired.get() {
            return Ok(());
        }
        {
            let mut guard = self.queue.lock()?;
            if guard.state().jobs[N - 1].is_some() {
                return Err(WorkError::Busy);
            }
        }
        // SAFETY: caller supplies the actual joins. No service job is live.
        unsafe { service.deadlines.borrow_mut().retire()? };
        service.retired.set(true);
        Ok(())
    }

    pub(super) fn schedule_service(self: Pin<&Self>) -> Result<(), WorkError> {
        let Some(service) = &self.service else {
            return Ok(());
        };
        if !service.can_deliver() || !service.deadlines.borrow_mut().due()? {
            return Ok(());
        }
        if matches!(service.mode, Mode::Persistent { .. }) {
            // SAFETY: the actual dispatcher owns every stopped frame.
            // Only this service assignment can publish its wait marker.
            let task = unsafe { &*self.task(self.count - 1) };
            task.signal.pending.store(true, Ordering::Release);
            return Ok(());
        }
        let mut guard = self.queue.lock()?;
        let state = guard.state();
        if state.jobs[N - 1].is_none() {
            let context = ptr::from_ref(self.get_ref()).cast_mut().cast();
            state.enqueue(Lane::Service, deliver::<N>, context, None, false)?;
        }
        Ok(())
    }

    /// Step once, or park on the owned service clock and event source.
    pub fn step_or_idle(self: Pin<&Self>) -> Result<bool, WorkError> {
        if self.step()? {
            return Ok(true);
        }
        let service = self.service()?;
        // SAFETY: step returned to the taskless dispatcher. No queue guard,
        // execution segment or callback is held. Only the timing owner is lent.
        unsafe { service.deadlines.borrow_mut().idle()? };
        self.step()
    }
}

unsafe extern "C" fn deliver<const N: usize>(context: *mut c_void) {
    // SAFETY: the reserved job points to this exact pinned executor. Its
    // container stays held through return, even if abandoned while suspended.
    let runtime = unsafe { &*context.cast::<HostedRuntime<N>>() };
    require(runtime.current_context());
    let service = require(runtime.service());
    let Mode::Bounded { callback, context } = service.mode else {
        std::process::abort();
    };
    let batch = require(service.deadlines.borrow_mut().begin());
    if let Some(batch) = batch {
        require(runtime.validate_service_batch(&batch));
        // SAFETY: construction retains the actual consumer and storage. This
        // runs on the reserved task, with no timing/queue borrow held.
        let next = unsafe { callback(context, &batch) };
        // SAFETY: the actual consumer returned after delivering this capture.
        require(unsafe { service.deadlines.borrow_mut().finish(batch, next) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::work::{
        Kind, LeaveReason,
        kernel_domain::{DomainRef, HostedClock, HostedExecution, HostedIdle},
    };

    struct Consumer {
        runtime: Cell<*const HostedRuntime<4>>,
        deliveries: Cell<usize>,
    }
    unsafe fn consume(context: *mut c_void, batch: &HostedBatch) -> Option<u64> {
        // SAFETY: this test retains the pinned runtime and its consumer through
        // all service and ordinary returns.
        let consumer = unsafe { &*context.cast::<Consumer>() };
        // SAFETY: set once from the pinned executor before its first step.
        let runtime = unsafe { Pin::new_unchecked(&*consumer.runtime.get()) };
        let domain = DomainRef::borrow_hosted(runtime).unwrap();
        assert_eq!(domain.hosted_segment().unwrap().check(), Ok(()));
        assert_eq!(runtime.current.get(), 3);
        assert_eq!(runtime.service_current(), Ok(true));
        assert!(batch.raised());
        assert_eq!(runtime.validate_service_batch(batch), Ok(()));
        let deliveries = consumer.deliveries.get();
        assert_eq!(batch.timer(), deliveries == 0);
        consumer.deliveries.set(deliveries + 1);
        if deliveries == 0 {
            runtime.service_raised_work().unwrap().raise().unwrap();
        }
        None
    }

    unsafe extern "C" fn ordinary(_: *mut c_void) {}

    #[test]
    fn reserved_service_delivers_real_capture_despite_full_ordinary_lane() {
        let execution = HostedExecution::new();
        let clock = HostedClock::new(&execution).unwrap();
        let idle = HostedIdle::new(&clock).unwrap();
        let deadlines = HostedDeadlines::new(&clock, &idle).unwrap();
        let queue = HostedQueue::new(execution, Arc::new(())).unwrap();
        let consumer = Consumer {
            runtime: Cell::new(ptr::null()),
            deliveries: Cell::new(0),
        };
        let stack = StackRequirement::exact(16 * 1024, 16 * 1024, PAGE).unwrap();
        // SAFETY: the consumer and static callbacks remain alive through this
        // bounded run. No callback unwinds or changes shadow-stack state.
        let executor = unsafe {
            HostedExecutor::new_with_service_stacks(
                queue.clone(),
                stack,
                2,
                deadlines,
                consume,
                ptr::from_ref(&consumer).cast_mut().cast(),
            )
        }
        .unwrap();
        let runtime = executor.runtime();
        consumer.runtime.set(ptr::from_ref(runtime.get_ref()));
        for _ in 0..3 {
            // SAFETY: static callback ignores the context.
            unsafe { queue.execute(Kind::General, ordinary, ptr::null_mut()) }.unwrap();
        }
        assert_eq!(
            // SAFETY: static callback ignores the context.
            unsafe { queue.execute(Kind::Notify, ordinary, ptr::null_mut()) },
            Err(WorkError::Full)
        );
        runtime
            .set_service_timer(Some(clock.now_ns().unwrap()))
            .unwrap();
        let raised = runtime.service_raised_work().unwrap();
        raised.raise().unwrap();
        for _ in 0..5 {
            assert!(runtime.step().unwrap());
        }
        assert_eq!(consumer.deliveries.get(), 2);
        assert!(!runtime.step().unwrap());
        runtime.stop_service_producers().unwrap();
        // SAFETY: all five actual callback returns have joined on the
        // dispatcher and no other producer or waiter was started.
        unsafe { runtime.retire_service() }.unwrap();
        assert_eq!(raised.raise(), Err(WorkError::Closed));
        queue.close().unwrap();
        runtime.retire().unwrap();
        // SAFETY: the sole producer stopped and every callback returned.
        unsafe { queue.retire() }.unwrap();
    }

    #[derive(Default)]
    struct SourceBinding {
        parked: Cell<bool>,
    }
    // SAFETY: this bounded fixture owns one source on the hosted service.
    // The hooks only update its local state and never switch or suspend.
    unsafe impl HostedSwitchBinding for SourceBinding {
        unsafe fn attach(&self, _: &TaskContext) -> Result<(), WorkError> {
            Ok(())
        }
        unsafe fn still_blocked(&self, _: &TaskContext) -> Result<bool, WorkError> {
            Ok(true)
        }
        unsafe fn leave(&self, _: &TaskContext, reason: LeaveReason) -> Result<(), WorkError> {
            assert_eq!(reason, LeaveReason::Blocked);
            assert!(!self.parked.replace(true));
            Ok(())
        }
        unsafe fn arrive(&self, _: &TaskContext, new_job: bool) -> Result<(), WorkError> {
            assert!(!new_job);
            assert!(self.parked.replace(false));
            Ok(())
        }
        unsafe fn complete(&self, _: &TaskContext) -> Result<(), WorkError> {
            assert!(!self.parked.get());
            Ok(())
        }
        unsafe fn detach(&self, _: &TaskContext) -> Result<(), WorkError> {
            Ok(())
        }
    }

    struct PersistentConsumer<'a> {
        runtime: Pin<&'a HostedRuntime<4>>,
        wake: RefCell<Option<HostedWake>>,
        batches: Cell<usize>,
    }

    unsafe extern "C" fn run_persistent(context: *mut c_void) {
        // SAFETY: the dispatcher retains this context and runtime through
        // all real waits and the final service return.
        let consumer = unsafe { &*context.cast::<PersistentConsumer<'_>>() };
        let runtime = consumer.runtime;
        let wake = runtime
            .bind_current(Rc::new(SourceBinding::default()))
            .unwrap();
        let sequence = wake.sequence();
        *consumer.wake.borrow_mut() = Some(wake);
        // A pending deadline reason must not wake this separate source wait.
        assert_eq!(runtime.park_if_blocked(), Ok(ParkOutcome::Resumed));
        assert_eq!(runtime.park_service_if_idle(), Ok(ParkOutcome::Skipped));

        for pass in 0..2 {
            if pass == 1 {
                assert_eq!(runtime.park_service_if_idle(), Ok(ParkOutcome::Resumed));
            }
            assert_eq!(runtime.current_wake().unwrap().sequence(), sequence);
            let batch = runtime.begin_service_batch().unwrap().unwrap();
            assert_eq!(batch.raised(), pass == 0);
            assert_eq!(batch.timer(), pass == 1);
            assert_eq!(runtime.validate_service_batch(&batch), Ok(()));
            assert_eq!(runtime.park_service_if_idle(), Err(WorkError::Busy));
            // SAFETY: this synchronous fixture owns and has consumed the
            // exact capture. It has no timer or outstanding callback users.
            unsafe { runtime.finish_service_batch(batch, None) }.unwrap();
            consumer.batches.set(pass + 1);
        }
    }

    #[test]
    fn persistent_service_keeps_one_assignment_and_separates_source_and_deadline_waits() {
        let execution = HostedExecution::new();
        let clock = HostedClock::new(&execution).unwrap();
        let idle = HostedIdle::new(&clock).unwrap();
        let deadlines = HostedDeadlines::new(&clock, &idle).unwrap();
        let queue = HostedQueue::new(execution, Arc::new(())).unwrap();
        let stack = StackRequirement::exact(16 * 1024, 16 * 1024, PAGE).unwrap();
        // SAFETY: bounded service fixture on this owning thread, with every
        // callback and suspension joined before releasing the stack.
        let executor = unsafe {
            HostedExecutor::new_with_persistent_service_stacks(queue.clone(), stack, 1, deadlines)
        }
        .unwrap();
        let runtime = executor.runtime();
        let consumer = PersistentConsumer {
            runtime,
            wake: RefCell::new(None),
            batches: Cell::new(0),
        };
        let raised = runtime.service_raised_work().unwrap();
        raised.raise().unwrap();
        assert_eq!(runtime.step(), Ok(false));
        let context = ptr::from_ref(&consumer).cast_mut().cast();
        // SAFETY: the test retains its exact callback, context and binding
        // through the dispatcher successor and all batch returns.
        let ticket = unsafe { runtime.start_service(run_persistent, context) }.unwrap();
        assert_eq!(runtime.step(), Ok(true));
        assert_eq!(consumer.batches.get(), 0);
        assert_eq!(runtime.step(), Ok(false));
        let wake = consumer.wake.borrow_mut().take().unwrap();
        wake.wake().unwrap();
        assert_eq!(runtime.step(), Ok(true));
        assert_eq!(consumer.batches.get(), 1);
        assert_eq!(queue.completed(ticket), Ok(false));
        assert_eq!(runtime.step(), Ok(false));
        runtime
            .set_service_timer(Some(clock.now_ns().unwrap()))
            .unwrap();
        assert_eq!(runtime.step(), Ok(true));
        assert_eq!(consumer.batches.get(), 2);
        assert_eq!(queue.completed(ticket), Ok(true));
        assert_eq!(
            // SAFETY: the test still retains the entire original context.
            unsafe { runtime.start_service(run_persistent, context) },
            Err(WorkError::Busy)
        );
        assert_eq!(wake.wake(), Err(WorkError::Closed));
        runtime.stop_service_producers().unwrap();
        // SAFETY: the service and all source users have returned; detach
        // checks the same exact completed assignment on the dispatcher.
        unsafe {
            drop(runtime.detach_binding(&wake).unwrap());
            runtime.retire_service().unwrap();
        }
        queue.close().unwrap();
        runtime.retire().unwrap();
        // SAFETY: the sole producer stopped and all work joined.
        unsafe { queue.retire() }.unwrap();
    }
}
