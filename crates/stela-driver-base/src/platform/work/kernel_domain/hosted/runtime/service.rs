//! Hosted deadline delivery through a reserved continuation.
use super::*;
use crate::platform::work::kernel_domain::{DomainRaised, HostedBatch, HostedDomain};
use core::cell::RefCell;

pub type HostedServiceCallback = unsafe fn(*mut c_void, &HostedBatch) -> Option<u64>;

pub(super) struct Service {
    deadlines: RefCell<HostedDeadlines>,
    callback: HostedServiceCallback,
    context: *mut c_void,
    pub(super) retired: Cell<bool>,
}

impl Service {
    pub(super) fn new(
        deadlines: HostedDeadlines,
        callback: HostedServiceCallback,
        context: *mut c_void,
    ) -> Self {
        Self {
            deadlines: RefCell::new(deadlines),
            callback,
            context,
            retired: Cell::new(false),
        }
    }

    pub(super) fn same_execution(&self, execution: &super::super::HostedExecution) -> bool {
        self.deadlines.borrow().execution().same_owner(execution)
    }
}

impl<const N: usize> HostedRuntime<N> {
    fn service(&self) -> Result<&Service, WorkError> {
        self.check()?;
        self.service.as_ref().ok_or(WorkError::Unavailable)
    }

    /// Check that this exact capture is live on its reserved service stack.
    pub fn validate_service_batch(&self, batch: &HostedBatch) -> Result<(), WorkError> {
        self.current_context()?;
        if self.current.get() != self.count - 1 || self.service.is_none() {
            return Err(WorkError::Unavailable);
        }
        self.service()?.deadlines.borrow().validate_batch(batch)
    }

    pub fn reschedule_requested(&self) -> Result<bool, WorkError> {
        if self.service_current()? {
            return Ok(false);
        }
        match &self.service {
            Some(service) if !service.retired.get() => service.deadlines.borrow_mut().due(),
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
        if service.retired.get() || !service.deadlines.borrow_mut().due()? {
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
    let batch = require(service.deadlines.borrow_mut().begin());
    if let Some(batch) = batch {
        require(runtime.validate_service_batch(&batch));
        // SAFETY: construction retains the actual consumer and storage. This
        // runs on the reserved task, with no timing/queue borrow held.
        let next = unsafe { (service.callback)(service.context, &batch) };
        // SAFETY: the actual consumer returned after delivering this capture.
        require(unsafe { service.deadlines.borrow_mut().finish(batch, next) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::work::{
        Kind,
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
        assert_eq!(runtime.current.get(), 2);
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
        // SAFETY: the consumer and static callbacks remain alive through this
        // bounded run. No callback unwinds or changes shadow-stack state.
        let executor = unsafe {
            HostedExecutor::new_with_service(
                queue.clone(),
                16,
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
}
