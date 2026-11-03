//! Linux userspace continuations with distinct guarded mmap stacks.
use super::{HostedDeadlines, HostedPages, HostedQueue, WorkError, std};
use crate::platform::work::{
    Continuation, Lane, Layout, NONE, TaskContext, TaskState, context, stack_requirement::Geometry,
};
use alloc::{boxed::Box, rc::Rc, sync::Arc, vec::Vec};
use core::{
    cell::{Cell, UnsafeCell},
    ffi::c_void,
    marker::{PhantomData, PhantomPinned},
    mem::ManuallyDrop,
    ops::Range,
    pin::Pin,
    ptr,
    sync::atomic::Ordering,
};

mod binding;
pub use binding::{HostedSwitchBinding, HostedWake};
mod service;
pub use service::HostedServiceCallback;
use service::Service;

struct Stack {
    _pages: HostedPages,
    bounds: Range<usize>,
    geometry: Geometry,
    guard: Range<usize>,
}
type Task = Continuation<Stack, (), Rc<dyn HostedSwitchBinding>>;

pub struct HostedExecutor<const N: usize> {
    runtime: ManuallyDrop<Pin<Box<HostedRuntime<N>>>>,
}
pub struct HostedRuntime<const N: usize> {
    queue: Arc<HostedQueue<N>>,
    tasks: UnsafeCell<Vec<Task>>,
    count: usize,
    service: Option<Service>,
    dispatcher: UnsafeCell<context::Frame>,
    current: Cell<usize>,
    dispatch_epoch: Cell<u64>,
    cursor: Cell<usize>,
    retired: Cell<bool>,
    _local: PhantomData<*mut ()>,
    _pinned: PhantomPinned,
}

impl<const N: usize> HostedExecutor<N> {
    /// Allocate exclusive guarded stacks for General and Notify callbacks.
    ///
    /// # Safety
    /// Callbacks must fit within the supplied stack and must not unwind or
    /// jump across the switch boundary. The original thread must keep shadow
    /// stacks disabled while this executor can run, including in callbacks.
    pub unsafe fn new(queue: Arc<HostedQueue<N>>, stack_pages: usize) -> Result<Self, WorkError> {
        Self::build(queue, stack_pages, None)
    }

    /// Add one guarded service stack and reserve one queue slot for its work.
    ///
    /// # Safety
    /// The requirements of `new` apply to all callbacks. Keep the service
    /// callback, context and reachable storage/code alive through actual
    /// retirement or retained abandonment. The callback must deliver its
    /// captured reasons and return the actual remaining timer deadline.
    pub unsafe fn new_with_service(
        queue: Arc<HostedQueue<N>>,
        stack_pages: usize,
        deadlines: HostedDeadlines,
        callback: HostedServiceCallback,
        context: *mut c_void,
    ) -> Result<Self, WorkError> {
        Self::build(
            queue,
            stack_pages,
            Some(Service::new(deadlines, callback, context)),
        )
    }

    fn build(
        queue: Arc<HostedQueue<N>>,
        stack_pages: usize,
        service: Option<Service>,
    ) -> Result<Self, WorkError> {
        queue.execution.check_current()?;
        let (layout, count) = if let Some(service) = &service {
            if !service.same_execution(&queue.execution) {
                return Err(WorkError::InvalidTicket);
            }
            (Layout::HostedService, 3)
        } else {
            (Layout::Ordinary, 2)
        };
        layout.validate(count, N)?;
        if stack_pages < 4 {
            return Err(WorkError::InvalidStack);
        }
        // This switch backend uses RET with a replacement RSP. Linux reports
        // the actual shadow-stack state of this thread through arch_prctl.
        let mut features = 0u64;
        // SAFETY: Linux x86-64 arch_prctl(ARCH_SHSTK_STATUS, &features).
        let result = unsafe {
            let result: i64;
            core::arch::asm!(
                "syscall", inlateout("rax") 158i64 => result,
                in("rdi") 0x5005usize, in("rsi") &mut features,
                lateout("rcx") _, lateout("r11") _, options(nostack),
            );
            result
        };
        if result != 0 || features != 0 {
            return Err(WorkError::Unavailable);
        }
        // SAFETY: reads the current thread's user-accessible FP controls.
        let controls = unsafe { context::read_controls() };
        let task = |lane| {
            let pages = HostedPages::allocate(&queue.execution, stack_pages, 4096, 1)
                .map_err(|_| WorkError::InvalidStack)?;
            let start = pages
                .cpu_address(0, 1)
                .map_err(|_| WorkError::InvalidStack)?
                .as_ptr()
                .addr();
            let bounds = start
                ..start
                    .checked_add(pages.bytes())
                    .ok_or(WorkError::InvalidStack)?;
            let guard = pages.guard();
            let geometry = Geometry::from_ranges(&bounds, &guard);
            Task::new(
                lane,
                Stack {
                    _pages: pages,
                    bounds,
                    geometry,
                    guard,
                },
                controls,
                (),
            )
        };
        let mut tasks = Vec::new();
        tasks
            .try_reserve_exact(count)
            .map_err(|_| WorkError::Full)?;
        tasks.push(task(Lane::General)?);
        tasks.push(task(Lane::Notify)?);
        if service.is_some() {
            tasks.push(task(Lane::Service)?);
        }
        let runtime = Box::pin(HostedRuntime {
            queue,
            tasks: UnsafeCell::new(tasks),
            count,
            service,
            dispatcher: UnsafeCell::new(context::Frame::new(controls)),
            current: Cell::new(NONE),
            dispatch_epoch: Cell::new(0),
            cursor: Cell::new(0),
            retired: Cell::new(false),
            _local: PhantomData,
            _pinned: PhantomPinned,
        });
        {
            let mut guard = runtime.queue.lock()?;
            let state = guard.state();
            if state.closed {
                return Err(WorkError::Closed);
            }
            if layout == Layout::HostedService && state.jobs[N - 1].is_some() {
                return Err(WorkError::Busy);
            }
            runtime
                .queue
                .attached
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| WorkError::Busy)?;
            state.layout = layout;
        }
        let address = ptr::from_ref(runtime.as_ref().get_ref()).addr();
        for index in 0..runtime.count {
            // SAFETY: this pinned runtime has no live frames yet and its
            // producer cannot execute tasks during construction.
            let task = unsafe { &mut *runtime.task(index) };
            // SAFETY: mmap provides aligned, exclusive writable stack tops.
            unsafe {
                task.frame
                    .start(task.stack.bounds.end, address, index, entry::<N>)
            };
        }
        Ok(Self {
            runtime: ManuallyDrop::new(runtime),
        })
    }

    pub fn runtime(&self) -> Pin<&HostedRuntime<N>> {
        self.runtime.as_ref()
    }
}

impl<const N: usize> Drop for HostedExecutor<N> {
    fn drop(&mut self) {
        if self.runtime.retired.get() {
            // SAFETY: dispatcher retirement excludes any live callback frame.
            unsafe { ManuallyDrop::drop(&mut self.runtime) };
        }
    }
}

impl<const N: usize> HostedRuntime<N> {
    fn task(&self, index: usize) -> *mut Task {
        // SAFETY: internal indices always name one initialized task in the
        // immutable, retained allocation.
        unsafe { (&mut *self.tasks.get()).as_mut_ptr().add(index) }
    }

    pub(in crate::platform::work::kernel_domain) fn check(&self) -> Result<(), WorkError> {
        self.queue.execution.check_current()?;
        if self.retired.get() {
            return Err(WorkError::Closed);
        }
        Ok(())
    }

    pub(in crate::platform::work::kernel_domain) fn current_context(
        &self,
    ) -> Result<crate::platform::work::TaskContext, WorkError> {
        self.check()?;
        let index = self.current.get();
        if index == NONE {
            return Err(WorkError::Unavailable);
        }
        // SAFETY: the checked original thread is executing this task. No
        // mutable task borrow spans a call to this observation.
        let task = unsafe { &*self.task(index) };
        let stack_pointer = context::stack_pointer();
        if task.state != TaskState::Running || !task.stack.bounds.contains(&stack_pointer) {
            return Err(WorkError::CorruptContext);
        }
        Ok(self.context_view(task, stack_pointer))
    }

    fn context_view(&self, task: &Task, stack_pointer: usize) -> TaskContext {
        TaskContext {
            queue_id: self.queue.id,
            context_id: task.id.get(),
            sequence: task.job.map_or(0, |(_, job)| job.sequence),
            stack_start: task.stack.bounds.start,
            stack_end: task.stack.bounds.end,
            guard_start: task.stack.guard.start,
            guard_end: task.stack.guard.end,
            stack_pointer,
        }
    }

    pub(in crate::platform::work::kernel_domain) fn segment_epoch(&self) -> Result<u64, WorkError> {
        self.current_context()?;
        Ok(self.dispatch_epoch.get())
    }

    pub(in crate::platform::work::kernel_domain) fn dispatcher_successor(
        &self,
    ) -> Result<(), WorkError> {
        self.check()?;
        if self.current.get() != NONE {
            return Err(WorkError::Busy);
        }
        Ok(())
    }

    pub fn step(self: Pin<&Self>) -> Result<bool, WorkError> {
        self.queue.execution.check_current()?;
        if self.current.get() != NONE {
            return Err(WorkError::WouldDeadlock);
        }
        if self.retired.get() {
            return Err(WorkError::Closed);
        }
        let epoch = self
            .dispatch_epoch
            .get()
            .checked_add(1)
            .ok_or(WorkError::Exhausted)?;
        self.schedule_service()?;
        for offset in 0..self.count {
            let index = (self.cursor.get() + offset) % self.count;
            let now = self.queue.execution.now_ns()?;
            {
                // SAFETY: dispatcher on the original thread, no task is running.
                let task = unsafe { &mut *self.task(index) };
                let mut guard = self.queue.lock()?;
                let state = guard.state();
                if task.state == TaskState::Idle {
                    let Some(job) = state.select_job(task.lane, task.stack.geometry, false)? else {
                        continue;
                    };
                    require(state.scheduling.insert(
                        task.id,
                        job.1.sequence,
                        task.lane == Lane::Service,
                    ));
                    task.assign(job, ());
                }
                let sequence = task.job.unwrap_or_else(|| std::process::abort()).1.sequence;
                if task.state == TaskState::Blocked {
                    if !task.signal.pending.swap(false, Ordering::AcqRel) {
                        continue;
                    }
                    require(state.scheduling.wake(task.id, sequence));
                    task.state = TaskState::Runnable;
                }
                require(state.scheduling.running(task.id, sequence, now));
                task.state = TaskState::Running;
            }
            self.dispatch_epoch.set(epoch);
            self.current.set(index);
            self.cursor.set((index + 1) % self.count);
            // SAFETY: both frames are pinned and owned by this thread. All
            // task/state borrows and queue guards ended before the switch.
            unsafe {
                context::switch(
                    self.dispatcher.get(),
                    ptr::addr_of!((*self.task(index)).frame),
                )
            };
            if self.current.get() != NONE {
                std::process::abort();
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn depart(&self, index: usize) {
        self.current.set(NONE);
        // SAFETY: called only from this live task with its dispatcher saved,
        // on its owning thread after ending all exclusive task/state borrows.
        unsafe {
            context::switch(
                ptr::addr_of_mut!((*self.task(index)).frame),
                self.dispatcher.get(),
            )
        };
    }

    /// Stop dispatch after the caller closes the queue and drains callbacks.
    pub fn retire(self: Pin<&Self>) -> Result<(), WorkError> {
        self.queue.execution.check_current()?;
        if self.retired.get() {
            return Ok(());
        }
        if self.current.get() != NONE {
            return Err(WorkError::Busy);
        }
        for index in 0..self.count {
            // SAFETY: all task stacks are stopped on the original dispatcher.
            if unsafe { (*self.task(index)).binding.is_some() } {
                return Err(WorkError::Busy);
            }
        }
        let mut guard = self.queue.lock()?;
        let state = guard.state();
        if !state.closed
            || state.jobs.iter().any(Option::is_some)
            || self
                .service
                .as_ref()
                .is_some_and(|service| !service.retired.get())
        {
            return Err(WorkError::Busy);
        }
        self.retired.set(true);
        self.queue.attached.store(false, Ordering::Release);
        Ok(())
    }
}

fn require<T>(result: Result<T, WorkError>) -> T {
    result.unwrap_or_else(|_| std::process::abort())
}

unsafe extern "sysv64" fn entry<const N: usize>(address: usize, index: usize) -> ! {
    // SAFETY: only the trampoline in this executor's own task stack enters,
    // with the original pinned runtime kept by HostedExecutor.
    let runtime = unsafe { &*(address as *const HostedRuntime<N>) };
    loop {
        // SAFETY: immutable assignment for the exact running task. No borrow
        // of its state survives the callback or any cooperative yield.
        let job = unsafe { (*runtime.task(index)).job }.unwrap_or_else(|| std::process::abort());
        runtime.arrive(index, true);
        // SAFETY: queue admission retains the original callback/context graph.
        unsafe { (job.1.callback)(job.1.context as *mut c_void) };
        runtime.complete_binding(index);
        let now = require(runtime.queue.execution.now_ns());
        {
            // SAFETY: only the original running task can complete this slot.
            let task = unsafe { &mut *runtime.task(index) };
            let mut guard = require(runtime.queue.lock());
            let state = guard.state();
            require(state.scheduling.account(now));
            require(state.scheduling.remove(task.id, job.1.sequence));
            task.signal.sequence.store(0, Ordering::Release);
            require(state.finish_job(job.0, job.1.sequence, None));
            task.job = None;
            task.state = TaskState::Idle;
        }
        runtime.depart(index);
    }
}

#[cfg(test)]
mod tests {
    use super::super::HostedExecution;
    use super::*;
    use crate::platform::work::Kind;
    use crate::platform::work::kernel_domain::DomainRef;

    struct Call<'a> {
        runtime: Pin<&'a HostedRuntime<4>>,
        lane: usize,
        visits: &'a Cell<u32>,
    }
    unsafe extern "C" fn run(raw: *mut c_void) {
        // SAFETY: the test retains this call and runtime through dispatch.
        let call = unsafe { &*raw.cast::<Call<'_>>() };
        assert_eq!(call.runtime.current.get(), call.lane);
        let domain = DomainRef::borrow_hosted(call.runtime).unwrap();
        let segment = domain.hosted_segment().unwrap();
        assert!(segment.matches(&domain));
        assert_eq!(segment.check(), Ok(()));
        assert_eq!(domain.dispatcher_successor(), Err(WorkError::Busy));
        // SAFETY: only this task runs, and the borrow ends before yielding.
        let bounds = unsafe { &(*call.runtime.task(call.lane)).stack.bounds };
        assert!(bounds.contains(&context::stack_pointer()));
        call.visits
            .set(call.visits.get() * 10 + call.lane as u32 + 1);
        if call.lane == 0 {
            call.runtime.yield_now().unwrap();
            assert_eq!(segment.check(), Err(WorkError::InvalidTicket));
            assert_eq!(domain.hosted_segment().unwrap().check(), Ok(()));
            call.visits.set(call.visits.get() * 10 + 3);
        }
    }

    #[test]
    fn callbacks_resume_on_their_owned_stacks_and_retire_after_return() {
        let queue = HostedQueue::new(HostedExecution::new(), Arc::new(())).unwrap();
        // SAFETY: bounded callbacks with no shadow-stack changes or unwinds.
        let executor = unsafe { HostedExecutor::<4>::new(queue.clone(), 16) }.unwrap();
        let runtime = executor.runtime();
        let domain = DomainRef::borrow_hosted(runtime).unwrap();
        assert_eq!(domain.dispatcher_successor(), Ok(()));
        assert!(matches!(
            domain.hosted_segment(),
            Err(WorkError::Unavailable)
        ));
        let visits = Cell::new(0);
        let general = Call {
            runtime,
            lane: 0,
            visits: &visits,
        };
        let notify = Call {
            runtime,
            lane: 1,
            visits: &visits,
        };
        // SAFETY: both call contexts stay on the dispatcher's live stack
        // until their tickets complete, and their contents remain valid.
        let general_ticket = unsafe {
            queue.execute(
                Kind::General,
                run,
                ptr::from_ref(&general).cast_mut().cast(),
            )
        }
        .unwrap();
        // SAFETY: same lifetime as the General call above.
        let notify_ticket =
            unsafe { queue.execute(Kind::Notify, run, ptr::from_ref(&notify).cast_mut().cast()) }
                .unwrap();
        queue.close().unwrap();
        assert!(runtime.step().unwrap());
        assert_eq!(visits.get(), 1);
        assert!(!queue.completed(general_ticket).unwrap());
        assert_eq!(runtime.retire(), Err(WorkError::Busy));
        assert!(runtime.step().unwrap());
        assert!(queue.completed(notify_ticket).unwrap());
        assert!(runtime.step().unwrap());
        assert!(queue.completed(general_ticket).unwrap());
        assert_eq!(visits.get(), 123);
        assert!(!runtime.step().unwrap());
        runtime.retire().unwrap();
        assert_eq!(domain.check(), Err(WorkError::Closed));
        // SAFETY: the only producer closed and both callbacks have returned.
        unsafe { queue.retire() }.unwrap();
    }
}
