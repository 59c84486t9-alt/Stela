//! The tasks of a Linux environment on a work [`Runtime`]: the service task
//! that takes the place of Linux's interrupts and tick, and the tasks its
//! workqueues and owner run on. All of them share one CPU and take turns, which
//! is the uniprocessor, non-preemptible execution Linux's code is built for.
//!
//! An interrupt only records its original epoch ([`IrqEvent::raise`]); the handlers
//! run on the service task, which sleeps until a line is raised or the next
//! timer is due (`compat/kernel/service.c`).
use super::{
    owner::{RawOwner, WorkerKind},
    task::TaskBinding,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    ffi::{c_int, c_void},
    marker::PhantomPinned,
    pin::Pin,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};
use stela_driver_base::platform::work::{
    Callback, Runtime, SwitchBinding, Ticket, WorkError,
    service::{Batch, Domain, RaisedWork},
};

/// `struct stela_linux_service_call`.
#[repr(C)]
struct Call {
    owner: *const RawOwner,
    context: *mut c_void,
    begin: unsafe extern "C" fn(*mut c_void) -> bool,
    next_irq: unsafe extern "C" fn(*mut c_void) -> c_int,
    complete_irq: unsafe extern "C" fn(*mut c_void),
    drain: unsafe extern "C" fn(*mut c_void),
    finish: unsafe extern "C" fn(*mut c_void, i64),
    done: unsafe extern "C" fn(*mut c_void) -> bool,
}

unsafe extern "C" {
    fn stela_linux_service_loop(call: *mut c_void);
    fn stela_linux_worker_main(call: *mut c_void);
    fn stela_linux_sleep_us(minimum: u64);
}

/// Run a delay that may sleep, from [`Platform::delay_us`]: the service task's
/// interrupts and timers run meanwhile, as they would not under a spin.
///
/// # Safety
/// Called by Linux on one of an [`Environment`]'s tasks, whose service runs.
///
/// [`Platform::delay_us`]: super::owner::Platform::delay_us
pub unsafe fn sleep_us(minimum: u64) {
    // SAFETY: the caller's contract.
    unsafe { stela_linux_sleep_us(minimum) };
}

/// Interrupt lines an owner may give Linux.
pub const LINES: u32 = 256;

const IRQ_OPEN: u8 = 0;
const IRQ_CLOSING: u8 = 1;
const IRQ_JOINED: u8 = 2;
struct IrqEpoch {
    line: u32,
    state: AtomicU8,
    pending: AtomicBool,
    active: AtomicUsize,
}
/// One original service notification epoch. Native callbacks retain this exact
/// endpoint instead of rediscovering the current epoch from a numeric line.
#[derive(Clone)]
pub struct IrqEvent {
    epoch: Arc<IrqEpoch>,
    raised: RaisedWork,
}
impl IrqEvent {
    pub fn raise(&self) -> Result<(), WorkError> {
        if self.epoch.state.load(Ordering::Acquire) != IRQ_OPEN {
            return Err(WorkError::Closed);
        }
        self.epoch.pending.store(true, Ordering::Release);
        if self.epoch.state.load(Ordering::Acquire) != IRQ_OPEN {
            return Err(WorkError::Closed);
        }
        self.raised.raise()
    }
    /// Prevent new old-epoch service entries. This alone proves no hardware,
    /// callback, thread or DMA retirement; those owners must join separately.
    pub fn begin_close(&self) {
        let _ = self.epoch.state.compare_exchange(
            IRQ_OPEN,
            IRQ_CLOSING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

/// A task to bind and run, in the box its job owns.
struct Job<const N: usize> {
    environment: *const Environment<N>,
    body: Callback,
    context: *mut c_void,
}

#[derive(Clone, Copy)]
enum TaskKind {
    Owner,
    Service,
    Worker(WorkerKind),
}
#[repr(C)]
struct WorkerCall {
    owner: *const RawOwner,
    kind: u32,
}
unsafe extern "C" fn worker(context: *mut c_void) {
    // SAFETY: start_worker transferred this box to this callback.
    let mut call = unsafe { Box::from_raw(context.cast::<WorkerCall>()) };
    // SAFETY: the environment keeps owner and call through every suspension.
    unsafe { stela_linux_worker_main((&raw mut *call).cast()) };
}

const DEFERRED_CAPACITY: usize = 32;
#[derive(Clone, Copy)]
struct Deferred {
    body: Callback,
    context: *mut c_void,
}
struct DeferredQueue {
    entries: [Option<Deferred>; DEFERRED_CAPACITY],
    head: usize,
    len: usize,
}

pub struct Environment<const N: usize> {
    owner: *const RawOwner,
    runtime: NonNull<Runtime<N>>,
    domain: Arc<Domain<N>>,
    raised: RaisedWork,
    lines: UnsafeCell<[Option<Arc<IrqEpoch>>; LINES as usize]>,
    active_irq: UnsafeCell<Option<Arc<IrqEpoch>>>,
    /// The batch the service task is delivering.
    batch: UnsafeCell<Option<Batch>>,
    stopping: AtomicBool,
    service_started: AtomicBool,
    deferred: UnsafeCell<DeferredQueue>,
    /// One per continuation that ran a task, as a continuation keeps its
    /// binding across jobs. Only tasks of this CPU touch it, between switches.
    bindings: UnsafeCell<Vec<Arc<TaskBinding<N>>>>,
    /// Every task not yet seen finished. Touched as `bindings` is.
    tickets: UnsafeCell<Vec<(Ticket, TaskKind)>>,
    _pin: PhantomPinned,
}

impl<const N: usize> Environment<N> {
    /// Attach to `runtime`, whose domain's clock must be the owner's `now_ns`.
    ///
    /// # Safety
    /// On the runtime's CPU, in its dispatcher. `owner` is entered by the
    /// tasks here, and it and `runtime` outlive them; the result stays alive
    /// until [`Self::retire`]. Other producers explicitly requesting Linux-size
    /// General stacks must honor this environment's two-per-pool headroom;
    /// default ordinary work in the native mixed profile uses different stacks.
    pub unsafe fn new(
        owner: *const RawOwner,
        runtime: Pin<&Runtime<N>>,
        domain: Arc<Domain<N>>,
    ) -> Result<Pin<Box<Self>>, WorkError> {
        // Four reserved pool continuations (two per nice class), plus at
        // least one owner/dedicated continuation. Smaller profiles refuse
        // rather than silently promising workqueue progress they cannot supply.
        if runtime.general_capacity(super::task::stack_requirement()?)? < 5 {
            return Err(WorkError::Unavailable);
        }
        unsafe extern "C" {
            fn stela_linux_kernel_environment(owner: *const RawOwner) -> i32;
        }
        // SAFETY: caller owns the original resident RawOwner; this only records
        // cold bootstrap and rejects a second canonical Environment before effects.
        if unsafe { stela_linux_kernel_environment(owner) } != 0 {
            return Err(WorkError::Unavailable);
        }
        runtime.attach_service_domain(domain.clone())?;
        Ok(Box::pin(Self {
            owner,
            runtime: NonNull::from(runtime.get_ref()),
            raised: domain.raised_work()?,
            domain,
            lines: UnsafeCell::new(core::array::from_fn(|_| None)),
            active_irq: UnsafeCell::new(None),
            batch: UnsafeCell::new(None),
            stopping: AtomicBool::new(false),
            service_started: AtomicBool::new(false),
            deferred: UnsafeCell::new(DeferredQueue {
                entries: [None; DEFERRED_CAPACITY],
                head: 0,
                len: 0,
            }),
            bindings: UnsafeCell::new(Vec::new()),
            tickets: UnsafeCell::new(Vec::new()),
            _pin: PhantomPinned,
        }))
    }

    fn runtime(&self) -> Pin<&Runtime<N>> {
        // SAFETY: `new`'s caller keeps the pinned runtime.
        unsafe { Pin::new_unchecked(self.runtime.as_ref()) }
    }

    /// Start the service task. Interrupts raised before it runs wait for it.
    pub fn start(self: Pin<&Self>) -> Result<(), WorkError> {
        let context = core::ptr::from_ref(self.get_ref()).cast_mut().cast();
        // SAFETY: `new`'s caller keeps `self` until the task has finished.
        let ticket = unsafe { self.runtime().start_service(service::<N>, context) }?;
        // SAFETY: tasks of this CPU, and nothing here switches.
        unsafe { &mut *self.tickets.get() }.push((ticket, TaskKind::Service));
        self.service_started.store(true, Ordering::Release);
        Ok(())
    }

    /// Whether every task has finished, which forgets the ones that have.
    pub fn finished(&self) -> Result<bool, WorkError> {
        let queue = self.runtime().get_ref().queue();
        let mut result = Ok(());
        // SAFETY: tasks of this CPU, and nothing here switches.
        let tickets = unsafe { &mut *self.tickets.get() };
        tickets.retain(|(ticket, _)| match queue.completed(*ticket) {
            Ok(completed) => !completed,
            Err(error) => {
                result = Err(error);
                true
            }
        });
        result.map(|()| tickets.is_empty())
    }

    /// Run `body` as a Linux task; it enters the owner itself.
    ///
    /// # Safety
    /// As [`TaskBinding::run_scoped`] for `body` and `context`, which stay
    /// valid until the ticket completes.
    pub unsafe fn spawn(
        self: Pin<&Self>,
        body: Callback,
        context: *mut c_void,
    ) -> Result<Ticket, WorkError> {
        // SAFETY: the public spawn contract is passed unchanged to admission.
        unsafe { self.spawn_kind(body, context, TaskKind::Owner) }
    }
    unsafe fn spawn_kind(
        self: Pin<&Self>,
        body: Callback,
        context: *mut c_void,
        kind: TaskKind,
    ) -> Result<Ticket, WorkError> {
        self.finished()?;
        let requirement = super::task::stack_requirement()?;
        // Accepted live jobs include pending startups and every persistent
        // worker. Protect each pool's deficit before admitting another class.
        let mut occupied = [0usize; 2];
        // SAFETY: this CPU owns the list; no switch spans this bounded read.
        for (_, task) in unsafe { &*self.tickets.get() } {
            match task {
                TaskKind::Worker(WorkerKind::Normal) => occupied[0] += 1,
                TaskKind::Worker(WorkerKind::HighPriority) => occupied[1] += 1,
                _ => {}
            }
        }
        let deficits = [
            2usize.saturating_sub(occupied[0]),
            2usize.saturating_sub(occupied[1]),
        ];
        let headroom = match kind {
            TaskKind::Worker(WorkerKind::Normal) => deficits[1],
            TaskKind::Worker(WorkerKind::HighPriority) => deficits[0],
            _ => deficits[0] + deficits[1],
        };
        let job = Box::into_raw(Box::new(Job {
            environment: self.get_ref(),
            body,
            context,
        }));
        // SAFETY: this CPU owns the list, and no switch spans the borrowed views.
        let reusable: Vec<&dyn SwitchBinding> = unsafe { &*self.bindings.get() }
            .iter()
            .map(|binding| binding.as_ref() as &dyn SwitchBinding)
            .collect();
        // SAFETY: a box the job owns, and `new`'s caller keeps `self` until
        // every task has finished. A refused job never runs.
        let ticket = unsafe {
            self.runtime().execute_idle_general_with_headroom(
                requirement,
                task::<N>,
                job.cast(),
                &reusable,
                headroom,
            )
        }
        .inspect_err(|_| {
            // SAFETY: refused, so still this function's.
            drop(unsafe { Box::from_raw(job) });
        })?;
        // SAFETY: tasks of this CPU, and nothing here switches.
        unsafe { &mut *self.tickets.get() }.push((ticket, kind));
        Ok(ticket)
    }

    /// Start a task running Linux's workers, the owner's `start_worker`.
    pub fn start_worker(self: Pin<&Self>, kind: WorkerKind) -> Result<Ticket, WorkError> {
        let call = Box::into_raw(Box::new(WorkerCall {
            owner: self.owner,
            kind: kind as u32,
        }));
        // SAFETY: the callback owns this box; the environment retains the owner.
        unsafe { self.spawn_kind(worker, call.cast(), TaskKind::Worker(kind)) }.inspect_err(|_| {
            // SAFETY: refusal admitted no callback, so the box remains ours.
            drop(unsafe { Box::from_raw(call) });
        })
    }

    /// Queue a bounded nonblocking process callback on the retained service
    /// continuation. It consumes no General task or workqueue pool credit and
    /// never executes inline. Full leaves ownership with the caller for retry.
    ///
    /// # Safety
    /// Called on the runtime process CPU (dispatcher or task). Keep callback,
    /// context and reachable resources until delivery or environment retirement.
    /// The callback runs already entered in this environment's owner, in normal
    /// process context. It must return promptly without sleeping, switching,
    /// entering/exiting an owner, or escaping the callback scope. No allocation
    /// or borrowing of the queue spans callback execution. An error accepts none.
    pub unsafe fn defer_service(
        self: Pin<&Self>,
        body: Callback,
        context: *mut c_void,
    ) -> Result<(), WorkError> {
        // Checks the real process CPU before accessing affine queue metadata.
        self.runtime()
            .general_capacity(super::task::stack_requirement()?)?;
        if self.stopping.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        if !self.service_started.load(Ordering::Acquire) {
            return Err(WorkError::Unavailable);
        }
        // SAFETY: same process CPU; no switch/callback while this borrow exists.
        let pending = unsafe { &mut *self.deferred.get() };
        if pending.len == DEFERRED_CAPACITY {
            return Err(WorkError::Full);
        }
        let tail = (pending.head + pending.len) % DEFERRED_CAPACITY;
        pending.entries[tail] = Some(Deferred { body, context });
        pending.len += 1;
        // RaisedWork performs bounded publication/notification, never inline
        // delivery or switching. On refusal the just-appended entry is ours.
        if let Err(error) = self.raised.raise() {
            pending.entries[tail] = None;
            pending.len -= 1;
            return Err(error);
        }
        Ok(())
    }

    /// Create one notification epoch for an original inactive IRQ action.
    /// # Safety
    /// Called on the original process CPU; the actual source/entry owner is
    /// exclusive. A prior epoch was joined, not merely masked or root-fenced.
    pub unsafe fn irq_epoch(&self, line: u32) -> Result<IrqEvent, WorkError> {
        self.runtime()
            .general_capacity(super::task::stack_requirement()?)?;
        if line >= LINES || self.stopping.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        // SAFETY: checked original process CPU, no yield/callback in this borrow.
        let slots = unsafe { &mut *self.lines.get() };
        if slots[line as usize]
            .as_ref()
            .is_some_and(|old| old.state.load(Ordering::Acquire) != IRQ_JOINED)
        {
            return Err(WorkError::Busy);
        }
        let epoch = Arc::new(IrqEpoch {
            line,
            state: AtomicU8::new(IRQ_OPEN),
            pending: AtomicBool::new(false),
            active: AtomicUsize::new(0),
        });
        slots[line as usize] = Some(epoch.clone());
        Ok(IrqEvent {
            epoch,
            raised: self.raised.clone(),
        })
    }
    /// Join/cancel old queued primary service only after real native root/CPU
    /// retirement and C action-thread joining. No entered permit spans a wait.
    /// # Safety
    /// This is the original source/event and its producers cannot resume;
    /// actual source mask/action-close and CPU/inflight/EOI join already completed.
    /// C primary callbacks cannot sleep; an active callback here would mean
    /// reentrant free_irq and is refused instead of pretending to wait itself.
    pub unsafe fn join_irq(&self, event: &IrqEvent) -> Result<(), WorkError> {
        self.runtime()
            .general_capacity(super::task::stack_requirement()?)?;
        // SAFETY: original process CPU, no switch while reading this table.
        let slots = unsafe { &*self.lines.get() };
        let epoch = slots
            .get(event.epoch.line as usize)
            .and_then(Option::as_ref)
            .ok_or(WorkError::InvalidTicket)?;
        if !Arc::ptr_eq(epoch, &event.epoch) {
            return Err(WorkError::InvalidTicket);
        }
        let state = epoch.state.load(Ordering::Acquire);
        if state != IRQ_CLOSING && state != IRQ_JOINED {
            return Err(WorkError::Pending);
        }
        if epoch.active.load(Ordering::Acquire) != 0 {
            return Err(WorkError::WouldDeadlock);
        }
        epoch.pending.store(false, Ordering::Release);
        epoch.state.store(IRQ_JOINED, Ordering::Release);
        Ok(())
    }
    /// Ask the service task to finish.
    pub fn stop(&self) -> Result<(), WorkError> {
        self.stopping.store(true, Ordering::Release);
        self.raised.raise()
    }

    /// This continuation's binding.
    fn binding(&self) -> Result<Arc<TaskBinding<N>>, WorkError> {
        let runtime = self.runtime();
        let id = runtime.get_ref().queue().current_id()?;
        // SAFETY: tasks of this CPU, and nothing here switches.
        let bindings = unsafe { &mut *self.bindings.get() };
        for binding in bindings.iter() {
            if binding.context_id()? == id {
                return Ok(binding.clone());
            }
        }
        // SAFETY: process context on the runtime's CPU, before entering Linux.
        let binding = unsafe { TaskBinding::new() }?;
        binding.bind_current(runtime)?;
        bindings.push(binding.clone());
        Ok(binding)
    }

    /// Release what the tasks held.
    ///
    /// # Safety
    /// [`Self::stop`] was called and [`Self::finished`] answered true, with
    /// nothing left to raise a line. On the runtime's CPU, in its dispatcher.
    pub unsafe fn retire(self: Pin<&Self>) -> Result<(), WorkError> {
        // SAFETY: the caller proves the process CPU and completed service.
        if unsafe { (*self.deferred.get()).len } != 0 {
            return Err(WorkError::Pending);
        }
        // SAFETY: the caller's contract; no timer or producer remains.
        unsafe { self.domain.retire() }?;
        // SAFETY: as above, so no task is using the list.
        for binding in unsafe { &mut *self.bindings.get() }.drain(..) {
            // SAFETY: the task on that continuation has finished.
            drop(unsafe { self.runtime().detach_binding(binding.context_id()?) }?);
            // SAFETY: detached, and no job or waker still uses it.
            if unsafe { binding.release_quiescent() }.is_err() {
                return Err(WorkError::Busy);
            }
        }
        Ok(())
    }
}

/// # Safety
/// `context` is the environment a task here was started with.
unsafe fn environment<'a, const N: usize>(context: *mut c_void) -> &'a Environment<N> {
    // SAFETY: the caller's contract; `new`'s caller keeps it through the task.
    unsafe { &*context.cast() }
}

// A failure on these paths means the work runtime's bookkeeping no longer
// matches its tasks. They run below C frames, so they stop rather than unwind.

unsafe extern "C" fn begin<const N: usize>(context: *mut c_void) -> bool {
    // SAFETY: the service call's context.
    let this = unsafe { environment::<N>(context) };
    let batch = this.domain.begin(this.runtime()).expect("a service batch");
    let due = batch.is_some();
    // SAFETY: only the service task touches the batch.
    unsafe { *this.batch.get() = batch };
    due
}

unsafe extern "C" fn next_irq<const N: usize>(context: *mut c_void) -> c_int {
    // SAFETY: the service call's context.
    let this = unsafe { environment::<N>(context) };
    // SAFETY: this one original service task owns the table cursor/active slot.
    let active = unsafe { &mut *this.active_irq.get() };
    assert!(
        active.is_none(),
        "previous IRQ service body did not complete"
    );
    // SAFETY: same service CPU; process table mutations cannot interleave here.
    for epoch in unsafe { &*this.lines.get() }.iter().flatten() {
        if epoch.state.load(Ordering::Acquire) != IRQ_OPEN
            || !epoch.pending.swap(false, Ordering::AcqRel)
        {
            continue;
        }
        epoch.active.fetch_add(1, Ordering::AcqRel);
        *active = Some(epoch.clone());
        return epoch.line as c_int;
    }
    -1
}

unsafe extern "C" fn complete_irq<const N: usize>(context: *mut c_void) {
    // SAFETY: this original service call remains entered through primary return.
    let this = unsafe { environment::<N>(context) };
    // SAFETY: only the same service task owns this active epoch reference.
    let epoch = unsafe { &mut *this.active_irq.get() }
        .take()
        .expect("active original IRQ service body");
    assert_eq!(epoch.active.fetch_sub(1, Ordering::AcqRel), 1);
}

unsafe extern "C" fn drain<const N: usize>(context: *mut c_void) {
    // SAFETY: the service call retains this environment through the callback.
    let this = unsafe { environment::<N>(context) };
    // Bound one batch even if a callback posts more leaves. Requeues retain a
    // raised epoch for the next original service pass.
    for _ in 0..DEFERRED_CAPACITY {
        let next = {
            // SAFETY: only this process CPU mutates this affine queue; the
            // borrow ends before invoking any foreign callback.
            let pending = unsafe { &mut *this.deferred.get() };
            if pending.len == 0 {
                None
            } else {
                let head = pending.head;
                pending.head = (head + 1) % DEFERRED_CAPACITY;
                pending.len -= 1;
                pending.entries[head].take()
            }
        };
        let Some(next) = next else {
            break;
        };
        // SAFETY: defer_service retained the nonblocking leaf/code/context.
        // C owns the entered process callback guard, never an IRQ scope.
        unsafe { (next.body)(next.context) };
    }
}

unsafe extern "C" fn finish<const N: usize>(context: *mut c_void, deadline: i64) {
    // SAFETY: the service call's context.
    let this = unsafe { environment::<N>(context) };
    // SAFETY: only the service task touches the batch.
    let batch = unsafe { &mut *this.batch.get() }.take().expect("a batch");
    let deadline = (deadline != i64::MAX).then_some(deadline as u64);
    // SAFETY: this task ran the batch's lines and expired timers, and the
    // deadline is the earliest timer still pending.
    unsafe { this.domain.finish(this.runtime(), batch, deadline) }.expect("a finished batch");
}

unsafe extern "C" fn done<const N: usize>(context: *mut c_void) -> bool {
    // SAFETY: the service call's context.
    let this = unsafe { environment::<N>(context) };
    this.stopping.load(Ordering::Acquire)
}

unsafe extern "C" fn service<const N: usize>(context: *mut c_void) {
    // SAFETY: `start`'s context.
    let this = unsafe { environment::<N>(context) };
    let runtime = this.runtime();
    let binding = this.binding().expect("a service task");
    this.domain
        .bind_current(runtime)
        .expect("the service's domain");
    let mut call = Call {
        owner: this.owner,
        context,
        begin: begin::<N>,
        next_irq: next_irq::<N>,
        complete_irq: complete_irq::<N>,
        drain: drain::<N>,
        finish: finish::<N>,
        done: done::<N>,
    };
    let call = (&raw mut call).cast();
    // SAFETY: the loop leaves the owner before it returns, and `call` outlives it.
    unsafe { binding.run_scoped(runtime, stela_linux_service_loop, call) }.expect("a service loop");
    this.domain.stop_producers().expect("stopped producers");
}

unsafe extern "C" fn task<const N: usize>(context: *mut c_void) {
    // SAFETY: `spawn` gave this job the box.
    let job = unsafe { Box::from_raw(context.cast::<Job<N>>()) };
    // SAFETY: `spawn`'s caller keeps the environment through the job.
    let this = unsafe { &*job.environment };
    let binding = this.binding().expect("a task");
    // SAFETY: `spawn`'s caller's contract for the body.
    unsafe { binding.run_scoped(this.runtime(), job.body, job.context) }.expect("a task's body");
}
