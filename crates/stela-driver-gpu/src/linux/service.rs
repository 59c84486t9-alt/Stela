//! The tasks of a Linux environment on a work [`Runtime`]: the service task
//! that takes the place of Linux's interrupts and tick, and the tasks its
//! workqueues and owner run on. All of them share one CPU and take turns, which
//! is the uniprocessor, non-preemptible execution Linux's code is built for.
//!
//! An interrupt only records its line ([`Environment::raise`]); the handlers
//! run on the service task, which sleeps until a line is raised or the next
//! timer is due (`compat/linux/kernel/service.c`).
use super::{owner::RawOwner, task::TaskBinding};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    ffi::{c_int, c_void},
    marker::PhantomPinned,
    pin::Pin,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use stela_driver_base::platform::work::{
    Callback, Kind, Runtime, Ticket, WorkError,
    service::{Batch, Domain, RaisedWork},
};

/// `struct stela_linux_service_call`.
#[repr(C)]
struct Call {
    owner: *const RawOwner,
    context: *mut c_void,
    begin: unsafe extern "C" fn(*mut c_void) -> bool,
    next_irq: unsafe extern "C" fn(*mut c_void) -> c_int,
    finish: unsafe extern "C" fn(*mut c_void, i64),
    done: unsafe extern "C" fn(*mut c_void) -> bool,
}

unsafe extern "C" {
    fn stela_linux_service_loop(call: *mut c_void);
    fn stela_linux_worker_main(owner: *mut c_void);
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

/// The lines raised and not yet served.
struct Lines([AtomicU64; LINES as usize / 64]);

impl Lines {
    fn raise(&self, line: u32) {
        self.0[line as usize / 64].fetch_or(1 << (line % 64), Ordering::Release);
    }

    fn take(&self) -> Option<u32> {
        self.0.iter().zip(0..).find_map(|(word, index)| {
            let bits = word.load(Ordering::Acquire);
            (bits != 0).then(|| {
                let bit = bits.trailing_zeros();
                word.fetch_and(!(1 << bit), Ordering::AcqRel);
                index * 64 + bit
            })
        })
    }
}

/// A task to bind and run, in the box its job owns.
struct Job<const N: usize> {
    environment: *const Environment<N>,
    body: Callback,
    context: *mut c_void,
}

pub struct Environment<const N: usize> {
    owner: *const RawOwner,
    runtime: NonNull<Runtime<N>>,
    domain: Arc<Domain<N>>,
    raised: RaisedWork,
    lines: Lines,
    /// The batch the service task is delivering.
    batch: UnsafeCell<Option<Batch>>,
    stopping: AtomicBool,
    /// One per continuation that ran a task, as a continuation keeps its
    /// binding across jobs. Only tasks of this CPU touch it, between switches.
    bindings: UnsafeCell<Vec<Arc<TaskBinding<N>>>>,
    /// Every task not yet seen finished. Touched as `bindings` is.
    tickets: UnsafeCell<Vec<Ticket>>,
    _pin: PhantomPinned,
}

impl<const N: usize> Environment<N> {
    /// Attach to `runtime`, whose domain's clock must be the owner's `now_ns`.
    ///
    /// # Safety
    /// On the runtime's CPU, in its dispatcher. `owner` is entered by the
    /// tasks here, and it and `runtime` outlive them; the result stays alive
    /// until [`Self::retire`].
    pub unsafe fn new(
        owner: *const RawOwner,
        runtime: Pin<&Runtime<N>>,
        domain: Arc<Domain<N>>,
    ) -> Result<Pin<Box<Self>>, WorkError> {
        runtime.attach_service_domain(domain.clone())?;
        Ok(Box::pin(Self {
            owner,
            runtime: NonNull::from(runtime.get_ref()),
            raised: domain.raised_work()?,
            domain,
            lines: Lines([const { AtomicU64::new(0) }; LINES as usize / 64]),
            batch: UnsafeCell::new(None),
            stopping: AtomicBool::new(false),
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
        unsafe { &mut *self.tickets.get() }.push(ticket);
        Ok(())
    }

    /// Whether every task has finished, which forgets the ones that have.
    pub fn finished(&self) -> Result<bool, WorkError> {
        let queue = self.runtime().get_ref().queue();
        let mut result = Ok(());
        // SAFETY: tasks of this CPU, and nothing here switches.
        let tickets = unsafe { &mut *self.tickets.get() };
        tickets.retain(|ticket| match queue.completed(*ticket) {
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
        self.finished()?;
        let job = Box::into_raw(Box::new(Job {
            environment: self.get_ref(),
            body,
            context,
        }));
        let queue = self.runtime().get_ref().queue();
        // SAFETY: a box the job owns, and `new`'s caller keeps `self` until
        // every task has finished. A refused job never runs.
        let ticket =
            unsafe { queue.execute(Kind::General, task::<N>, job.cast()) }.inspect_err(|_| {
                // SAFETY: refused, so still this function's.
                drop(unsafe { Box::from_raw(job) });
            })?;
        // SAFETY: tasks of this CPU, and nothing here switches.
        unsafe { &mut *self.tickets.get() }.push(ticket);
        Ok(ticket)
    }

    /// Start a task running Linux's workers, the owner's `start_worker`.
    pub fn start_worker(self: Pin<&Self>) -> Result<Ticket, WorkError> {
        // SAFETY: the worker's body enters and leaves the owner it is given,
        // which `new`'s caller keeps.
        unsafe { self.spawn(stela_linux_worker_main, self.owner.cast_mut().cast()) }
    }

    /// Record that `line`, below [`LINES`], fired. Safe in an interrupt.
    pub fn raise(&self, line: u32) -> Result<(), WorkError> {
        self.lines.raise(line);
        self.raised.raise()
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
    this.lines.take().map_or(-1, |line| line as c_int)
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
