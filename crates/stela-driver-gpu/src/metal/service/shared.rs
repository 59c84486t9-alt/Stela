//! [`Service`] for every PE at once, as the call gate's [`GateService`].
//!
//! The device is one Vulkan device with one state, so calls take turns under
//! a lock. A PE waiting its turn runs the platform's `relax`, since the call
//! it waits for may need that PE: on the CPU that runs the kernel, waiting
//! without running it would never end. Each call runs through the platform's
//! `run`, as a compile needs more stack than a PE keeps; the lock makes one
//! such stack enough for a device.
//!
//! The gate asks about completed work under the board's lock, where a Vulkan
//! call would hold up every PE, so [`GateService::signaled`] only reads a
//! flag. The platform reports each GPU interrupt ([`SharedService::interrupted`]);
//! whoever next holds the service looks at the device for what completed.
//!
//! A `Poll` that finds another call holding the service is answered with the
//! newest serial a holder saw completed, rather than waiting out a commit or
//! a compile: the completion interrupt that wakes a frontend's poll is raised
//! only once a holder has seen that serial, so the answer covers it. Only a
//! connection whose poll the service itself answered is answered this way,
//! and never once the device is lost.
//!
//! The platform's waiter on the device's completion timeline may publish a
//! completed serial itself ([`SharedService::completed_through`]), without a
//! turn, when every host-visible memory type is coherent: completion then
//! needs no invalidation before the CPU reads what the GPU wrote. The next
//! holder looks at the device before its call, so what it answers agrees.
//!
//! A pipeline creation or commit whose compilation the compiler's cache
//! misses runs that compilation outside the lock, on a stack of its own
//! ([`SharedService::set_compile_stack`]), then runs again: the compiler
//! defers the compilation and the call fails without writing to its caller;
//! the compilation runs under the compiler's own lock, which only AIR
//! compilations take; its NIR enters the cache under the turn and the call's
//! next run finds it. Other calls are served meanwhile. Only immutable
//! inputs cross: the libraries' bytes, which the compilation holds, and the
//! driver's NIR options. No Vulkan object is used outside the turn, so the
//! device's externally synchronized objects (its queue, command pools and
//! the pipeline caches it creates pipelines with) keep the turn as their
//! one owner.
use super::{
    Service,
    wire::{self, GateCall, Operation, Status},
};
use crate::metal::{
    compiler::{self, AirCompiler, CompileLock},
    shader::Compiler,
    timing::CallPhases,
    vulkan::{MemoryProperties, backend::Backend},
};
use alloc::sync::Arc;
use core::{
    any::Any,
    cell::UnsafeCell,
    mem::size_of,
    num::NonZeroU64,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use stela_contracts::gate::{BundleReport, CallerFault, CallerMemory, GateService, MemoryRange};

pub struct SharedService<B: Backend, C: Compiler> {
    service: UnsafeCell<Service<B, C>>,
    locked: AtomicBool,
    /// The GPU interrupted since the device was last asked.
    stale: AtomicBool,
    /// Completed work the gate has not taken.
    completed: AtomicBool,
    /// The newest serial a holder saw completed, or POLL_UNAVAILABLE.
    reached: AtomicU64,
    /// Connections whose `Poll` the service answered, zero for a free slot:
    /// those a busy service answers from `reached`.
    polling: [AtomicU64; POLLING],
    /// Submissions not yet seen complete, with when each was submitted;
    /// only a turn's holder touches it.
    pending: UnsafeCell<Pending>,
    /// Since [`SharedService::take_latency`]: submissions seen complete,
    /// the ticks from submission until a holder saw each complete, and the
    /// longest of those.
    latency: [AtomicU64; 3],
    /// The completion timelines handed to the platform, one per device: a
    /// waiter publishes for the newest only.
    timeline: AtomicU64,
    /// The newest serial a holder saw submitted, past which nothing is
    /// published.
    submitted: AtomicU64,
    /// Whether a waiter may publish completions without a turn: no
    /// host-visible memory needs an invalidation.
    publishable: AtomicBool,
    /// When a serial was published without a turn, by serial modulo
    /// [`PENDING`]: the serial and the tick.
    early: [(AtomicU64, AtomicU64); PENDING],
    /// The stack compilations outside the lock run on, zero for none, and
    /// the compiler's lock they take.
    compile_stack: AtomicU64,
    compile_lock: Option<Arc<CompileLock>>,
    host: ServiceHost,
}

/// The most times one call runs again for a compilation outside the lock;
/// past it, the call compiles in its turn.
const DEFERRALS: u32 = 8;

/// The newest submissions, as a ring of serial and submission tick.
struct Pending {
    submitted: u64,
    ring: [(u64, u64); PENDING],
    head: usize,
    len: usize,
}

/// More submissions than are in flight at once; older ones go uncounted.
const PENDING: usize = 64;

/// More connections than a device's gates open.
const POLLING: usize = 64;
/// A lost device or this serial must use the normal poll path.
const POLL_UNAVAILABLE: u64 = u64::MAX;

/// What the platform does for the shared service.
#[derive(Clone, Copy)]
pub struct ServiceHost {
    /// Waits a moment for the turn's holder.
    pub relax: fn(),
    /// What `run` takes first: this service's stack.
    pub stack: u64,
    /// Calls its argument on a stack a compile fits on. Only a turn's holder
    /// comes here.
    pub run: fn(u64, &mut dyn FnMut()),
    /// Told why the service refused a guest's call.
    pub report: fn(&str),
    /// Told what a guest's call made, such as a render pipeline's stages and
    /// vertex fetch.
    pub note: fn(&str),
    /// The platform's tick counter, which times [`Served`].
    pub ticks: fn() -> u64,
    /// Told of each guest call the gate served.
    pub served: fn(Served),
    /// Asks the platform to call [`SharedService::interrupted`] again soon,
    /// outside this turn: a turn held the service when the GPU interrupted.
    pub wake: fn(),
    /// Told what the kext found of the Metal plugin, which the platform's
    /// boot decides on: the plugin is the boot's.
    pub bundle: fn(BundleReport),
}

/// A guest call the gate served, in the platform's ticks: the PE that rang
/// for it runs no guest code from the doorbell until the call returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Served {
    /// The call's operation code, zero when its record was out of reach.
    pub operation: u32,
    pub status: Status,
    /// Waiting for the turn another call held.
    pub waited: u64,
    /// Holding the turn, the look at completed work after the call included.
    pub held: u64,
    /// The serials of the last command buffer submitted and the last seen
    /// complete after the call, when it held the service.
    pub progress: Option<(u64, u64)>,
    /// Where the call's time went, for the operations timed by phase.
    pub phases: Option<CallPhases>,
    /// Compiling outside the lock for the call, which its other calls'
    /// turns were served meanwhile, and how many compilations that was.
    pub compiled: u64,
    pub deferrals: u32,
    /// The longest one of the call's waits for a turn.
    pub longest_wait: u64,
}

// SAFETY: the lock gives one PE at a time the service, which `Send` lets move
// between them.
unsafe impl<B: Backend + Send, C: Compiler + Send> Sync for SharedService<B, C> {}
// SAFETY: every field is, given the bounds.
unsafe impl<B: Backend + Send, C: Compiler + Send> Send for SharedService<B, C> {}

/// A turn at the service.
/// The service held, and whether a look in this turn found work completed.
pub(super) struct Turn<'a, B: Backend, C: Compiler>(&'a SharedService<B, C>, bool);

impl<B: Backend, C: Compiler> Deref for Turn<'_, B, C> {
    type Target = Service<B, C>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: this turn holds the lock.
        unsafe { &*self.0.service.get() }
    }
}

impl<B: Backend, C: Compiler> DerefMut for Turn<'_, B, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: this turn holds the lock.
        unsafe { &mut *self.0.service.get() }
    }
}

impl<B: Backend, C: Compiler> Turn<'_, B, C> {
    /// Asks the device what completed for the interrupt that raised `stale`.
    /// The turn's drop publishes what it found.
    fn look(&mut self) {
        self.0.stale.store(false, Ordering::SeqCst);
        let mut completed = false;
        // Polling enters Vulkan too. An interrupt can take this path without
        // a guest call's stack switch around it.
        (self.0.host.run)(self.0.host.stack, &mut || completed = (**self).signaled());
        self.1 |= completed;
    }
}

impl<B: Backend, C: Compiler> Turn<'_, B, C> {
    /// Looks at the device when a waiter published past what it last saw,
    /// so the call's answers agree with the completion the guest was told.
    fn catch_up(&mut self) {
        let shown = self.0.reached.load(Ordering::Acquire);
        let device = self.device();
        if shown != POLL_UNAVAILABLE && !device.is_lost() && shown > device.completed_serial() {
            self.look();
        }
    }

    /// Notes when submissions through `submitted` were made and how long
    /// those through `reached` took to be seen complete.
    fn time_submissions(&self, submitted: u64, reached: u64) {
        // SAFETY: this turn holds the lock, which owns `pending`.
        let pending = unsafe { &mut *self.0.pending.get() };
        let due = pending.len != 0 && pending.ring[pending.head].0 <= reached;
        if pending.submitted >= submitted && !due {
            return;
        }
        let now = (self.0.host.ticks)();
        while pending.submitted < submitted {
            pending.submitted += 1;
            let at = (pending.head + pending.len) % PENDING;
            pending.ring[at] = (pending.submitted, now);
            if pending.len == PENDING {
                pending.head = (pending.head + 1) % PENDING;
            } else {
                pending.len += 1;
            }
        }
        while pending.len != 0 && pending.ring[pending.head].0 <= reached {
            let (serial, at) = pending.ring[pending.head];
            // Seen when a waiter published it, if one did first.
            let (published, when) = &self.0.early[serial as usize % PENDING];
            let seen = if published.load(Ordering::Acquire) == serial {
                when.load(Ordering::Relaxed).min(now)
            } else {
                now
            };
            let took = seen.wrapping_sub(at);
            pending.head = (pending.head + 1) % PENDING;
            pending.len -= 1;
            self.0.latency[0].fetch_add(1, Ordering::Relaxed);
            self.0.latency[1].fetch_add(took, Ordering::Relaxed);
            self.0.latency[2].fetch_max(took, Ordering::Relaxed);
        }
    }
}

impl<B: Backend, C: Compiler> Drop for Turn<'_, B, C> {
    fn drop(&mut self) {
        // A lost device answers without entering the driver.
        let mut completed = self.1;
        if self.device().is_lost() {
            (self.0.host.run)(self.0.host.stack, &mut || completed |= (**self).signaled());
        }
        let device = self.device();
        let submitted = device.submitted_serial();
        let serial = device.completed_serial();
        // While some connection's work is held or completes on the late
        // timeline, completion differs by connection: the service answers
        // each poll, and no waiter publishes the timeline's value.
        let lost = device.is_lost();
        let reached = if lost || device.holds() {
            POLL_UNAVAILABLE
        } else {
            serial
        };
        self.time_submissions(submitted, if lost { reached } else { serial });
        self.0.submitted.store(submitted, Ordering::Release);
        // Publish one snapshot before making the completion observable. A
        // waiter may have published past what this holder saw; a lost device
        // answers no poll, and its replacement starts again.
        let shown = self.0.reached.load(Ordering::Acquire);
        if reached == POLL_UNAVAILABLE || shown == POLL_UNAVAILABLE || shown > submitted {
            self.0.reached.store(reached, Ordering::Release);
        } else {
            self.0.reached.fetch_max(reached, Ordering::AcqRel);
        }
        if completed || self.retiring() {
            self.0.completed.store(true, Ordering::Release);
        }
        self.0.locked.store(false, Ordering::SeqCst);
        // An interrupt this turn kept from looking is the platform's to look
        // at again: a guest call's processor would wait for the boot
        // processor to answer the query on its behalf.
        if self.0.stale.load(Ordering::SeqCst) {
            (self.0.host.wake)();
        }
    }
}

impl<B: Backend, C: Compiler + 'static> SharedService<B, C> {
    pub fn new(mut service: Service<B, C>, host: ServiceHost) -> Self {
        service.device().set_clock(host.ticks);
        // Completion needs no invalidation when every host-visible memory
        // type is coherent.
        let publishable = service
            .device()
            .backend()
            .physical_device()
            .memory
            .types
            .iter()
            .all(|kind| {
                !kind.properties.contains(MemoryProperties::HOST_VISIBLE)
                    || kind.properties.contains(MemoryProperties::HOST_COHERENT)
            });
        // The AIR compiler keeps what it reflects and compiles for the boot,
        // and compiles outside the lock once the platform gives a stack.
        let compile_lock = air(service.device().compiler_mut()).map(|compiler| {
            compiler.keep_compilations(compiler::NIR_BUDGET);
            // A warm boot deserializes the NIR the pipeline store kept.
            #[cfg(feature = "metal-vulkan")]
            {
                use crate::metal::native::pipeline_store;
                compiler.persist(pipeline_store::stored_nir(), pipeline_store::add_nir);
            }
            compiler.compile_lock(host.relax)
        });
        Self {
            service: UnsafeCell::new(service),
            locked: AtomicBool::new(false),
            stale: AtomicBool::new(false),
            completed: AtomicBool::new(false),
            reached: AtomicU64::new(0),
            polling: [const { AtomicU64::new(0) }; POLLING],
            pending: UnsafeCell::new(Pending {
                submitted: 0,
                ring: [(0, 0); PENDING],
                head: 0,
                len: 0,
            }),
            latency: [const { AtomicU64::new(0) }; 3],
            timeline: AtomicU64::new(0),
            submitted: AtomicU64::new(0),
            publishable: AtomicBool::new(publishable),
            early: [const { (AtomicU64::new(0), AtomicU64::new(0)) }; PENDING],
            compile_stack: AtomicU64::new(0),
            compile_lock,
            host,
        }
    }

    /// Runs pipeline compilations the compiler's cache misses on `stack`, a
    /// stack as deep as the service's own, outside the lock.
    pub fn set_compile_stack(&self, stack: u64) {
        self.compile_stack.store(stack, Ordering::Release);
    }

    /// The compiler's counts, unless a call holds the service now.
    pub fn compiler_report(&self) -> Option<alloc::string::String> {
        let mut turn = self.try_turn()?;
        air(turn.device().compiler_mut()).map(|compiler| compiler.report())
    }

    /// A descriptor of the device's completion timeline, once per device,
    /// unless a call holds the service now, with the timeline's generation
    /// for [`Self::completed_through`]: the platform waits on it to look
    /// for completed work as soon as some completes.
    pub fn take_completion(&self) -> Option<(i32, u64)> {
        let fd = self
            .try_turn()
            .and_then(|mut turn| turn.device().take_completion())?;
        Some((fd, self.timeline.fetch_add(1, Ordering::AcqRel) + 1))
    }

    /// The platform's waiter saw the completion timeline of generation
    /// `timeline` reach `value`, every serial through it complete. Published
    /// at once when a waiter may publish, so a call holding the service
    /// delays no frame; the platform still looks at the device
    /// ([`Self::interrupted`]) once a turn is free.
    pub fn completed_through(&self, timeline: u64, value: u64) {
        if timeline == self.timeline.load(Ordering::Acquire)
            && self.publishable.load(Ordering::Acquire)
        {
            let value = value.min(self.submitted.load(Ordering::Acquire));
            let mut shown = self.reached.load(Ordering::Acquire);
            while shown != POLL_UNAVAILABLE && shown < value {
                match self.reached.compare_exchange_weak(
                    shown,
                    value,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        let now = (self.host.ticks)();
                        // The newest PENDING serials are those timed.
                        for serial in shown.max(value.saturating_sub(PENDING as u64)) + 1..=value {
                            let (published, when) = &self.early[serial as usize % PENDING];
                            when.store(now, Ordering::Relaxed);
                            published.store(serial, Ordering::Release);
                        }
                        self.completed.store(true, Ordering::Release);
                        break;
                    }
                    Err(now) => shown = now,
                }
            }
        }
        // The look itself is the platform's, outside the waiter's context
        // (`interrupted`): it enters the driver.
        self.stale.store(true, Ordering::SeqCst);
    }

    /// Submissions seen complete since the last call, the ticks from their
    /// submission until a holder saw them complete, and the longest of those.
    pub fn take_latency(&self) -> (u64, u64, u64) {
        (
            self.latency[0].swap(0, Ordering::Relaxed),
            self.latency[1].swap(0, Ordering::Relaxed),
            self.latency[2].swap(0, Ordering::Relaxed),
        )
    }

    fn polls(&self, connection: NonZeroU64) -> bool {
        self.polling
            .iter()
            .any(|slot| slot.load(Ordering::Acquire) == connection.get())
    }

    /// Answers `connection`'s `Poll` at `record` from `reached`, or leaves
    /// the call to the service: any other operation or record, a connection
    /// the service never answered a poll for, a lost device, or a span out
    /// of the caller's reach.
    pub(super) fn poll_while_held(
        &self,
        connection: NonZeroU64,
        record: u64,
        caller: &mut dyn CallerMemory,
    ) -> bool {
        let mut raw = [0; size_of::<GateCall>()];
        if caller.read(record, &mut raw).is_err() {
            return false;
        }
        let mut call: GateCall = wire::read(&raw).expect("a record of its own size");
        let (request_bytes, response_bytes) = Operation::Poll.sizes();
        if call.operation != Operation::Poll.raw()
            || call.request.length != request_bytes as u64
            || call.response.length != response_bytes as u64
        {
            return false;
        }
        let reached = self.reached.load(Ordering::Acquire);
        // Check membership after acquiring the serial. A close that
        // precedes its publication has already removed that connection.
        if reached == POLL_UNAVAILABLE || !self.polls(connection) {
            return false;
        }
        let value = wire::Value { value: reached };
        let mut response = [0; size_of::<wire::Value>()];
        wire::write(&value, &mut response).expect("a record of its own size");
        if caller.write(call.response.address, &response).is_err() {
            return false;
        }
        call.status = Status::Ok.raw();
        call.reason_length = 0;
        wire::write(&call, &mut raw).expect("a record of its own size");
        caller.write(record, &raw).is_ok()
    }

    /// Whether the call at `record` creates a pipeline or commits commands,
    /// whose compilations may run outside the lock: nothing it does before
    /// compiling stays. A commit's replay compiles the variants its draws
    /// and dispatches need, and its command buffer is discarded when it
    /// defers one; once replay changes an indirect command buffer, it
    /// compiles in its turn ([`Compiler::stop_deferring`]).
    fn compiles(&self, record: u64, caller: &mut dyn CallerMemory) -> bool {
        let mut raw = [0; size_of::<GateCall>()];
        if caller.read(record, &mut raw).is_err() {
            return false;
        }
        let call: GateCall = wire::read(&raw).expect("a record of its own size");
        [
            Operation::NewRenderPipeline,
            Operation::NewMeshPipeline,
            Operation::NewComputePipeline,
            Operation::NewTilePipeline,
            Operation::Commit,
        ]
        .iter()
        .any(|operation| operation.raw() == call.operation)
    }

    pub(super) fn try_turn(&self) -> Option<Turn<'_, B, C>> {
        (!self.locked.swap(true, Ordering::SeqCst)).then(|| Turn(self, false))
    }

    fn turn(&self) -> Turn<'_, B, C> {
        loop {
            if let Some(turn) = self.try_turn() {
                return turn;
            }
            (self.host.relax)();
        }
    }

    /// Runs `call` on the service in a turn of its own.
    fn call<R>(&self, call: impl FnOnce(&mut Service<B, C>) -> R) -> R {
        let mut turn = self.turn();
        turn.catch_up();
        let (mut call, mut result) = (Some(call), None);
        (self.host.run)(self.host.stack, &mut || {
            if let Some(call) = call.take() {
                result = Some(call(&mut turn));
            }
        });
        result.expect("the platform runs what it is given")
    }

    /// What the service holds, unless a call holds it now: a report never
    /// waits for the service.
    pub fn memory(&self) -> Option<super::MemoryReport> {
        self.try_turn().map(|turn| turn.memory())
    }

    /// Where retired command buffers' time went since the last call, unless
    /// a call holds the service now; it is then counted for the next.
    pub fn gpu_times(&self) -> Option<crate::metal::device::gpu_times::GpuTimes> {
        self.try_turn()
            .map(|mut turn| turn.device().take_gpu_times())
    }

    /// The GPU interrupted: look for what completed now or, while a call
    /// holds the service, once it leaves.
    pub fn interrupted(&self) {
        self.stale.store(true, Ordering::SeqCst);
        if let Some(mut turn) = self.try_turn() {
            turn.look();
        }
    }

    /// Closes admission while holding the same turn as guest calls, so a
    /// call either precedes closure or observes it.
    pub fn begin_quiesce(&self) {
        self.call(|service| service.begin_quiesce());
    }

    /// Advances the native owner's GPU stop protocol on the service stack.
    /// An idle answer does not disconnect the gate or invalidate DMA maps.
    pub fn quiesce_step(&self) -> crate::metal::device::lifecycle::QuiesceStatus {
        self.call(|service| service.quiesce_step())
    }
}

impl<B: Backend + Send, C: Compiler + Send + 'static> GateService for SharedService<B, C> {
    fn connect(&self) -> Result<NonZeroU64, &'static str> {
        self.call(|service| service.connect()).map_err(|fault| {
            (self.host.report)(&alloc::format!("{fault} in a connection"));
            fault.reason
        })
    }

    fn disconnect(&self, connection: NonZeroU64) {
        // The gate closes only connections it opened and holds.
        let closed = self.call(|service| {
            for slot in &self.polling {
                let _ =
                    slot.compare_exchange(connection.get(), 0, Ordering::AcqRel, Ordering::Acquire);
            }
            service.disconnect(connection)
        });
        debug_assert!(closed.is_ok());
    }

    fn serve(
        &self,
        connection: NonZeroU64,
        record: u64,
        caller: &mut dyn CallerMemory,
    ) -> Result<(), CallerFault> {
        let rang = (self.host.ticks)();
        let mut turn = match self.try_turn() {
            Some(turn) => turn,
            None if self.poll_while_held(connection, record, caller) => {
                let left = (self.host.ticks)();
                (self.host.served)(Served {
                    operation: Operation::Poll.raw(),
                    status: Status::Ok,
                    waited: 0,
                    held: left.wrapping_sub(rang),
                    progress: None,
                    phases: None,
                    compiled: 0,
                    deferrals: 0,
                    longest_wait: 0,
                });
                return Ok(());
            }
            None => self.turn(),
        };
        let mut entered = (self.host.ticks)();
        let (mut waited, mut held, mut compiled, mut deferrals) =
            (entered.wrapping_sub(rang), 0, 0, 0);
        let mut longest_wait = waited;
        let compile_stack = self.compile_stack.load(Ordering::Acquire);
        let offloads = compile_stack != 0 && self.compiles(record, caller);
        // What runs the deferral ended reported, which their reports keep.
        let mut carried = alloc::vec::Vec::new();
        let (served, mut refused, noted, (operation, status)) = loop {
            turn.catch_up();
            let deferring = offloads && deferrals < DEFERRALS;
            if let Some(compiler) = air(turn.device().compiler_mut()) {
                compiler.set_deferring(deferring);
            }
            let mut answer = None;
            (self.host.run)(self.host.stack, &mut || {
                let mut deferrable = Deferrable {
                    caller: &mut *caller,
                    lock: self.compile_lock.as_deref().filter(|_| deferring),
                };
                let served = turn.serve(connection, record, &mut deferrable);
                answer = Some((
                    served,
                    core::mem::take(&mut turn.refused),
                    turn.noted.take(),
                    turn.served,
                ));
            });
            let answer = answer.expect("the platform runs what it is given");
            let job = air(turn.device().compiler_mut()).and_then(AirCompiler::take_deferred);
            let (Some(job), Some(lock)) = (job, self.compile_lock.as_deref()) else {
                break answer;
            };
            // The call left nothing but the compilation: it runs again with
            // the compiled shader, outside of which the turn is free.
            let _ = turn.device().take_phases();
            let left = (self.host.ticks)();
            held += left.wrapping_sub(entered);
            deferrals += 1;
            drop(turn);
            let mut finished = None;
            let mut job = Some(job);
            // Every PE defers onto the one compile stack: the lock is held
            // before the switch and until the job is off it.
            let held = lock.hold(self.host.relax);
            (self.host.run)(compile_stack, &mut || {
                if let Some(job) = job.take() {
                    finished = Some(job.run_outside(&held));
                }
            });
            drop(held);
            let ready = (self.host.ticks)();
            compiled += ready.wrapping_sub(left);
            turn = self.turn();
            entered = (self.host.ticks)();
            longest_wait = longest_wait.max(entered.wrapping_sub(ready));
            waited += entered.wrapping_sub(ready);
            if let (Some(compiler), Some(finished)) = (air(turn.device().compiler_mut()), finished)
            {
                compiler.adopt(finished);
            }
            // What the deferred run reported, its deferral aside, stays.
            let deferral = alloc::format!("{}", super::wire::Fault::from(compiler::DEFERRED));
            carried.extend(
                answer
                    .1
                    .into_iter()
                    .filter(|reason| !reason.contains(&deferral)),
            );
        };
        carried.append(&mut refused);
        let refused = carried;
        if let Some(compiler) = air(turn.device().compiler_mut()) {
            compiler.end_call();
        }
        if served.is_ok()
            && operation == Operation::Poll.raw()
            && status == Status::Ok
            && !self.polls(connection)
        {
            // The turn serializes enrollment with other polls and close.
            let _ = self.polling.iter().find(|slot| {
                slot.compare_exchange(0, connection.get(), Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            });
        }
        let progress = turn.device().progress();
        let phases = turn.device().take_phases();
        drop(turn);
        let left = (self.host.ticks)();
        (self.host.served)(Served {
            operation,
            status,
            waited,
            held: held + left.wrapping_sub(entered),
            progress: Some(progress),
            phases,
            compiled,
            deferrals,
            longest_wait,
        });
        for reason in &refused {
            (self.host.report)(reason);
        }
        if let Some(text) = noted {
            (self.host.note)(&text);
        }
        served
    }

    fn import(
        &self,
        connection: NonZeroU64,
        ranges: &[MemoryRange],
        token: NonZeroU64,
    ) -> Result<NonZeroU64, &'static str> {
        self.call(|service| service.import(connection, ranges, token))
            .map_err(|fault| {
                let bytes: u64 = ranges.iter().map(|range| range.bytes).sum();
                (self.host.report)(&alloc::format!(
                    "{fault} in an import of {} ranges, {bytes} bytes",
                    ranges.len()
                ));
                fault.reason
            })
    }

    fn retired(&self) -> Option<NonZeroU64> {
        self.call(|service| service.retired())
    }

    fn quiesced(&self) -> bool {
        self.call(|service| service.quiesced())
    }

    fn signaled(&self) -> bool {
        self.completed.swap(false, Ordering::Acquire)
    }

    fn bundle(&self, report: BundleReport) {
        (self.host.bundle)(report);
    }

    fn dropped(&self, reason: &'static str) {
        (self.host.report)(reason);
    }
}

/// The device's compiler, when it is the AIR compiler, whose compilations
/// can run outside the lock.
fn air<C: Compiler + 'static>(compiler: &mut C) -> Option<&mut AirCompiler> {
    (compiler as &mut dyn Any).downcast_mut::<AirCompiler>()
}

/// The caller's memory for a run that may defer a compilation: once one is
/// deferred, the run's writes, which only answer the deferral, are dropped,
/// as the call runs again.
struct Deferrable<'a> {
    caller: &'a mut dyn CallerMemory,
    lock: Option<&'a CompileLock>,
}

impl CallerMemory for Deferrable<'_> {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), CallerFault> {
        self.caller.read(address, buffer)
    }

    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), CallerFault> {
        if self.lock.is_some_and(CompileLock::deferred) {
            return Ok(());
        }
        self.caller.write(address, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::{
        device::fixture::{MockBackend, device_on},
        service::identity::DeviceEpoch,
    };

    const HOST: ServiceHost = ServiceHost {
        relax: || panic!("nothing waits"),
        stack: 0x4000,
        run: |_, call| call(),
        report: |_| {},
        note: |_| {},
        ticks: || 7,
        served: |_| {},
        wake: || {},
        bundle: |_| {},
    };

    fn shared() -> SharedService<MockBackend, crate::metal::device::fixture::MockCompiler> {
        let service = Service::new(
            device_on(MockBackend::new()),
            DeviceEpoch::from_registered(NonZeroU64::MIN),
        );
        SharedService::new(service, HOST)
    }

    #[test]
    fn a_waiter_publishes_completion_while_a_call_holds_the_service() {
        let shared = shared();
        shared.publishable.store(true, Ordering::Release);
        shared.submitted.store(3, Ordering::Release);
        let timeline = shared.timeline.fetch_add(1, Ordering::AcqRel) + 1;
        let held = shared.try_turn().unwrap();
        // Another timeline's waiter, and one past what was submitted.
        shared.completed_through(timeline + 1, 2);
        assert!(!shared.signaled());
        shared.completed_through(timeline, 5);
        assert!(shared.signaled());
        assert_eq!(shared.reached.load(Ordering::Acquire), 3);
        assert_eq!(shared.early[3].0.load(Ordering::Acquire), 3);
        // An older point publishes nothing more.
        shared.completed_through(timeline, 2);
        assert!(!shared.signaled());
        assert!(shared.stale.load(Ordering::Acquire));
        drop(held);
    }

    #[test]
    fn without_coherent_memory_completion_waits_for_a_turn() {
        let shared = shared();
        shared.publishable.store(false, Ordering::Release);
        shared.submitted.store(3, Ordering::Release);
        let timeline = shared.timeline.fetch_add(1, Ordering::AcqRel) + 1;
        let held = shared.try_turn().unwrap();
        shared.completed_through(timeline, 3);
        assert!(!shared.signaled());
        assert_eq!(shared.reached.load(Ordering::Acquire), 0);
        drop(held);
    }

    #[test]
    fn a_deferred_run_writes_nothing_to_its_caller() {
        struct Writes(u32);
        impl CallerMemory for Writes {
            fn read(&mut self, _: u64, _: &mut [u8]) -> Result<(), CallerFault> {
                Ok(())
            }
            fn write(&mut self, _: u64, _: &[u8]) -> Result<(), CallerFault> {
                self.0 += 1;
                Ok(())
            }
        }
        let lock = CompileLock::new_for_tests();
        let mut writes = Writes(0);
        let mut deferrable = Deferrable {
            caller: &mut writes,
            lock: Some(&lock),
        };
        deferrable.write(0, &[1]).unwrap();
        lock.set_deferred_for_tests(true);
        deferrable.write(0, &[1]).unwrap();
        assert_eq!(writes.0, 1);
    }
}
