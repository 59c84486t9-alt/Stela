//! One scoped ownership transfer to one fixed physical AP. Erasure is private;
//! the heap-pinned job retains the actual non-'static native frame loan.
use super::*;
use stela_runtime::machine::engine::publication::{
    self, NativeFrame, NativeLoan, NativeReturned, WithPayload, WorkerOwner,
};

const IDLE: u8 = 0;
const RESERVED: u8 = 1;
const PENDING: u8 = 2;
const RUNNING: u8 = 3;
const DONE: u8 = 4;
type Invoke = unsafe fn(*mut (), &mut host::HostOwner, &mut Option<WorkerOwner>);

pub(super) struct Mailbox {
    state: AtomicU8,
    pointer: UnsafeCell<*mut ()>,
    invoke: UnsafeCell<Option<Invoke>>,
}
// SAFETY: one BSP producer owns a RESERVED/PENDING job until DONE; one fixed AP
// owns RUNNING. Release/Acquire publishes the exact pinned job and its return.
// No reader touches the other phase's non-atomic fields, and no erased pointer
// outlives Pending's heap owner or the original native frame borrow.
unsafe impl Sync for Mailbox {}
impl Mailbox {
    pub(super) const fn new() -> Self {
        Self {
            state: AtomicU8::new(IDLE),
            pointer: UnsafeCell::new(core::ptr::null_mut()),
            invoke: UnsafeCell::new(None),
        }
    }
    pub(super) fn poll(&self, host: &mut host::HostOwner, owner: &mut Option<WorkerOwner>) -> bool {
        if self.state.load(Ordering::Acquire) != PENDING {
            return false;
        }
        self.state.store(RUNNING, Ordering::Relaxed);
        // SAFETY: the producer Release-published this pinned typed job and its
        // monomorphized private callback. Only this AP consumes it, exactly once.
        unsafe {
            (*self.invoke.get()).expect("published AP job")(*self.pointer.get(), host, owner)
        };
        self.state.store(DONE, Ordering::Release);
        true
    }
}
trait Command: Send {
    type Output: Send;
    fn execute(self, host: &mut host::HostOwner, owner: &mut Option<WorkerOwner>) -> Self::Output;
}
struct Job<C: Command> {
    input: UnsafeCell<Option<C>>,
    output: UnsafeCell<Option<C::Output>>,
}
unsafe fn invoke<C: Command>(
    pointer: *mut (),
    host: &mut host::HostOwner,
    owner: &mut Option<WorkerOwner>,
) {
    // SAFETY: send<C> publishes this exact heap allocation, retained by Pending
    // until Acquire DONE. There is no concurrent access to its typed fields.
    let job = unsafe { &*(pointer as *const Job<C>) };
    let input = unsafe { (&mut *job.input.get()).take().expect("unconsumed AP job") };
    let output = input.execute(host, owner);
    unsafe { *job.output.get() = Some(output) };
}
struct Pending<C: Command> {
    mailbox: &'static Mailbox,
    job: Box<Job<C>>,
    started: u64,
    timeout: u64,
    slot: usize,
    collected: bool,
    _bsp: core::marker::PhantomData<*mut ()>,
}
impl<C: Command> Pending<C> {
    fn complete(&mut self) {
        while self.mailbox.state.load(Ordering::Acquire) != DONE {
            if apic::rdtsc().wrapping_sub(self.started) >= self.timeout {
                crate::output::arguments(format_args!(
                    "STELA FATAL native worker {} missed actual frame return; retaining all borrowed resources\n",
                    self.slot
                ));
                // A timeout is not quiescence. Never unwind/free guest frames,
                // services, descriptors, stack or this job while the AP can run.
                loop {
                    unsafe {
                        asm!("cli", "hlt", options(nomem, nostack));
                    }
                }
            }
            core::hint::spin_loop();
        }
    }
    fn finish(mut self) -> C::Output {
        self.complete();
        // SAFETY: Acquire DONE follows all AP accesses; the callback has ended.
        let output = unsafe {
            (&mut *self.job.output.get())
                .take()
                .expect("actual AP return")
        };
        self.collected = true;
        self.mailbox.state.store(IDLE, Ordering::Release);
        output
    }
}
impl<C: Command> Drop for Pending<C> {
    fn drop(&mut self) {
        if !self.collected {
            self.complete();
            // The actual returned payload is still owned by this job. Dropping
            // it never tells WorkerPublications that the CPU was recovered.
            self.mailbox.state.store(IDLE, Ordering::Release);
        }
    }
}
impl Processor {
    fn send<C: Command>(&self, command: C, sender: &Apic, tsc_hz: u64) -> Result<Pending<C>, C> {
        let mailbox = &self.argument.mailbox;
        if tsc_hz == 0
            || tsc_hz > u64::MAX / 10
            || self.argument.status.load(Ordering::Acquire) != READY
            || mailbox
                .state
                .compare_exchange(IDLE, RESERVED, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(command);
        }
        let mut job = Box::new(Job {
            input: UnsafeCell::new(Some(command)),
            output: UnsafeCell::new(None),
        });
        let pointer = (&mut *job as *mut Job<C>).cast();
        // SAFETY: sole RESERVED producer; no AP reads until Release PENDING.
        unsafe {
            *mailbox.pointer.get() = pointer;
            *mailbox.invoke.get() = Some(invoke::<C>);
        }
        let pending = Pending {
            mailbox,
            job,
            started: apic::rdtsc(),
            timeout: tsc_hz * 10,
            slot: self.slot,
            collected: false,
            _bsp: core::marker::PhantomData,
        };
        mailbox.state.store(PENDING, Ordering::Release);
        // SAFETY: the selected AP's descriptors/GS and vector0x60 are online.
        // A delivery failure cannot return borrowed ownership: pending waits
        // for actual completion or stops permanently retaining all resources.
        let delivered = unsafe {
            sender.notify(
                self.apic_id() as u32,
                interrupts::NATIVE_WAKE_VECTOR,
                tsc_hz,
            )
        };
        if let Err(error) = delivered {
            crate::output::arguments(format_args!(
                "NATIVE notification slot={} error={error:?}; waiting for actual return\n",
                self.slot
            ));
        }
        Ok(pending)
    }
    pub(crate) fn initialize(
        &self,
        owner: WorkerOwner,
        sender: &Apic,
        tsc_hz: u64,
    ) -> Result<publication::InitialPublication, &'static str> {
        let command = Initial {
            owner,
            apic: self.apic_id() as u32,
        };
        self.send(command, sender, tsc_hz)
            .map_err(|_| "native initialization transport busy")?
            .finish()
    }
    /// # Safety
    /// The BSP must retain every original frame/service borrow until finish or
    /// Drop has observed the actual AP return. It must not forget/leak Pending
    /// and then reuse those borrowed resources, migrate, or release their stack.
    /// The blocking outer execution scope owns this obligation; no 'static
    /// native payload, copied CPU snapshot or numeric ACK can replace it.
    pub(crate) unsafe fn submit<T: NativeFrame>(
        &self,
        loan: NativeLoan<T>,
        sender: &Apic,
        tsc_hz: u64,
    ) -> Result<NativePending<T>, NativeLoan<T>> {
        self.send(Run { loan }, sender, tsc_hz)
            .map(|pending| NativePending { pending })
            .map_err(|command| command.loan)
    }
    pub(crate) fn invalidate(
        &self,
        command: publication::NativeStopCommand,
        sender: &Apic,
        tsc_hz: u64,
    ) -> Result<publication::NativeStopReceipt, WithPayload<publication::NativeStopCommand>> {
        match self.send(Invalidate { command }, sender, tsc_hz) {
            Ok(pending) => pending.finish(),
            Err(command) => Err(WithPayload {
                error: publication::PublicationError::StopBusy,
                payload: command.command,
            }),
        }
    }
    pub(crate) fn release(
        &self,
        command: publication::WorkerRelease,
        sender: &Apic,
        tsc_hz: u64,
    ) -> Result<publication::ReleaseReceipt, WithPayload<publication::WorkerRelease>> {
        match self.send(Release { command }, sender, tsc_hz) {
            Ok(pending) => pending.finish(),
            Err(command) => Err(WithPayload {
                error: publication::PublicationError::StopBusy,
                payload: command.command,
            }),
        }
    }
}
pub(crate) struct NativePending<T: NativeFrame> {
    pending: Pending<Run<T>>,
}
impl<T: NativeFrame> NativePending<T> {
    pub(crate) fn finish(self) -> Result<NativeReturned<T::Returned>, WithPayload<NativeLoan<T>>> {
        self.pending.finish()
    }
}
struct Initial {
    owner: WorkerOwner,
    apic: u32,
}
impl Command for Initial {
    type Output = Result<publication::InitialPublication, &'static str>;
    fn execute(
        mut self,
        host: &mut host::HostOwner,
        owner: &mut Option<WorkerOwner>,
    ) -> Self::Output {
        if owner.is_some() {
            return Err("native worker already initialized");
        }
        host.bind_worker(self.owner.binding().worker, self.apic)?;
        let published = self
            .owner
            .publish_initial(&mut host.host())
            .map_err(|_| "native initial publication refused")?;
        *owner = Some(self.owner);
        Ok(published)
    }
}
struct Run<T: NativeFrame> {
    loan: NativeLoan<T>,
}
impl<T: NativeFrame> Command for Run<T> {
    type Output = Result<NativeReturned<T::Returned>, WithPayload<NativeLoan<T>>>;
    fn execute(self, host: &mut host::HostOwner, owner: &mut Option<WorkerOwner>) -> Self::Output {
        let Some(owner) = owner else {
            return Err(WithPayload {
                error: publication::PublicationError::NotInitialized,
                payload: self.loan,
            });
        };
        owner.execute(self.loan, &mut host.host())
    }
}
struct Invalidate {
    command: publication::NativeStopCommand,
}
impl Command for Invalidate {
    type Output =
        Result<publication::NativeStopReceipt, WithPayload<publication::NativeStopCommand>>;
    fn execute(self, host: &mut host::HostOwner, owner: &mut Option<WorkerOwner>) -> Self::Output {
        let Some(owner) = owner else {
            return Err(WithPayload {
                error: publication::PublicationError::NotInitialized,
                payload: self.command,
            });
        };
        owner.invalidate(self.command, &mut host.host())
    }
}
struct Release {
    command: publication::WorkerRelease,
}
impl Command for Release {
    type Output = Result<publication::ReleaseReceipt, WithPayload<publication::WorkerRelease>>;
    fn execute(self, _: &mut host::HostOwner, owner: &mut Option<WorkerOwner>) -> Self::Output {
        let Some(owner) = owner else {
            return Err(WithPayload {
                error: publication::PublicationError::NotInitialized,
                payload: self.command,
            });
        };
        owner.release(self.command)
    }
}
