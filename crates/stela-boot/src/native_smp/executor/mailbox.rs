//! One scoped ownership transfer to one fixed physical AP. Erasure is private;
//! the heap-pinned job keeps the non-'static native frame loan.
use super::*;
use crate::Result;
use stela_contracts::refuse;
use stela_engine::machine::engine::publication;
use stela_engine::machine::engine::publication::NativeFrame;
use stela_engine::machine::engine::publication::NativeLoan;
use stela_engine::machine::engine::publication::NativeReturned;
use stela_engine::machine::engine::publication::WithPayload;
use stela_engine::machine::engine::publication::WorkerOwner;

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
    // SAFETY: send<C> publishes this exact heap allocation, kept by Pending
    // until Acquire DONE. There is no concurrent access to its typed fields.
    let job = unsafe { &*(pointer as *const Job<C>) };
    // SAFETY: the job is this AP's alone until it publishes DONE, so nothing else reaches `input`.
    let input = unsafe { (&mut *job.input.get()).take().expect("unconsumed AP job") };
    let output = input.execute(host, owner);
    // SAFETY: nothing else reaches `output` until this AP publishes DONE.
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
                    // SAFETY: halts this AP with maskable interrupts off; it touches no memory.
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
            // The returned payload is still owned by this job. Dropping
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
        // for completion or stops permanently keeping all resources.
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
        ram: alloc::sync::Arc<stela_engine::memory::RegisteredSystemRam>,
        sender: &Apic,
        tsc_hz: u64,
    ) -> Result<publication::InitialPublication> {
        let command = Initial {
            owner,
            apic: self.apic_id() as u32,
            ram,
        };
        self.send(command, sender, tsc_hz)
            .map_err(|_| refuse!("native initialization transport busy"))?
            .finish()
    }
    /// # Safety
    /// The BSP must keep every original frame/service borrow until finish or
    /// Drop has observed the AP return. It must not forget/leak Pending
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
    pub(crate) fn host_effect(
        &self,
        command: publication::HostEffectCommand,
        sender: &Apic,
        tsc_hz: u64,
    ) -> Result<publication::HostEffectReceipt, WithPayload<publication::HostEffectCommand>> {
        match self.send(Effect { command }, sender, tsc_hz) {
            Ok(pending) => pending.finish(),
            Err(command) => Err(WithPayload {
                error: publication::PublicationError::StopBusy,
                payload: command.command,
            }),
        }
    }
}
impl Processor {
    /// Hand this AP work that runs for the rest of the boot on its own Host.
    /// Its mailbox stays busy, and nothing collects the job: the work owns
    /// everything it reaches.
    pub(crate) fn spawn(
        &self,
        work: Box<dyn FnOnce(&mut host::HostOwner) + Send>,
        sender: &Apic,
        tsc_hz: u64,
    ) -> Result<()> {
        let pending = self
            .send(Spawned(work), sender, tsc_hz)
            .map_err(|_| refuse!("AP mailbox busy"))?;
        // Its drop would wait for a return that never comes; the leaked job
        // stays where the AP reads it.
        core::mem::forget(pending);
        Ok(())
    }
}
struct Spawned(Box<dyn FnOnce(&mut host::HostOwner) + Send>);
impl Command for Spawned {
    type Output = ();
    fn execute(self, host: &mut host::HostOwner, _: &mut Option<WorkerOwner>) {
        (self.0)(host);
    }
}
struct Effect {
    command: publication::HostEffectCommand,
}
impl Command for Effect {
    type Output =
        Result<publication::HostEffectReceipt, WithPayload<publication::HostEffectCommand>>;
    fn execute(self, host: &mut host::HostOwner, owner: &mut Option<WorkerOwner>) -> Self::Output {
        match owner {
            Some(owner) => owner.apply_host_effect(self.command, &mut host.host()),
            None => Err(WithPayload {
                error: publication::PublicationError::NotInitialized,
                payload: self.command,
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
    ram: alloc::sync::Arc<stela_engine::memory::RegisteredSystemRam>,
}
impl Command for Initial {
    type Output = Result<publication::InitialPublication>;
    fn execute(
        mut self,
        host: &mut host::HostOwner,
        owner: &mut Option<WorkerOwner>,
    ) -> Self::Output {
        if owner.is_some() {
            return Err(refuse!("native worker already initialized"));
        }
        // Check the same physical bytes in this AP's MMU and
        // cache controls before its owner publishes any runtime admission.
        for (_, physical, bytes) in self.ram.placements() {
            let cpu = crate::layout::physical(physical);
            // SAFETY: fixed pristine AP owner; the caller keeps the canonical
            // reservation and its complete closed all-writer contract.
            unsafe { crate::native_memory::qualify_reserved_writeback(cpu, physical, bytes) }
                .map_err(|_| refuse!("AP canonical RAM effective cache type refused"))?;
        }
        // SAFETY: same canonical owner, no raw guest dispatch/DMA;
        // this pristine physical Host remains pinned through all later loans.
        unsafe { host.register_system_ram(self.ram) }?;
        host.bind_worker(self.owner.binding().worker, self.apic)?;
        let published = self
            .owner
            .publish_initial(&mut host.host())
            .map_err(|_| refuse!("native initial publication refused"))?;
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
