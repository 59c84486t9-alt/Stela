//! The guest's threads: each is one host thread running its own engine (PE
//! registers, block cache and native code arena) over the process's shared
//! memory and identity stage 1, as the threads of a task share its map.
//!
//! The engine performs a store-exclusive as a check of its own PE's monitor
//! followed by a plain copy, so two engines executing at once could both
//! pass an LDXR/STXR pair and lose an update. Guest code therefore runs
//! under one [`ExecutionLock`]: one thread executes translated code at a
//! time, which orders every guest memory effect totally, a valid execution
//! of the Arm memory model. A thread gives the lock up at each exception it
//! takes to the kernel (the hosted kernel's services run concurrently with
//! other threads' guest code, as XNU's do), in a WFE or WFI wait and at the
//! end of a time slice another thread waits for. As at the engine's own PE
//! switch, a thread that resumes after another ran has lost its exclusive
//! reservation, and a thread preempted inside a registered restartable
//! range resumes at its recovery address (XNU `thread_reset_pcs_in_range`).
//!
//! Guest memory the hosted kernel maps, unmaps or rewrites drops compiled
//! blocks in the calling thread's engine at once and, through the
//! [`Registry`], in every other engine before it next executes guest code.
//! Process exit closes the execution lock for good and wakes the host
//! thread waiting in [`Lifetime::wait`]; the host process's exit then ends
//! every thread.
use super::{
    Termination,
    host::ProcessHost,
    kernel::{End, Kernel, Pe, Process, control::Control, signals},
    pe,
    tables::Tables,
};
use crate::hosted::darwin::THREAD_SELF_TRAP;
use crate::hosted::unsupported::{self, Failure, Kind};
use crate::machine::engine::RequirementKind;
use crate::machine::{Chip, CpuProfile, Machine, NoDevices, Stop, system::Register};
use anyhow::{Context as _, Result, anyhow, bail};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        mpsc,
    },
};
use stela_compiler::TargetCpu;

#[cfg(feature = "native-profile")]
mod profile_output;
mod statistics;
use statistics::Statistics;

/// Blocks a thread runs before it yields the execution lock to a waiting
/// thread: the engine's own PE time slice (`processors::QUANTUM`).
pub(super) const SLICE_BLOCKS: u64 = 1 << 14;
/// How long, in counter ticks, the engine waits in a WFE or WFI before it
/// returns to the thread's loop, which then gives the execution lock up.
const WAIT_LIMIT_TICKS: u64 = 1;
/// The host stack of a thread running an engine: the engine and the hosted
/// kernel run on it, never guest code.
const HOST_STACK_BYTES: usize = 16 << 20;
/// `thread_self_trap`: the calling host thread's port, with a new user
/// reference.
const MACH_PORT_DEALLOCATE_TRAP: u32 = 18;
/// The code an IC IVAU makes stale in a machine: its whole fetch page.
const CODE_PAGE: u64 = 4096;

/// Lock a process mutex. A thread that panicked while holding one leaves
/// state the kernel personality cannot trust, but the process is ending
/// with that failure already, so its last value serves the report.
pub(super) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What builds one thread's engine: every PE of the process has the same
/// chip, identification, translation tables, PAC keys and user JOP state.
pub(super) struct Engine {
    pub(super) chip: Chip,
    pub(super) profile: CpuProfile,
    pub(super) target: TargetCpu,
    pub(super) tables: Arc<Tables>,
    pub(super) keys: pe::Keys,
    pub(super) jop: pe::UserJop,
    #[cfg(feature = "native-profile")]
    pub(super) profile_output: Option<std::path::PathBuf>,
    #[cfg(feature = "native-profile")]
    pub(super) sample_floating_point: bool,
}

impl Engine {
    /// A PE at EL0t entering at `pc`, with the hosted vectors as host
    /// breakpoints and waits returned to the thread's loop.
    pub(super) fn machine(&self, pc: u64) -> Result<Box<Pe>> {
        let cpu = pe::user_thread(self.chip, pc, &self.tables, &self.keys, self.jop);
        let host = ProcessHost::new(self.tables.clone())?;
        let mut machine = Box::new(Machine::new(
            cpu,
            host,
            NoDevices,
            self.profile.clone(),
            self.target,
        ));
        machine.set_breakpoints(&pe::vectors());
        machine.set_wait_limit(Some(WAIT_LIMIT_TICKS));
        // One process's threads read one clock: no thread's slow slices
        // hold its counter behind the others'.
        machine.follow_host_counter();
        Ok(machine)
    }
}

/// FIFO ownership of guest execution. `closed` is set once the process
/// ends: no thread executes guest code after it.
#[derive(Default)]
struct LockState {
    next_ticket: u64,
    serving: u64,
    holder: Option<u64>,
    /// The thread that held the lock last, to tell a resuming thread
    /// whether another ran since.
    last: Option<u64>,
    closed: bool,
}

#[derive(Default)]
pub(super) struct ExecutionLock {
    state: Mutex<LockState>,
    turn: Condvar,
    waiting: AtomicU32,
}

impl ExecutionLock {
    /// Wait for the lock in arrival order. True when another thread held
    /// it since `thread` last did. Never returns once the process ended.
    fn acquire(&self, thread: u64) -> bool {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let mut state = lock(&self.state);
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        while state.closed || state.serving != ticket {
            state = self
                .turn
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        self.waiting.fetch_sub(1, Ordering::SeqCst);
        state.holder = Some(thread);
        state.last != Some(thread)
    }

    fn release(&self, thread: u64) {
        let mut state = lock(&self.state);
        debug_assert_eq!(state.holder, Some(thread));
        state.holder = None;
        state.last = Some(thread);
        state.serving += 1;
        drop(state);
        self.turn.notify_all();
    }

    /// Whether a thread waits for the lock.
    fn contended(&self) -> bool {
        self.waiting.load(Ordering::SeqCst) != 0
    }

    /// Take the lock (unless `thread` holds it) and close it for good:
    /// false when another thread closed it first, whose end is the
    /// process's.
    fn close(&self, thread: u64) -> bool {
        let mut state = lock(&self.state);
        if state.holder != Some(thread) {
            self.waiting.fetch_add(1, Ordering::SeqCst);
            let ticket = state.next_ticket;
            state.next_ticket += 1;
            while !state.closed && state.serving != ticket {
                state = self
                    .turn
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            if state.closed {
                return false;
            }
            state.holder = Some(thread);
        }
        if state.closed {
            return false;
        }
        state.closed = true;
        drop(state);
        self.turn.notify_all();
        true
    }
}

/// One live guest thread as the other threads see it.
pub(super) struct Member {
    /// Its port name, the host thread's (a fork child's thread has its
    /// own).
    port: AtomicU32,
    /// Guest ranges whose compiled blocks it must drop before it next
    /// executes guest code.
    stale: Mutex<Vec<(u64, u64)>>,
    has_stale: AtomicBool,
    /// Its suspension and published user state.
    control: Arc<Control>,
}

/// The registry identifier of the main thread, the first one spawned.
pub(super) const MAIN_THREAD: u64 = 0;

/// The process's live threads.
#[derive(Default)]
pub(super) struct Registry {
    members: Mutex<BTreeMap<u64, Arc<Member>>>,
    next_id: AtomicU64,
}

impl Registry {
    fn insert(&self, port: u32) -> (u64, Arc<Member>) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let member = Arc::new(Member {
            port: AtomicU32::new(port),
            stale: Mutex::new(Vec::new()),
            has_stale: AtomicBool::new(false),
            control: Arc::default(),
        });
        lock(&self.members).insert(id, member.clone());
        (id, member)
    }

    /// Remove the thread `id`: whether it was the last.
    fn remove(&self, id: u64) -> bool {
        let mut members = lock(&self.members);
        members.remove(&id);
        members.is_empty()
    }

    /// The thread ports of the process's threads, in creation order.
    pub(super) fn ports(&self) -> Vec<u32> {
        lock(&self.members)
            .values()
            .map(|member| member.port.load(Ordering::SeqCst))
            .collect()
    }

    /// The control of the thread `id`.
    pub(super) fn control(&self, id: u64) -> Option<Arc<Control>> {
        lock(&self.members)
            .get(&id)
            .map(|member| member.control.clone())
    }

    /// The control of the thread whose port is `port`.
    pub(super) fn control_by_port(&self, port: u32) -> Option<Arc<Control>> {
        lock(&self.members)
            .values()
            .find(|member| member.port.load(Ordering::SeqCst) == port)
            .map(|member| member.control.clone())
    }

    /// The process ended: wake every parked thread for good and interrupt
    /// the host calls of those in one.
    fn close(&self) {
        let members: Vec<(u32, Arc<Control>)> = lock(&self.members)
            .values()
            .map(|member| (member.port.load(Ordering::SeqCst), member.control.clone()))
            .collect();
        for (_, control) in &members {
            control.close();
        }
        for (port, control) in &members {
            control.interrupt(*port);
        }
    }

    /// Whether `port` names one of the process's threads.
    pub(super) fn contains_port(&self, port: u32) -> bool {
        lock(&self.members)
            .values()
            .any(|member| member.port.load(Ordering::SeqCst) == port)
    }

    /// Record a range the hosted kernel changed for every thread but
    /// `from`, whose own engine it already invalidated.
    pub(super) fn invalidate(&self, from: u64, address: u64, bytes: u64) {
        for (&id, member) in lock(&self.members).iter() {
            if id != from {
                lock(&member.stale).push((address, bytes));
                member.has_stale.store(true, Ordering::SeqCst);
            }
        }
    }
}

/// How the process ends: kept for the main thread when the main thread
/// ends it, which takes it when its guest thread ends. Any other thread
/// carries the end out itself, as does every thread once no host thread
/// waits (a fork child, or after the main thread ended alone): the main
/// thread may be blocked in a host call that nothing will complete, and
/// the kernel ends a process whichever of its threads exits.
#[derive(Default)]
pub(super) struct Lifetime {
    end: Mutex<Ending>,
}

#[derive(Default)]
pub(super) struct Ending {
    outcome: Option<Result<Termination>>,
    /// No host thread waits in [`Lifetime::leave`].
    unwaited: bool,
    /// The host thread that will take the end in [`Lifetime::leave`].
    waiter: Option<libc::pthread_t>,
}

impl Ending {
    /// Whether the calling thread ends the host process itself rather
    /// than leave the end to the waiting thread.
    fn ends_here(&self) -> bool {
        // SAFETY: thread identities of this process, compared.
        self.unwaited
            || self.waiter.is_some_and(
                |waiter| unsafe { libc::pthread_equal(waiter, libc::pthread_self()) } == 0,
            )
    }
}

impl Lifetime {
    /// The calling host thread will take the end in [`Lifetime::leave`].
    fn wait_here(&self) {
        // SAFETY: the calling thread's identity.
        lock(&self.end).waiter = Some(unsafe { libc::pthread_self() });
    }

    fn end(&self, outcome: Result<Termination>) {
        let mut end = lock(&self.end);
        if end.ends_here() {
            drop(end);
            // The host process ends as the command's would.
            match outcome {
                Ok(termination) => termination.end_host_process(),
                Err(error) => {
                    super::translations::finish();
                    eprintln!("error: {error:#}");
                    std::process::exit(1)
                }
            }
        }
        if end.outcome.is_none() {
            end.outcome = Some(outcome);
        }
    }

    /// The process's end, if a guest thread ended it. Otherwise the host
    /// thread asking no longer waits for it, and the thread that ends it
    /// ends the host process itself.
    pub(super) fn leave(&self) -> Option<Result<Termination>> {
        let mut end = lock(&self.end);
        let outcome = end.outcome.take();
        if outcome.is_none() {
            end.unwaited = true;
        }
        outcome
    }
}

/// The threads of one process.
#[derive(Default)]
pub(super) struct Runtime {
    pub(super) execution: ExecutionLock,
    pub(super) registry: Registry,
    pub(super) lifetime: Lifetime,
    /// The engine statistics of every thread that ended.
    statistics: Mutex<Statistics>,
}

/// Take `mutex` if no other thread holds it.
pub(super) fn try_lock<T>(mutex: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match mutex.try_lock() {
        Ok(guard) => Some(guard),
        Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

/// The runtime's locks, held across a host `fork` so that the child's one
/// thread finds none of them held by a thread it does not have.
pub(super) struct ForkHeld<'a> {
    execution: MutexGuard<'a, LockState>,
    members: MutexGuard<'a, BTreeMap<u64, Arc<Member>>>,
    end: MutexGuard<'a, Ending>,
    _statistics: MutexGuard<'a, Statistics>,
}

impl Runtime {
    pub(super) fn new(serviced_words: bool) -> Self {
        Self {
            statistics: Mutex::new(Statistics::new(serviced_words)),
            ..Self::default()
        }
    }

    pub(super) fn statistics(&self) -> (crate::machine::Statistics, BTreeMap<u32, u64>) {
        lock(&self.statistics).snapshot()
    }

    /// The runtime's locks, or `None` while another thread holds one.
    pub(super) fn hold_for_fork(&self) -> Option<ForkHeld<'_>> {
        Some(ForkHeld {
            execution: try_lock(&self.execution.state)?,
            members: try_lock(&self.registry.members)?,
            end: try_lock(&self.lifetime.end)?,
            _statistics: try_lock(&self.statistics)?,
        })
    }

    /// In a fork child: `thread` is the process's one thread, now with the
    /// host thread port `port`, no thread holds or waits for the execution
    /// lock, and the process's end exits the host process.
    pub(super) fn fork_child(&self, held: ForkHeld<'_>, thread: u64, port: u32) {
        let ForkHeld {
            mut execution,
            mut members,
            mut end,
            _statistics,
        } = held;
        let ticket = execution.next_ticket;
        *execution = LockState {
            next_ticket: ticket,
            serving: ticket,
            ..LockState::default()
        };
        self.execution.waiting.store(0, Ordering::SeqCst);
        members.retain(|&id, _| id == thread);
        if let Some(member) = members.get(&thread) {
            member.port.store(port, Ordering::SeqCst);
        }
        // No host thread waits in the child: its end exits the host
        // process itself.
        *end = Ending {
            outcome: None,
            unwaited: true,
            waiter: None,
        };
    }
}

impl Runtime {
    /// Run `section` with no guest code executing anywhere: for changes to
    /// guest memory no thread may observe half done.
    pub(super) fn exclusive<T>(&self, thread: u64, section: impl FnOnce() -> T) -> T {
        self.execution.acquire(thread);
        let result = section();
        self.execution.release(thread);
        result
    }

    /// End the process with `outcome`: no guest code runs after it, and
    /// no thread stays parked.
    fn end(&self, thread: u64, outcome: Result<Termination>) {
        if !self.execution.close(thread) {
            return;
        }
        self.registry.close();
        self.lifetime.end(outcome);
    }

    /// End the process with the failure of one of the hosted kernel's own
    /// service threads (the workqueue's monitors).
    pub(super) fn fail(&self, error: anyhow::Error) {
        self.end(SERVICE_THREAD, Err(error));
    }
}

/// The identifier a service thread ends the process under; the registry
/// never reaches it.
const SERVICE_THREAD: u64 = u64::MAX;

/// The calling host thread's port, with a user reference for the guest.
fn own_port() -> u32 {
    super::forward::mach(THREAD_SELF_TRAP, &[]).rax as u32
}

/// Start a guest thread on a new host thread with the signal mask `mask`.
/// `prepare` runs there first, with the thread's kernel (its port already
/// its own) and its PE entering at `pc`; it sets the entry registers or
/// refuses with an errno, which ends the thread before it runs. The
/// creator waits for `prepare` and receives the new thread's port or that
/// errno. The host thread starts with every signal blocked and takes the
/// guest mask once its signal slot is registered.
pub(super) fn spawn<F>(
    process: &Arc<Process>,
    pc: u64,
    mask: u32,
    prepare: F,
) -> Result<Result<u32, u64>>
where
    F: FnOnce(&mut Kernel, &mut Pe) -> Result<Result<(), u64>> + Send + 'static,
{
    let (sender, receiver) = mpsc::channel::<Result<Result<u32, u64>>>();
    let process = process.clone();
    // Unnamed, as a new thread's `pth_name` is.
    let builder = std::thread::Builder::new().stack_size(HOST_STACK_BYTES);
    let spawned = signals::without_signals(|| {
        builder.spawn(move || enter(&process, pc, mask, prepare, sender))
    });
    if let Err(error) = spawned {
        return Ok(Err(if error.kind() == std::io::ErrorKind::OutOfMemory {
            crate::hosted::darwin::ENOMEM
        } else {
            crate::hosted::darwin::EAGAIN
        }));
    }
    receiver
        .recv()
        .map_err(|_| anyhow!("a new guest thread ended before it was prepared"))?
}

/// Run the main thread on the calling host thread, the process's first,
/// with the signal mask `mask`: the host kernel then parks a signal every
/// thread blocks on a guest thread, as XNU parks it on the main thread,
/// rather than on a host thread that runs no guest code. `prepare` is
/// [`spawn`]'s. Once the thread ends, the process's end if it ended it;
/// otherwise this host thread stops waiting for the process, which the
/// thread that ends it ends on the host itself.
pub(super) fn run_main<F>(
    process: &Arc<Process>,
    pc: u64,
    mask: u32,
    prepare: F,
) -> Result<Result<Option<Result<Termination>>, u64>>
where
    F: FnOnce(&mut Kernel, &mut Pe) -> Result<Result<(), u64>>,
{
    let (sender, receiver) = mpsc::channel::<Result<Result<u32, u64>>>();
    process.runtime.lifetime.wait_here();
    // A new process's main thread is unnamed (`pth_name`); the host
    // runtime may have named this one.
    // SAFETY: a NUL-terminated name for the calling thread.
    unsafe { libc::pthread_setname_np(c"".as_ptr()) };
    enter(process, pc, mask, prepare, sender);
    match receiver.recv() {
        Ok(Ok(Ok(_))) => {}
        Ok(Ok(Err(errno))) => return Ok(Err(errno)),
        Ok(Err(error)) => return Err(error),
        Err(_) => bail!("the main thread ended before it was prepared"),
    }
    Ok(Ok(process.runtime.lifetime.leave()))
}

/// Run a guest thread on the calling host thread: `prepare`, then the
/// thread until it ends, which may end the process. `sender` receives the
/// thread's port or the errno `prepare` refused with.
fn enter<F>(
    process: &Arc<Process>,
    pc: u64,
    mask: u32,
    prepare: F,
    sender: mpsc::Sender<Result<Result<u32, u64>>>,
) where
    F: FnOnce(&mut Kernel, &mut Pe) -> Result<Result<(), u64>>,
{
    let port = own_port();
    let (id, member) = process.runtime.registry.insert(port);
    let mut kernel = Kernel::new(process.clone(), id, port, mask);
    let prepared = process
        .engine
        .machine(pc)
        .map(|mut pe| {
            let process = Arc::downgrade(process);
            pe.host.set_peers(Box::new(move |page| {
                if let Some(process) = process.upgrade() {
                    let (address, bytes) = page.map_or((0, u64::MAX), |page| (page, CODE_PAGE));
                    process.runtime.registry.invalidate(id, address, bytes);
                }
            }));
            pe
        })
        .and_then(|mut pe| Ok((prepare(&mut kernel, &mut pe)?, pe)));
    let pe = match prepared {
        Ok((Ok(()), pe)) => {
            let _ = sender.send(Ok(Ok(port)));
            pe
        }
        Ok((Err(errno), _)) => {
            process.runtime.registry.remove(id);
            super::forward::mach(
                MACH_PORT_DEALLOCATE_TRAP,
                &[u64::from(process.task_port()), u64::from(port)],
            );
            let _ = sender.send(Ok(Err(errno)));
            return;
        }
        Err(error) => {
            process.runtime.registry.remove(id);
            let _ = sender.send(Err(error));
            return;
        }
    };
    drop(sender);
    let mut pe = pe;
    let ends = EndsControl(&member.control);
    #[cfg(not(feature = "native-profile"))]
    let outcome = run(&mut kernel, &mut pe, &member);
    #[cfg(feature = "native-profile")]
    let outcome = profile_output::execute(&mut kernel, &mut pe, &member);
    lock(&process.runtime.statistics).record(pe.statistics, || pe.exit_words());
    process.exception_ports.thread_ended(port);
    // A thread ending the process records the end while it is still a
    // member, so that no thread the end wakes counts itself the last.
    let ending = match outcome {
        Ok(None) => false,
        Ok(Some(termination)) => {
            // `proc_exit` first ends the process's asynchronous I/O.
            process.aio.exit();
            process.runtime.end(id, Ok(termination));
            true
        }
        Err(error) => {
            process.runtime.end(id, Err(error));
            true
        }
    };
    // The last thread's termination is the process's exit
    // (`thread_terminate_self`, `proc_exit`), with the status no `exit`
    // set.
    if process.runtime.registry.remove(id) && !ending {
        process.aio.exit();
        process.runtime.end(id, Ok(Termination::Exited(0)));
    }
    drop(ends);
}

/// Take the execution lock for the thread and bring its engine up to date:
/// the reservation another thread's execution may have broken, the
/// compiled blocks the hosted kernel made stale, and the host protection
/// of the MAP_JIT pages, which follows its view ([`Kernel::jit_view`]).
fn resume(
    kernel: &mut Kernel,
    member: &Member,
    pe: &mut Pe,
    #[cfg(feature = "native-profile")] profile: &mut Option<profile_output::ThreadOutput>,
) -> Result<()> {
    #[cfg(feature = "native-profile")]
    if let Some(profile) = profile {
        profile.resume(pe);
    }
    if kernel.process.runtime.execution.acquire(kernel.thread) {
        pe.cpu.monitor = None;
    }
    kernel.jit_view(pe)?;
    if member.has_stale.swap(false, Ordering::SeqCst) {
        let ranges = std::mem::take(&mut *lock(&member.stale));
        for (address, bytes) in ranges {
            pe.invalidate_code(address, bytes);
        }
        // A stale range may have become an RWX JIT page this view refuses.
        if pe.host.jit_writable() {
            pe.fetch_permissions_changed();
        }
    }
    Ok(())
}

/// A thread preempted inside a restartable range resumes at its recovery
/// address (`thread_reset_pcs_in_range`).
fn restart_ranges(process: &Process, pe: &mut Pe) {
    let ranges = lock(&process.restartable_ranges);
    let Some(ranges) = ranges.as_ref() else {
        return;
    };
    let pc = pe.cpu.pc;
    if let Some(&(location, _, recovery, _)) = ranges
        .iter()
        .find(|&&(location, length, _, _)| (location..location + u64::from(length)).contains(&pc))
    {
        pe.cpu.pc = location + u64::from(recovery);
    }
}

/// Marks the thread's control ended however its host thread leaves the
/// guest thread: after the process's end, when the thread ended it, so
/// that the thread stays active to the others until no guest code runs
/// (`exit` terminates the task's other threads before the exiting one,
/// `task_terminate_internal`; a `thread_suspend` of it until then
/// succeeds).
struct EndsControl<'a>(&'a Control);

impl Drop for EndsControl<'_> {
    fn drop(&mut self) {
        self.0.ended();
    }
}

/// Execute the thread until it ends: `Some` when it ended the process.
/// At each return to guest code the thread's control parks it while it is
/// suspended or held (`thread_suspend`, `thread_get_state`); a thread the
/// process's end wakes there ends.
fn run(
    kernel: &mut Kernel,
    pe: &mut Box<Pe>,
    member: &Member,
    #[cfg(feature = "native-profile")] profile: &mut Option<profile_output::ThreadOutput>,
) -> Result<Option<Termination>> {
    let process = kernel.process.clone();
    let thread = kernel.thread;
    let execution = &process.runtime.execution;
    let control = member.control.clone();
    if let Some(end) = kernel.begin(pe)? {
        return Ok(ended(end));
    }
    control.set_thread_pointer(pe.cpu.read(Register::TPIDRRO_EL0));
    // `PTHREAD_START_SUSPENDED` parks before the first instruction.
    if !control.leave(pe) {
        return Ok(None);
    }
    resume(
        kernel,
        member,
        pe,
        #[cfg(feature = "native-profile")]
        profile,
    )?;
    loop {
        let stop = pe.run(pe.statistics.blocks + SLICE_BLOCKS);
        #[cfg(feature = "native-profile")]
        if let Some(profile) = &mut *profile {
            profile.checkpoint(pe, false);
        }
        match stop {
            Stop::Breakpoint(pe::LOWER_SYNCHRONOUS) if kernel.jit_register(pe)? => {
                pe.return_from_exception().map_err(|status| {
                    anyhow::anyhow!("exception-return monitor/event settlement: {status:?}")
                })?;
            }
            Stop::Breakpoint(pe::LOWER_SYNCHRONOUS) => {
                execution.release(thread);
                control.enter_kernel(pe);
                kernel.blocked(true);
                kernel.synchronous(pe)?;
                kernel.blocked(false);
                match kernel.end.take() {
                    Some(End::Process(termination)) => return Ok(Some(termination)),
                    Some(End::Thread) => return Ok(None),
                    None => {}
                }
                if !control.leave(pe) {
                    return Ok(None);
                }
                resume(
                    kernel,
                    member,
                    pe,
                    #[cfg(feature = "native-profile")]
                    profile,
                )?;
                pe.return_from_exception().map_err(|status| {
                    anyhow::anyhow!("exception-return monitor/event settlement: {status:?}")
                })?;
            }
            // XNU defers an AST taken inside the commpage's
            // preemption-free zone until the zone's exit, marking X15 for
            // the zone's routine to come back through `pfz_exit`.
            Stop::Budget if crate::hosted::commpage::preemption_free(pe.cpu.pc) => {
                crate::hosted::commpage::note_time();
                pe.cpu.state.x[crate::hosted::commpage::DEFERRED_PREEMPTION_REGISTER] = 1;
            }
            Stop::Budget => {
                // The quantum's end stores the approximate time
                // (`thread_quantum_expire`).
                crate::hosted::commpage::note_time();
                if kernel.signals.deliverable().is_some() {
                    restart_ranges(&process, pe);
                    execution.release(thread);
                    if let Some(end) = deliver(kernel, pe)? {
                        return Ok(ended(end));
                    }
                    resume(
                        kernel,
                        member,
                        pe,
                        #[cfg(feature = "native-profile")]
                        profile,
                    )?;
                } else if control.pending() {
                    restart_ranges(&process, pe);
                    execution.release(thread);
                    if !control.leave(pe) {
                        return Ok(None);
                    }
                    resume(
                        kernel,
                        member,
                        pe,
                        #[cfg(feature = "native-profile")]
                        profile,
                    )?;
                } else if execution.contended() {
                    restart_ranges(&process, pe);
                    execution.release(thread);
                    resume(
                        kernel,
                        member,
                        pe,
                        #[cfg(feature = "native-profile")]
                        profile,
                    )?;
                }
            }
            Stop::Waiting => {
                execution.release(thread);
                if !control.leave(pe) {
                    return Ok(None);
                }
                std::thread::yield_now();
                if let Some(end) = deliver(kernel, pe)? {
                    return Ok(ended(end));
                }
                resume(
                    kernel,
                    member,
                    pe,
                    #[cfg(feature = "native-profile")]
                    profile,
                )?;
            }
            // An instruction the runtime does not implement: as an Apple
            // CPU's UNDEFINED encoding, EXC_BAD_INSTRUCTION at its pc.
            Stop::Unsupported(requirement)
                if requirement.el == 0
                    && matches!(
                        requirement.kind,
                        RequirementKind::Instruction { .. }
                            | RequirementKind::SystemRegister { .. }
                            | RequirementKind::SystemInstruction { .. }
                    ) =>
            {
                execution.release(thread);
                unsupported::report(
                    Kind::Instruction,
                    requirement.pc,
                    &requirement.to_string(),
                    Failure::BadInstruction,
                    None,
                )?;
                pe.cpu.pc = requirement.pc;
                kernel.bad_instruction(pe, || format!("unsupported {requirement}"))?;
                if let Some(end) = deliver(kernel, pe)? {
                    return Ok(ended(end));
                }
                resume(
                    kernel,
                    member,
                    pe,
                    #[cfg(feature = "native-profile")]
                    profile,
                )?;
            }
            Stop::Breakpoint(pc) => {
                execution.release(thread);
                bail!(
                    "the guest took an exception to EL1 vector {pc:#x} (ESR {:#x}, ELR {:#x}): \
                     only synchronous exceptions from EL0 are serviced",
                    pe.cpu.read(Register::ESR_EL1),
                    pe.cpu.read(Register::ELR_EL1)
                )
            }
            other => {
                execution.release(thread);
                bail!("the guest PE stopped at pc {:#x}: {other:?}", pe.cpu.pc)
            }
        }
    }
}

/// At a time-slice stop or a wait, outside the execution lock: deliver the
/// thread's deliverable signals onto its running context, and whether that
/// ended it.
fn deliver(kernel: &mut Kernel, pe: &mut Pe) -> Result<Option<End>> {
    kernel.deliver_pending(pe)?;
    Ok(kernel.end.take())
}

fn ended(end: End) -> Option<Termination> {
    match end {
        End::Process(termination) => Some(termination),
        End::Thread => None,
    }
}

/// The guest thread's initial integer registers, SP and thread pointer.
pub(super) struct Entry {
    /// X0 upward.
    pub(super) arguments: Vec<u64>,
    pub(super) sp: u64,
    /// TPIDRRO_EL0, the TSD base.
    pub(super) thread_pointer: Option<u64>,
}

impl Entry {
    /// Give a PE at its entry these registers.
    pub(super) fn apply(&self, pe: &mut Pe) {
        for (index, &value) in self.arguments.iter().enumerate() {
            pe.cpu.state.x[index] = value;
        }
        pe.cpu.set_sp(0, self.sp);
        if let Some(pointer) = self.thread_pointer {
            pe.cpu.registers.set_raw(Register::TPIDRRO_EL0, 0, pointer);
        }
    }
}

/// Build what the threads of a new process share: the engine description
/// and the signer of its user JOP key, none when user JOP is disabled.
pub(super) fn engine(
    chip: Chip,
    profile: CpuProfile,
    target: TargetCpu,
    keys: pe::Keys,
    jop: pe::UserJop,
) -> Result<(Engine, Option<crate::pauth::Context>)> {
    let engine = Engine {
        chip,
        profile,
        target,
        tables: Arc::new(Tables::new()?),
        keys,
        jop,
        #[cfg(feature = "native-profile")]
        profile_output: None,
        #[cfg(feature = "native-profile")]
        sample_floating_point: false,
    };
    if jop == pe::UserJop::Disabled {
        return Ok((engine, None));
    }
    let signer = engine
        .machine(0)?
        .pointer_signer()
        .map_err(|stop| anyhow!("the PE cannot sign pointers: {stop:?}"))
        .context("the process's pointer-authentication context")?;
    Ok((engine, Some(signer)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_quiescence_includes_completed_thread_statistics() {
        let runtime = Runtime::new(true);
        let statistics = lock(&runtime.statistics);
        assert!(runtime.hold_for_fork().is_none());
        drop(statistics);
        let held = runtime.hold_for_fork().unwrap();
        assert!(try_lock(&runtime.statistics).is_none());
        drop(held);
        assert!(try_lock(&runtime.statistics).is_some());
    }

    #[test]
    fn a_fork_child_keeps_only_the_forking_thread() {
        let runtime = Runtime::default();
        let (main, _) = runtime.registry.insert(0x103);
        let (forking, member) = runtime.registry.insert(0x203);
        // The main thread holds the lock and a third waits for it: tickets
        // the child's threads will never take.
        assert!(runtime.execution.acquire(main));
        lock(&runtime.execution.state).next_ticket += 1;
        runtime.execution.waiting.store(1, Ordering::SeqCst);
        let held = runtime.hold_for_fork().unwrap();
        assert!(runtime.hold_for_fork().is_none(), "the locks are held");
        runtime.fork_child(held, forking, 0x303);
        assert_eq!(runtime.registry.ports(), [0x303]);
        assert_eq!(member.port.load(Ordering::SeqCst), 0x303);
        assert!(!runtime.execution.contended());
        // The child's thread takes the lock at once.
        runtime.execution.acquire(forking);
        runtime.execution.release(forking);
        assert!(lock(&runtime.lifetime.end).unwaited);
    }

    #[test]
    fn the_execution_lock_is_fifo_and_reports_other_holders() {
        let lock = Arc::new(ExecutionLock::default());
        assert!(lock.acquire(1));
        assert!(!lock.contended());
        lock.release(1);
        assert!(!lock.acquire(1), "only this thread held it since");
        let order = Arc::new(Mutex::new(Vec::new()));
        let waiters: Vec<_> = [2u64, 3]
            .into_iter()
            .map(|thread| {
                let (shared, order) = (lock.clone(), order.clone());
                let handle = std::thread::spawn(move || {
                    assert!(shared.acquire(thread));
                    order.lock().unwrap().push(thread);
                    shared.release(thread);
                });
                while lock.waiting.load(Ordering::SeqCst) < (thread - 1) as u32 {
                    std::thread::yield_now();
                }
                handle
            })
            .collect();
        assert!(lock.contended());
        lock.release(1);
        for waiter in waiters {
            waiter.join().unwrap();
        }
        assert_eq!(*order.lock().unwrap(), vec![2, 3]);
        assert!(lock.acquire(1), "threads 2 and 3 ran since");
        lock.release(1);
    }

    #[test]
    fn the_process_end_wakes_every_thread_waiting_on_a_control() {
        let runtime = Arc::new(Runtime::default());
        let (id, _) = runtime.registry.insert(0x103);
        let (_, other) = runtime.registry.insert(0x203);
        // A caller waits for a thread that never stops (it has not started
        // and never will), as a parked thread waits for its resume.
        let control = runtime.registry.control_by_port(0x203).unwrap();
        assert!(Arc::ptr_eq(&control, &other.control));
        let waiter = std::thread::spawn(move || control.with_state(false, |_| ((), None)));
        while !other.control.pending() {
            std::thread::yield_now();
        }
        runtime.end(id, Ok(Termination::Exited(0)));
        assert_eq!(
            waiter.join().unwrap(),
            Err(crate::hosted::kernel::control::KERN_ABORTED)
        );
        assert!(Arc::ptr_eq(
            &runtime.registry.control(id).unwrap(),
            &runtime.registry.control(id).unwrap()
        ));
    }

    #[test]
    fn closing_the_lock_stops_every_later_holder() {
        let lock = Arc::new(ExecutionLock::default());
        lock.close(1);
        let blocked = {
            let lock = lock.clone();
            std::thread::spawn(move || {
                lock.acquire(2);
                unreachable!("a closed lock is never granted");
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(!blocked.is_finished());
        assert!(lock.contended());
    }

    #[test]
    fn invalidations_reach_every_other_member() {
        let registry = Registry::default();
        let (first, first_member) = registry.insert(0x103);
        let (_, second_member) = registry.insert(0x203);
        registry.invalidate(first, 0x4000, 0x8000);
        assert!(!first_member.has_stale.load(Ordering::SeqCst));
        assert!(second_member.has_stale.load(Ordering::SeqCst));
        assert_eq!(*second_member.stale.lock().unwrap(), vec![(0x4000, 0x8000)]);
        assert!(registry.contains_port(0x203));
        assert!(!registry.remove(first));
        assert!(!registry.contains_port(0x103));
    }

    #[test]
    fn the_lifetime_keeps_the_first_end_for_the_main_thread() {
        let lifetime = Lifetime::default();
        lifetime.end(Ok(Termination::Exited(3)));
        lifetime.end(Ok(Termination::Exited(4)));
        assert_eq!(lifetime.leave().unwrap().unwrap(), Termination::Exited(3));
        // With no end yet, leaving hands the end to the ending thread.
        let lifetime = Lifetime::default();
        assert!(lifetime.leave().is_none());
        assert!(lock(&lifetime.end).unwaited);
    }

    #[test]
    fn only_the_waiting_thread_leaves_the_end_to_itself() {
        let lifetime = Arc::new(Lifetime::default());
        lifetime.wait_here();
        assert!(!lock(&lifetime.end).ends_here());
        // Another thread (a worker's exit, a refused call on it) cannot hand
        // the end to a main thread blocked in a host call.
        let other = lifetime.clone();
        assert!(
            std::thread::spawn(move || lock(&other.end).ends_here())
                .join()
                .unwrap()
        );
        assert!(lifetime.leave().is_none());
        assert!(lock(&lifetime.end).ends_here(), "no thread waits any more");
    }
}
