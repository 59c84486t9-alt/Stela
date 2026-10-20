//! The process's workqueue (xnu `bsd/pthread/pthread_workqueue.c`, the
//! kext's `workq_setup_thread` in libpthread `kern/kern_support.c`): the
//! thread pool libdispatch asks for threads by QoS, whose threads enter
//! the registered `wqthread` and return to the kernel to park.
//!
//! Requests are kept by QoS, FIFO within one. Overcommit requests are
//! always admissible; constrained requests while fewer than
//! `wq_max_constrained_threads` constrained threads are scheduled and the
//! threads active at or above their QoS bucket (running, or blocked in a
//! kernel call within the stalled window) are fewer than the bucket's
//! parallelism (`workq_constrained_allowance`); cooperative requests while
//! fewer than one thread per CPU of their QoS are scheduled; the event
//! manager's request while no other thread runs it
//! (`workq_may_start_event_mgr_thread`). Admission is decided whenever
//! requests, threads or their blocking change, and while a blocked thread
//! holds requests back, again as its stalled window passes
//! (`workq_schedule_delayed_thread_creation`). A selected idle thread is
//! woken; otherwise a new one is created while below `wq_max_threads`.
//!
//! The [`kqworkq`](super::kqworkq) makes one kevent request per bucket
//! with active knotes: overcommit at the bucket's QoS, or the event
//! manager's; each [workloop](super::kqworkloop) one at its wakeup QoS.
//! The thread bound to one leaves the kernel with its events and stays
//! bound while its returns find more.
use super::{
    Call, EFAULT, EINVAL, Kernel, Outcome, Pe,
    kqworkloop::{self, WorkloopRequest},
    kqworkq::{self, DATA_BYTES, DataBuffer, KEVENT_BYTES, LIST_LEN, MANAGER_BUCKET},
    priority::{
        self, COOPERATIVE_FLAG, FLAGS_MASK, MIN_TIER_IMPORTANCE, OVERCOMMIT_FLAG, SCHED_PRI_FLAG,
        SCHED_PRI_MASK, THREAD_QOS_BACKGROUND, THREAD_QOS_LAST, THREAD_QOS_UNSPECIFIED,
    },
    thread::{
        SET_SELF_QOS_FLAG, SET_SELF_QOS_OVERRIDE_FLAG, SET_SELF_VOUCHER_FLAG,
        SET_SELF_WQ_KEVENT_UNBIND,
    },
};
use crate::hosted::{
    kernel::{End, Process},
    memory::{self, PAGE_BYTES, Protection, round_page},
    pe,
    threads::{self, Entry, lock},
};
use crate::machine::system::Register;
use anyhow::{Result, bail};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::{Duration, Instant},
};

/// `workq_kernreturn` operations (`workqueue_syscalls.h`).
const WQOPS_THREAD_RETURN: u64 = 0x004;
const WQOPS_QUEUE_NEWSPISUPP: u64 = 0x010;
const WQOPS_QUEUE_REQTHREADS: u64 = 0x020;
const WQOPS_QUEUE_REQTHREADS2: u64 = 0x030;
const WQOPS_THREAD_KEVENT_RETURN: u64 = 0x040;
const WQOPS_SET_EVENT_MANAGER_PRIORITY: u64 = 0x080;
const WQOPS_THREAD_WORKLOOP_RETURN: u64 = 0x100;
const WQOPS_SHOULD_NARROW: u64 = 0x200;
const WQOPS_SETUP_DISPATCH: u64 = 0x400;
/// Upcall flags (`WQ_FLAG_THREAD_*`).
const WQ_FLAG_THREAD_PRIO_QOS: u64 = 0x0000_4000;
const WQ_FLAG_THREAD_OVERCOMMIT: u64 = 0x0001_0000;
const WQ_FLAG_THREAD_REUSE: u64 = 0x0002_0000;
const WQ_FLAG_THREAD_NEWSPI: u64 = 0x0004_0000;
const WQ_FLAG_THREAD_KEVENT: u64 = 0x0008_0000;
const WQ_FLAG_THREAD_EVENT_MANAGER: u64 = 0x0010_0000;
const WQ_FLAG_THREAD_TSD_BASE_SET: u64 = 0x0020_0000;
const WQ_FLAG_THREAD_WORKLOOP: u64 = 0x0040_0000;
const WQ_FLAG_THREAD_COOPERATIVE: u64 = 0x0100_0000;
/// `WORKQ_THREAD_QOS_MANAGER`: the event manager's QoS, past the tiers.
const WORKQ_THREAD_QOS_MANAGER: u8 = THREAD_QOS_LAST + 1;
/// `WORKQ_THREAD_QOS_CLEANUP`: the highest QoS a thread exits at.
const WORKQ_THREAD_QOS_CLEANUP: u8 = priority::THREAD_QOS_LEGACY;
/// The event count that tells a thread to exit (`WORKQ_EXIT_THREAD_NKEVENT`).
const WORKQ_EXIT_THREAD_NKEVENT: i64 = -1;
/// `WORKQUEUE_MAXTHREADS`, the constrained pool's floor (an eighth of it)
/// and `WORKQUEUE_CONSTRAINED_FACTOR` per CPU.
const MAX_THREADS: usize = 512;
const MAX_CONSTRAINED_FLOOR: u32 = MAX_THREADS as u32 / 8;
const CONSTRAINED_FACTOR: u32 = 5;
/// `WQ_STALLED_WINDOW_USECS` and `WQ_REDUCE_POOL_WINDOW_USECS`.
const STALLED_WINDOW: Duration = Duration::from_micros(200);
const REDUCE_POOL_WINDOW: Duration = Duration::from_secs(5);
/// `struct workq_dispatch_config`: version, flags, serial-number offset,
/// label offset (version 2).
const DISPATCH_CONFIG_BYTES: usize = 24;
const DISPATCH_MIN_SUPPORTED_VERSION: u32 = 1;
const DISPATCH_LABEL_VERSION: u32 = 2;
/// The kext's thread stack: a guard page, `PTH_DEFAULT_STACKSIZE`, then the
/// pthread structure `PTHREAD_T_OFFSET` above the stack, 16-byte aligned
/// (`C_WORKQ_STK_ALIGN`).
const GUARD_BYTES: u64 = PAGE_BYTES;
const DEFAULT_STACK_BYTES: u64 = 512 << 10;
const PTHREAD_T_OFFSET: u64 = 12 << 10;
const STACK_ALIGNMENT: u64 = 16;
/// `ulock_owner_value_to_port_name`: the low bits of a lock word are flags.
const ULOCK_OWNER_FLAG_BITS: u32 = 0x3;
const ENOTSUP: u64 = 45;
const EALREADY: u64 = 37;
const EBADMSG: u64 = 94;

/// The pool a request or thread belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pool {
    Overcommit,
    Constrained,
    Cooperative,
    /// The event manager's single thread.
    Manager,
}

impl Pool {
    fn of(priority: u64) -> Self {
        if priority & OVERCOMMIT_FLAG != 0 {
            Self::Overcommit
        } else if priority & COOPERATIVE_FLAG != 0 {
            Self::Cooperative
        } else {
            Self::Constrained
        }
    }

    fn upcall_flag(self) -> u64 {
        match self {
            Self::Overcommit => WQ_FLAG_THREAD_OVERCOMMIT,
            Self::Constrained => 0,
            Self::Cooperative => WQ_FLAG_THREAD_COOPERATIVE,
            Self::Manager => WQ_FLAG_THREAD_EVENT_MANAGER,
        }
    }
}

/// The kevent request a thread is bound to (`uu_kqr_bound`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Binding {
    /// A workqueue kqueue bucket's.
    Bucket(u8),
    /// A workloop's, by its identifier.
    Workloop(u64),
}

/// What a thread runs: a request's QoS and pool, and for a kevent request
/// what it is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Assignment {
    qos: u8,
    pool: Pool,
    kevent: Option<Binding>,
}

impl Assignment {
    fn plain(qos: u8, pool: Pool) -> Self {
        Self {
            qos,
            pool,
            kevent: None,
        }
    }

    /// The kevent request of a workqueue kqueue bucket
    /// (`kqworkq_alloc`): overcommit at its QoS, or the event manager.
    fn kevent(bucket: u8) -> Self {
        if bucket == MANAGER_BUCKET {
            Self {
                qos: WORKQ_THREAD_QOS_MANAGER,
                pool: Pool::Manager,
                kevent: Some(Binding::Bucket(bucket)),
            }
        } else {
            Self {
                qos: bucket,
                pool: Pool::Overcommit,
                kevent: Some(Binding::Bucket(bucket)),
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Request {
    assignment: Assignment,
    count: u16,
    sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Run {
    /// Bound to a request and running it, or about to.
    Scheduled(Assignment),
    /// Parked since.
    Idle(Instant),
}

/// One workqueue thread as the workqueue sees it.
#[derive(Debug)]
struct Thread {
    port: u32,
    /// The base of its stack allocation (`uu_workq_stackaddr`).
    stack: u64,
    run: Run,
    /// The QoS a dispatch override raised it to (`qos_override`).
    override_qos: u8,
    /// When it entered the kernel call it is in, if any.
    blocked: Option<Instant>,
    /// Its last assignment, whose QoS an exit upcall still carries.
    last: Assignment,
    first_use: bool,
    kill_allowed: bool,
}

impl Thread {
    /// Its QoS bucket: MT and BG share one (`_wq_bucket`).
    fn bucket(&self) -> Option<(u8, Pool)> {
        match self.run {
            Run::Scheduled(assignment) => Some((
                bucket(assignment.qos.max(self.override_qos)),
                assignment.pool,
            )),
            Run::Idle(_) => None,
        }
    }
}

fn bucket(qos: u8) -> u8 {
    qos.max(THREAD_QOS_BACKGROUND)
}

#[derive(Debug, Default)]
struct State {
    open: bool,
    /// `p_dispatchqueue_serialno_offset` and `p_dispatchqueue_label_offset`.
    serial_offset: u64,
    label_offset: u64,
    manager_priority: u64,
    /// `p_workq_allow_sigmask`.
    allowed_signals: u32,
    /// Per-QoS parallelism (`wq_max_parallelism`), the constrained pool's
    /// limit and the cooperative pool's per-QoS size.
    parallelism: [u32; THREAD_QOS_LAST as usize],
    max_constrained: u32,
    max_cooperative: u32,
    requests: Vec<Request>,
    sequence: u64,
    /// By the thread's registry identifier.
    threads: BTreeMap<u64, Thread>,
    /// Assignments made for threads being created, which take them as they
    /// start.
    creating: VecDeque<Assignment>,
}

impl State {
    /// Threads scheduled in each pool and bucket, with how many of them are
    /// blocked (and since when), creations included.
    fn scheduled(&self, exclude: Option<u64>) -> impl Iterator<Item = (u8, Pool, Option<Instant>)> {
        self.threads
            .iter()
            .filter(move |(id, _)| Some(**id) != exclude)
            .filter_map(|(_, thread)| {
                thread
                    .bucket()
                    .map(|(bucket, pool)| (bucket, pool, thread.blocked))
            })
            .chain(
                self.creating
                    .iter()
                    .map(|assignment| (bucket(assignment.qos), assignment.pool, None)),
            )
    }

    /// `workq_constrained_allowance`: how many more constrained threads of
    /// `qos` may run now, not counting `exclude`.
    fn constrained_allowance(&self, qos: u8, exclude: Option<u64>, now: Instant) -> u32 {
        let constrained = self
            .scheduled(exclude)
            .filter(|&(_, pool, _)| pool == Pool::Constrained)
            .count() as u32;
        if constrained >= self.max_constrained {
            return 0;
        }
        // The manager's bucket is outside the QoS buckets counted.
        let at_or_above = self
            .scheduled(exclude)
            .filter(|&(bucket, pool, blocked)| {
                pool != Pool::Manager
                    && bucket >= self::bucket(qos)
                    && blocked.is_none_or(|since| now.duration_since(since) < STALLED_WINDOW)
            })
            .count() as u32;
        self.parallelism[usize::from(qos)]
            .saturating_sub(at_or_above)
            .min(self.max_constrained - constrained)
    }

    fn admissible(&self, assignment: Assignment, exclude: Option<u64>, now: Instant) -> bool {
        match assignment.pool {
            Pool::Overcommit => true,
            Pool::Constrained => self.constrained_allowance(assignment.qos, exclude, now) > 0,
            Pool::Cooperative => {
                self.scheduled(exclude)
                    .filter(|&(bucket, pool, _)| {
                        pool == Pool::Cooperative && bucket == self::bucket(assignment.qos)
                    })
                    .count()
                    < self.max_cooperative as usize
            }
            Pool::Manager => !self
                .scheduled(exclude)
                .any(|(_, pool, _)| pool == Pool::Manager),
        }
    }

    /// The QoS a request competes at: the event manager's is its priority's
    /// (`workq_priority_for_req`), above every tier when it is a
    /// scheduling priority.
    fn competing_qos(&self, assignment: Assignment) -> u8 {
        if assignment.pool != Pool::Manager {
            assignment.qos
        } else if self.manager_priority & SCHED_PRI_FLAG != 0 {
            THREAD_QOS_LAST
        } else {
            priority::thread_qos(self.manager_priority)
        }
    }

    /// Take one unit of the best admissible request: the highest QoS,
    /// earliest first (`workq_threadreq_select`).
    fn select(&mut self, exclude: Option<u64>, now: Instant) -> Option<Assignment> {
        let mut order: Vec<usize> = (0..self.requests.len()).collect();
        order.sort_by_key(|&index| {
            let request = &self.requests[index];
            (
                core::cmp::Reverse(self.competing_qos(request.assignment)),
                request.sequence,
            )
        });
        let index = order
            .into_iter()
            .find(|&index| self.admissible(self.requests[index].assignment, exclude, now))?;
        let request = &mut self.requests[index];
        let assignment = request.assignment;
        request.count -= 1;
        if request.count == 0 {
            self.requests.remove(index);
        }
        Some(assignment)
    }

    /// Bind admissible requests to idle threads, most recently parked
    /// first, then to new threads while below the limit: how many threads
    /// to create.
    fn schedule(&mut self, now: Instant) -> usize {
        let mut idle: Vec<(Instant, u64)> = self
            .threads
            .iter()
            .filter_map(|(&id, thread)| match thread.run {
                Run::Idle(since) => Some((since, id)),
                Run::Scheduled(_) => None,
            })
            .collect();
        idle.sort();
        while let Some(&(_, id)) = idle.last() {
            let Some(assignment) = self.select(None, now) else {
                return 0;
            };
            idle.pop();
            let thread = self.threads.get_mut(&id).expect("an idle thread");
            thread.run = Run::Scheduled(assignment);
        }
        let mut created = 0;
        while self.threads.len() + self.creating.len() < MAX_THREADS {
            let Some(assignment) = self.select(None, now) else {
                break;
            };
            self.creating.push_back(assignment);
            created += 1;
        }
        created
    }

    /// Where the kevent request `binding` names is: queued (or being
    /// created for) at a QoS, bound to a thread's port, or idle.
    fn kevent_request(&self, binding: Binding) -> WorkloopRequest {
        let names = |assignment: &Assignment| assignment.kevent == Some(binding);
        if let Some(request) = self
            .requests
            .iter()
            .find(|request| names(&request.assignment))
        {
            return WorkloopRequest::Queued(request.assignment.qos);
        }
        if let Some(assignment) = self.creating.iter().find(|assignment| names(assignment)) {
            return WorkloopRequest::Queued(assignment.qos);
        }
        self.threads
            .values()
            .find(|thread| matches!(&thread.run, Run::Scheduled(assignment) if names(assignment)))
            .map_or(WorkloopRequest::Idle, |thread| {
                WorkloopRequest::Bound(thread.port)
            })
    }

    /// Queue the one request of a kevent binding.
    fn push_kevent(&mut self, assignment: Assignment) {
        self.sequence += 1;
        let sequence = self.sequence;
        self.requests.push(Request {
            assignment,
            count: 1,
            sequence,
        });
    }

    /// Whether a blocked thread holds an inadmissible request back, so that
    /// admission must be decided again once its stalled window passes.
    fn stalled(&self) -> bool {
        !self.requests.is_empty()
            && self
                .threads
                .values()
                .any(|thread| thread.blocked.is_some() && thread.bucket().is_some())
    }
}

/// The process's workqueue.
#[derive(Default)]
pub(crate) struct Workqueue {
    state: Mutex<State>,
    /// Wakes parked threads and the stall monitor.
    changed: Condvar,
}

/// The workqueue's state, held across a host `fork`.
pub(crate) struct ForkHeld<'a>(MutexGuard<'a, State>);

impl Workqueue {
    pub(crate) fn hold_for_fork(&self) -> Option<ForkHeld<'_>> {
        threads::try_lock(&self.state).map(ForkHeld)
    }
}

impl ForkHeld<'_> {
    /// In the fork child: no workqueue, as a new process has none
    /// (`p_wqptr`), with the process's dispatch offsets and allowed signals
    /// (`forkproc` copies them). The parent's threads' state is forgotten,
    /// never dropped: nothing of it belongs to the child.
    pub(crate) fn child(mut self) {
        let kept = State {
            serial_offset: self.0.serial_offset,
            label_offset: self.0.label_offset,
            allowed_signals: self.0.allowed_signals,
            ..State::default()
        };
        core::mem::forget(core::mem::replace(&mut *self.0, kept));
    }
}

/// A workqueue thread's handle in its own kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Worker {
    id: u64,
}

/// Why a parked thread leaves the kernel.
enum Unpark {
    Run(Assignment),
    /// The pool shrank (`workq_death_policy_evaluate`): rerun to exit, at
    /// this QoS (`workq_unpark_for_death_and_unlock`).
    Exit(u8),
}

impl Workqueue {
    fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    /// Whether `port` is a workqueue thread that has not allowed
    /// `__pthread_kill` (`uu_workq_pthread_kill_allowed`).
    pub(crate) fn refuses_kill(&self, port: u32) -> bool {
        self.state()
            .threads
            .values()
            .any(|thread| thread.port == port && !thread.kill_allowed)
    }

    pub(crate) fn allow_kill(&self, worker: &Worker, allowed: bool) {
        if let Some(thread) = self.state().threads.get_mut(&worker.id) {
            thread.kill_allowed = allowed;
        }
    }

    pub(crate) fn allow_signals(&self, mask: u32) {
        self.state().allowed_signals |= mask;
    }

    fn allowed_signals(&self) -> u32 {
        self.state().allowed_signals
    }

    /// `workq_thread_add_dispatch_override`: false when `port` is not a
    /// workqueue thread (EPERM). An override is skipped when the lock word
    /// at `ulock` no longer names the thread as its owner.
    pub(crate) fn add_override(&self, port: u32, qos: u8, ulock: u64) -> bool {
        let mut state = self.state();
        let Some(thread) = state
            .threads
            .values_mut()
            .find(|thread| thread.port == port)
        else {
            return false;
        };
        if ulock != 0
            && let Some(value) = memory::read_u32(ulock)
            && value | ULOCK_OWNER_FLAG_BITS != port
        {
            return true;
        }
        thread.override_qos = thread.override_qos.max(qos);
        true
    }

    pub(crate) fn reset_override(&self, worker: &Worker) {
        if let Some(thread) = self.state().threads.get_mut(&worker.id) {
            thread.override_qos = THREAD_QOS_UNSPECIFIED;
        }
    }

    /// The thread ended (`workq_thread_terminate`).
    pub(crate) fn terminated(&self, worker: &Worker) {
        self.state().threads.remove(&worker.id);
        self.changed.notify_all();
    }

    /// A workqueue thread entered (`true`) or left a kernel call.
    pub(crate) fn blocked(&self, worker: &Worker, blocked: bool) {
        let mut state = self.state();
        let stalled_before = state.stalled();
        if let Some(thread) = state.threads.get_mut(&worker.id) {
            thread.blocked = blocked.then(Instant::now);
        }
        if blocked && !stalled_before && state.stalled() {
            drop(state);
            self.changed.notify_all();
        }
    }

    /// Park the thread until it is bound to a request or the pool shrinks
    /// it (`workq_park_and_unlock`, `workq_unpark_continue`).
    fn park(&self, id: u64) -> Unpark {
        let mut state = self.state();
        loop {
            let now = Instant::now();
            let thread = state.threads.get(&id).expect("a workqueue thread");
            if let Run::Scheduled(assignment) = thread.run {
                return Unpark::Run(assignment);
            }
            let Run::Idle(since) = thread.run else {
                unreachable!("a thread is scheduled or idle")
            };
            if let Some(assignment) = state.select(Some(id), now) {
                let thread = state.threads.get_mut(&id).expect("a workqueue thread");
                thread.run = Run::Scheduled(assignment);
                thread.last = assignment;
                return Unpark::Run(assignment);
            }
            let idle_for = now.duration_since(since);
            if idle_for >= REDUCE_POOL_WINDOW {
                let oldest = state
                    .threads
                    .iter()
                    .filter_map(|(&other, thread)| match thread.run {
                        Run::Idle(since) => Some((since, other)),
                        Run::Scheduled(_) => None,
                    })
                    .min();
                let idle = state
                    .threads
                    .values()
                    .filter(|thread| matches!(thread.run, Run::Idle(_)))
                    .count();
                if idle > 1 && oldest.is_some_and(|(_, oldest)| oldest == id) {
                    let thread = state.threads.get_mut(&id).expect("a workqueue thread");
                    let qos = thread
                        .last
                        .qos
                        .max(thread.override_qos)
                        .min(WORKQ_THREAD_QOS_CLEANUP);
                    thread.run = Run::Scheduled(Assignment::plain(qos, Pool::Overcommit));
                    return Unpark::Exit(qos);
                }
            }
            let wait = REDUCE_POOL_WINDOW
                .saturating_sub(idle_for)
                .max(STALLED_WINDOW);
            state = self
                .changed
                .wait_timeout(state, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    /// Return the thread to the pool: idle, unless it takes the best
    /// admissible request at once (`workq_select_threadreq_or_park`).
    fn unschedule(&self, worker: &Worker) {
        let mut state = self.state();
        if let Some(thread) = state.threads.get_mut(&worker.id) {
            thread.run = Run::Idle(Instant::now());
            thread.blocked = None;
        }
    }

    /// Decide admission and wake the threads bound: how many threads to
    /// create.
    fn schedule(&self) -> usize {
        let created = self.state().schedule(Instant::now());
        self.changed.notify_all();
        created
    }

    /// The thread's assignment while it runs one.
    fn assignment(&self, worker: &Worker) -> Option<Assignment> {
        match self.state().threads.get(&worker.id)?.run {
            Run::Scheduled(assignment) => Some(assignment),
            Run::Idle(_) => None,
        }
    }

    /// Unbind the thread from its kevent request, which becomes idle
    /// (`kqworkq_unbind_locked`, `kqworkloop_unbind_locked`): what it was
    /// bound to.
    fn unbind(&self, worker: &Worker) -> Option<Binding> {
        let mut state = self.state();
        let thread = state.threads.get_mut(&worker.id)?;
        let Run::Scheduled(assignment) = &mut thread.run else {
            return None;
        };
        assignment.kevent.take()
    }
}

/// Create the threads `schedule` asked for; each takes its assignment as
/// it starts.
fn create_threads(process: &Arc<Process>, count: usize) -> Result<()> {
    for _ in 0..count {
        spawn(process)?;
    }
    Ok(())
}

/// A new workqueue thread (`workq_add_new_idle_thread`,
/// `workq_create_threadstack`): its stack at the registration's hint, a
/// guard page below it, and every signal blocked but the per-thread ones.
fn spawn(process: &Arc<Process>) -> Result<()> {
    let Some(registration) = process.threads.registration() else {
        bail!("a workqueue thread was requested before bsdthread_register");
    };
    let pthread_bytes = round_page(registration.pthread_size + PTHREAD_T_OFFSET)
        .expect("the pthread size is bounded");
    let size = GUARD_BYTES + DEFAULT_STACK_BYTES + pthread_bytes;
    // A workqueue thread inherits no mask (`~workq_threadmask`).
    let created = threads::spawn(
        process,
        registration.workqueue_thread,
        !super::signal::WORKQ_THREADMASK,
        move |kernel, _pe| {
            let workqueue = &kernel.process.workqueue;
            let Ok(stack) =
                memory::allocate(registration.stack_hint, size, true, Protection::READ_WRITE)
            else {
                workqueue.state().creating.pop_front();
                return Ok(Err(super::ENOMEM));
            };
            memory::protect(stack, GUARD_BYTES, Protection::NONE)?;
            kernel.signals.set_mask(!super::signal::WORKQ_THREADMASK);
            let mut state = workqueue.state();
            let run = match state.creating.pop_front() {
                Some(assignment) => Run::Scheduled(assignment),
                None => Run::Idle(Instant::now()),
            };
            let last = match run {
                Run::Scheduled(assignment) => assignment,
                Run::Idle(_) => Assignment::plain(priority::THREAD_QOS_LEGACY, Pool::Constrained),
            };
            state.threads.insert(
                kernel.thread,
                Thread {
                    port: kernel.thread_port,
                    stack,
                    run,
                    override_qos: THREAD_QOS_UNSPECIFIED,
                    blocked: None,
                    last,
                    first_use: true,
                    kill_allowed: false,
                },
            );
            kernel.worker = Some(Worker { id: kernel.thread });
            Ok(Ok(()))
        },
    )?;
    if let Err(errno) = created {
        bail!("a workqueue thread could not be created: errno {errno}");
    }
    Ok(())
}

/// Start a new workqueue thread: park until it is bound, then enter
/// `wqthread` (`workq_unpark_continue` on first use).
pub(crate) fn begin(kernel: &mut Kernel, pe: &mut Pe) -> Result<Option<End>> {
    let Some(worker) = kernel.worker else {
        return Ok(None);
    };
    let unpark = kernel.process.workqueue.park(worker.id);
    upcall(kernel, pe, &worker, unpark, false)?;
    Ok(None)
}

/// The address of a workqueue thread's `pthread_t` above its stack
/// (`workq_thread_get_addrs`).
fn self_address(stack: u64) -> u64 {
    stack + GUARD_BYTES + DEFAULT_STACK_BYTES + PTHREAD_T_OFFSET
}

/// What an upcall passes besides the thread: the kevent list, the event
/// count and the stack top.
struct Delivery {
    list: u64,
    count: u64,
    top: u64,
}

impl Delivery {
    fn none(self_address: u64) -> Self {
        Self {
            list: 0,
            count: 0,
            top: self_address & !(STACK_ALIGNMENT - 1),
        }
    }
}

/// `workq_kevent`: the bound request's events collected below `self`, the
/// list first and the out-of-line data under it, the stack top below the
/// data used; with `changes` (a return), those registered first. A failed
/// collection delivers none and reports its errno.
fn collect(
    kernel: &Kernel,
    binding: Binding,
    self_address: u64,
    changes: Option<(u64, i64)>,
) -> Result<Result<Delivery, u64>> {
    let list = self_address - LIST_LEN * KEVENT_BYTES;
    let base = list - DATA_BYTES;
    let mut data = DataBuffer::new(base, DATA_BYTES, true);
    let collected = match binding {
        Binding::Bucket(bucket) => match kernel.process.kqworkq.existing() {
            Some(kqueue) => {
                let registered = match changes {
                    Some((changes, count)) => {
                        kqueue.register_all(changes, count, list, LIST_LEN as i64)?
                    }
                    None => Ok(0),
                };
                match registered {
                    Ok(0) => kqueue.scan(bucket, list, &mut data),
                    other => other,
                }
            }
            None => Ok(0),
        },
        Binding::Workloop(id) => kqworkloop::servicer_events(kernel, id, changes, list, &mut data)?,
    };
    Ok(collected.map(|count| Delivery {
        list,
        count,
        top: (base + data.remaining) & !(STACK_ALIGNMENT - 1),
    }))
}

/// The upcall flags of a bound kevent request.
fn kevent_flags(binding: Binding) -> u64 {
    match binding {
        Binding::Bucket(_) => WQ_FLAG_THREAD_KEVENT,
        Binding::Workloop(_) => WQ_FLAG_THREAD_KEVENT | WQ_FLAG_THREAD_WORKLOOP,
    }
}

/// Leave the kernel on the request the thread was unparked for, or to
/// exit (`workq_setup_and_run`, `workq_unpark_for_death_and_unlock`).
fn upcall(
    kernel: &mut Kernel,
    pe: &mut Pe,
    worker: &Worker,
    unpark: Unpark,
    in_exception: bool,
) -> Result<()> {
    let (stack, first_use) = {
        let mut state = kernel.process.workqueue.state();
        let thread = state
            .threads
            .get_mut(&worker.id)
            .expect("a workqueue thread");
        if let Unpark::Run(assignment) = unpark {
            thread.last = assignment;
        }
        (
            thread.stack,
            core::mem::replace(&mut thread.first_use, false),
        )
    };
    let address = self_address(stack);
    let mut flags = WQ_FLAG_THREAD_NEWSPI;
    let delivery = match unpark {
        Unpark::Run(assignment) => {
            flags |=
                assignment.pool.upcall_flag() | u64::from(assignment.qos) | WQ_FLAG_THREAD_PRIO_QOS;
            match assignment.kevent {
                Some(binding) => {
                    flags |= kevent_flags(binding);
                    collect(kernel, binding, address, None)?
                        .unwrap_or_else(|_| Delivery::none(address))
                }
                None => Delivery::none(address),
            }
        }
        Unpark::Exit(qos) => {
            flags |= u64::from(qos) | WQ_FLAG_THREAD_PRIO_QOS;
            Delivery {
                count: WORKQ_EXIT_THREAD_NKEVENT as u64,
                ..Delivery::none(address)
            }
        }
    };
    if !first_use {
        flags |= WQ_FLAG_THREAD_REUSE;
    }
    enter(kernel, pe, stack, first_use, flags, &delivery, in_exception);
    Ok(())
}

/// Set the registers of the upcall (`workq_setup_thread`,
/// `workq_set_register_state`): `wqthread(self, port, stack_bottom,
/// kevent_list, flags, nkevents)` on the stack below `self`, and on first
/// use the TSD base. In an exception the return goes there; at a new
/// thread's entry its PC does.
fn enter(
    kernel: &Kernel,
    pe: &mut Pe,
    stack: u64,
    first_use: bool,
    mut flags: u64,
    delivery: &Delivery,
    in_exception: bool,
) {
    let registration = kernel
        .process
        .threads
        .registration()
        .expect("workqueue threads exist only after registration");
    let tsd_offset = u64::from(registration.tsd_offset);
    let address = self_address(stack);
    let set_tsd = first_use && tsd_offset != 0;
    if set_tsd {
        flags |= WQ_FLAG_THREAD_TSD_BASE_SET;
    }
    Entry {
        arguments: vec![
            address,
            kernel.thread_port.into(),
            stack + GUARD_BYTES,
            delivery.list,
            flags,
            delivery.count,
        ],
        sp: delivery.top,
        thread_pointer: set_tsd.then_some(address + tsd_offset),
    }
    .apply(pe);
    let entry = registration.workqueue_thread;
    if in_exception {
        pe.cpu.registers.set_raw(Register::ELR_EL1, 0, entry);
        pe.cpu
            .registers
            .set_raw(Register::SPSR_EL1, 0, pe::user_spsr());
    } else {
        pe.cpu.pc = entry;
    }
    if kernel.trace {
        eprintln!(
            "stela: workqueue thread {:#x} enters with flags {flags:#x} and {} events",
            kernel.thread_port, delivery.count as i64
        );
    }
}

/// Clear the thread's voucher before it leaves for a new work item or
/// parks (`WQ_SETUP_CLEAR_VOUCHER`).
fn clear_voucher() {
    let _ = super::thread::set_self(0, 0, SET_SELF_VOUCHER_FLAG);
}

pub(super) const CALLS: &[&str] = &["workq_open", "workq_kernreturn", "kevent_qos", "kevent_id"];

pub(super) fn call(kernel: &mut Kernel, pe: &mut Pe, call: &Call) -> Result<Option<Outcome>> {
    Ok(Some(match call.entry.name {
        "workq_open" => open(kernel),
        "workq_kernreturn" => kernreturn(kernel, pe, call)?,
        // `kevent_qos(fd, changelist, nchanges, eventlist, nevents,
        // data_out, data_available, flags)`: an ordinary kqueue's events
        // have one layout in both ABIs.
        "kevent_qos" if call.argument(7) & kqworkq::KEVENT_FLAG_WORKQ == 0 => {
            super::timer::kevent(kernel, call, super::timer::KEVENT_QOS)?
        }
        "kevent_qos" => match kqworkq::kevent(&kernel.process, call.arguments)? {
            Ok(count) => Outcome::value(count),
            Err(errno) => Outcome::Error(errno),
        },
        "kevent_id" => match kqworkloop::kevent_id(kernel, call.arguments)? {
            Ok(count) => Outcome::value(count),
            Err(errno) => Outcome::Error(errno),
        },
        _ => return Ok(None),
    }))
}

/// A bucket of the workqueue kqueue has active knotes and no request:
/// request its kevent thread (`kqueue_threadreq_initiate`).
pub(super) fn request_kevent(process: &Arc<Process>, bucket: u8) -> Result<()> {
    let workqueue = &process.workqueue;
    let mut state = workqueue.state();
    if !state.open {
        bail!("the workqueue kqueue requested a kevent thread before workq_open");
    }
    if state.kevent_request(Binding::Bucket(bucket)) != WorkloopRequest::Idle {
        return Ok(());
    }
    state.push_kevent(Assignment::kevent(bucket));
    drop(state);
    schedule(process)
}

/// Decide admission and create the threads it asks for.
pub(super) fn schedule(process: &Arc<Process>) -> Result<()> {
    let created = process.workqueue.schedule();
    create_threads(process, created)
}

/// Where workloop `id`'s thread request is.
pub(super) fn workloop_request(process: &Arc<Process>, id: u64) -> WorkloopRequest {
    process
        .workqueue
        .state()
        .kevent_request(Binding::Workloop(id))
}

/// Queue workloop `id`'s thread request (`workq_kern_threadreq_initiate`):
/// constrained unless the workloop is overcommit. [`schedule`] admits it.
pub(super) fn request_workloop(process: &Arc<Process>, id: u64, qos: u8, overcommit: bool) {
    let pool = if overcommit {
        Pool::Overcommit
    } else {
        Pool::Constrained
    };
    process.workqueue.state().push_kevent(Assignment {
        qos,
        pool,
        kevent: Some(Binding::Workloop(id)),
    });
}

/// Move workloop `id`'s queued request to `qos`
/// (`workq_kern_threadreq_modify`).
pub(super) fn retarget_workloop(process: &Arc<Process>, id: u64, qos: u8) {
    let mut state = process.workqueue.state();
    let binding = Some(Binding::Workloop(id));
    for request in &mut state.requests {
        if request.assignment.kevent == binding {
            request.assignment.qos = qos;
        }
    }
    for assignment in &mut state.creating {
        if assignment.kevent == binding {
            assignment.qos = qos;
        }
    }
}

/// The workloop the calling thread serves, if any.
pub(super) fn workloop_of(kernel: &Kernel) -> Option<u64> {
    let worker = kernel.worker?;
    match kernel.process.workqueue.assignment(&worker)?.kevent? {
        Binding::Workloop(id) => Some(id),
        Binding::Bucket(_) => None,
    }
}

/// Unbind the thread from its kevent request and watch the bucket again,
/// which requests a thread at once if its knotes are still active
/// (`kqworkq_acknowledge_events` with `KQWQAE_UNBIND`).
fn unbind(kernel: &Kernel, worker: &Worker) -> Result<()> {
    match kernel.process.workqueue.unbind(worker) {
        Some(Binding::Bucket(bucket)) => match kernel.process.kqworkq.existing() {
            Some(kqueue) => kqueue.rearm(bucket),
            None => Ok(()),
        },
        Some(Binding::Workloop(id)) => kqworkloop::unbound(&kernel.process, id),
        None => Ok(()),
    }
}

/// `workq_handle_stack_events`: a bound kevent thread returning. Its
/// returned changes are registered, their error events delivered back;
/// with none, the bound request's events (`KEVENT_FLAG_PARKING`). With
/// events it leaves the kernel again still bound; with none it unbinds and
/// parks (`None`).
fn stack_events(
    kernel: &mut Kernel,
    pe: &mut Pe,
    worker: &Worker,
    assignment: Assignment,
    binding: Binding,
    events: u64,
    count: i64,
) -> Result<Option<Outcome>> {
    let stack = kernel
        .process
        .workqueue
        .state()
        .threads
        .get(&worker.id)
        .expect("a workqueue thread")
        .stack;
    let address = self_address(stack);
    let delivery = match collect(kernel, binding, address, Some((events, count)))? {
        Ok(delivery) => delivery,
        Err(errno) => return Ok(Some(Outcome::Error(errno))),
    };
    if delivery.count == 0 {
        unbind(kernel, worker)?;
        return Ok(None);
    }
    clear_voucher();
    let mut flags = WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_REUSE | kevent_flags(binding);
    if assignment.pool == Pool::Manager {
        flags |= WQ_FLAG_THREAD_EVENT_MANAGER;
    } else {
        flags |=
            assignment.pool.upcall_flag() | u64::from(assignment.qos) | WQ_FLAG_THREAD_PRIO_QOS;
    }
    enter(kernel, pe, stack, false, flags, &delivery, true);
    Ok(Some(Outcome::JustReturn))
}

/// `workq_open`: the pool's limits from the modeled CPUs.
fn open(kernel: &mut Kernel) -> Outcome {
    if kernel.process.threads.registration().is_none() {
        return Outcome::Error(EINVAL);
    }
    let cpus: u32 = kernel
        .process
        .hardware
        .clusters
        .iter()
        .map(|cluster| u32::from(cluster.cores))
        .sum();
    let mut state = kernel.process.workqueue.state();
    if !state.open {
        state.open = true;
        state.max_constrained = MAX_CONSTRAINED_FLOOR.max(cpus * CONSTRAINED_FACTOR);
        state.max_cooperative = cpus;
        for qos in 1..THREAD_QOS_LAST {
            state.parallelism[usize::from(qos)] =
                super::thread::parallelism(&kernel.process.hardware, qos);
        }
        // `task_get_default_manager_qos`: the main thread's QoS, legacy
        // raised to user-initiated.
        state.manager_priority =
            priority::from_thread_qos(priority::THREAD_QOS_USER_INITIATED, 0, 0);
        drop(state);
        start_monitor(kernel.process.clone());
    }
    Outcome::value(0)
}

/// Re-decide admission as blocked threads' stalled windows pass
/// (`workq_schedule_delayed_thread_creation`).
fn start_monitor(process: Arc<Process>) {
    let builder = std::thread::Builder::new().name("stela-workqueue".into());
    super::signal::host::without_signals(|| {
        builder.spawn(move || {
            let workqueue = &process.workqueue;
            loop {
                let mut state = workqueue.state();
                while !state.stalled() {
                    state = workqueue
                        .changed
                        .wait(state)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                drop(state);
                std::thread::sleep(STALLED_WINDOW);
                let created = workqueue.schedule();
                if let Err(error) = create_threads(&process, created) {
                    process.runtime.fail(error);
                    return;
                }
            }
        })
    })
    .expect("the workqueue monitor thread starts");
}

/// `workq_kernreturn(options, item, affinity, prio)`.
fn kernreturn(kernel: &mut Kernel, pe: &mut Pe, call: &Call) -> Result<Outcome> {
    let [operation, item, second, third, ..] = call.arguments;
    let (second, third) = (second as u32 as i32, third as u32 as i32);
    if kernel.process.threads.registration().is_none() {
        return Ok(Outcome::Error(EINVAL));
    }
    let workqueue = &kernel.process.workqueue;
    Ok(match operation as u32 as u64 {
        WQOPS_QUEUE_NEWSPISUPP => {
            workqueue.state().serial_offset = i64::from(second) as u64;
            Outcome::value(0)
        }
        WQOPS_SETUP_DISPATCH => {
            let bytes = (second as u32 as usize).min(DISPATCH_CONFIG_BYTES);
            let Some(copied) = memory::read(item, bytes) else {
                return Ok(Outcome::Error(EFAULT));
            };
            let mut config = [0u8; DISPATCH_CONFIG_BYTES];
            config[..bytes].copy_from_slice(&copied);
            let word = |at: usize| u32::from_le_bytes(config[at..at + 4].try_into().unwrap());
            let double = |at: usize| u64::from_le_bytes(config[at..at + 8].try_into().unwrap());
            let (version, flags) = (word(0), word(4));
            if flags != 0 || version < DISPATCH_MIN_SUPPORTED_VERSION {
                return Ok(Outcome::Error(ENOTSUP));
            }
            let mut state = workqueue.state();
            state.serial_offset = double(8);
            if version >= DISPATCH_LABEL_VERSION {
                state.label_offset = double(16);
            }
            Outcome::value(0)
        }
        WQOPS_QUEUE_REQTHREADS | WQOPS_QUEUE_REQTHREADS2 => request_threads(
            kernel,
            second,
            third as u32 as u64,
            operation as u32 as u64 == WQOPS_QUEUE_REQTHREADS2,
        )?,
        WQOPS_SET_EVENT_MANAGER_PRIORITY => {
            let mut priority = second as u32 as u64;
            let mut state = workqueue.state();
            if !state.open {
                return Ok(Outcome::Error(EINVAL));
            }
            if priority & SCHED_PRI_FLAG != 0 {
                priority &= SCHED_PRI_MASK | SCHED_PRI_FLAG;
            } else {
                let relative = priority::relative_priority(priority);
                if !(MIN_TIER_IMPORTANCE..=0).contains(&relative)
                    || priority::thread_qos(priority) == THREAD_QOS_UNSPECIFIED
                {
                    return Ok(Outcome::Error(EINVAL));
                }
                priority &= !FLAGS_MASK;
            }
            state.manager_priority = state.manager_priority.max(priority);
            Outcome::value(0)
        }
        WQOPS_SHOULD_NARROW => {
            let Some(worker) = kernel.worker else {
                return Ok(Outcome::Error(EINVAL));
            };
            let qos = priority::thread_qos(second as u32 as u64);
            let state = workqueue.state();
            let constrained = state
                .threads
                .get(&worker.id)
                .and_then(Thread::bucket)
                .is_some_and(|(_, pool)| pool == Pool::Constrained);
            if !constrained || qos == THREAD_QOS_UNSPECIFIED {
                return Ok(Outcome::Error(EINVAL));
            }
            let narrow = state.constrained_allowance(qos, Some(worker.id), Instant::now()) == 0;
            Outcome::value(u64::from(narrow))
        }
        WQOPS_THREAD_RETURN | WQOPS_THREAD_KEVENT_RETURN | WQOPS_THREAD_WORKLOOP_RETURN => {
            let Some(worker) = kernel.worker else {
                return Ok(Outcome::Error(EINVAL));
            };
            let assignment = workqueue.assignment(&worker);
            let bound = assignment.and_then(|assignment| assignment.kevent);
            // A thread no kevent request bound may return no events.
            if item != 0 && second != 0 && bound.is_none() {
                return Ok(Outcome::Error(EINVAL));
            }
            kernel
                .signals
                .reset_for_workqueue(workqueue.allowed_signals());
            if let (Some(assignment), Some(binding)) = (assignment, bound)
                && let Some(outcome) = stack_events(
                    kernel,
                    pe,
                    &worker,
                    assignment,
                    binding,
                    item,
                    second.into(),
                )?
            {
                return Ok(outcome);
            }
            thread_return(kernel, pe, worker)?
        }
        _ => Outcome::Error(EINVAL),
    })
}

/// `workq_reqthreads(count, priority, cooperative)`.
fn request_threads(
    kernel: &mut Kernel,
    count: i32,
    priority: u64,
    cooperative: bool,
) -> Result<Outcome> {
    let qos = priority::thread_qos(priority);
    let workqueue = &kernel.process.workqueue;
    let mut state = workqueue.state();
    if !state.open || count <= 0 || count > i32::from(u16::MAX) || qos == THREAD_QOS_UNSPECIFIED {
        return Ok(Outcome::Error(EINVAL));
    }
    let pool = if cooperative {
        if count > 1 {
            return Ok(Outcome::Error(ENOTSUP));
        }
        if priority & OVERCOMMIT_FLAG != 0 {
            return Ok(Outcome::Error(EINVAL));
        }
        Pool::Cooperative
    } else {
        Pool::of(priority & !COOPERATIVE_FLAG)
    };
    state.sequence += 1;
    let sequence = state.sequence;
    state.requests.push(Request {
        assignment: Assignment::plain(qos, pool),
        count: count as u16,
        sequence,
    });
    drop(state);
    let created = workqueue.schedule();
    create_threads(&kernel.process, created)?;
    Ok(Outcome::value(0))
}

/// `workq_select_threadreq_or_park_and_unlock`: rerun the returning thread
/// on the best admissible request or park it.
fn thread_return(kernel: &mut Kernel, pe: &mut Pe, worker: Worker) -> Result<Outcome> {
    let process = kernel.process.clone();
    let workqueue = &process.workqueue;
    clear_voucher();
    workqueue.unschedule(&worker);
    let created = workqueue.schedule();
    create_threads(&process, created)?;
    let unpark = workqueue.park(worker.id);
    upcall(kernel, pe, &worker, unpark, true)?;
    Ok(Outcome::JustReturn)
}

/// `bsdthread_ctl(BSDTHREAD_CTL_SET_SELF, priority, voucher, flags)`
/// (`bsdthread_set_self`): the workqueue's own part, then the QoS and the
/// voucher and scheduling flags applied to the host thread.
pub(super) fn set_self(
    kernel: &mut Kernel,
    priority: u64,
    voucher: u64,
    flags: u64,
) -> Result<Outcome> {
    let workqueue = &kernel.process.workqueue;
    let assignment = kernel
        .worker
        .and_then(|worker| workqueue.assignment(&worker));
    let manager = assignment.is_some_and(|assignment| assignment.pool == Pool::Manager);
    let unbind_error = if flags & SET_SELF_WQ_KEVENT_UNBIND != 0 {
        match (kernel.worker, assignment) {
            (None, _) => Some(EINVAL),
            _ if manager => Some(EINVAL),
            (
                _,
                Some(Assignment {
                    kevent: Some(Binding::Workloop(_)),
                    ..
                }),
            ) => Some(EINVAL),
            (
                Some(worker),
                Some(Assignment {
                    kevent: Some(_), ..
                }),
            ) => {
                unbind(kernel, &worker)?;
                None
            }
            _ => Some(EALREADY),
        }
    } else {
        None
    };
    let mut qos_error = None;
    let mut host_flags = flags & !(SET_SELF_WQ_KEVENT_UNBIND | SET_SELF_QOS_OVERRIDE_FLAG);
    if flags & (SET_SELF_QOS_FLAG | SET_SELF_QOS_OVERRIDE_FLAG) != 0 {
        let cooperative = priority & COOPERATIVE_FLAG != 0;
        let override_valid = if flags & SET_SELF_QOS_OVERRIDE_FLAG != 0 {
            priority::has_override_qos(priority) && cooperative
        } else {
            !priority::has_override_qos(priority)
        };
        match priority::to_policy(priority) {
            // The event manager's thread keeps its QoS.
            Some(_) if manager => qos_error = Some(EINVAL),
            Some((qos, _)) if override_valid => {
                if let Some(worker) = kernel.worker {
                    let mut state = workqueue.state();
                    if let Some(thread) = state.threads.get_mut(&worker.id)
                        && let Run::Scheduled(assignment) = thread.run
                    {
                        let requested = Pool::of(priority);
                        let allowed = match (assignment.pool, requested) {
                            (Pool::Cooperative, Pool::Cooperative) => true,
                            (Pool::Cooperative, _) | (_, Pool::Cooperative) => false,
                            _ => true,
                        };
                        if allowed {
                            thread.run = Run::Scheduled(Assignment {
                                qos,
                                pool: requested,
                                ..assignment
                            });
                        } else {
                            qos_error = Some(EINVAL);
                        }
                    }
                }
            }
            _ => qos_error = Some(EINVAL),
        }
        if qos_error.is_some() {
            host_flags &= !SET_SELF_QOS_FLAG;
        }
    }
    let host_priority = priority::to_policy(priority).map_or(0, |(qos, relative)| {
        priority::from_thread_qos(qos, relative, 0)
    });
    let host = if host_flags != 0 {
        super::thread::set_self(host_priority, voucher, host_flags)
    } else {
        crate::hosted::forward::Returned {
            rax: 0,
            rdx: 0,
            carry: false,
        }
    };
    if kernel.worker.is_some() {
        let created = workqueue.schedule();
        create_threads(&kernel.process, created)?;
    }
    let host_error = host.carry.then_some(host.rax);
    Ok(match (unbind_error, qos_error, host_error) {
        (_, Some(_), Some(_)) => Outcome::Error(EBADMSG),
        (Some(errno), _, _) | (None, Some(errno), _) | (None, None, Some(errno)) => {
            Outcome::Error(errno)
        }
        (None, None, None) => Outcome::value(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opened() -> State {
        let mut state = State {
            open: true,
            max_constrained: 64,
            max_cooperative: 8,
            ..State::default()
        };
        for qos in 1..THREAD_QOS_LAST {
            state.parallelism[usize::from(qos)] = if matches!(
                qos,
                THREAD_QOS_BACKGROUND | priority::THREAD_QOS_MAINTENANCE
            ) {
                4
            } else {
                8
            };
        }
        state
    }

    fn request(state: &mut State, qos: u8, pool: Pool, count: u16) {
        state.sequence += 1;
        let sequence = state.sequence;
        state.requests.push(Request {
            assignment: Assignment::plain(qos, pool),
            count,
            sequence,
        });
    }

    fn worker(state: &mut State, id: u64, run: Run) {
        state.threads.insert(
            id,
            Thread {
                port: 0x1003 + id as u32 * 0x100,
                stack: 0,
                run,
                override_qos: THREAD_QOS_UNSPECIFIED,
                blocked: None,
                last: Assignment::plain(priority::THREAD_QOS_LEGACY, Pool::Constrained),
                first_use: false,
                kill_allowed: false,
            },
        );
    }

    #[test]
    fn constrained_requests_stop_at_the_buckets_parallelism() {
        let mut state = opened();
        let now = Instant::now();
        request(
            &mut state,
            priority::THREAD_QOS_LEGACY,
            Pool::Constrained,
            12,
        );
        assert_eq!(state.schedule(now), 8, "eight CPUs at the default QoS");
        assert_eq!(state.requests[0].count, 4);
        request(&mut state, priority::THREAD_QOS_LEGACY, Pool::Overcommit, 2);
        assert_eq!(state.schedule(now), 2, "overcommit is always admitted");
        assert_eq!(state.creating.len(), 10);
    }

    #[test]
    fn idle_threads_take_requests_before_new_ones_are_made() {
        let mut state = opened();
        let now = Instant::now();
        worker(&mut state, 1, Run::Idle(now));
        worker(&mut state, 2, Run::Idle(now + Duration::from_millis(1)));
        request(
            &mut state,
            priority::THREAD_QOS_USER_INTERACTIVE,
            Pool::Constrained,
            1,
        );
        request(&mut state, THREAD_QOS_BACKGROUND, Pool::Constrained, 1);
        assert_eq!(state.schedule(now), 0);
        // The most recently parked thread takes the highest QoS.
        assert_eq!(
            state.threads[&2].run,
            Run::Scheduled(Assignment::plain(
                priority::THREAD_QOS_USER_INTERACTIVE,
                Pool::Constrained
            ))
        );
        assert!(matches!(state.threads[&1].run, Run::Scheduled(_)));
        assert!(state.requests.is_empty());
    }

    #[test]
    fn a_long_blocked_thread_stops_counting_against_admission() {
        let mut state = opened();
        let now = Instant::now();
        let busy = Assignment::plain(THREAD_QOS_BACKGROUND, Pool::Constrained);
        for id in 0..4 {
            worker(&mut state, id, Run::Scheduled(busy));
        }
        request(&mut state, THREAD_QOS_BACKGROUND, Pool::Constrained, 1);
        assert_eq!(state.schedule(now), 0, "four background CPUs in use");
        state.threads.get_mut(&0).unwrap().blocked = Some(now);
        assert!(state.stalled());
        assert_eq!(state.schedule(now), 0, "blocked within its stalled window");
        assert_eq!(state.schedule(now + STALLED_WINDOW), 1);
    }

    #[test]
    fn narrowing_excludes_the_asking_thread() {
        let mut state = opened();
        let now = Instant::now();
        let legacy = Assignment::plain(priority::THREAD_QOS_LEGACY, Pool::Constrained);
        for id in 0..8 {
            worker(&mut state, id, Run::Scheduled(legacy));
        }
        assert_eq!(state.constrained_allowance(legacy.qos, None, now), 0);
        assert_eq!(state.constrained_allowance(legacy.qos, Some(3), now), 1);
    }

    #[test]
    fn one_event_manager_runs_at_a_time_outside_the_qos_buckets() {
        let mut state = opened();
        let now = Instant::now();
        let manager = Assignment::kevent(MANAGER_BUCKET);
        assert_eq!(manager.pool, Pool::Manager);
        worker(&mut state, 1, Run::Scheduled(manager));
        worker(&mut state, 2, Run::Idle(now));
        state.push_kevent(manager);
        assert_eq!(state.schedule(now), 0);
        assert_eq!(state.threads[&2].run, Run::Idle(now), "the manager runs");
        assert_eq!(
            state.constrained_allowance(priority::THREAD_QOS_LEGACY, None, now),
            8,
            "the manager's bucket is not a QoS bucket"
        );
        // The manager itself may take the next manager request.
        assert_eq!(state.select(Some(1), now), Some(manager));
    }

    #[test]
    fn a_kevent_request_is_queued_then_bound_then_idle() {
        let mut state = opened();
        let now = Instant::now();
        let binding = Binding::Workloop(0x1234);
        assert_eq!(state.kevent_request(binding), WorkloopRequest::Idle);
        let assignment = Assignment {
            qos: priority::THREAD_QOS_LEGACY,
            pool: Pool::Constrained,
            kevent: Some(binding),
        };
        state.push_kevent(assignment);
        assert_eq!(
            state.kevent_request(binding),
            WorkloopRequest::Queued(priority::THREAD_QOS_LEGACY)
        );
        worker(&mut state, 1, Run::Idle(now));
        assert_eq!(state.schedule(now), 0);
        let port = state.threads[&1].port;
        assert_eq!(state.kevent_request(binding), WorkloopRequest::Bound(port));
        if let Run::Scheduled(assignment) = &mut state.threads.get_mut(&1).unwrap().run {
            assignment.kevent = None;
        }
        assert_eq!(state.kevent_request(binding), WorkloopRequest::Idle);
    }
}
