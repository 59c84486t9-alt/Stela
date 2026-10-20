//! Workloops (xnu `struct kqworkloop`, `kevent_id`, `EVFILT_WORKLOOP`):
//! the dynamic kqueues libdispatch keeps one of per serial queue
//! hierarchy, each served by at most one workqueue thread at a time.
//!
//! A workloop's ordinary knotes live on private host kqueues by QoS bucket
//! ([`HostBuckets`]), watched by the kevent monitor. Its `EVFILT_WORKLOOP`
//! knotes are modeled here as XNU's `workloop_filtops` define them: the
//! thread request knote (`NOTE_WL_THREAD_REQUEST`, one per workloop, with
//! its debounced QoS updates), the synchronous waiters' knotes
//! (`NOTE_WL_SYNC_WAIT`, whose registration blocks until a
//! `NOTE_WL_SYNC_WAKE`), and the owner a debounced `dq_state` names
//! (`NOTE_WL_DISCOVER_OWNER`, `NOTE_WL_END_OWNERSHIP`).
//!
//! The workloop's wakeup QoS is its highest bucket with an active knote
//! (`kqwl_wakeup_qos`). While it has one, no servicer and no owner, it has
//! one thread request in the workqueue (`kqworkloop_update_threads_qos`),
//! overcommit once any knote was attached overcommit. The servicer
//! receives the workloop's identifier below its event list and the events
//! of its buckets, highest first, and keeps the workloop while its returns
//! find more (`kqworkloop_end_processing`).
//!
//! QoS overrides, turnstile priority inheritance and the return-to-kernel
//! notification adjust only scheduling and are not modeled. Sync IPC
//! knotes (`NOTE_WL_SYNC_IPC`) only link priority inheritance chains; no
//! port here can start one, so attaching one finds no chain (ENOENT, as
//! for a port whose chain broke).
//!
//! `kqueue_workloop_ctl(cmd, options, addr, sz)` (`kern_event.c`) copies
//! in `struct kqueue_workloop_params`, whose version must be `sz`.
//! `KQ_WORKLOOP_CREATE` validates the scheduling parameters, creates a
//! workloop that must not exist with them, and keeps it alive while they
//! are unreleased (the creation's reference); `KQ_WORKLOOP_DESTROY`
//! releases them once (EINVAL for a workloop without them or already
//! released). Another command succeeds doing nothing, as XNU's switch
//! falls through. The parameters' fixed priority, policy and CPU limit
//! adjust only the servicer's scheduling, which the hosted workqueue does
//! by QoS. A work interval to preadopt (`KQ_WORKLOOP_CREATE_WORK_INTERVAL`)
//! and a permanently bound servicer
//! (`KQ_WORKLOOP_CREATE_WITH_BOUND_THREAD`) stop the run.
use super::{
    EFAULT, EINVAL, Kernel,
    kqworkq::{
        self, DataBuffer, EV_ADD, EV_CLEAR, EV_DELETE, EV_DISABLE, EV_ENABLE, EV_ERROR, EV_RECEIPT,
        HostBuckets, KEVENT_BYTES, KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST,
        KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST, KEVENT_FLAG_ERROR_EVENTS, KEVENT_FLAG_STACK_DATA,
        KEVENT_FLAG_USER, KEVENT_FLAG_WORKLOOP, KEVENT_FLAG_WORKQ, Kevent, Knote,
    },
    priority, workqueue,
};
use crate::hosted::{kernel::Process, memory, threads::lock};
use anyhow::{Result, bail};
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, MutexGuard},
};

/// `KQWL_NBUCKETS`: one per thread QoS tier.
const BUCKETS: u8 = priority::THREAD_QOS_LAST - 1;
const EVFILT_WORKLOOP: i16 = -17;
/// `NOTE_WL_*` commands and updates (`sys/event_private.h`).
const NOTE_WL_THREAD_REQUEST: u32 = 0x0000_0001;
const NOTE_WL_SYNC_WAIT: u32 = 0x0000_0004;
const NOTE_WL_SYNC_WAKE: u32 = 0x0000_0008;
const NOTE_WL_SYNC_IPC: u32 = 0x8000_0000;
const NOTE_WL_COMMANDS_MASK: u32 = 0x8000_000f;
const NOTE_WL_UPDATE_QOS: u32 = 0x0000_0010;
const NOTE_WL_END_OWNERSHIP: u32 = 0x0000_0020;
const NOTE_WL_DISCOVER_OWNER: u32 = 0x0000_0080;
const NOTE_WL_IGNORE_ESTALE: u32 = 0x0000_0100;
const NOTE_WL_UPDATES_MASK: u32 = 0x0000_01f0;
/// `EV_EXTIDX_WL_*`: the debounce address, mask and value.
const EXT_ADDR: usize = 1;
const EXT_MASK: usize = 2;
const EXT_VALUE: usize = 3;
/// `ipc_entry_name_mask`: the generation bits a port name in a lock word
/// lost.
const PORT_NAME_ROLL_BITS: u32 = 0x3;
/// The `kqueue_id_t` a servicer finds below its event list.
const ID_BYTES: u64 = 8;
const ENOENT: u64 = kqworkq::ENOENT as u64;
const EEXIST: u64 = 17;
const EXDEV: u64 = 18;
const ERANGE: u64 = 34;
const EALREADY: u64 = 37;
const ENOTSUP: u64 = 45;
const ESTALE: u64 = 70;
const EOWNERDEAD: u64 = 105;
/// `kqueue_workloop_ctl` commands and `kqwlp_flags`
/// (`bsd/pthread/workqueue_syscalls.h`).
const KQ_WORKLOOP_CREATE: u64 = 0x01;
const KQ_WORKLOOP_DESTROY: u64 = 0x02;
const KQ_WORKLOOP_CREATE_SCHED_PRI: i32 = 0x01;
const KQ_WORKLOOP_CREATE_SCHED_POL: i32 = 0x02;
const KQ_WORKLOOP_CREATE_CPU_PERCENT: i32 = 0x04;
const KQ_WORKLOOP_CREATE_WORK_INTERVAL: i32 = 0x08;
const KQ_WORKLOOP_CREATE_WITH_BOUND_THREAD: i32 = 0x10;
/// The packed `struct kqueue_workloop_params`.
const PARAMS_BYTES: usize = 36;
/// `MAXPRI_USER`.
const MAXPRI_USER: i32 = 63;
/// `POLICY_TIMESHARE`, `POLICY_RR` and `POLICY_FIFO`.
const POLICIES: [i32; 3] = [1, 2, 4];
/// The largest `kqwlp_cpu_refillms`.
const MAX_REFILL_MS: i32 = 0x00ff_ffff;

/// The thread request knote (`NOTE_WL_THREAD_REQUEST`).
#[derive(Debug, Clone, Copy)]
struct RequestKnote {
    /// `kn_kevent`: the attach's identity and flags (with `EV_CLEAR`), its
    /// normalized QoS, and the last update's fflags and extensions.
    kevent: Kevent,
    /// `kn_sfflags`: the commands and updates accepted.
    saved: u32,
    active: bool,
    disabled: bool,
}

impl RequestKnote {
    fn bucket(&self) -> u8 {
        priority::thread_qos(self.kevent.qos as u32 as u64)
    }

    /// `filt_wlprocess`: the event a servicer receives.
    fn event(&self) -> Kevent {
        Kevent {
            fflags: self.saved,
            xflags: 0,
            data: 0,
            ..self.kevent
        }
    }
}

/// A workloop's `workq_threadreq_param_t` (`kqwl_params`): what
/// `kqueue_workloop_ctl` set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Params {
    priority: Option<u8>,
    policy: Option<u8>,
    /// `trp_cpupercent` and `trp_refillms`.
    cpu_limit: Option<(u8, u32)>,
    /// `TRP_RELEASED`.
    released: bool,
}

/// A synchronous waiter's knote, named by the waiter's thread port.
#[derive(Debug, Clone, Copy)]
struct SyncKnote {
    saved: u32,
    /// The thread blocked on it (`kn_thread`), by registry identifier.
    waiter: Option<u64>,
}

impl SyncKnote {
    fn woken(&self) -> bool {
        self.saved & NOTE_WL_SYNC_WAKE != 0
    }
}

struct Workloop {
    tag: u32,
    host: HostBuckets,
    /// Host buckets whose watch fired since they were last collected.
    queued: [bool; BUCKETS as usize],
    request: Option<RequestKnote>,
    sync: HashMap<u64, SyncKnote>,
    /// `kqwl_owner`, by thread port.
    owner: Option<u32>,
    /// `tr_kq_qos_index`: the thread request knote's QoS.
    qos_index: u8,
    overcommit: bool,
    /// Calls in flight on it, each holding it alive.
    calls: u32,
    params: Option<Params>,
}

impl Workloop {
    fn new(tag: u32) -> Self {
        Self {
            tag,
            host: HostBuckets::new(BUCKETS, tag),
            queued: [false; BUCKETS as usize],
            request: None,
            sync: HashMap::new(),
            owner: None,
            qos_index: 0,
            overcommit: false,
            calls: 0,
            params: None,
        }
    }

    /// Created with parameters not yet released: `kqueue_workloop_ctl`'s
    /// creation reference holds it.
    fn live(&self) -> bool {
        self.params.is_some_and(|params| !params.released)
    }

    /// `kqwl_wakeup_qos`.
    fn wakeup_qos(&self) -> u8 {
        let request = self
            .request
            .filter(|request| request.active && !request.disabled)
            .map_or(0, |request| request.bucket());
        let host = (1..=BUCKETS)
            .rev()
            .find(|&bucket| self.queued[usize::from(bucket - 1)])
            .unwrap_or(0);
        request.max(host)
    }

    fn idle(&self) -> bool {
        self.calls == 0
            && !self.live()
            && self.request.is_none()
            && self.sync.is_empty()
            && self.host.is_empty()
    }
}

#[derive(Default)]
struct Table {
    by_id: HashMap<u64, Workloop>,
    by_tag: HashMap<u32, u64>,
    next_tag: u32,
}

/// The process's workloops (`fd_kqhash`).
#[derive(Default)]
pub(crate) struct Workloops {
    table: Mutex<Table>,
    /// Wakes synchronous waiters.
    woken: Condvar,
}

/// How one registration ended.
enum Registered {
    Done(Option<Kevent>),
    /// A `NOTE_WL_SYNC_WAIT` knote the caller now waits on.
    Wait(u64),
}

/// What a registration knows of its caller.
struct Caller {
    port: u32,
    thread: u64,
    /// The workqueue's own registration of a returning servicer's changes
    /// (`KEVENT_FLAG_KERNEL`), which never waits.
    kernel: bool,
}

impl Workloops {
    fn table(&self) -> MutexGuard<'_, Table> {
        lock(&self.table)
    }

    pub(crate) fn hold_for_fork(&self) -> Option<WorkloopsHeld<'_>> {
        crate::hosted::threads::try_lock(&self.table).map(WorkloopsHeld)
    }
}

/// The workloop table, held across a host `fork`.
pub(crate) struct WorkloopsHeld<'a>(MutexGuard<'a, Table>);

impl WorkloopsHeld<'_> {
    /// In the fork child: no workloops, as `fdt_fork` copies no
    /// `fd_kqhash`. The parent's are forgotten, never dropped.
    pub(crate) fn child(mut self) {
        core::mem::forget(core::mem::take(&mut *self.0));
    }
}

/// The lock word at `address`, read with no guest code running so that
/// no update is half seen (`copyin_atomic64`).
fn load_word(process: &Arc<Process>, thread: u64, address: u64) -> Option<u64> {
    process
        .runtime
        .exclusive(thread, || memory::read_u64(address))
}

/// Phase 1 of `filt_wlupdate`: the debounce. The value loaded replaces the
/// change's; a mismatch under the mask is ESTALE. With
/// `NOTE_WL_DISCOVER_OWNER` the loaded word's port names the new owner.
fn debounce(
    process: &Arc<Process>,
    caller: &Caller,
    change: &mut Kevent,
    owner: Option<u32>,
) -> Result<Option<u32>, u64> {
    let mut new_owner = owner;
    let address = change.ext[EXT_ADDR];
    if address != 0 {
        let expected = change.ext[EXT_VALUE];
        let mask = change.ext[EXT_MASK];
        let Some(value) = load_word(process, caller.thread, address) else {
            return Err(EFAULT);
        };
        change.ext[EXT_VALUE] = value;
        if value & mask != expected & mask {
            return Err(ESTALE);
        }
        if change.fflags & NOTE_WL_DISCOVER_OWNER != 0 {
            let name = value as u32 & !PORT_NAME_ROLL_BITS;
            if name != 0 {
                let name = name | PORT_NAME_ROLL_BITS;
                if !process.runtime.registry.contains_port(name) {
                    return Err(EOWNERDEAD);
                }
                new_owner = Some(name);
            }
        }
    }
    if change.fflags & NOTE_WL_END_OWNERSHIP != 0 && new_owner == Some(caller.port) {
        new_owner = None;
    }
    Ok(new_owner)
}

/// `filt_wlvalidate_kev_flags`: the QoS a `NOTE_WL_UPDATE_QOS` asks for.
fn validate(saved: u32, change: &Kevent) -> Result<u8, u64> {
    let commands = change.fflags & NOTE_WL_COMMANDS_MASK;
    let saved_commands = saved & NOTE_WL_COMMANDS_MASK;
    let deleting = change.flags & EV_DELETE != 0;
    if change.fflags & NOTE_WL_DISCOVER_OWNER != 0 && deleting {
        return Err(EINVAL);
    }
    let mut qos = 0;
    if change.fflags & NOTE_WL_UPDATE_QOS != 0 {
        if deleting || saved_commands != NOTE_WL_THREAD_REQUEST {
            return Err(EINVAL);
        }
        qos = priority::thread_qos(change.qos as u32 as u64);
        if qos == 0 {
            return Err(ERANGE);
        }
    }
    let enables_only = change.flags & (EV_ENABLE | EV_DELETE) == EV_ENABLE;
    match commands {
        NOTE_WL_THREAD_REQUEST if saved_commands != NOTE_WL_THREAD_REQUEST => Err(EINVAL),
        NOTE_WL_THREAD_REQUEST => Ok(qos),
        NOTE_WL_SYNC_WAIT if change.fflags & NOTE_WL_END_OWNERSHIP != 0 => Err(EINVAL),
        NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE
            if saved_commands & (NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE) == 0 || enables_only =>
        {
            Err(EINVAL)
        }
        NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE => Ok(qos),
        _ => Err(EINVAL),
    }
}

impl Table {
    fn get_or_create(&mut self, id: u64, flags: u64) -> Result<(), u64> {
        if id == 0 || id == u64::MAX {
            return Err(EINVAL);
        }
        if self.by_id.contains_key(&id) {
            if flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST != 0 {
                return Err(EEXIST);
            }
            return Ok(());
        }
        if flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST != 0 {
            return Err(ENOENT);
        }
        self.next_tag += 1;
        let tag = self.next_tag;
        self.by_tag.insert(tag, id);
        self.by_id.insert(id, Workloop::new(tag));
        Ok(())
    }

    /// Free a workloop nothing holds any longer (`kqworkloop_dealloc`).
    fn release(&mut self, process: &Arc<Process>, id: u64) {
        let Some(workloop) = self.by_id.get(&id) else {
            return;
        };
        if workloop.idle() && workqueue::workloop_request(process, id) == WorkloopRequest::Idle {
            let mut workloop = self.by_id.remove(&id).expect("the workloop");
            self.by_tag.remove(&workloop.tag);
            workloop.host.close();
        }
    }
}

/// The workqueue's view of a workloop's thread request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkloopRequest {
    Idle,
    Queued(u8),
    /// Bound to the servicer with this port.
    Bound(u32),
}

/// `kqworkloop_update_threads_qos`: make, retarget or leave the thread
/// request. True when a request was made and the workqueue must schedule.
fn redrive(process: &Arc<Process>, id: u64, workloop: &Workloop) -> bool {
    let wakeup = workloop.wakeup_qos();
    let qos = workloop.qos_index.max(wakeup);
    match workqueue::workloop_request(process, id) {
        WorkloopRequest::Idle if workloop.owner.is_none() && wakeup != 0 => {
            workqueue::request_workloop(process, id, qos, workloop.overcommit);
            true
        }
        WorkloopRequest::Queued(current) if qos != 0 && qos != current => {
            workqueue::retarget_workloop(process, id, qos);
            false
        }
        _ => false,
    }
}

/// `kevent_register` on a workloop.
fn register(
    process: &Arc<Process>,
    id: u64,
    workloop: &mut Workloop,
    watch: &kqworkq::Watch,
    caller: &Caller,
    change: &Kevent,
) -> Result<Registered> {
    if change.filter == EVFILT_WORKLOOP {
        return Ok(register_workloop_knote(
            process, id, workloop, caller, change,
        ));
    }
    let mut change = *change;
    let requested = change.flags;
    if change.flags & EV_DELETE != 0 {
        change.flags &= !EV_ADD;
    }
    if change.flags & EV_DISABLE != 0 {
        change.flags &= !EV_ENABLE;
    }
    let recorded = workloop.host.knote(&change);
    // `kevent_register_validate_priority`: an enabled knote needs a QoS.
    if change.flags & (EV_DISABLE | EV_DELETE) == 0 {
        let qos = recorded.map_or(change.qos, |knote| knote.qos);
        if priority::thread_qos(qos as u32 as u64) == priority::THREAD_QOS_UNSPECIFIED {
            return Ok(Registered::Done(Some(change.failed_with(ERANGE))));
        }
    }
    let priority = change.qos as u32 as u64;
    let attach = Knote {
        bucket: priority::thread_qos(priority).max(1),
        qos: kqworkq::normalize(priority) as u32 as i32,
    };
    let mut result = workloop.host.register(&change, attach, watch)?;
    // Workloops take `EV_ADD | EV_DELETE` of nothing as done.
    let soft = requested & (EV_ADD | EV_DELETE) == EV_ADD | EV_DELETE;
    if soft && result.is_some_and(|result| result.failed() && result.data as u64 == ENOENT) {
        result = (change.flags & EV_RECEIPT != 0).then(|| change.failed_with(0));
    }
    if recorded.is_none()
        && workloop.host.knote(&change).is_some()
        && priority & priority::OVERCOMMIT_FLAG != 0
    {
        workloop.overcommit = true;
    }
    Ok(Registered::Done(result))
}

/// `kevent_register` of an `EVFILT_WORKLOOP` knote, through
/// `filt_wlattach`, `filt_wltouch` and `filt_wlallow_drop`.
fn register_workloop_knote(
    process: &Arc<Process>,
    id: u64,
    workloop: &mut Workloop,
    caller: &Caller,
    change: &Kevent,
) -> Registered {
    let mut change = *change;
    let requested = change.flags;
    if change.flags & EV_DELETE != 0 {
        change.flags &= !EV_ADD;
    }
    if change.flags & EV_DISABLE != 0 {
        change.flags &= !EV_ENABLE;
    }
    let is_request = workloop
        .request
        .is_some_and(|request| request.kevent.ident == change.ident);
    let exists = is_request || workloop.sync.contains_key(&change.ident);
    // `kevent_register_validate_priority`.
    if change.flags & (EV_DISABLE | EV_DELETE) == 0 {
        let qos = match workloop.request {
            Some(request) if is_request => request.kevent.qos,
            _ => change.qos,
        };
        if (!exists || is_request)
            && priority::thread_qos(qos as u32 as u64) == priority::THREAD_QOS_UNSPECIFIED
        {
            return Registered::Done(Some(change.failed_with(ERANGE)));
        }
    }
    let servicer = match workqueue::workloop_request(process, id) {
        WorkloopRequest::Bound(port) => Some(port),
        _ => None,
    };
    let done = |result: Result<(), u64>, change: Kevent| {
        Registered::Done(match result {
            Ok(()) if change.flags & EV_RECEIPT != 0 => Some(change.failed_with(0)),
            Ok(()) => None,
            Err(errno) => Some(change.failed_with(errno)),
        })
    };
    if !exists {
        if change.flags & EV_ADD == 0 {
            // Workloops take `EV_ADD | EV_DELETE` of nothing as done.
            let soft = requested & (EV_ADD | EV_DELETE) == EV_ADD | EV_DELETE;
            return done(if soft { Ok(()) } else { Err(ENOENT) }, change);
        }
        return attach(process, id, workloop, caller, servicer, change);
    }
    let saved = if is_request {
        workloop.request.expect("the thread request").saved
    } else {
        workloop.sync[&change.ident].saved
    };
    let qos_index = match validate(saved, &change) {
        Ok(qos_index) => qos_index,
        Err(errno) => return done(Err(errno), change),
    };
    let ignore_stale = change.fflags & NOTE_WL_IGNORE_ESTALE != 0;
    let new_owner = match debounce(process, caller, &mut change, workloop.owner) {
        Ok(new_owner) => Some(new_owner),
        Err(ESTALE) if ignore_stale => None,
        Err(errno) => return done(Err(errno), change),
    };
    let deleting = change.flags & EV_DELETE != 0;
    if let Some(new_owner) = new_owner {
        // Phase 2: commit the QoS index, the knote's update and the owner.
        if is_request && deleting {
            workloop.qos_index = 0;
        } else if qos_index != 0 {
            workloop.qos_index = qos_index;
        }
        let mut wake = false;
        if let Some(knote) = workloop.sync.get_mut(&change.ident) {
            if deleting {
                if knote.saved & (NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE) == NOTE_WL_SYNC_WAIT {
                    knote.saved |= NOTE_WL_SYNC_WAKE;
                    wake = true;
                }
            } else {
                knote.saved = (knote.saved & !NOTE_WL_UPDATES_MASK) | change.fflags;
                wake = change.fflags & NOTE_WL_SYNC_WAKE != 0;
            }
        } else if let Some(request) = workloop.request.as_mut()
            && !deleting
        {
            request.saved = (request.saved & !NOTE_WL_UPDATES_MASK) | change.fflags;
            // `filt_wlremember_last_update`.
            request.kevent.fflags = change.fflags;
            request.kevent.data = 0;
            request.kevent.ext = change.ext;
        }
        workloop.owner = new_owner.filter(|&owner| Some(owner) != servicer);
        if wake {
            process.workloops.woken.notify_all();
        }
    } else if deleting {
        // An ignored ESTALE keeps the knote.
        return done(Ok(()), change);
    }
    if deleting {
        if is_request {
            workloop.request = None;
        } else {
            workloop.sync.remove(&change.ident);
            process.workloops.woken.notify_all();
        }
        return done(Ok(()), change);
    }
    // The touch: a thread request fires again unless its update was stale;
    // a waiter not yet woken waits again.
    if let Some(request) = workloop.request.as_mut().filter(|_| is_request) {
        if new_owner.is_some() {
            request.active = true;
            if change.fflags & NOTE_WL_UPDATE_QOS != 0 && change.qos != 0 {
                request.kevent.qos = kqworkq::normalize(change.qos as u32 as u64) as u32 as i32;
            }
        }
        if change.flags & EV_ENABLE != 0 {
            request.disabled = false;
        }
        if change.flags & EV_DISABLE != 0 {
            request.disabled = true;
        }
        request.kevent.udata = change.udata;
        return done(Ok(()), change);
    }
    let knote = workloop.sync.get_mut(&change.ident).expect("a sync knote");
    if new_owner.is_some()
        && change.fflags & NOTE_WL_COMMANDS_MASK == NOTE_WL_SYNC_WAIT
        && !knote.woken()
    {
        return wait(knote, caller, change);
    }
    done(Ok(()), change)
}

/// `kevent_register_wait_prepare`: the waiter is the caller, unless an
/// earlier wait of another thread left its mark (EXDEV).
fn wait(knote: &mut SyncKnote, caller: &Caller, change: Kevent) -> Registered {
    match knote.waiter {
        Some(waiter) if waiter != caller.thread => {
            Registered::Done(Some(change.failed_with(EXDEV)))
        }
        _ => {
            knote.waiter = Some(caller.thread);
            Registered::Wait(change.ident)
        }
    }
}

/// `filt_wlattach`.
fn attach(
    process: &Arc<Process>,
    id: u64,
    workloop: &mut Workloop,
    caller: &Caller,
    servicer: Option<u32>,
    mut change: Kevent,
) -> Registered {
    let failed = |change: Kevent, errno| Registered::Done(Some(change.failed_with(errno)));
    let command = change.fflags & NOTE_WL_COMMANDS_MASK;
    let disabled = change.flags & EV_DISABLE != 0;
    let mut qos_index = 0;
    match command {
        NOTE_WL_THREAD_REQUEST => {
            if change.ident != id {
                return failed(change, EINVAL);
            }
            qos_index = priority::thread_qos(change.qos as u32 as u64);
            if qos_index == priority::THREAD_QOS_UNSPECIFIED {
                return failed(change, ERANGE);
            }
            if workloop.qos_index != 0 {
                return failed(change, EALREADY);
            }
        }
        NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE => {
            if change.ident == id || !disabled || change.fflags & NOTE_WL_END_OWNERSHIP != 0 {
                return failed(change, EINVAL);
            }
        }
        NOTE_WL_SYNC_IPC => {
            if !disabled || change.fflags & (NOTE_WL_UPDATE_QOS | NOTE_WL_DISCOVER_OWNER) != 0 {
                return failed(change, EINVAL);
            }
            let mut probe = change;
            probe.fflags &= !NOTE_WL_DISCOVER_OWNER;
            return match debounce(process, caller, &mut probe, workloop.owner) {
                Err(ESTALE) if change.fflags & NOTE_WL_IGNORE_ESTALE != 0 => Registered::Done(None),
                Err(errno) => failed(change, errno),
                // No port here links a sync IPC chain.
                Ok(_) => failed(change, ENOENT),
            };
        }
        _ => return failed(change, EINVAL),
    }
    let new_owner = match debounce(process, caller, &mut change, workloop.owner) {
        Ok(new_owner) => new_owner,
        // A hidden ESTALE fails the attach quietly.
        Err(ESTALE) if change.fflags & NOTE_WL_IGNORE_ESTALE != 0 => {
            return Registered::Done(None);
        }
        Err(errno) => return failed(change, errno),
    };
    if qos_index != 0 {
        workloop.qos_index = qos_index;
    }
    workloop.owner = new_owner.filter(|&owner| Some(owner) != servicer);
    let priority = change.qos as u32 as u64;
    if priority & priority::OVERCOMMIT_FLAG != 0 {
        workloop.overcommit = true;
    }
    let receipt = change.flags & EV_RECEIPT != 0;
    if command == NOTE_WL_THREAD_REQUEST {
        workloop.request = Some(RequestKnote {
            kevent: Kevent {
                flags: change.flags | EV_CLEAR,
                qos: kqworkq::normalize(priority) as u32 as i32,
                fflags: 0,
                xflags: 0,
                ..change
            },
            saved: change.fflags,
            active: true,
            disabled,
        });
    } else {
        let knote = workloop.sync.entry(change.ident).or_insert(SyncKnote {
            saved: change.fflags,
            waiter: None,
        });
        if command == NOTE_WL_SYNC_WAIT {
            return wait(knote, caller, change);
        }
    }
    Registered::Done(receipt.then(|| change.failed_with(0)))
}

/// Collect a servicer's events (`kqueue_process` of its workloop): the
/// thread request while no owner holds the workloop, then each bucket's
/// host events, highest bucket first, up to `capacity`.
fn process_events(
    workloop: &mut Workloop,
    watch: &kqworkq::Watch,
    list: u64,
    capacity: u64,
    data: &mut DataBuffer,
) -> Result<Result<u64, u64>> {
    let mut count = 0;
    for bucket in (1..=BUCKETS).rev() {
        if count == capacity {
            break;
        }
        if workloop.owner.is_none()
            && let Some(request) = workloop.request.as_mut()
            && request.active
            && !request.disabled
            && request.bucket() == bucket
        {
            if !request.event().write(list, count) {
                return Ok(Err(EFAULT));
            }
            count += 1;
            // `EV_CLEAR`: delivering consumes it until its next touch.
            request.active = false;
        }
        let scanned =
            workloop
                .host
                .scan(bucket, list + count * KEVENT_BYTES, capacity - count, data);
        match scanned {
            Ok(scanned) => count += scanned,
            Err(errno) => return Ok(Err(errno)),
        }
        workloop.queued[usize::from(bucket - 1)] = false;
        workloop.host.rearm(bucket, watch)?;
    }
    Ok(Ok(count))
}

/// The monitor saw a workloop bucket's host kqueue become readable.
pub(super) fn fired(process: &Arc<Process>, tag: u32, bucket: u8) -> Result<()> {
    let mut table = process.workloops.table();
    let Some(&id) = table.by_tag.get(&tag) else {
        return Ok(());
    };
    let workloop = table.by_id.get_mut(&id).expect("a tagged workloop");
    workloop.queued[usize::from(bucket - 1)] = true;
    let schedule = redrive(process, id, workloop);
    drop(table);
    if schedule {
        workqueue::schedule(process)?;
    }
    Ok(())
}

/// The workloop a servicer is bound to lost it (`kqworkloop_unbind`):
/// request a new servicer if it still has events, or free it.
pub(super) fn unbound(process: &Arc<Process>, id: u64) -> Result<()> {
    let mut table = process.workloops.table();
    let schedule = match table.by_id.get(&id) {
        Some(workloop) => redrive(process, id, workloop),
        None => false,
    };
    table.release(process, id);
    drop(table);
    if schedule {
        workqueue::schedule(process)?;
    }
    Ok(())
}

/// The bound servicer's events as it leaves the kernel
/// (`kevent_workq_internal`): the workloop's identifier below `list`
/// (taken from the data area's top), then, with `changes` registered
/// first when it returns (`KEVENT_FLAG_PARKING`), their error events or
/// the workloop's events. A parking servicer of an owned workloop
/// receives none.
pub(super) fn servicer_events(
    kernel: &Kernel,
    id: u64,
    changes: Option<(u64, i64)>,
    list: u64,
    data: &mut DataBuffer,
) -> Result<Result<u64, u64>> {
    let process = &kernel.process;
    if !memory::write_u64(list - ID_BYTES, id) {
        return Ok(Err(EFAULT));
    }
    data.remaining = data.remaining.saturating_sub(ID_BYTES);
    let watch = match process.kqworkq.get(process) {
        Ok(kqueue) => kqueue,
        Err(errno) => return Ok(Err(errno)),
    };
    let caller = Caller {
        port: kernel.thread_port,
        thread: kernel.thread,
        kernel: true,
    };
    let mut table = process.workloops.table();
    let Some(workloop) = table.by_id.get_mut(&id) else {
        return Ok(Ok(0));
    };
    let mut schedule = false;
    if let Some((changes, count)) = changes {
        let registered =
            kqworkq::register_all(changes, count, list, kqworkq::LIST_LEN as i64, |change| {
                Ok(
                    match register(process, id, workloop, &watch.watch, &caller, change)? {
                        Registered::Done(result) => result,
                        Registered::Wait(_) => Some(change.failed_with(ENOTSUP)),
                    },
                )
            })?;
        schedule = redrive(process, id, workloop);
        match registered {
            Ok(0) => {}
            outputs => {
                drop(table);
                if schedule {
                    workqueue::schedule(process)?;
                }
                return Ok(outputs);
            }
        }
        if workloop.owner.is_some() {
            drop(table);
            if schedule {
                workqueue::schedule(process)?;
            }
            return Ok(Ok(0));
        }
    }
    let delivered = process_events(workloop, &watch.watch, list, kqworkq::LIST_LEN, data)?;
    drop(table);
    if schedule {
        workqueue::schedule(process)?;
    }
    Ok(delivered)
}

/// `kevent_id(id, changelist, nchanges, eventlist, nevents, data_out,
/// data_available, flags)`.
pub(super) fn kevent_id(kernel: &Kernel, arguments: [u64; 8]) -> Result<Result<u64, u64>> {
    let [
        id,
        changes,
        nchanges,
        events,
        nevents,
        data_out,
        data_available,
        flags,
    ] = arguments;
    let flags = match kqworkq::user_flags(flags, data_out, data_available) {
        Ok(flags) => flags & KEVENT_FLAG_USER,
        Err(errno) => return Ok(Err(errno)),
    };
    if flags & (KEVENT_FLAG_WORKQ | KEVENT_FLAG_WORKLOOP) != KEVENT_FLAG_WORKLOOP {
        return Ok(Err(EINVAL));
    }
    let (nchanges, nevents) = (i64::from(nchanges as i32), i64::from(nevents as i32));
    let requesting = flags & KEVENT_FLAG_ERROR_EVENTS == 0 && nevents > 0;
    let process = &kernel.process;
    let watch = match process.kqworkq.get(process) {
        Ok(kqueue) => kqueue,
        Err(errno) => return Ok(Err(errno)),
    };
    let bound = workqueue::workloop_of(kernel) == Some(id);
    let caller = Caller {
        port: kernel.thread_port,
        thread: kernel.thread,
        kernel: false,
    };
    let mut table = process.workloops.table();
    if bound {
        if flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST != 0 {
            return Ok(Err(EEXIST));
        }
    } else if requesting {
        return Ok(Err(EXDEV));
    }
    if let Err(errno) = table.get_or_create(id, flags) {
        return Ok(Err(errno));
    }
    table.by_id.get_mut(&id).expect("the workloop").calls += 1;
    let mut outputs: u64 = 0;
    let mut error = None;
    let mut index = 0;
    while index < nchanges.max(0) as u64 && error.is_none() {
        let Some(change) = Kevent::read(changes, index) else {
            error = Some(EFAULT);
            break;
        };
        let workloop = table.by_id.get_mut(&id).expect("a workloop in use");
        let registered = register(process, id, workloop, &watch.watch, &caller, &change)?;
        let result = match registered {
            Registered::Done(result) => result,
            Registered::Wait(ident) => {
                let last = index + 1 == nchanges as u64;
                if last
                    && (outputs as i64) < nevents
                    && flags & KEVENT_FLAG_ERROR_EVENTS != 0
                    && !caller.kernel
                {
                    // `filt_wlpost_register_wait`, then
                    // `kevent_register_wait_return`.
                    if redrive(process, id, workloop) {
                        drop(table);
                        workqueue::schedule(process)?;
                        table = process.workloops.table();
                    }
                    table = wait_for_wake(process, table, id, ident);
                    let result = (change.flags & EV_RECEIPT != 0).then(|| change.failed_with(0));
                    if let Some(result) = result {
                        if !result.write(events, outputs) {
                            error = Some(EFAULT);
                        } else {
                            outputs += 1;
                        }
                    }
                    index += 1;
                    continue;
                }
                Some(change.failed_with(ENOTSUP))
            }
        };
        if let Some(result) = result {
            if (outputs as i64) < nevents {
                if result.write(events, outputs) {
                    outputs += 1;
                } else {
                    error = Some(EFAULT);
                }
            } else if result.flags & EV_ERROR != 0 && result.data != 0 {
                error = Some(result.data as u64);
            }
        }
        index += 1;
    }
    let mut delivered = Ok(outputs);
    if let Some(errno) = error {
        delivered = Err(errno);
    } else if requesting && outputs == 0 {
        let workloop = table.by_id.get_mut(&id).expect("a workloop in use");
        let available = if data_out != 0 && data_available != 0 {
            memory::read_u64(data_available).unwrap_or(0)
        } else {
            0
        };
        let mut data = DataBuffer::new(data_out, available, flags & KEVENT_FLAG_STACK_DATA != 0);
        delivered = process_events(workloop, &watch.watch, events, nevents as u64, &mut data)?;
        if data_out != 0
            && data_available != 0
            && !memory::write_u64(data_available, data.remaining)
        {
            delivered = Err(EFAULT);
        }
    }
    let workloop = table.by_id.get_mut(&id).expect("a workloop in use");
    workloop.calls -= 1;
    let schedule = redrive(process, id, workloop);
    table.release(process, id);
    drop(table);
    if schedule {
        workqueue::schedule(process)?;
    }
    Ok(delivered)
}

/// `kqueue_workloop_ctl` and `kqueue_workloop_ctl_internal`.
pub(super) fn ctl(kernel: &Kernel, arguments: [u64; 8]) -> Result<Result<u64, u64>> {
    let [command, _options, address, size, ..] = arguments;
    if size < 4 {
        return Ok(Err(EINVAL));
    }
    let copied = (size as usize).min(PARAMS_BYTES);
    let Some(bytes) = memory::read(address, copied) else {
        return Ok(Err(EFAULT));
    };
    let mut raw = [0u8; PARAMS_BYTES];
    raw[..copied].copy_from_slice(&bytes);
    let word = |at: usize| i32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
    if word(0) != size as i32 {
        return Ok(Err(EINVAL));
    }
    let id = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let process = &kernel.process;
    match command {
        KQ_WORKLOOP_CREATE => {
            let params = match create_params(word(4), word(16), word(20), word(24), word(28)) {
                Ok(params) => params,
                Err(errno) => return Ok(Err(errno)),
            };
            let flags = word(4);
            // XNU looks the work interval up before the workloop.
            if flags & KQ_WORKLOOP_CREATE_WORK_INTERVAL != 0 {
                bail!(
                    "kqueue_workloop_ctl creating workloop {id:#x} with work interval port \
                     {:#x}: preadopting a work interval's thread group is not implemented",
                    word(32) as u32
                );
            }
            let mut table = process.workloops.table();
            if id == 0 || id == u64::MAX {
                return Ok(Err(EINVAL));
            }
            if table.by_id.contains_key(&id) {
                return Ok(Err(EEXIST));
            }
            if flags & KQ_WORKLOOP_CREATE_WITH_BOUND_THREAD != 0 {
                bail!(
                    "kqueue_workloop_ctl creating workloop {id:#x} with a bound thread: a \
                     servicer permanently bound to its workloop is not implemented"
                );
            }
            if let Err(errno) = table.get_or_create(id, KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST) {
                return Ok(Err(errno));
            }
            table.by_id.get_mut(&id).expect("the workloop").params = Some(params);
            Ok(Ok(0))
        }
        KQ_WORKLOOP_DESTROY => {
            let mut table = process.workloops.table();
            if let Err(errno) = table.get_or_create(id, KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST) {
                return Ok(Err(errno));
            }
            let workloop = table.by_id.get_mut(&id).expect("the workloop");
            let result = match workloop.params.as_mut() {
                Some(params) if !params.released => {
                    params.released = true;
                    Ok(0)
                }
                _ => Err(EINVAL),
            };
            table.release(process, id);
            Ok(result)
        }
        _ => Ok(Ok(0)),
    }
}

/// The parameters `KQ_WORKLOOP_CREATE` sets from `kqwlp_flags`,
/// `kqwlp_sched_pri`, `kqwlp_sched_pol`, `kqwlp_cpu_percent` and
/// `kqwlp_cpu_refillms`, or EINVAL as XNU checks them.
fn create_params(
    flags: i32,
    priority: i32,
    policy: i32,
    cpu_percent: i32,
    refill_ms: i32,
) -> Result<Params, u64> {
    if flags == 0 {
        return Err(EINVAL);
    }
    let priority = (flags & KQ_WORKLOOP_CREATE_SCHED_PRI != 0).then_some(priority);
    let policy = (flags & KQ_WORKLOOP_CREATE_SCHED_POL != 0).then_some(policy);
    let cpu_limit =
        (flags & KQ_WORKLOOP_CREATE_CPU_PERCENT != 0).then_some((cpu_percent, refill_ms));
    if priority.is_some_and(|priority| !(1..=MAXPRI_USER).contains(&priority))
        || policy.is_some_and(|policy| !POLICIES.contains(&policy))
        || cpu_limit.is_some_and(|(percent, refill)| {
            !(1..=100).contains(&percent) || !(1..=MAX_REFILL_MS).contains(&refill)
        })
    {
        return Err(EINVAL);
    }
    let params = Params {
        priority: priority.map(|priority| priority as u8),
        policy: policy.map(|policy| policy as u8),
        cpu_limit: cpu_limit.map(|(percent, refill)| (percent as u8, refill as u32)),
        released: false,
    };
    let any = params.priority.is_some() || params.policy.is_some() || params.cpu_limit.is_some();
    let other = flags & (KQ_WORKLOOP_CREATE_WORK_INTERVAL | KQ_WORKLOOP_CREATE_WITH_BOUND_THREAD);
    if !any && other == 0 {
        return Err(EINVAL);
    }
    Ok(params)
}

/// Block until the sync knote `ident` is woken or dropped.
fn wait_for_wake<'a>(
    process: &'a Arc<Process>,
    mut table: MutexGuard<'a, Table>,
    id: u64,
    ident: u64,
) -> MutexGuard<'a, Table> {
    loop {
        let waiting = table
            .by_id
            .get(&id)
            .and_then(|workloop| workloop.sync.get(&ident))
            .is_some_and(|knote| !knote.woken());
        if !waiting {
            return table;
        }
        table = process
            .workloops
            .woken
            .wait(table)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workloop_updates_validate_as_xnu() {
        let wait = Kevent {
            flags: EV_ADD | EV_DISABLE,
            fflags: NOTE_WL_SYNC_WAKE,
            ..Kevent::default()
        };
        assert_eq!(validate(NOTE_WL_SYNC_WAIT, &wait), Ok(0));
        assert_eq!(validate(NOTE_WL_THREAD_REQUEST, &wait), Err(EINVAL));
        let enable = Kevent {
            flags: EV_ENABLE,
            ..wait
        };
        assert_eq!(validate(NOTE_WL_SYNC_WAIT, &enable), Err(EINVAL));
        let update = Kevent {
            flags: EV_ADD | EV_ENABLE,
            fflags: NOTE_WL_THREAD_REQUEST | NOTE_WL_UPDATE_QOS,
            qos: priority::from_thread_qos(priority::THREAD_QOS_USER_INITIATED, 0, 0) as i32,
            ..Kevent::default()
        };
        assert_eq!(
            validate(NOTE_WL_THREAD_REQUEST, &update),
            Ok(priority::THREAD_QOS_USER_INITIATED)
        );
        assert_eq!(
            validate(NOTE_WL_THREAD_REQUEST, &Kevent { qos: 0, ..update }),
            Err(ERANGE)
        );
        let delete = Kevent {
            flags: EV_DELETE,
            fflags: NOTE_WL_THREAD_REQUEST | NOTE_WL_DISCOVER_OWNER,
            ..Kevent::default()
        };
        assert_eq!(validate(NOTE_WL_THREAD_REQUEST, &delete), Err(EINVAL));
    }

    #[test]
    fn the_wakeup_qos_is_the_highest_active_bucket() {
        let mut workloop = Workloop::new(1);
        assert_eq!(workloop.wakeup_qos(), 0);
        workloop.queued[usize::from(priority::THREAD_QOS_BACKGROUND - 1)] = true;
        assert_eq!(workloop.wakeup_qos(), priority::THREAD_QOS_BACKGROUND);
        let qos = priority::from_thread_qos(priority::THREAD_QOS_USER_INITIATED, 0, 0) as i32;
        workloop.request = Some(RequestKnote {
            kevent: Kevent {
                qos,
                ..Kevent::default()
            },
            saved: NOTE_WL_THREAD_REQUEST,
            active: true,
            disabled: false,
        });
        assert_eq!(workloop.wakeup_qos(), priority::THREAD_QOS_USER_INITIATED);
        workloop.request.as_mut().unwrap().active = false;
        assert_eq!(workloop.wakeup_qos(), priority::THREAD_QOS_BACKGROUND);
        assert!(!workloop.idle());
    }

    #[test]
    fn workloop_parameters_validate_and_hold_the_workloop_as_xnu() {
        assert_eq!(create_params(0, 0, 0, 0, 0), Err(EINVAL));
        // A flag naming no parameter sets none.
        assert_eq!(create_params(0x20, 0, 0, 0, 0), Err(EINVAL));
        assert_eq!(
            create_params(KQ_WORKLOOP_CREATE_SCHED_PRI, 64, 0, 0, 0),
            Err(EINVAL)
        );
        assert_eq!(
            create_params(KQ_WORKLOOP_CREATE_SCHED_POL, 0, 3, 0, 0),
            Err(EINVAL)
        );
        assert_eq!(
            create_params(KQ_WORKLOOP_CREATE_CPU_PERCENT, 0, 0, 50, 0x0100_0000),
            Err(EINVAL)
        );
        let params = create_params(
            KQ_WORKLOOP_CREATE_SCHED_PRI | KQ_WORKLOOP_CREATE_SCHED_POL,
            47,
            4,
            0,
            0,
        )
        .unwrap();
        assert_eq!(
            (params.priority, params.policy, params.cpu_limit),
            (Some(47), Some(4), None)
        );
        let mut workloop = Workloop::new(1);
        assert!(workloop.idle());
        workloop.params = Some(params);
        assert!(!workloop.idle());
        workloop.params.as_mut().unwrap().released = true;
        assert!(workloop.idle());
    }
}
