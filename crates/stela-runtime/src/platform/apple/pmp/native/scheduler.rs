//! Concrete Stela cooperative native queue and keyed waiter resource.
//!
//! Original26A434 T8112 PMP SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! 102fe64..103031c owns queue registration/dispatch/recursive locks;
//! 1023624/102380c owns keyed notification/wait;1030250 releases and restores
//! queue recursion around a wait. Evidence: metrics-backend-destinations-r1.
//!
//! This executes mandatory native Rust callbacks with kept continuations;
//! it never runs Apple firmware or invents a source thread pointer. Thread IDs
//! are identities allocated by this cooperative runtime. Source stack
//! bytes are held configuration metadata, not a claim to execute the Apple
//! stack ABI. Rc ownership restricts this resource to one cooperative executor.
use super::platform::owner::Completion;
use alloc::{
    boxed::Box,
    rc::{Rc, Weak},
    string::String,
    vec::Vec,
};
use core::{
    cell::{Cell, RefCell},
    sync::atomic::{Ordering, fence},
};
use stela_contracts::bus::Access;

mod dispatch;
mod waits;
pub use waits::{Key, Lease, Wait};

type Result<T> = core::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Contract(&'static str),
    Callback(&'static str),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueConfiguration {
    pub name: String,
    pub stack_bytes: u32,
    pub priority: u8,
}
impl QueueConfiguration {
    ///1031064: global queue, distinct from the MC callback queue.
    pub fn global_reporting() -> Self {
        Self {
            name: "rtk_ep_work".into(),
            stack_bytes: 0x800,
            priority: 57,
        }
    }
    ///1003344/10165d4: MC queue, priority61-selector2.
    pub fn mc_metrics() -> Self {
        Self {
            name: "mem-cache".into(),
            stack_bytes: 0x800,
            priority: 59,
        }
    }
}
/// A required callback, not a default completion or an unbound target ID.
/// Busy/refusal keeps the same Invocation and the callback's prefix.
/// Retired value is the source return: nonzero requeues queued work. A callback
/// may wake its own Work while Busy; retirement0 never clears that later wake.
pub trait Callback {
    fn advance(&mut self, invocation: &Invocation, access: &mut Access<'_>) -> Completion<u32>;
}
impl<F> Callback for F
where
    F: FnMut(&Invocation, &mut Access<'_>) -> Completion<u32>,
{
    fn advance(&mut self, i: &Invocation, a: &mut Access<'_>) -> Completion<u32> {
        self(i, a)
    }
}
#[derive(Clone)]
pub struct Runtime {
    state: Rc<RefCell<State>>,
}
/// Weak callback capture avoids Runtime -> callback -> service/runtime cycles.
#[derive(Clone)]
pub struct WeakRuntime {
    state: Weak<RefCell<State>>,
}
impl WeakRuntime {
    pub fn upgrade(&self) -> Option<Runtime> {
        self.state.upgrade().map(|state| Runtime { state })
    }
}
#[derive(Clone)]
pub struct Queue {
    runtime: Weak<RefCell<State>>,
    id: usize,
    thread: Rc<Thread>,
}
impl Queue {
    pub fn configuration(&self) -> Result<QueueConfiguration> {
        let state = self
            .runtime
            .upgrade()
            .ok_or(Error::Contract("native scheduler abandoned"))?;
        let config = state.borrow().queues[self.id].config.clone();
        Ok(config)
    }
    pub fn thread_id(&self) -> u32 {
        self.thread.id
    }
    pub fn same_queue(&self, other: &Self) -> bool {
        self.runtime.ptr_eq(&other.runtime) && self.id == other.id
    }
}
struct WorkCells {
    enabled: Cell<bool>,
    pending: Cell<bool>,
}
/// Clones reference the SAME source work.enabled/work.pending cells. Services
/// must remove local copies of those bits. No public set-pending/complete API.
#[derive(Clone)]
pub struct Work {
    runtime: Weak<RefCell<State>>,
    id: usize,
    cells: Rc<WorkCells>,
}
impl Work {
    pub fn pending(&self) -> bool {
        self.cells.pending.get()
    }
    pub fn enabled(&self) -> bool {
        self.cells.enabled.get()
    }
    /// Registered queue, not a local backend promise of registration.
    pub fn registered_queue(&self) -> Result<Option<Queue>> {
        let state = self
            .runtime
            .upgrade()
            .ok_or(Error::Contract("native scheduler abandoned"))?;
        let s = state.borrow();
        Ok(s.works[self.id].queue.map(|id| Queue {
            runtime: self.runtime.clone(),
            id,
            thread: s.queues[id].thread.clone(),
        }))
    }
    pub fn same_work(&self, other: &Self) -> bool {
        self.runtime.ptr_eq(&other.runtime) && self.id == other.id
    }
    /// Valid only inside this work's scheduler-entered callback. The
    /// pending bit was already cleared; numeric flags are not dispatch proof.
    pub fn validate_dispatch(&self, invocation: &Invocation) -> Result<()> {
        invocation.check_current()?;
        if !self.runtime.ptr_eq(&invocation.runtime) || invocation.frame.kind != Kind::Work(self.id)
        {
            return Err(Error::Contract("foreign native work dispatch"));
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct Immediate {
    runtime: Weak<RefCell<State>>,
    id: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Work(usize),
    Immediate(usize),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Active,
    Retired,
}
struct Thread {
    id: u32,
    priority: u8,
    wait: RefCell<Option<Rc<waits::Waiting>>>,
    mutex: Cell<Option<usize>>,
}
struct Frame {
    serial: u64,
    kind: Kind,
    thread: Rc<Thread>,
    status: Cell<Status>,
    executing: Cell<bool>,
    deadline: Cell<Option<u64>>,
    leases: Cell<u32>,
}
/// Execution context of a cooperative native callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    /// Callback executes on this native cooperative thread, outside
    /// scheduler critical sections; it is not an Apple IRQ/firmware context.
    CooperativeThread { thread_id: u32, priority: u8 },
}
/// Opaque callback context, minted only by dispatch. Cloning keeps
/// identity, not completion/arrival permission. Stale/outside-execution contexts
/// fail validation. Thread ID belongs to the real cooperative owner, not a cast
/// of a host or fictional Apple object address.
#[derive(Clone)]
pub struct Invocation {
    runtime: Weak<RefCell<State>>,
    frame: Rc<Frame>,
}
impl Invocation {
    pub fn thread_id(&self) -> u32 {
        self.frame.thread.id
    }
    pub fn serial(&self) -> u64 {
        self.frame.serial
    }
    pub fn context(&self) -> Result<Context> {
        self.check_current()?;
        Ok(Context::CooperativeThread {
            thread_id: self.thread_id(),
            priority: self.priority(),
        })
    }
    pub fn priority(&self) -> u8 {
        self.frame.thread.priority
    }
    pub fn same_dispatch(&self, other: &Self) -> bool {
        self.runtime.ptr_eq(&other.runtime) && Rc::ptr_eq(&self.frame, &other.frame)
    }
    pub fn work(&self) -> Result<Option<Work>> {
        let state = self
            .runtime
            .upgrade()
            .ok_or(Error::Contract("native scheduler abandoned"))?;
        let s = state.borrow();
        Ok(match self.frame.kind {
            Kind::Work(id) => Some(s.work_handle(&state, id)),
            Kind::Immediate(_) => None,
        })
    }
    pub fn check_current(&self) -> Result<()> {
        let state = self
            .runtime
            .upgrade()
            .ok_or(Error::Contract("native scheduler abandoned"))?;
        let s = state.borrow();
        if self.frame.status.get() != Status::Active
            || !self.frame.executing.get()
            || !s.context.last().is_some_and(|f| Rc::ptr_eq(f, &self.frame))
        {
            return Err(Error::Contract(
                "native invocation is stale or not executing",
            ));
        }
        Ok(())
    }
}
/// Callback outcome. Retired-with-refusal has already retired its real
/// prefix and cannot be replayed. No public method invents this outcome.
pub enum Progress {
    Idle,
    Busy {
        deadline: Option<u64>,
    },
    Retired {
        invocation: Invocation,
        source_return: u32,
        refusal: Option<&'static str>,
    },
}
struct QueueState {
    config: QueueConfiguration,
    thread: Rc<Thread>,
    order: Vec<usize>,
    sorted: bool,
    cursor: usize,
    scanning: bool,
    retry_cycle: bool,
    notified: bool,
    active: Option<usize>,
    lock: Option<u32>,
    depth: u32,
}
struct Target {
    callback: Option<Box<dyn Callback>>,
    frame: Option<Rc<Frame>>,
    retired: Option<(u32, Option<&'static str>)>,
}
struct WorkState {
    cells: Rc<WorkCells>,
    priority: u8,
    queue: Option<usize>,
    target: Target,
}
struct ImmediateState {
    name: String,
    thread: Rc<Thread>,
    target: Target,
}
struct State {
    serial: u64,
    next_thread: u32,
    global: Option<usize>,
    queues: Vec<QueueState>,
    works: Vec<WorkState>,
    immediate: Vec<ImmediateState>,
    context: Vec<Rc<Frame>>,
    waiters: Vec<Weak<waits::Waiting>>,
}
impl State {
    fn next_serial(&self) -> Result<u64> {
        self.serial
            .checked_add(1)
            .ok_or(Error::Contract("native scheduler serial exhausted"))
    }
    fn thread(&mut self, priority: u8) -> Result<Rc<Thread>> {
        let id = self
            .next_thread
            .checked_add(1)
            .ok_or(Error::Contract("native thread IDs exhausted"))?;
        self.next_thread = id;
        Ok(Rc::new(Thread {
            id,
            priority,
            wait: RefCell::new(None),
            mutex: Cell::new(None),
        }))
    }
    fn work_handle(&self, runtime: &Rc<RefCell<Self>>, id: usize) -> Work {
        Work {
            runtime: Rc::downgrade(runtime),
            id,
            cells: self.works[id].cells.clone(),
        }
    }
    fn target(&self, kind: Kind) -> &Target {
        match kind {
            Kind::Work(id) => &self.works[id].target,
            Kind::Immediate(id) => &self.immediate[id].target,
        }
    }
    fn target_mut(&mut self, kind: Kind) -> &mut Target {
        match kind {
            Kind::Work(id) => &mut self.works[id].target,
            Kind::Immediate(id) => &mut self.immediate[id].target,
        }
    }
}
impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}
impl Runtime {
    pub fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(State {
                serial: 0,
                next_thread: 0,
                global: None,
                queues: Vec::new(),
                works: Vec::new(),
                immediate: Vec::new(),
                context: Vec::new(),
                waiters: Vec::new(),
            })),
        }
    }
    pub fn downgrade(&self) -> WeakRuntime {
        WeakRuntime {
            state: Rc::downgrade(&self.state),
        }
    }
    fn check_runtime(&self, other: &Weak<RefCell<State>>) -> Result<()> {
        if !Rc::downgrade(&self.state).ptr_eq(other) {
            return Err(Error::Contract("foreign native scheduler resource"));
        }
        Ok(())
    }
    pub fn create_queue(&self, config: QueueConfiguration) -> Result<Queue> {
        if config.name.is_empty() || config.stack_bytes == 0 || config.priority >= 64 {
            return Err(Error::Contract("invalid native queue source configuration"));
        }
        let mut s = self.state.borrow_mut();
        let thread = s.thread(config.priority)?;
        let id = s.queues.len();
        s.queues.push(QueueState {
            config,
            thread: thread.clone(),
            order: Vec::new(),
            sorted: false,
            cursor: 0,
            scanning: false,
            retry_cycle: false,
            notified: false,
            active: None,
            lock: None,
            depth: 0,
        });
        Ok(Queue {
            runtime: Rc::downgrade(&self.state),
            id,
            thread,
        })
    }
    /// Canonical107a908 queue shared by reporting and trace in this native
    /// runtime. It is not a second queue per backend or per registration.
    pub fn global_reporting_queue(&self) -> Result<Queue> {
        if let Some(id) = self.state.borrow().global {
            return Ok(Queue {
                runtime: Rc::downgrade(&self.state),
                id,
                thread: self.state.borrow().queues[id].thread.clone(),
            });
        }
        let queue = self.create_queue(QueueConfiguration::global_reporting())?;
        self.state.borrow_mut().global = Some(queue.id);
        Ok(queue)
    }
    pub fn queue_configuration(&self, queue: &Queue) -> Result<QueueConfiguration> {
        self.check_runtime(&queue.runtime)?;
        Ok(self.state.borrow().queues[queue.id].config.clone())
    }
    ///10302c0 binds a callback, enabled1/pending0, not a fake resource ID.
    pub fn bind_work<C: Callback + 'static>(&self, priority: u8, callback: C) -> Result<Work> {
        let cells = Rc::new(WorkCells {
            enabled: Cell::new(true),
            pending: Cell::new(false),
        });
        let mut s = self.state.borrow_mut();
        let id = s.works.len();
        s.works.push(WorkState {
            cells: cells.clone(),
            priority,
            queue: None,
            target: Target {
                callback: Some(Box::new(callback)),
                frame: None,
                retired: None,
            },
        });
        Ok(Work {
            runtime: Rc::downgrade(&self.state),
            id,
            cells,
        })
    }
    ///1030144: one registration; stable descending priority insertion, equal
    ///priority registration order. Wake-before-registration remains pending.
    pub fn register_work(&self, queue: &Queue, work: &Work) -> Completion<()> {
        if self
            .check_runtime(&queue.runtime)
            .and_then(|()| self.check_runtime(&work.runtime))
            .is_err()
        {
            return Completion::Refused("foreign native queue/work registration");
        }
        let mut s = self.state.borrow_mut();
        if s.works[work.id].queue.is_some() {
            return Completion::Refused("native work already registered");
        }
        let current = s.context.last().map(|f| f.thread.clone());
        let q = &s.queues[queue.id];
        if q.lock
            .is_some_and(|owner| current.as_ref().is_none_or(|t| t.id != owner))
        {
            if let Some(thread) = current {
                thread.mutex.set(Some(queue.id));
            }
            return Completion::Busy { deadline: None };
        }
        let priority = s.works[work.id].priority;
        let sorted = q.sorted || priority != 15;
        let position = if sorted {
            q.order
                .iter()
                .position(|id| priority > s.works[*id].priority)
                .unwrap_or(q.order.len())
        } else {
            q.order.len()
        };
        if let Some(thread) = current {
            thread.mutex.set(None);
        }
        s.works[work.id].queue = Some(queue.id);
        let q = &mut s.queues[queue.id];
        q.sorted = sorted;
        q.order.insert(position, work.id);
        // A sorted queue restarts at head after each callback; an insertion
        // before the scan cursor must preserve its current logical successor.
        if position < q.cursor {
            q.cursor += 1;
        }
        if work.enabled() && work.pending() {
            q.notified = true;
        }
        Completion::Retired {
            value: (),
            refusal: None,
        }
    }
    /// Source10302e4: real enabled check, release boundary, sole pending cell
    /// mutation and queue wake credit. Wake is scheduling, not completion.
    pub fn wake(&self, work: &Work) -> Result<()> {
        self.check_runtime(&work.runtime)?;
        if !work.enabled() {
            return Err(Error::Contract("source native work is disabled"));
        }
        let mut s = self.state.borrow_mut();
        fence(Ordering::Release);
        work.cells.pending.set(true);
        if let Some(queue) = s.works[work.id].queue {
            s.queues[queue].notified = true;
        }
        Ok(())
    }
    pub fn current(&self) -> Option<Invocation> {
        self.state.borrow().context.last().map(|frame| Invocation {
            runtime: Rc::downgrade(&self.state),
            frame: frame.clone(),
        })
    }
    /// Mandatory real endpoint/source callback, separately dispatchable while
    ///queued DB work is waiting. It receives no manufactured mailbox input.
    pub fn register_immediate<C: Callback + 'static>(
        &self,
        name: &str,
        priority: u8,
        callback: C,
    ) -> Result<Immediate> {
        if name.is_empty() || priority >= 64 {
            return Err(Error::Contract(
                "invalid native immediate callback configuration",
            ));
        }
        let mut s = self.state.borrow_mut();
        let thread = s.thread(priority)?;
        let id = s.immediate.len();
        s.immediate.push(ImmediateState {
            name: name.into(),
            thread,
            target: Target {
                callback: Some(Box::new(callback)),
                frame: None,
                retired: None,
            },
        });
        Ok(Immediate {
            runtime: Rc::downgrade(&self.state),
            id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;
    struct Count(Rc<Cell<u32>>);
    impl Callback for Count {
        fn advance(&mut self, i: &Invocation, _: &mut Access<'_>) -> Completion<u32> {
            i.check_current().unwrap();
            self.0.set(self.0.get() + 1);
            Completion::Retired {
                value: 0,
                refusal: None,
            }
        }
    }
    fn step(r: &Runtime) -> Result<Progress> {
        let mut latch = InterruptLatch::new();
        r.step(&mut Access::new(0, 7, &mut latch))
    }
    #[test]
    fn shared_work_pending_before_registration_is_one_actual_source_cell() {
        let runtime = Runtime::new();
        let count = Rc::new(Cell::new(0));
        let work = runtime.bind_work(15, Count(count.clone())).unwrap();
        let same = work.clone();
        assert!(work.enabled());
        assert!(!work.pending());
        runtime.wake(&work).unwrap();
        assert!(same.pending());
        assert!(matches!(step(&runtime).unwrap(), Progress::Idle));
        let global = runtime
            .create_queue(QueueConfiguration::global_reporting())
            .unwrap();
        assert!(matches!(
            runtime.register_work(&global, &work),
            Completion::Retired { .. }
        ));
        assert!(matches!(
            step(&runtime).unwrap(),
            Progress::Retired {
                source_return: 0,
                ..
            }
        ));
        assert_eq!(count.get(), 1);
        assert!(!same.pending());
        assert!(runtime.current().is_none());
        assert!(matches!(
            runtime.register_work(&global, &same),
            Completion::Refused(_)
        ));
    }
    #[test]
    fn source_queues_are_distinct_and_foreign_handles_cannot_wake_or_register() {
        let runtime = Runtime::new();
        let other = Runtime::new();
        let global = runtime
            .create_queue(QueueConfiguration::global_reporting())
            .unwrap();
        let mc = runtime
            .create_queue(QueueConfiguration::mc_metrics())
            .unwrap();
        assert!(!global.same_queue(&mc));
        assert_ne!(global.thread_id(), mc.thread_id());
        assert_eq!(
            runtime.queue_configuration(&global).unwrap().name,
            "rtk_ep_work"
        );
        assert_eq!(runtime.queue_configuration(&mc).unwrap().priority, 59);
        let w = runtime.bind_work(15, Count(Rc::new(Cell::new(0)))).unwrap();
        assert!(other.wake(&w).is_err());
        let q = other
            .create_queue(QueueConfiguration::mc_metrics())
            .unwrap();
        assert!(matches!(
            other.register_work(&q, &w),
            Completion::Refused(_)
        ));
        assert!(!w.pending());
    }
    #[test]
    fn serial_exhaustion_precedes_pending_clear_lock_or_callback_effects() {
        let runtime = Runtime::new();
        let q = runtime
            .create_queue(QueueConfiguration::mc_metrics())
            .unwrap();
        let count = Rc::new(Cell::new(0));
        let w = runtime.bind_work(15, Count(count.clone())).unwrap();
        runtime.register_work(&q, &w);
        runtime.wake(&w).unwrap();
        runtime.state.borrow_mut().serial = u64::MAX;
        assert!(matches!(step(&runtime), Err(Error::Contract(_))));
        assert!(w.pending());
        assert_eq!(runtime.queue_lock_depth(&q).unwrap(), 0);
        assert_eq!(count.get(), 0);
    }
}

#[cfg(all(test, feature = "std"))]
mod original_tests {
    #[test]
    #[ignore = "oracle: STELA_TEST_PMP_T8112"]
    fn original_t8112_scheduler_pending_callback_wait_and_queue_operands() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        let word = |address: usize| {
            u32::from_le_bytes(
                bytes[address - 0xfff000..address - 0xfff000 + 4]
                    .try_into()
                    .unwrap(),
            )
        };
        for (address, expected) in [
            (0x102ff10, 0x3900077f),
            (0x102ff14, 0xd5033bbf),
            (0x102ff2c, 0xd63f0100),
            (0x103002c, 0xb9401013),
            (0x1030030, 0xb900101f),
            (0x10302b4, 0xb9001275),
            (0x10302d4, 0x3900041f),
            (0x10302dc, 0x39000008),
            (0x10302f4, 0xd5033bbf),
            (0x10302f8, 0x39000409),
            (0x1023684, 0xeb16015f),
        ] {
            assert_eq!(word(address), expected, "{address:x}");
        }
        for (address, expected) in [
            (0x103022c, 0x1030048),
            (0x1030240, 0x1030074),
            (0x1030284, 0x10323a8),
            (0x103028c, 0x1030020),
            (0x10302a4, 0x102380c),
            (0x10302ac, 0x10235a0),
            (0x10302bc, 0x1023624),
            (0x103030c, 0x1023cf0),
        ] {
            let instruction = word(address);
            assert_eq!(instruction & 0x7c000000, 0x14000000);
            let displacement = ((instruction << 6) as i32 >> 6) as i64;
            assert_eq!(address as i64 + displacement * 4, expected);
        }
        assert_eq!(&bytes[0x37c14..0x37c20], b"rtk_ep_work\0");
    }
}
