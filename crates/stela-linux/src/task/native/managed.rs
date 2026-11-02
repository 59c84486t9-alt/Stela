//! CPU-local owned jobs through original PID1 -> kthread_create -> kthreadd.
//! Queue acceptance is NOT a native Ticket, child, callback or Ready.
use super::*;
use core::sync::atomic::AtomicI32;
const QUEUED: u8 = 0;
const CREATING: u8 = 1;
const WAITING: u8 = 2;
const CANCELLED: u8 = 3;
const CALLBACK_ENTERED: u64 = 1;
const CALLBACK_RETURNED: u64 = 2;
const ASSOCIATED: u64 = 4;
const NATIVE_RETIRED: u64 = 8;
const PRODUCERS_JOINED: u64 = 16;
const JOINED: u64 = 32;
const NO_C_OWNER: u64 = 64;
const SKIPPED: u64 = 128;
const CREATE_FAILED: u64 = 256;
const INTERRUPTED: u64 = 512;
const CALLER_RETURNED: u64 = 1024;
#[repr(C)]
struct Lease {
    _opaque: [u8; 0],
}
unsafe extern "C" {
    fn stela_linux_managed_create(
        owner: *const RawOwner,
        context: *mut c_void,
        run: unsafe extern "C" fn(*mut c_void) -> i32,
        lease: *mut *mut Lease,
    ) -> i32;
    fn stela_linux_managed_lease_release(lease: *mut Lease, owner: *const RawOwner) -> i32;
    fn stela_linux_managed_lease_context(lease: *mut Lease, owner: *const RawOwner) -> *mut c_void;
    fn stela_linux_task_managed_birth_owner(
        task: *mut CTask,
        owner: *const RawOwner,
        generation: u64,
    ) -> *mut Lease;
}
/// Actual owned Rust job; no Send requirement because one checked native CPU
/// and the same original managed source runtime execute it.
/// # Safety
/// Retain all callback/code/context resources through final JoinedJob, not just
/// callback return. run may park in original source code but must not expose a
/// mutable job borrow to another continuation. Original C resources must close
/// in real source process context BEFORE completion, or remain safely retained;
/// extracting/dropping JoinedJob never manufactures a source current.
pub unsafe trait ManagedJob: 'static {
    fn run(self: Pin<&mut Self>);
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    CallbackReturned,
    Skipped(i32),
    CreationFailed(i32),
    ExitedWithoutReturn,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    pub callback_entered: bool,
    pub callback_returned: bool,
    pub source_interrupted: bool,
    pub native_birth_associated: bool,
    pub native_record_retired: bool,
    pub source_producers_joined: bool,
    pub joined: bool,
}
#[derive(Debug)]
pub enum SubmitError {
    Capacity,
    Context(WorkError),
}
pub struct RejectedJob {
    pub error: SubmitError,
    pub job: Pin<Box<dyn ManagedJob>>,
}
/// Constructed only by exact Pending::try_join after real source/native closure.
/// Ownership joins this exact job, not arbitrary device/DMA/transport resources.
pub struct JoinedJob {
    outcome: Outcome,
    job: Pin<Box<dyn ManagedJob>>,
}
impl JoinedJob {
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }
    /// Recover the exact originally submitted owned job after the genuine join.
    /// Job's own original C resources must already close in source context or
    /// remain retained; this extraction grants no C current/device retirement.
    pub fn into_job(self) -> Pin<Box<dyn ManagedJob>> {
        self.job
    }
}
/// Default abandonment retains real job/context/producers; never cancels them.
pub struct Pending {
    node: ManuallyDrop<Arc<Node>>,
    _local: PhantomData<Rc<()>>,
}
struct Node {
    queue: &'static Queue,
    slot: &'static ManagedSlot,
    job: UnsafeCell<ManuallyDrop<Option<Pin<Box<dyn ManagedJob>>>>>,
    phase: AtomicU8,
    flags: AtomicU64,
    events: AtomicBool,
    result: AtomicI32,
    // C writes exactly once BEFORE its first publication/event. All source
    // producers and this transport are serialized on the same checked CPU.
    lease: UnsafeCell<*mut Lease>,
    native_generation: AtomicU64,
}
struct ManagedSlot {
    pointer: AtomicPtr<Node>,
    readers: AtomicUsize,
    closing: AtomicBool,
    close_pending: AtomicBool,
    retired: UnsafeCell<ManuallyDrop<Option<Arc<Node>>>>,
    delivery: Arc<Delivery>,
}
pub(super) struct Queue {
    owner: *const RawOwner,
    slots: Box<[ManagedSlot]>,
    delivery: Arc<Delivery>,
}
struct Reader<'a> {
    slot: &'a ManagedSlot,
    pointer: *mut Node,
}
impl Drop for Reader<'_> {
    fn drop(&mut self) {
        if self.slot.readers.fetch_sub(1, Ordering::Release) == 0 {
            fatal();
        }
        if !self.pointer.is_null() && self.slot.closing.load(Ordering::Acquire) {
            self.slot.close_pending.store(true, Ordering::Release);
            self.slot.delivery.record();
        }
    }
}
impl ManagedSlot {
    fn read(&self) -> Reader<'_> {
        if self
            .readers
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .is_err()
        {
            fatal();
        }
        Reader {
            slot: self,
            pointer: self.pointer.load(Ordering::Acquire),
        }
    }
}
impl Queue {
    pub(super) fn new(
        owner: *const RawOwner,
        delivery: Arc<Delivery>,
        capacity: usize,
    ) -> Result<Self, WorkError> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| WorkError::Full)?;
        for _ in 0..capacity {
            slots.push(ManagedSlot {
                pointer: AtomicPtr::new(ptr::null_mut()),
                readers: AtomicUsize::new(0),
                closing: AtomicBool::new(false),
                close_pending: AtomicBool::new(false),
                retired: UnsafeCell::new(ManuallyDrop::new(None)),
                delivery: delivery.clone(),
            });
        }
        Ok(Self {
            owner,
            slots: slots.into_boxed_slice(),
            delivery,
        })
    }
    pub(super) fn submit(
        &'static self,
        job: Pin<Box<dyn ManagedJob>>,
    ) -> Result<Pending, RejectedJob> {
        // Checked caller holds one bounded native metadata segment. Reserve a
        // row with closing CAS; no C constructor/child exists in this branch.
        let Some(slot) = self.slots.iter().find(|slot| {
            slot.pointer.load(Ordering::Acquire).is_null()
                && slot
                    .closing
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
        }) else {
            return Err(RejectedJob {
                error: SubmitError::Capacity,
                job,
            });
        };
        slot.close_pending.store(false, Ordering::Release);
        let node = Arc::new(Node {
            queue: self,
            slot,
            job: UnsafeCell::new(ManuallyDrop::new(Some(job))),
            phase: AtomicU8::new(QUEUED),
            flags: AtomicU64::new(0),
            events: AtomicBool::new(true),
            result: AtomicI32::new(0),
            lease: UnsafeCell::new(ptr::null_mut()),
            native_generation: AtomicU64::new(0),
        });
        let held = node.clone();
        slot.pointer
            .store(Arc::into_raw(node) as *mut Node, Ordering::Release);
        slot.closing.store(false, Ordering::Release);
        self.delivery.record();
        Ok(Pending {
            node: ManuallyDrop::new(held),
            _local: PhantomData,
        })
    }
    pub(super) fn pending(&self) -> bool {
        for slot in &self.slots {
            if slot.close_pending.load(Ordering::Acquire) {
                return true;
            }
            let read = slot.read();
            if !read.pointer.is_null() && unsafe { &*read.pointer }.events.load(Ordering::Acquire) {
                return true;
            }
        }
        false
    }
    /// Called only against an actual Factory-born record under fresh bounded
    /// constructor metadata scope. NULL is genuine unmanaged source ancestry.
    pub(super) unsafe fn associate(&self, record: *mut CTask, generation: u64) {
        let lease = unsafe { stela_linux_task_managed_birth_owner(record, self.owner, generation) };
        if lease.is_null() {
            return;
        }
        let context = unsafe { stela_linux_managed_lease_context(lease, self.owner) };
        let node = unsafe { node(context, lease, self.owner) };
        if !ptr::eq(node.queue, self)
            || node.flags.fetch_or(ASSOCIATED, Ordering::AcqRel) & ASSOCIATED != 0
        {
            fatal();
        }
        node.native_generation.store(generation, Ordering::Release);
    }
    /// Genuine PID1 source process. NO row guard/native permission survives the
    /// original create wait; EINTR leaves the actual C lease/context retained.
    pub(super) unsafe fn process_one(&self) -> i32 {
        for slot in &self.slots {
            if slot.close_pending.swap(false, Ordering::AcqRel) {
                return unsafe { self.close_slot(slot) };
            }
            let read = slot.read();
            if read.pointer.is_null() {
                continue;
            }
            let value = unsafe { &*read.pointer };
            if !value.events.swap(false, Ordering::AcqRel) {
                continue;
            }
            unsafe { Arc::increment_strong_count(read.pointer) };
            let mut value = ManuallyDrop::new(unsafe { Arc::from_raw(read.pointer) });
            drop(read);
            let phase = value.phase.load(Ordering::Acquire);
            if phase == CANCELLED {
                self.retire(slot, &value);
                unsafe { ManuallyDrop::drop(&mut value) };
                return unsafe { self.close_slot(slot) };
            }
            if phase == QUEUED
                && value
                    .phase
                    .compare_exchange(QUEUED, CREATING, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                let context = Arc::as_ptr(&value) as *mut c_void;
                // Actual stable heap output BEFORE C can queue, sleep or call
                // kthreadd/native association. No guard/RefCell/permit remains.
                let result = unsafe {
                    stela_linux_managed_create(self.owner, context, run, value.lease.get())
                };
                if value.flags.load(Ordering::Acquire) & (CREATE_FAILED | SKIPPED) == 0 {
                    value.result.store(result, Ordering::Release);
                }
                if unsafe { *value.lease.get() }.is_null() {
                    if result >= 0 || value.flags.load(Ordering::Acquire) & ASSOCIATED != 0 {
                        fatal();
                    }
                    // Exact producer's no-C-allocation branch, never generic
                    // errno=>NoChild. No create_info was ever accepted.
                    value.flags.fetch_or(
                        NO_C_OWNER | CREATE_FAILED | CALLER_RETURNED,
                        Ordering::Release,
                    );
                }
                value.phase.store(WAITING, Ordering::Release);
            }
            // Cancellation may win between the first phase read and CAS;
            // consume that actual state now rather than lose its coalesced event.
            if value.phase.load(Ordering::Acquire) == CANCELLED {
                self.retire(slot, &value);
                unsafe { ManuallyDrop::drop(&mut value) };
                return unsafe { self.close_slot(slot) };
            }
            let flags = value.flags.load(Ordering::Acquire);
            let native_joined = flags & ASSOCIATED == 0 || flags & NATIVE_RETIRED != 0;
            if native_joined && (flags & NO_C_OWNER != 0 || flags & PRODUCERS_JOINED != 0) {
                let lease = unsafe { *value.lease.get() };
                if !lease.is_null() {
                    // All actual C lease/free/ref work occurs HERE in PID1,
                    // never Pending.try_join or native dispatcher extraction.
                    let result = unsafe { stela_linux_managed_lease_release(lease, self.owner) };
                    if result != 0 {
                        return result;
                    }
                }
                self.retire(slot, &value);
                unsafe { ManuallyDrop::drop(&mut value) };
                return unsafe { self.close_slot(slot) };
            }
            // Keep source owner and job; only a genuine later source/native
            // event enqueues another process attempt, no periodic retry.
            unsafe { ManuallyDrop::drop(&mut value) };
            return 1;
        }
        0
    }
    fn retire(&self, slot: &ManagedSlot, value: &Arc<Node>) {
        slot.closing.store(true, Ordering::Release);
        let pointer = slot.pointer.swap(ptr::null_mut(), Ordering::AcqRel);
        if pointer != Arc::as_ptr(value) as *mut Node {
            fatal();
        }
        let actual = unsafe { Arc::from_raw(pointer) };
        unsafe {
            *slot.retired.get().cast::<Option<Arc<Node>>>() = Some(actual);
        }
    }
    unsafe fn close_slot(&self, slot: &ManagedSlot) -> i32 {
        if slot.readers.load(Ordering::Acquire) != 0 {
            return 0;
        }
        let Some(actual) =
            (unsafe { (&mut *slot.retired.get().cast::<Option<Arc<Node>>>()).take() })
        else {
            return 0;
        };
        // Source/native producers and row readers actually closed above. This
        // flag alone grants nothing; Pending also needs unique owned Node.
        actual.flags.fetch_or(JOINED, Ordering::Release);
        slot.closing.store(false, Ordering::Release);
        drop(actual);
        1
    }
}
impl Pending {
    pub fn status(&self) -> Status {
        let f = self.node.flags.load(Ordering::Acquire);
        Status {
            callback_entered: f & CALLBACK_ENTERED != 0,
            callback_returned: f & CALLBACK_RETURNED != 0,
            source_interrupted: f & INTERRUPTED != 0,
            native_birth_associated: f & ASSOCIATED != 0,
            native_record_retired: f & NATIVE_RETIRED != 0,
            source_producers_joined: f & PRODUCERS_JOINED != 0,
            joined: f & JOINED != 0,
        }
    }
    /// Only requests cancellation BEFORE source submission. It returns no job,
    /// NoChild or completion; actual queue reader/ref joins still must occur.
    pub fn cancel_queued(&self) -> bool {
        if self
            .node
            .phase
            .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.node.events.store(true, Ordering::Release);
        self.node.queue.delivery.record();
        true
    }
    /// # Safety
    /// Qualified same-CPU native/source process control, outside IRQ/leaf and
    /// borrowed metadata scopes. This does NO C operation or bare entry. All
    /// C cleanup was performed by actual PID1 before JOINED. Job Drop must not
    /// manufacture source current; C resources close there or remain retained.
    pub unsafe fn try_join(self) -> Result<JoinedJob, Self> {
        if self.node.flags.load(Ordering::Acquire) & JOINED == 0 {
            return Err(self);
        }
        let mut this = ManuallyDrop::new(self);
        let held = unsafe { ManuallyDrop::take(&mut this.node) };
        let actual = match Arc::try_unwrap(held) {
            Ok(value) => value,
            Err(held) => {
                this.node = ManuallyDrop::new(held);
                return Err(ManuallyDrop::into_inner(this));
            }
        };
        let f = actual.flags.load(Ordering::Acquire);
        let result = actual.result.load(Ordering::Acquire);
        let outcome = if actual.phase.load(Ordering::Acquire) == CANCELLED {
            Outcome::Cancelled
        } else if f & CALLBACK_RETURNED != 0 {
            Outcome::CallbackReturned
        } else if f & SKIPPED != 0 {
            Outcome::Skipped(result)
        } else if f & CREATE_FAILED != 0 {
            Outcome::CreationFailed(result)
        } else {
            Outcome::ExitedWithoutReturn
        };
        let job =
            unsafe { (&mut *actual.job.get().cast::<Option<Pin<Box<dyn ManagedJob>>>>()).take() }
                .unwrap_or_else(|| fatal());
        Ok(JoinedJob { outcome, job })
    }
}
unsafe fn node<'a>(context: *mut c_void, lease: *mut Lease, owner: *const RawOwner) -> &'a Node {
    if context.is_null() || lease.is_null() {
        fatal();
    }
    let actual = unsafe { &*context.cast::<Node>() };
    if actual.queue.owner != owner || unsafe { *actual.lease.get() } != lease {
        fatal();
    }
    actual
}
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_managed_source_event(
    context: *mut c_void,
    lease: *mut Lease,
    owner: *const RawOwner,
    event: u32,
    result: i32,
) {
    let actual = unsafe { node(context, lease, owner) };
    let flag = match event {
        1 => INTERRUPTED,
        2 => CREATE_FAILED,
        3 | 4 => SKIPPED,
        5 => CALLER_RETURNED,
        6 => NATIVE_RETIRED,
        7 => PRODUCERS_JOINED,
        _ => fatal(),
    };
    if event == 6 && actual.flags.load(Ordering::Acquire) & ASSOCIATED == 0 {
        fatal();
    }
    if event == 2
        || event == 3
        || event == 4
        || (event == 5 && actual.flags.load(Ordering::Acquire) & (CREATE_FAILED | SKIPPED) == 0)
    {
        actual.result.store(result, Ordering::Release);
    }
    actual.flags.fetch_or(flag, Ordering::Release);
    actual.events.store(true, Ordering::Release);
    actual.queue.delivery.record();
}
unsafe extern "C" fn run(context: *mut c_void) -> i32 {
    if context.is_null() {
        fatal();
    }
    let actual = unsafe { &*context.cast::<Node>() };
    if actual.flags.fetch_or(CALLBACK_ENTERED, Ordering::AcqRel) & CALLBACK_ENTERED != 0 {
        fatal();
    }
    // Exclusive pinned owned job; status/cancel never borrow it and final
    // extraction is impossible until actual complete source/native closure.
    let job =
        unsafe { (&mut *actual.job.get().cast::<Option<Pin<Box<dyn ManagedJob>>>>()).as_mut() }
            .unwrap_or_else(|| fatal());
    job.as_mut().run();
    actual.flags.fetch_or(CALLBACK_RETURNED, Ordering::Release);
    actual.events.store(true, Ordering::Release);
    actual.queue.delivery.record();
    0 // original kthread/do_exit remains authoritative after this callback.
}
