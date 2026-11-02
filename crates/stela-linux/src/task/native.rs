//! Required original-child ABI on the same retained Factory/native owner.
//! No source supervisor, scheduler, workqueue or Ready is installed here.
use super::data::StoppedTaskData;
use super::factory::{self, Child, Factory, NoPublication, RetiredMetadata};
use super::{CTask, OriginalBirth, Rank, TaskBinding};
use crate::{
    kernel::KernelOwner,
    owner::RawOwner,
    pages::{Catalog, Provider},
    threads::KernelThreadPlatform,
};
use alloc::{boxed::Box, rc::Rc, sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    marker::PhantomData,
    mem::{self, ManuallyDrop},
    pin::Pin,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering},
};
use stela_driver_base::platform::work::{Callback, RaisedWork, Runtime, SwitchBinding, WorkError};
mod abi;
mod lifecycle;
pub(super) mod managed;
mod process;
mod registry;
mod request;
mod stopped_data;
pub(crate) use registry::{Event, EventKind, FinalMetadata, RequestHandle, RetiringRequest};

const EMPTY: u8 = 0;
const RESERVED: u8 = 1;
const LIVE: u8 = 2;
const RETIRING: u8 = 3;
const CREATED: u8 = 1;
const SOURCE_FREED: u8 = 2;
const TERMINAL_RETURNED: u8 = 4;
const ABORT_RECORDED: u8 = 8;
const SOURCE_TAIL: u8 = 16;
const NATIVE_RELEASED: u8 = 32;
const FAILED: u8 = 64;
type OwnedChild<K, P, const N: usize> = Child<'static, 'static, 'static, 'static, K, P, N>;
type NativeEntry = unsafe extern "C" fn(*mut c_void) -> i32;
unsafe extern "C" {
    fn stela_linux_task_run_original(context: *mut c_void);
}

/// Non-clone native installer control; no FullReady/current proof.
pub(crate) struct Mounted<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>
{
    broker: &'static Broker<K, P, N>,
    _affine: PhantomData<Rc<()>>,
}
struct Broker<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> {
    kernel: ManuallyDrop<Arc<KernelOwner<K, N>>>,
    factory: ManuallyDrop<Box<Factory<'static, 'static, 'static, K, P, N>>>,
    runtime: Pin<&'static Runtime<N>>,
    wake: ManuallyDrop<RaisedWork>,
    delivery: Arc<Delivery>,
    slots: Box<[Slot<K, P, N>]>,
    managed: managed::Queue,
}
struct Delivery {
    pending: AtomicBool,
    epoch: AtomicU64,
    blocked_until: AtomicU64,
    wake: ManuallyDrop<RaisedWork>,
}
impl Delivery {
    fn record(&self) {
        if self
            .epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .is_err()
        {
            fatal();
        }
        self.pending.store(true, Ordering::Release);
        if self.wake.raise().is_err() {
            fatal();
        }
    }
}
struct Slot<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> {
    phase: AtomicU8,
    readers: AtomicUsize,
    request: AtomicPtr<Request<K, P, N>>,
    delivery: Arc<Delivery>,
    finalize_pending: AtomicBool,
    dispatch_pending: AtomicBool,
    retiring: UnsafeCell<ManuallyDrop<Option<RetiringRequest<K, P, N>>>>,
    final_metadata: UnsafeCell<ManuallyDrop<Option<FinalMetadata<K, N>>>>,
}
struct CallbackContext<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> {
    // Nonowning backpointer. The live registry owner survives actual native
    // return AND source callback-tail joins; there is no Arc self-cycle.
    request: NonNull<Request<K, P, N>>,
}
struct Request<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> {
    broker: &'static Broker<K, P, N>,
    slot: &'static Slot<K, P, N>,
    service_stage: AtomicU8,
    source_tail_seen: AtomicBool,
    record: AtomicPtr<CTask>,
    generation: AtomicU64,
    binding: UnsafeCell<ManuallyDrop<Option<Arc<TaskBinding<N>>>>>,
    context: UnsafeCell<ManuallyDrop<Option<Box<CallbackContext<K, P, N>>>>>,
    state: UnsafeCell<ManuallyDrop<Owned<K, P, N>>>,
    // Actual stopped publication/source-ref owner. Default abandonment retains.
    data_stop: UnsafeCell<ManuallyDrop<StoppedDataState>>,
    busy: AtomicBool,
    prepared: AtomicBool,
    entered: AtomicBool,
    events: AtomicU8,
    entry: UnsafeCell<Option<(NativeEntry, *mut c_void)>>,
    fault: UnsafeCell<ManuallyDrop<Option<factory::Error>>>,
    detached: UnsafeCell<ManuallyDrop<Option<Arc<dyn SwitchBinding>>>>,
}
enum Owned<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> {
    Child(OwnedChild<K, P, N>),
    NoPublication(NoPublication<N>),
    Retired(RetiredMetadata<N>),
    BeginFailure(factory::BeginFailure<N>),
    Transitioning,
}
enum StoppedDataState {
    Unclaimed,
    Stopped(StoppedTaskData),
    SourceReleased(StoppedTaskData),
    Finished,
    // A refusal after stop_data may have retained an accepted native token
    // inside that producer; no error code permits retry or source cleanup.
    Uncertain,
    Transitioning,
}
struct Mutation<'a, K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> {
    request: &'a Request<K, P, N>,
}
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> Drop
    for Mutation<'_, K, P, N>
{
    fn drop(&mut self) {
        self.request.busy.store(false, Ordering::Release);
    }
}
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>
    Mutation<'_, K, P, N>
{
    fn take(&mut self) -> Owned<K, P, N> {
        // SAFETY: exact CAS-exclusive bounded mutation, never a C wait scope.
        unsafe {
            mem::replace(
                &mut *self.request.state.get().cast::<Owned<K, P, N>>(),
                Owned::Transitioning,
            )
        }
    }
    fn put(&mut self, state: Owned<K, P, N>) {
        // SAFETY: prior state moved to its retained actual owner.
        unsafe {
            *self.request.state.get().cast::<Owned<K, P, N>>() = state;
        }
    }
}
#[derive(Debug)]
pub(crate) enum Error {
    Work(WorkError),
    Native(factory::Error),
    Source(i32),
    Busy,
    WrongPhase,
}
#[inline(never)]
fn fatal() -> ! {
    // SAFETY: uncertain publication is terminal before source reclaims owners.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> Mounted<K, P, N> {
    /// Install the ONE typed ABI, never source task-service readiness.
    /// # Safety
    /// The actual canonical kernel OBJECT, original source/code, catalog and
    /// pinned Runtime CONTROL/storage outlive this complete mounted kernel.
    /// Static catalog/Runtime references are backed by that actual owning mount.
    /// Kernel platform must NOT own the adapter: no owning Kernel->Platform->
    /// adapter->Kernel cycle. The SAME Domain minted wake, whose graph must not
    /// back-own a request. The checked native dispatcher metadata phase may
    /// install this before original Initial; it enters no C/current helper.
    /// Actual heap/page/stack/code/root and scheduling providers are retained.
    /// Every later child constructor independently requires genuine source
    /// current. No boolean/callback-presence grant.
    /// This is one permanent installation attempt; refusal does not authorize
    /// destroying the already-kept source/native graph or retrying publication.
    pub(crate) unsafe fn install(
        kernel: Arc<KernelOwner<K, N>>,
        runtime: Pin<&'static Runtime<N>>,
        catalog: &'static Catalog<P>,
        wake: RaisedWork,
        capacity: usize,
    ) -> Result<Self, Error> {
        // Keep the already-canonical actual kernel OBJECT and signal before
        // ANY fallible adapter preparation; refusal cannot drop their roots.
        let kernel = ManuallyDrop::new(kernel);
        let wake = ManuallyDrop::new(wake);
        if capacity == 0 {
            return Err(Error::Work(WorkError::Full));
        }
        if !abi::DISPATCH.load(Ordering::Acquire).is_null() {
            return Err(Error::Busy);
        }
        let delivery = Arc::new(Delivery {
            pending: AtomicBool::new(false),
            epoch: AtomicU64::new(1),
            blocked_until: AtomicU64::new(0),
            wake: ManuallyDrop::new(RaisedWork::clone(&wake)),
        });
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Work(WorkError::Full))?;
        for _ in 0..capacity {
            slots.push(Slot {
                phase: AtomicU8::new(EMPTY),
                readers: AtomicUsize::new(0),
                request: AtomicPtr::new(ptr::null_mut()),
                delivery: delivery.clone(),
                finalize_pending: AtomicBool::new(false),
                dispatch_pending: AtomicBool::new(false),
                retiring: UnsafeCell::new(ManuallyDrop::new(None)),
                final_metadata: UnsafeCell::new(ManuallyDrop::new(None)),
            });
        }

        // SAFETY: real Arc is kept BEFORE forming the permanent factory view.
        let actual_kernel: &'static KernelOwner<K, N> = unsafe { &*Arc::as_ptr(&kernel) };
        // SAFETY: actual same runtime/catalog/source owning mount above.
        let factory =
            unsafe { Factory::new(actual_kernel, runtime, catalog) }.map_err(Error::Native)?;
        let managed = managed::Queue::new(actual_kernel.raw(), delivery.clone(), capacity)
            .map_err(Error::Work)?;
        let broker = ManuallyDrop::new(Box::new(Broker {
            kernel,
            factory: ManuallyDrop::new(Box::new(factory)),
            runtime,
            wake,
            delivery,
            slots: slots.into_boxed_slice(),
            managed,
        }));
        // SAFETY: stable kept Box before C publication, one canonical lifetime.
        let reference: &'static Broker<K, P, N> =
            unsafe { &*(&**broker as *const Broker<K, P, N>) };
        unsafe { abi::publish(reference) }?;
        Ok(Self {
            broker: reference,
            _affine: PhantomData,
        })
    }
    /// Negative association check only, never source readiness.
    pub(crate) fn matches_kernel(&self, kernel: &KernelOwner<K, N>) -> bool {
        core::ptr::eq(&**self.broker.kernel, kernel)
    }

    /// Actual process receiver; no original wait/body while table is borrowed.
    pub(crate) unsafe fn next_event(&self) -> Result<Option<Event<K, P, N>>, Error> {
        self.broker.next_event()
    }
    /// No count-derived kernel/source shutdown. A real joined global retirement
    /// producer is not supplied by this source SDK.
    pub(crate) fn shutdown(self) -> Result<(), Self> {
        Err(self)
    }
}

impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> Mounted<K, P, N> {
    /// Accept one CPU-local owned job into the SAME actual source broker.
    /// # Safety
    /// Actual checked native process/dispatcher metadata phase; keep the real
    /// kernel mount. Acceptance is pending only; no source readiness or native
    /// Ticket/current/child is synthesized. ManagedJob's resource contract holds.
    pub(crate) unsafe fn submit(
        &self,
        job: Pin<Box<dyn managed::ManagedJob>>,
    ) -> Result<managed::Pending, managed::RejectedJob> {
        let mut kept = ManuallyDrop::new(Some(job));
        // SAFETY: fresh bounded actual metadata; no original C body/wait.
        match unsafe {
            self.broker.kernel.platform().with_process(|_entered| {
                self.broker
                    .managed
                    .submit(kept.take().unwrap_or_else(|| fatal()))
            })
        } {
            Ok(result) => result,
            Err(error) => Err(managed::RejectedJob {
                error: managed::SubmitError::Context(error),
                // Outer Err means body never ran. If a provider violated that
                // after acceptance, retain/fatal rather than return false error.
                job: kept.take().unwrap_or_else(|| fatal()),
            }),
        }
    }
}
