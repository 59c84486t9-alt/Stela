//! Public affine control of the SAME original-child native broker.
//! This does not create an Environment, alternate scheduler or FullReady.
use super::native;
pub use super::native::managed::{
    JoinedJob, ManagedJob, Outcome, Pending, RejectedJob, Status, SubmitError,
};
use crate::{
    kernel::KernelOwner,
    pages::{Catalog, Provider},
    threads::KernelThreadPlatform,
};
use alloc::{boxed::Box, sync::Arc};
use core::{cell::UnsafeCell, mem::ManuallyDrop, pin::Pin};
use stela_driver_base::platform::work::{GeneralRefusal, Runtime, WorkError};

/// Typed complete native/source failure, including retained admission reason.
/// Its private implementation is not a no-publication/cancellation receipt.
pub struct RuntimeError {
    inner: native::Error,
}
impl RuntimeError {
    pub fn work(&self) -> Option<&WorkError> {
        match &self.inner {
            native::Error::Work(e) | native::Error::Native(super::factory::Error::Work(e)) => {
                Some(e)
            }
            _ => None,
        }
    }
    pub fn admission(&self) -> Option<&GeneralRefusal> {
        match &self.inner {
            native::Error::Native(super::factory::Error::Admission(e)) => Some(e),
            _ => None,
        }
    }
    pub fn source_status(&self) -> Option<i32> {
        match &self.inner {
            native::Error::Source(e) | native::Error::Native(super::factory::Error::Source(e)) => {
                Some(*e)
            }
            _ => None,
        }
    }
}
impl core::fmt::Debug for RuntimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.inner, f)
    }
}
impl core::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "original native task runtime: {:?}", self.inner)
    }
}
impl core::error::Error for RuntimeError {}

/// Unique CPU-local native task control. Broker retains the same actual Kernel;
/// neither Platform nor Environment owns this control. Initial stores only a
/// borrowed pointer kept by the mount, avoiding Kernel→Broker→Kernel ownership.
/// Default abandonment retains the actual mounted graph; no safe shutdown or
/// count-derived extraction is supplied.
pub struct TaskRuntime<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> {
    mounted: ManuallyDrop<native::Mounted<K, P, N>>,
    failure: UnsafeCell<ManuallyDrop<Option<RuntimeError>>>,
}
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>
    TaskRuntime<K, P, N>
{
    /// Install the single actual original-child broker before Initial execution.
    ///
    /// # Safety
    /// Same actual admitted native dispatcher; keep canonical Kernel OBJECT,
    /// static pinned Runtime and canonical Catalog plus their actual root/code/
    /// heap/page/stack providers permanently mounted, including refusals/unwind.
    /// No task or source activity from another owner is adopted. The scheduler
    /// Domain must be attached before original child publication. The exact
    /// shared Environment signal is derived internally, never caller-supplied.
    /// This operation registers a descriptor ABI, not original task/resources,
    /// WQ progress, entered CPU/IRQ authority or joined FullReady.
    pub unsafe fn install(
        kernel: Arc<KernelOwner<K, N>>,
        runtime: Pin<&'static Runtime<N>>,
        catalog: &'static Catalog<P>,
        capacity: usize,
    ) -> Result<Self, RuntimeError> {
        let kernel = ManuallyDrop::new(kernel);
        runtime
            .general_capacity(crate::task::stack_requirement().map_err(|e| RuntimeError {
                inner: native::Error::Work(e),
            })?)
            .map_err(|e| RuntimeError {
                inner: native::Error::Work(e),
            })?;
        let wake = kernel.environment().thread_wake();
        // Transfer directly into the same installer's first retained field;
        // no foreign action or fallible operation intervenes after extraction.
        let mounted = unsafe {
            native::Mounted::install(
                ManuallyDrop::into_inner(kernel),
                runtime,
                catalog,
                wake,
                capacity,
            )
        }
        .map_err(|inner| RuntimeError { inner })?;
        Ok(Self {
            mounted: ManuallyDrop::new(mounted),
            failure: UnsafeCell::new(ManuallyDrop::new(None)),
        })
    }
    /// Accept an owned CPU-local job for the original PID1/kthreadd path.
    /// Acceptance is Pending, never created/current/completed or a native Ticket.
    ///
    /// # Safety
    /// Actual same-CPU native process/dispatcher metadata context with this
    /// permanent mount retained. The exact ManagedJob resource contract holds
    /// through full source/native/page/RCU/reader join. No Send/current/task or
    /// C resource release permission is inferred from queue acceptance.
    pub unsafe fn submit(&self, job: Pin<Box<dyn ManagedJob>>) -> Result<Pending, RejectedJob> {
        // SAFETY: unchanged actual producer and owned input contract; the
        // private source adapter preserves accepted ownership on uncertainty.
        unsafe { self.mounted.submit(job) }
    }
    pub(crate) fn matches_kernel(&self, kernel: &KernelOwner<K, N>) -> bool {
        self.mounted.matches_kernel(kernel)
    }
    /// Advance actual native-release work only on a genuine physical-return
    /// dispatcher. No C process/reaper body runs here.
    /// # Safety
    /// Runtime physically returned off EVERY constructor stack, with no actual
    /// source/current/loan/RefCell/queue guard; use fresh native metadata scopes
    /// for bounded leaf operations. No parked frame uses the old segment epoch.
    pub unsafe fn dispatcher_step(&self) -> Result<bool, RuntimeError> {
        unsafe { self.mounted.dispatcher_step() }.map_err(|inner| RuntimeError { inner })
    }
    pub(crate) unsafe fn service_delivery(&self) {
        // This consumes ONLY a distinct genuinely recorded event; calling on a
        // timer pass cannot manufacture progress/retry. No passive leaf active.
        if let Err(inner) = unsafe { self.mounted.service_delivery() } {
            // Retain the complete exact typed source/admission failure before
            // a payload-free terminal path, never reenter a C logger here.
            unsafe { *self.failure.get() = ManuallyDrop::new(Some(RuntimeError { inner })) };
            unsafe { core::arch::asm!("ud2", options(noreturn)) }
        }
    }
    /// Observation only. No continuation, cleanup or readiness is granted.
    pub fn failure(&self) -> Option<&RuntimeError> {
        // SAFETY: CPU-local control; only terminal service failure publishes
        // this immutable value and it never returns to another producer.
        unsafe { &*self.failure.get() }.as_ref()
    }
}
