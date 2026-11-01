//! One mount-lifetime canonical Linux execution owner and device catalogue.
//! Failed or abandoned bootstrap retains the actual owner/environment roots;
//! there is no implemented full-kernel cache teardown or reinstallation.
use super::{
    catalogue::{self, Authority, FirmwareTarget},
    owner::{Owner, Platform, RawOwner},
    service::Environment,
};
use alloc::{boxed::Box, sync::Arc};
use core::{ffi::c_void, mem::ManuallyDrop, pin::Pin};
use stela_driver_base::platform::work::{RetainedOwner, Runtime, WorkError, service::Domain};
use stela_driver_core::firmware::Catalog;

/// Actual original canonical work queue, which owns its provider/context/code/
/// root lease. No caller ranges, read-only data classifier or dummy Arc can
/// construct this pin; only the same KernelOwner Runtime supplies it.
#[derive(Clone)]
pub(crate) struct ExecutionPin {
    _queue: RetainedOwner,
}
impl ExecutionPin {
    fn from_runtime<const N: usize>(runtime: Pin<&Runtime<N>>) -> Self {
        Self {
            _queue: runtime.queue().clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Work(WorkError),
    Native(i32),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "canonical Linux bootstrap: {self:?}")
    }
}
impl core::error::Error for Error {}

unsafe extern "C" {
    fn stela_linux_kernel_claim(owner: *const RawOwner) -> i32;
    fn stela_linux_kernel_ready(owner: *const RawOwner) -> i32;
}
/// Real roots survive a refused/partial bootstrap; dropping failure does not
/// make an attached service domain or published RawOwner disappear.
pub struct Failure<P: Platform, const N: usize> {
    pub error: Error,
    _owner: ManuallyDrop<Pin<Box<Owner<P>>>>,
    _environment: ManuallyDrop<Option<Pin<Box<Environment<N>>>>>,
    _domain: ManuallyDrop<Arc<Domain<N>>>,
    _execution: ManuallyDrop<ExecutionPin>,
}
impl<P: Platform, const N: usize> Failure<P, N> {
    fn new(
        error: Error,
        owner: ManuallyDrop<Pin<Box<Owner<P>>>>,
        environment: Option<Pin<Box<Environment<N>>>>,
        domain: Arc<Domain<N>>,
        execution: ExecutionPin,
    ) -> Self {
        Self {
            error,
            _owner: owner,
            _environment: ManuallyDrop::new(environment),
            _domain: ManuallyDrop::new(domain),
            _execution: ManuallyDrop::new(execution),
        }
    }
}
pub struct KernelOwner<P: Platform, const N: usize> {
    owner: ManuallyDrop<Pin<Box<Owner<P>>>>,
    environment: ManuallyDrop<Pin<Box<Environment<N>>>>,
    _domain: ManuallyDrop<Arc<Domain<N>>>,
    execution: ManuallyDrop<ExecutionPin>,
}
impl<P: Platform, const N: usize> KernelOwner<P, N> {
    /// # Safety
    /// In the actual runtime's admitted dispatcher CPU. Runtime/domain,
    /// platform services, code/image and global resource owners stay kept for
    /// the whole kernel lifetime, including partial failure and abandoned Drop.
    /// This Runtime queue's original retained owner covers this compiled
    /// shared Linux/driver/provider executable code and all execution roots,
    /// not merely runtime metadata. No unload is permitted while pins remain.
    /// Cold bootstrap, before any prior Linux environment, task, initcall,
    /// work/RCU queue or device activity: adopting old global queues is not
    /// implemented. Caller starts this Environment/service before dispatch.
    /// This constructor grants no PCI/root/IRQ/device permission.
    pub unsafe fn new(
        platform: P,
        runtime: Pin<&Runtime<N>>,
        domain: Arc<Domain<N>>,
    ) -> Result<Self, Failure<P, N>> {
        let execution = ExecutionPin::from_runtime(runtime);
        let owner = ManuallyDrop::new(Owner::new(platform));
        // SAFETY: pinned resident owner above; claim is one irreversible registration.
        let status = unsafe { stela_linux_kernel_claim(owner.raw()) };
        if status != 0 {
            return Err(Failure::new(
                Error::Native(status),
                owner,
                None,
                domain,
                execution,
            ));
        }
        // SAFETY: caller keeps the real runtime/domain and pinned owner through all tasks.
        let environment = match unsafe { Environment::new(owner.raw(), runtime, domain.clone()) } {
            Ok(environment) => environment,
            Err(error) => {
                return Err(Failure::new(
                    Error::Work(error),
                    owner,
                    None,
                    domain,
                    execution,
                ));
            }
        };
        // SAFETY: this same claimed owner now has its actual retained Environment.
        let status = unsafe { stela_linux_kernel_ready(owner.raw()) };
        if status != 0 {
            return Err(Failure::new(
                Error::Native(status),
                owner,
                Some(environment),
                domain,
                execution,
            ));
        }
        Ok(Self {
            owner,
            environment: ManuallyDrop::new(environment),
            _domain: ManuallyDrop::new(domain),
            execution: ManuallyDrop::new(execution),
        })
    }
    pub(crate) fn execution(&self) -> ExecutionPin {
        ExecutionPin::clone(&self.execution)
    }
    pub fn raw(&self) -> *const RawOwner {
        self.owner.raw()
    }
    pub fn platform(&self) -> &P {
        self.owner.platform()
    }
    pub fn environment(&self) -> Pin<&Environment<N>> {
        self.environment.as_ref()
    }

    /// Enroll the actual original regulatory faux device before its first
    /// firmware request. No name/NULL-device fallback selects this route.
    ///
    /// # Safety
    /// Entered in this canonical process owner, with a real retained original
    /// reg_fdev created by the qualified cfg80211/faux path. Original regulatory
    /// global state/code/context remains valid through its real release. The
    /// exact target/Catalog resources are explicitly approved for this original
    /// global regulatory authority; another device's valid manifest or a name
    /// match does not qualify this assignment.
    pub unsafe fn bind_regulatory(
        &self,
        device: *mut c_void,
        target: FirmwareTarget,
        catalog: Arc<Catalog>,
    ) -> Result<(), (Box<Authority>, catalogue::Error)> {
        // SAFETY: the caller supplies that exact original object and global authority.
        unsafe {
            catalogue::bind(
                device,
                Box::new(Authority::global_regulatory(
                    target,
                    catalog,
                    self.execution(),
                )),
            )
        }
    }
}
