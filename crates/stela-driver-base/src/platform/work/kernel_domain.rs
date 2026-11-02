//! Sealed execution-domain loans; native admission never accepts host transport.
//! Hosted runtime/segment admission stays unconstructible until its real core exists.
use super::{EnteredProcess, Runtime, TaskContext, WorkError};
use core::{marker::PhantomData, pin::Pin};
mod native;
mod raised;
pub use raised::DomainRaised;
#[cfg(all(feature = "test-support", unix))]
mod hosted;
#[cfg(all(feature = "test-support", unix))]
pub use hosted::{
    HostFrameId, HostedClock, HostedExecution, HostedIdle, HostedPages, HostedReason,
};
mod storage;
pub use storage::{CpuSpan, StorageShape, StorageView};
mod sealed;
/// A domain marker cannot be supplied by another crate or reconstructed from
/// an address, CPU number, epoch, cookie or enum discriminant.
pub trait Domain: sealed::Domain + 'static {}
pub struct NativeDomain {
    _private: (),
}
impl Domain for NativeDomain {}
#[cfg(all(feature = "test-support", unix))]
pub enum HostedDomain {}
#[cfg(all(feature = "test-support", unix))]
impl Domain for HostedDomain {}
/// Borrow of the actual domain's runtime, not a native root/process permit.
/// No raw/core accessor, Deref, From/Into or domain conversion is supplied.
pub struct DomainRef<'runtime, D: Domain, const N: usize> {
    inner: D::Loan<'runtime, N>,
    _domain: PhantomData<&'runtime D>,
}
impl<D: Domain, const N: usize> DomainRef<'_, D, N> {
    pub fn check(&self) -> Result<(), WorkError> {
        D::check::<N>(&self.inner)
    }
    pub fn current_context(&self) -> Result<TaskContext, WorkError> {
        D::current::<N>(&self.inner)
    }
    pub fn dispatcher_successor(&self) -> Result<(), WorkError> {
        D::dispatcher::<N>(&self.inner)
    }
    pub fn same_runtime(&self, other: &DomainRef<'_, D, N>) -> bool {
        D::same::<N>(&self.inner, &other.inner)
    }
}
impl<'runtime, const N: usize> DomainRef<'runtime, NativeDomain, N> {
    /// Read/check the exact existing native Runtime; this creates no new root.
    pub fn borrow(runtime: Pin<&'runtime Runtime<N>>) -> Result<Self, WorkError> {
        runtime.queue().process()?;
        Ok(Self {
            inner: runtime,
            _domain: PhantomData,
        })
    }
    pub fn segment<'scope>(
        &'scope self,
        entered: &'scope dyn EnteredProcess,
    ) -> Result<Segment<'scope, NativeDomain, N>, WorkError> {
        entered.check()?;
        self.check()?;
        Ok(Segment {
            inner: native::NativeSegment {
                runtime: self.inner,
                entered,
            },
            _domain: PhantomData,
        })
    }
    /// Keep the SAME actual runtime under the existing unsafe kernel lifetime
    /// obligation. This is not ownership of its container or a safe erasure.
    /// # Safety
    /// Caller retains this actual pinned Runtime CONTAINER, its native code,
    /// stacks, allocation/root owners and CPU for the full kept kernel lifetime,
    /// including failures/abandonment. A Queue ExecutionPin alone is not this
    /// proof. No runtime retirement/replacement occurs while a kept loan exists.
    /// No borrowed execution segment or process permit is retained here.
    pub unsafe fn keep_for_kernel_lifetime(self) -> KeptDomainRef<NativeDomain, N> {
        KeptDomainRef {
            inner: native::NativeKept::from_runtime(self.inner),
            _local: PhantomData,
        }
    }
}
/// Mount-lifetime runtime reference established only by the native unsafe
/// constructor above, or a future real hosted mount producer. No raw constructor.
/// The actual container/code/root lifetime obligation remains with that owner.
pub struct KeptDomainRef<D: Domain, const N: usize> {
    inner: D::Kept<N>,
    _local: PhantomData<*mut ()>,
}
impl<D: Domain, const N: usize> KeptDomainRef<D, N> {
    pub fn borrow(&self) -> DomainRef<'_, D, N> {
        DomainRef {
            inner: D::reborrow::<N>(&self.inner),
            _domain: PhantomData,
        }
    }
}
/// Fresh short metadata-segment loan. It cannot escape across original C
/// allocation/wait/reaper/callback code or a native context switch.
pub struct Segment<'scope, D: Domain, const N: usize> {
    inner: D::Segment<'scope, N>,
    _domain: PhantomData<&'scope D>,
}
impl<D: Domain, const N: usize> Segment<'_, D, N> {
    pub fn check(&self) -> Result<(), WorkError> {
        D::check_segment::<N>(&self.inner)
    }
    pub fn matches(&self, runtime: &DomainRef<'_, D, N>) -> bool {
        D::segment_matches::<N>(&self.inner, &runtime.inner)
    }
}

impl<const N: usize> Segment<'_, NativeDomain, N> {
    /// Delegate an unchanged native contract through this same actual borrowed
    /// guard. Host/generic segments have no native-guard bridge or extractor.
    /// The callback's result is returned unchanged inside Ok; an outer Err
    /// proves the body was never called, never a post-publication failure.
    ///
    /// # Safety
    /// The callback is bounded native metadata work on this same Runtime/root.
    /// It must not wait, switch, reenter with_process, invoke a source callback,
    /// or extract/store/erase the guard loan. Native adapters retain their real
    /// Runtime/container/code/root owners independently. Any reservation which
    /// borrows this loan must transfer into its actual borrow-free owner/error
    /// before return; no GeneralReservation<'loan> or borrowed permit escapes.
    pub unsafe fn with_native<R>(
        &self,
        body: impl for<'loan> FnOnce(&'loan dyn EnteredProcess) -> R,
    ) -> Result<R, WorkError> {
        self.check()?;
        Ok(body(self.inner.entered))
    }
}
