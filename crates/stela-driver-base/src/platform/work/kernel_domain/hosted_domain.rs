//! Checked hosted domain loans, tied to the actual pinned continuation owner.
use super::*;
use crate::bus::dma::memory::MemoryError;
use core::ptr::NonNull;

pub struct HostKept<const N: usize>(NonNull<HostedRuntime<N>>);
pub struct HostSegment<'a, const N: usize> {
    runtime: Pin<&'a HostedRuntime<N>>,
    epoch: u64,
}

impl<'runtime, const N: usize> DomainRef<'runtime, HostedDomain, N> {
    pub fn borrow_hosted(runtime: Pin<&'runtime HostedRuntime<N>>) -> Result<Self, WorkError> {
        runtime.check()?;
        Ok(Self {
            inner: runtime,
            _domain: PhantomData,
        })
    }

    pub fn hosted_segment(&self) -> Result<Segment<'_, HostedDomain, N>, WorkError> {
        let epoch = self.inner.segment_epoch()?;
        Ok(Segment {
            inner: HostSegment {
                runtime: self.inner,
                epoch,
            },
            _domain: PhantomData,
        })
    }

    /// # Safety
    /// Retain the exact pinned executor container and all its owners for the
    /// entire mount, including on failure. Do not retire it while loans exist.
    pub unsafe fn keep_hosted_for_kernel_lifetime(self) -> KeptDomainRef<HostedDomain, N> {
        KeptDomainRef {
            inner: HostKept(NonNull::from(self.inner.get_ref())),
            _local: PhantomData,
        }
    }
}

impl sealed::Domain for HostedDomain {
    type Loan<'a, const N: usize> = Pin<&'a HostedRuntime<N>>;
    type Kept<const N: usize> = HostKept<N>;
    type Segment<'a, const N: usize> = HostSegment<'a, N>;
    type Storage<'a> = &'a HostedPages;
    type Raised = hosted::HostedRaisedWork;

    fn raise(event: &Self::Raised) -> Result<(), WorkError> {
        event.raise()
    }
    fn check<const N: usize>(runtime: &Self::Loan<'_, N>) -> Result<(), WorkError> {
        runtime.check()
    }
    fn current<const N: usize>(runtime: &Self::Loan<'_, N>) -> Result<TaskContext, WorkError> {
        runtime.current_context()
    }
    fn dispatcher<const N: usize>(runtime: &Self::Loan<'_, N>) -> Result<(), WorkError> {
        runtime.dispatcher_successor()
    }
    fn same<const N: usize>(a: &Self::Loan<'_, N>, b: &Self::Loan<'_, N>) -> bool {
        core::ptr::eq(a.get_ref(), b.get_ref())
    }
    fn reborrow<const N: usize>(kept: &Self::Kept<N>) -> Self::Loan<'_, N> {
        // SAFETY: only the kept loan constructor records this pointer, with
        // the exact pinned executor lifetime retained by its caller.
        unsafe { Pin::new_unchecked(kept.0.as_ref()) }
    }
    fn check_segment<const N: usize>(segment: &Self::Segment<'_, N>) -> Result<(), WorkError> {
        if segment.runtime.segment_epoch()? != segment.epoch {
            return Err(WorkError::InvalidTicket);
        }
        Ok(())
    }
    fn segment_matches<const N: usize>(
        segment: &Self::Segment<'_, N>,
        runtime: &Self::Loan<'_, N>,
    ) -> bool {
        Self::same::<N>(&segment.runtime, runtime)
    }
    fn shape(pages: &Self::Storage<'_>) -> StorageShape {
        StorageShape {
            bytes: pages.bytes(),
            alignment: pages.alignment(),
            page_shift: pages.page_shift(),
        }
    }
    fn span(
        pages: &Self::Storage<'_>,
        offset: usize,
        bytes: usize,
    ) -> Result<NonNull<u8>, MemoryError> {
        pages.cpu_address(offset, bytes)
    }
}
