//! Real native adapters: all execution checks delegate to the existing Runtime.
use super::{EnteredProcess, NativeDomain, Runtime, StorageShape, TaskContext, WorkError, sealed};
use crate::bus::dma::memory::{MemoryError, PinnedPages};
use core::{marker::PhantomData, pin::Pin, ptr::NonNull};
pub struct NativeKept<const N: usize> {
    runtime: NonNull<Runtime<N>>,
    _local: PhantomData<*mut ()>,
}
impl<const N: usize> NativeKept<N> {
    pub(super) fn from_runtime(runtime: Pin<&Runtime<N>>) -> Self {
        Self {
            runtime: NonNull::from(runtime.get_ref()),
            _local: PhantomData,
        }
    }
}
pub struct NativeSegment<'a, const N: usize> {
    pub(super) runtime: Pin<&'a Runtime<N>>,
    pub(super) entered: &'a dyn EnteredProcess,
}
impl sealed::Domain for NativeDomain {
    type Loan<'a, const N: usize> = Pin<&'a Runtime<N>>;
    type Kept<const N: usize> = NativeKept<N>;
    type Segment<'a, const N: usize> = NativeSegment<'a, N>;
    type Storage<'a> = &'a PinnedPages;
    fn check<const N: usize>(runtime: &Self::Loan<'_, N>) -> Result<(), WorkError> {
        runtime.queue().process()
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
        // SAFETY: the only constructor requires the actual pinned Runtime
        // CONTAINER/code/root/stack lifetime for the complete kept kernel mount.
        // No execution segment is reconstructed or retained by this borrow.
        unsafe { Pin::new_unchecked(kept.runtime.as_ref()) }
    }
    fn check_segment<const N: usize>(segment: &Self::Segment<'_, N>) -> Result<(), WorkError> {
        segment.entered.check()?;
        segment.runtime.queue().process()
    }
    fn segment_matches<const N: usize>(
        segment: &Self::Segment<'_, N>,
        runtime: &Self::Loan<'_, N>,
    ) -> bool {
        core::ptr::eq(segment.runtime.get_ref(), runtime.get_ref())
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
        super::storage::check_range(pages.bytes(), offset, bytes)?;
        let mapping = pages.cpu_mapping(pages.cache_attribute())?;
        mapping.address(offset, bytes)
    }
}
