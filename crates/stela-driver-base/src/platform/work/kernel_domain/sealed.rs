//! Private dispatch protocol. Implementations are fixed by this crate, not users.
use super::{StorageShape, TaskContext, WorkError};
use crate::bus::dma::memory::MemoryError;
use core::ptr::NonNull;
pub trait Domain: 'static {
    type Loan<'a, const N: usize>: Copy;
    type Kept<const N: usize>;
    type Segment<'a, const N: usize>;
    type Storage<'a>: Copy;
    type Raised: Clone;
    fn raise(event: &Self::Raised) -> Result<(), WorkError>;
    fn check<const N: usize>(loan: &Self::Loan<'_, N>) -> Result<(), WorkError>;
    fn current<const N: usize>(loan: &Self::Loan<'_, N>) -> Result<TaskContext, WorkError>;
    fn dispatcher<const N: usize>(loan: &Self::Loan<'_, N>) -> Result<(), WorkError>;
    fn same<const N: usize>(a: &Self::Loan<'_, N>, b: &Self::Loan<'_, N>) -> bool;
    fn reborrow<const N: usize>(kept: &Self::Kept<N>) -> Self::Loan<'_, N>;
    fn check_segment<const N: usize>(segment: &Self::Segment<'_, N>) -> Result<(), WorkError>;
    fn segment_matches<const N: usize>(
        segment: &Self::Segment<'_, N>,
        loan: &Self::Loan<'_, N>,
    ) -> bool;
    fn shape(storage: &Self::Storage<'_>) -> StorageShape;
    fn span(
        storage: &Self::Storage<'_>,
        offset: usize,
        bytes: usize,
    ) -> Result<NonNull<u8>, MemoryError>;
}
// Where the stack switch backend is unavailable, a
// hosted loan is uninhabited. These are not executable success/error stubs and
// cannot be constructed by a caller, raw scalar or native wrapper conversion.
#[cfg(all(
    feature = "test-support",
    unix,
    not(all(target_os = "linux", target_arch = "x86_64"))
))]
#[derive(Clone, Copy)]
enum Unwired {}
#[cfg(all(
    feature = "test-support",
    unix,
    not(all(target_os = "linux", target_arch = "x86_64"))
))]
#[derive(Clone, Copy)]
pub struct HostLoan<'a, const N: usize> {
    never: Unwired,
    _life: core::marker::PhantomData<&'a [(); N]>,
}
#[cfg(all(
    feature = "test-support",
    unix,
    not(all(target_os = "linux", target_arch = "x86_64"))
))]
pub struct HostKept<const N: usize> {
    never: Unwired,
    _size: core::marker::PhantomData<[(); N]>,
}
#[cfg(all(
    feature = "test-support",
    unix,
    not(all(target_os = "linux", target_arch = "x86_64"))
))]
impl Domain for super::HostedDomain {
    type Loan<'a, const N: usize> = HostLoan<'a, N>;
    type Kept<const N: usize> = HostKept<N>;
    type Segment<'a, const N: usize> = HostLoan<'a, N>;
    type Storage<'a> = &'a super::HostedPages;
    type Raised = super::hosted::HostedRaisedWork;
    fn raise(event: &Self::Raised) -> Result<(), WorkError> {
        event.raise()
    }
    fn check<const N: usize>(v: &Self::Loan<'_, N>) -> Result<(), WorkError> {
        match v.never {}
    }
    fn current<const N: usize>(v: &Self::Loan<'_, N>) -> Result<TaskContext, WorkError> {
        match v.never {}
    }
    fn dispatcher<const N: usize>(v: &Self::Loan<'_, N>) -> Result<(), WorkError> {
        match v.never {}
    }
    fn same<const N: usize>(a: &Self::Loan<'_, N>, _: &Self::Loan<'_, N>) -> bool {
        match a.never {}
    }
    fn reborrow<const N: usize>(v: &Self::Kept<N>) -> Self::Loan<'_, N> {
        match v.never {}
    }
    fn check_segment<const N: usize>(v: &Self::Segment<'_, N>) -> Result<(), WorkError> {
        match v.never {}
    }
    fn segment_matches<const N: usize>(v: &Self::Segment<'_, N>, _: &Self::Loan<'_, N>) -> bool {
        match v.never {}
    }
    fn shape(v: &Self::Storage<'_>) -> StorageShape {
        StorageShape {
            bytes: v.bytes(),
            alignment: v.alignment(),
            page_shift: v.page_shift(),
        }
    }
    fn span(
        v: &Self::Storage<'_>,
        offset: usize,
        bytes: usize,
    ) -> Result<NonNull<u8>, MemoryError> {
        v.cpu_address(offset, bytes)
    }
}
