//! Private dispatch protocol. Implementations are fixed by this crate, not users.
use super::{StorageShape, TaskContext, WorkError};
use crate::bus::dma::memory::MemoryError;
use core::ptr::NonNull;
pub trait Domain: 'static {
    type Loan<'a, const N: usize>: Copy;
    type Kept<const N: usize>;
    type Segment<'a, const N: usize>;
    type Storage<'a>: Copy;
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
// Until the real mapped/thread/event/shared-work producer is implemented, a
// hosted loan is uninhabited. These are not executable success/error stubs and
// cannot be constructed by a caller, raw scalar or native wrapper conversion.
#[cfg(all(feature = "test-support", unix))]
#[derive(Clone, Copy)]
enum Unwired {}
#[cfg(all(feature = "test-support", unix))]
#[derive(Clone, Copy)]
pub struct HostLoan<'a, const N: usize> {
    never: Unwired,
    _life: core::marker::PhantomData<&'a [(); N]>,
}
#[cfg(all(feature = "test-support", unix))]
pub struct HostKept<const N: usize> {
    never: Unwired,
    _size: core::marker::PhantomData<[(); N]>,
}
#[cfg(all(feature = "test-support", unix))]
#[derive(Clone, Copy)]
pub struct HostStorage<'a> {
    never: Unwired,
    _life: core::marker::PhantomData<&'a ()>,
}
#[cfg(all(feature = "test-support", unix))]
impl Domain for super::HostedDomain {
    type Loan<'a, const N: usize> = HostLoan<'a, N>;
    type Kept<const N: usize> = HostKept<N>;
    type Segment<'a, const N: usize> = HostLoan<'a, N>;
    type Storage<'a> = HostStorage<'a>;
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
        match v.never {}
    }
    fn span(v: &Self::Storage<'_>, _: usize, _: usize) -> Result<NonNull<u8>, MemoryError> {
        match v.never {}
    }
}
