//! Synchronous native ABI calls over a borrowed ORIGINAL executable storage owner.
//! Storage proves byte lifetime/RX ownership only. No CPU/PE/domain admission,
//! source association, helper completion, finalization or PC settlement is minted.
use core::{convert::Infallible, ptr::NonNull};
use stela_compiler::{GuestState, block::BlockExit, context::ExecutionContext};

/// Implemented only by concrete original hosted RX or protected boot-frame owners.
///
/// # Safety
/// While borrowed, this owner retains the exact initialized immutable executable
/// bytes, actual mapping/root/cache controls and exclusive reclamation authority.
/// No writer, remap, reclamation or alias can revoke that contract during FFI.
/// entry is nonnull and points to the first byte of the original owned image.
/// revalidate checks actual fallible storage controls, never caller truth flags.
/// This trait supplies no architectural state, Execute source right or PE permit.
/// The caller must bind the exact compiler/profile/ABI/artifact before calling.
pub(super) unsafe trait ExecutableStorage {
    type Error;
    fn entry(&self) -> NonNull<u8>;
    fn revalidate(&self) -> Result<(), Self::Error>;
}

/// Every reached FFI carrier survives even when storage's postcheck fails.
/// Consumers must retain BOTH this observation and canonical context/finalizer
/// outcomes; storage failure cannot authorize retry, Ready or prefix completion.
#[must_use]
pub(crate) struct ReachedCall<R, E> {
    pub(super) returned: R,
    pub(super) storage_after: Result<(), E>,
}
impl<R, E> ReachedCall<R, E> {
    /// Consume owned observations only. Neither carrier nor storage status is
    /// a CPU permit, finalized-context proof or authority to settle/retry a PC.
    pub(crate) fn into_observations(self) -> (R, Result<(), E>) {
        (self.returned, self.storage_after)
    }
}

impl<R> ReachedCall<R, Infallible> {
    pub(super) fn into_infallible(self) -> R {
        let (returned, storage_after) = self.into_observations();
        match storage_after {
            Ok(()) => returned,
            Err(never) => match never {},
        }
    }
}

/// Lifetime borrows concrete storage; there is no raw-pointer constructor.
pub(super) struct NativeImage<'rx, S: ExecutableStorage + ?Sized> {
    storage: &'rx S,
}
impl<'rx, S: ExecutableStorage + ?Sized> NativeImage<'rx, S> {
    pub(super) fn borrow(storage: &'rx S) -> Self {
        Self { storage }
    }
    pub(super) fn revalidate(&self) -> Result<(), S::Error> {
        self.storage.revalidate()
    }

    /// # Safety
    /// Caller proves the exact System V GuestState leaf ABI, bounded execution,
    /// host target support and all direct-RAM nonaliasing/access prerequisites.
    /// An adopted PE may call ONLY under its original canonical retained Active,
    /// full ThreadState/System/backend/source/domain loan through finalization and
    /// once-only PC settlement. No raw component call can bypass that owner.
    pub(super) unsafe fn call(
        &self,
        state: &mut GuestState,
    ) -> Result<ReachedCall<(), S::Error>, S::Error> {
        self.revalidate()?;
        let function: unsafe extern "C" fn(*mut GuestState) =
            unsafe { core::mem::transmute(self.storage.entry().as_ptr()) };
        unsafe { function(state) };
        Ok(ReachedCall {
            returned: (),
            storage_after: self.revalidate(),
        })
    }

    /// # Safety
    /// Exact context-block struct-return ABI and original source/body/map/typed
    /// requirements must be bound. All actual state/context/policy views remain
    /// pinned through this synchronous call and complete canonical finalization.
    /// The adopted-PE retained Active/full-resource contract above is mandatory.
    pub(super) unsafe fn call_context_block(
        &self,
        state: &mut GuestState,
        context: &mut ExecutionContext,
    ) -> Result<ReachedCall<BlockExit, S::Error>, S::Error> {
        self.revalidate()?;
        let function: unsafe extern "C" fn(*mut GuestState, *mut ExecutionContext) -> BlockExit =
            unsafe { core::mem::transmute(self.storage.entry().as_ptr()) };
        let returned = unsafe { function(state, context) };
        Ok(ReachedCall {
            returned,
            storage_after: self.revalidate(),
        })
    }

    /// # Safety
    /// Exact direct-RAM block struct-return ABI and all memory/fault/target
    /// prerequisites apply. The adopted-PE retained Active contract above remains
    /// mandatory; a raw GuestState argument is not CPU or retirement authority.
    pub(super) unsafe fn call_block(
        &self,
        state: &mut GuestState,
    ) -> Result<ReachedCall<BlockExit, S::Error>, S::Error> {
        self.revalidate()?;
        let function: unsafe extern "C" fn(*mut GuestState) -> BlockExit =
            unsafe { core::mem::transmute(self.storage.entry().as_ptr()) };
        let returned = unsafe { function(state) };
        Ok(ReachedCall {
            returned,
            storage_after: self.revalidate(),
        })
    }
}
