//! Only original canonical sessions may call boot native storage. Both pre-FFI
//! refusal and reached carrier plus fallible postcheck remain typed observations.
use super::{
    boot_frames::{BootFrames, FrameError},
    native_image::NativeImage,
};
use anyhow::Result;
use stela_compiler::{GuestState, block::BlockExit, context::ExecutionContext};

pub(crate) type StorageError = FrameError;
#[derive(Debug)]
pub struct Mapping {
    frames: BootFrames,
}
pub fn ensure_supported() -> Result<()> {
    crate::platform::boot::ensure_live()?;
    Ok(())
}
impl Mapping {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            frames: crate::platform::boot::native(bytes)?,
        })
    }
    /// # Safety
    /// Caller retains the original full canonical Active/session, actual source,
    /// context, state, backend and outer through typed finalization/settlement.
    pub(crate) unsafe fn call_context_block_observed(
        &self,
        state: &mut GuestState,
        context: &mut ExecutionContext,
    ) -> core::result::Result<super::ObservedNativeCall<BlockExit, StorageError>, StorageError>
    {
        // SAFETY: caller binds the original complete canonical ownership/ABI;
        // NativeImage borrows this actual checked protected frame allocation.
        unsafe { NativeImage::borrow(&self.frames).call_context_block(state, context) }
    }
    /// # Safety
    /// Exact one-state-pointer ABI and full original canonical owner contract
    /// apply. The raw carrier and storage postcheck both survive a reached call.
    pub(crate) unsafe fn call_block_observed(
        &self,
        state: &mut GuestState,
    ) -> core::result::Result<super::ObservedNativeCall<BlockExit, StorageError>, StorageError>
    {
        unsafe { NativeImage::borrow(&self.frames).call_block(state) }
    }

    // Legacy research calls have no fallible-storage report/finalizer contract.
    // Refuse BEFORE FFI; mounted canonical paths use the two observed methods.
    pub unsafe fn call(&self, _state: &mut GuestState) -> Result<()> {
        anyhow::bail!("freestanding native entry requires the original observed canonical session")
    }
    pub unsafe fn call_context(
        &self,
        _state: &mut GuestState,
        _context: &mut ExecutionContext,
    ) -> Result<()> {
        anyhow::bail!("freestanding context leaf entry has no canonical storage finalizer")
    }
    pub unsafe fn call_context_block(
        &self,
        _state: &mut GuestState,
        _context: &mut ExecutionContext,
    ) -> Result<BlockExit> {
        anyhow::bail!("freestanding context entry requires the original observed canonical session")
    }
    pub unsafe fn call_budgeted_block(
        &self,
        _state: &mut GuestState,
        _budget: &mut stela_compiler::block::loop_budget::LoopBudget,
    ) -> Result<BlockExit> {
        anyhow::bail!("freestanding resident entry has no canonical storage finalizer")
    }
    pub unsafe fn call_block(&self, _state: &mut GuestState) -> Result<BlockExit> {
        anyhow::bail!("freestanding native entry requires the original observed canonical session")
    }
}
