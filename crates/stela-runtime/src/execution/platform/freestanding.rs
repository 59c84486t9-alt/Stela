//! Native-image calls in the freestanding build.
use crate::execution::{
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
    /// The caller's session holds the source, context, state, backend and outer
    /// object through finalization and settlement.
    pub(crate) unsafe fn call_context_block_observed(
        &self,
        state: &mut GuestState,
        context: &mut ExecutionContext,
    ) -> core::result::Result<
        crate::execution::ObservedNativeCall<BlockExit, StorageError>,
        StorageError,
    > {
        // SAFETY: the caller upholds the ownership and ABI contract;
        // `NativeImage` borrows this checked frame allocation.
        unsafe { NativeImage::borrow(&self.frames).call_context_block(state, context) }
    }
    /// # Safety
    /// The one-pointer block ABI and the session contract apply. The raw result
    /// and the storage check are both kept.
    pub(crate) unsafe fn call_block_observed(
        &self,
        state: &mut GuestState,
    ) -> core::result::Result<
        crate::execution::ObservedNativeCall<BlockExit, StorageError>,
        StorageError,
    > {
        unsafe { NativeImage::borrow(&self.frames).call_block(state) }
    }

    // Plain context calls have no storage report or finalizer, so they are
    // refused before the call; the freestanding build uses the observed
    // methods.
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
