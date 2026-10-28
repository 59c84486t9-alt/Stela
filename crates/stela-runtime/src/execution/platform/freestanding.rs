//! Native-image calls in the freestanding build.
use anyhow::Result;
use stela_compiler::{GuestState, block::BlockExit, context::ExecutionContext};

#[derive(Debug)]
pub struct Mapping;
pub fn ensure_supported() -> Result<()> {
    anyhow::bail!("UNSUPPORTED native blocks: the freestanding build maps no native code")
}
impl Mapping {
    pub fn new(_bytes: &[u8]) -> Result<Self> {
        anyhow::bail!("UNSUPPORTED native blocks: the freestanding build maps no native code")
    }
    // Freestanding entries are refused before the call.
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
        anyhow::bail!("freestanding context entry is not implemented")
    }
    pub unsafe fn call_budgeted_block(
        &self,
        _state: &mut GuestState,
        _budget: &mut stela_compiler::block::loop_budget::LoopBudget,
    ) -> Result<BlockExit> {
        anyhow::bail!("freestanding resident entry has no canonical storage finalizer")
    }
    pub unsafe fn call_block(&self, _state: &mut GuestState) -> Result<BlockExit> {
        anyhow::bail!("freestanding native entry is not implemented")
    }
    /// The boot platform admits only the baseline target, so no AMX kernel
    /// tier is ever mapped here.
    pub(crate) unsafe fn call_amx_kernel(
        &self,
        _offset: usize,
        _z: *mut u8,
        _x: *const u8,
        _y: *const u8,
        _row: u64,
    ) -> Result<()> {
        anyhow::bail!("freestanding AMX kernels are not admitted")
    }
}
