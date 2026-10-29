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
    /// # Safety
    /// The bytes must implement the two-argument context-leaf ABI for the
    /// actual admitted target. The caller retains exclusive state and a valid
    /// context with all borrowed memory/service owners until call completion
    /// and architectural failure finalization. No callback may reenter them.
    pub unsafe fn call_context(
        &self,
        _state: &mut GuestState,
        _context: &mut ExecutionContext,
    ) -> Result<()> {
        anyhow::bail!("freestanding context leaf entry has no canonical storage finalizer")
    }
    /// Invoke this owned mapping with the compiler's context-block ABI.
    ///
    /// # Safety
    /// The code, target, source map and context requirements must describe the
    /// same checked compilation. The caller retains exclusive state, the live
    /// context and all reachable memory/service owners through return, context
    /// finalization and recovered source-PC settlement; entry cannot reenter.
    pub unsafe fn call_context_block(
        &self,
        _state: &mut GuestState,
        _context: &mut ExecutionContext,
    ) -> Result<BlockExit> {
        anyhow::bail!("freestanding context entry is not implemented")
    }
    /// Invoke the compiler's resident-budget block ABI.
    ///
    /// # Safety
    /// Code, target, guest state and live budget must use the same resident
    /// ABI. Resident loops must be nonfaulting integer code; any fallback also
    /// requires the ordinary block memory/fault contract. This entry does not
    /// admit system, checked or asynchronous producer-domain execution.
    pub unsafe fn call_budgeted_block(
        &self,
        _state: &mut GuestState,
        _budget: &mut stela_compiler::block::loop_budget::LoopBudget,
    ) -> Result<BlockExit> {
        anyhow::bail!("freestanding resident entry has no canonical storage finalizer")
    }
    /// Invoke this owned mapping with the compiler's ordinary block ABI.
    ///
    /// # Safety
    /// The bytes must implement the struct-return block ABI for the actual
    /// admitted target. Every directly addressed guest range must remain
    /// mapped with the compiled rights, and the caller retains exclusive
    /// state, memory/fault owners and source identity through full settlement.
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
