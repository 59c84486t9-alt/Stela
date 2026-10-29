//! Hosts without native execution: every mapping operation fails.
use anyhow::{Result, bail};
use stela_compiler::GuestState;

pub fn ensure_supported() -> Result<()> {
    #[cfg(feature = "std")]
    bail!("native leaf execution requires x86-64 macOS or Linux with the System V ABI");
    #[cfg(not(feature = "std"))]
    bail!("freestanding executable storage owner is not mounted")
}

#[derive(Debug)]
pub struct Mapping;

impl Mapping {
    pub fn new(_bytes: &[u8]) -> Result<Self> {
        ensure_supported()?;
        unreachable!()
    }

    /// Invoke this owned mapping with the compiler's leaf ABI.
    ///
    /// # Safety
    /// The bytes must implement the leaf ABI for the actual admitted host
    /// target. The caller retains exclusive guest state and every accessed
    /// memory/service owner through return and any fault settlement.
    pub unsafe fn call(&self, _state: &mut GuestState) -> Result<()> {
        ensure_supported()
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
        _context: &mut stela_compiler::context::ExecutionContext,
    ) -> Result<stela_compiler::block::BlockExit> {
        ensure_supported()?;
        unreachable!()
    }

    /// # Safety
    /// The bytes must implement the two-argument context-leaf ABI for the
    /// actual admitted target. The caller retains exclusive state and a valid
    /// context with all borrowed memory/service owners until call completion
    /// and architectural failure finalization. No callback may reenter them.
    pub unsafe fn call_context(
        &self,
        _state: &mut GuestState,
        _context: &mut stela_compiler::context::ExecutionContext,
    ) -> Result<()> {
        ensure_supported()
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
    ) -> Result<stela_compiler::block::BlockExit> {
        ensure_supported()?;
        unreachable!()
    }

    /// Invoke this owned mapping with the compiler's ordinary block ABI.
    ///
    /// # Safety
    /// The bytes must implement the struct-return block ABI for the actual
    /// admitted target. Every directly addressed guest range must remain
    /// mapped with the compiled rights, and the caller retains exclusive
    /// state, memory/fault owners and source identity through full settlement.
    pub unsafe fn call_block(
        &self,
        _state: &mut GuestState,
    ) -> Result<stela_compiler::block::BlockExit> {
        ensure_supported()?;
        unreachable!()
    }

    pub(crate) unsafe fn call_amx_kernel(
        &self,
        _offset: usize,
        _z: *mut u8,
        _x: *const u8,
        _y: *const u8,
        _row: u64,
    ) -> Result<()> {
        ensure_supported()
    }
}
