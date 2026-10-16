//! Hosts without native execution: every mapping operation fails.
use anyhow::{Result, bail};
use stela_compiler::GuestState;
pub(crate) type StorageError = core::convert::Infallible;

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

    pub unsafe fn call(&self, _state: &mut GuestState) -> Result<()> {
        ensure_supported()
    }

    pub unsafe fn call_context_block(
        &self,
        _state: &mut GuestState,
        _context: &mut stela_compiler::context::ExecutionContext,
    ) -> Result<stela_compiler::block::BlockExit> {
        ensure_supported()?;
        unreachable!()
    }

    pub unsafe fn call_context(
        &self,
        _state: &mut GuestState,
        _context: &mut stela_compiler::context::ExecutionContext,
    ) -> Result<()> {
        ensure_supported()
    }

    pub unsafe fn call_budgeted_block(
        &self,
        _state: &mut GuestState,
        _budget: &mut stela_compiler::block::loop_budget::LoopBudget,
    ) -> Result<stela_compiler::block::BlockExit> {
        ensure_supported()?;
        unreachable!()
    }

    pub unsafe fn call_block(
        &self,
        _state: &mut GuestState,
    ) -> Result<stela_compiler::block::BlockExit> {
        ensure_supported()?;
        unreachable!()
    }
}
