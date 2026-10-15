//! Checked data-memory entry through existing registered BlockRuntime owners.
//!
//! No guest opcode, raw native pointer, or caller-selected requirements enters
//! this helper. The parent supplies one source-derived plan and owned RX mapping.
use crate::{
    execution::{context::ContextLoan, floating_environment::HostFloatingEnvironment, platform},
    system::execution::{Dispatcher, EntryBoundary, Failure},
};
use anyhow::{Result, ensure};
use stela_compiler::{
    GuestAddress, GuestState,
    block::BlockExit,
    context::{
        ExecutionContext,
        memory::{MemoryRequirements, MemoryStatus},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MemoryFault {
    pub status: MemoryStatus,
    pub address: GuestAddress,
    pub pc: GuestAddress,
    pub completed_bytes: u64,
}
#[derive(Debug)]
pub(super) enum CheckedReturn {
    CpuDeclined(Failure),
    EntryDeclined(MemoryStatus),
    MemoryFault(MemoryFault),
    Returned(BlockExit),
    FinalizationFailed {
        status: MemoryStatus,
        native_executed: bool,
        original_fault: Option<MemoryFault>,
        completed_bytes: u64,
        observed_exit: Option<(u64, u64)>,
    },
}

/// Parent validation binds source map, source bytes, compiler/target/profile,
/// generation, cache identity and real ASID before this synchronous call.
///
/// # Safety
/// Only the checked context-block mapping emitted from this exact source/plan
/// may be passed. Backing contracts pin disjoint coherent raw RAM/host rights;
/// no live Rust guest-byte reference, concurrent protection change, unwind or
/// unsupported host-fault recovery is allowed. Native code must return finitely.
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn call(
    dispatcher: &mut dyn Dispatcher,
    boundary: &EntryBoundary,
    source: &[u8],
    source_map: &[(GuestAddress, usize)],
    cpu_profile_id: &'static str,
    requirements: MemoryRequirements,
    mapping: &platform::Mapping,
    registers: &mut GuestState,
    context: &mut ExecutionContext,
) -> Result<CheckedReturn> {
    let _floating_environment = HostFloatingEnvironment::capture();
    ensure!(
        context.has_supported_header(),
        "unsupported checked execution context"
    );
    // Preserve the existing source/execution boundary authority. Memory-policy
    // eligibility cannot replace IL, execution-state, debug/step or source gates.
    if let Err(failure) = dispatcher.validate_entry(boundary, source, registers) {
        return Ok(CheckedReturn::CpuDeclined(failure));
    }
    // The actual CPU/backend owner validates dynamic SystemState plus its fixed
    // immutable control declaration and refreshes this exact thread's policy.
    // No GuestState reference survives in the returned opaque borrow.
    let process_memory =
        match dispatcher.prepare_memory_entry(boundary, source, requirements, registers) {
            Ok(entry) => entry,
            Err(failure) => return Ok(CheckedReturn::CpuDeclined(failure)),
        };
    ensure!(
        process_memory.profile_id() == cpu_profile_id,
        "checked CPU/artifact profile mismatch"
    );
    ensure!(
        process_memory.requirements() == requirements,
        "checked body/token requirements mismatch"
    );
    let mut native_executed = false;
    let mut observed_fault = None;
    let mut completed_bytes = 0;
    let mut observed_exit = None;
    // SAFETY: source/target/CPU/policy/storage preflight is complete. Both guards
    // restore their scoped view before owner loans expire, including errors.
    unsafe {
        match process_memory.with_view(|view| {
            let mut loan = ContextLoan::memory(context, view);
            let native_return = mapping.call_context_block(registers, loan.context())?;
            native_executed = true;
            completed_bytes = view.completed_bytes;
            let status = MemoryStatus::from_code(view.fault_kind).ok_or_else(|| {
                anyhow::anyhow!("unknown checked memory status {}", view.fault_kind)
            })?;
            // Fault service state takes precedence: a failed inner body intentionally
            // does not produce a valid RAX/RDX block exit and must not be decoded.
            if status == MemoryStatus::Success {
                observed_exit = Some((native_return.next_pc, native_return.kind));
                return Ok(CheckedReturn::Returned(native_return));
            }
            let pc = GuestAddress(view.fault_pc);
            let fault = MemoryFault {
                status,
                address: GuestAddress(view.fault_address),
                pc,
                completed_bytes: view.completed_bytes,
            };
            observed_fault = Some(fault);
            ensure!(
                source_map.iter().any(|(address, _)| *address == pc),
                "checked fault PC is outside consumed source"
            );
            Ok(CheckedReturn::MemoryFault(fault))
        }) {
            Ok(result) => result,
            Err(status) if !native_executed => Ok(CheckedReturn::EntryDeclined(status)),
            Err(status) => Ok(CheckedReturn::FinalizationFailed {
                status,
                native_executed,
                original_fault: observed_fault,
                completed_bytes,
                observed_exit,
            }),
        }
    }
}

#[cfg(test)]
#[path = "memory/tests.rs"]
mod tests;
