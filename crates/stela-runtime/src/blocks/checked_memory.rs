//! Entering blocks whose data accesses use the checked memory service.
use crate::{
    execution::{context::ContextLoan, floating_environment::HostFloatingEnvironment, platform},
    system::execution::{Dispatcher, EntryBoundary, Failure},
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString};
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
/// Raw same-call diagnostics. These fields are never an entry or retirement grant.
#[derive(Debug, Clone, Copy)]
// Only hosted diagnostics read these raw fields back.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(super) struct RawMemoryObservation {
    pub status_code: u32,
    pub address: u64,
    pub pc: u64,
    pub completed_bytes: u64,
}

#[derive(Debug)]
// Only hosted diagnostics read these raw fields back.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
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
        native_invoked: bool,
        callback_failure: Option<String>,
        raw_memory: Option<RawMemoryObservation>,
        raw_returned_carrier: Option<(u64, u64)>,
    },
    InvocationFailed {
        detail: String,
        native_invoked: bool,
        native_executed: bool,
        original_fault: Option<MemoryFault>,
        raw_memory: Option<RawMemoryObservation>,
        completed_bytes: u64,
        observed_exit: Option<(u64, u64)>,
        raw_returned_carrier: Option<(u64, u64)>,
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
#[cfg_attr(not(feature = "std"), allow(dead_code))]
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
    // Entry validation still applies; memory-policy eligibility does not bypass
    // the execution-state, debug-step or source checks.
    if let Err(failure) = dispatcher.validate_entry(boundary, source, registers) {
        return Ok(CheckedReturn::CpuDeclined(failure));
    }
    // The backend validates the dynamic system state against its fixed controls
    // and refreshes this thread's policy. No GuestState reference escapes in
    // the returned borrow.
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
    let mut callback_started = false;
    let mut native_invoked = false;
    let mut native_executed = false;
    let mut observed_fault = None;
    let mut completed_bytes = 0;
    let mut observed_exit = None;
    let mut raw_returned_carrier = None;
    let mut raw_memory = None;
    let mut callback_failure = None;
    // SAFETY: source, target, CPU, policy and storage are validated. Both
    // guards restore their views before the borrows end, including on error.
    let finalized = unsafe {
        process_memory.with_view(|view| {
            callback_started = true;
            let invoked = (|| -> Result<CheckedReturn> {
                let mut loan = ContextLoan::memory(context, view);
                native_invoked = true;
                let returned = mapping.call_context_block(registers, loan.context());
                native_executed = returned.is_ok();
                // Capture every reached observation before a fallible check.
                // Raw carrier bits are unqualified and fault state dominates.
                raw_returned_carrier = returned.as_ref().ok().map(|exit| (exit.next_pc, exit.kind));
                completed_bytes = view.completed_bytes;
                raw_memory = Some(RawMemoryObservation {
                    status_code: view.fault_kind,
                    address: view.fault_address,
                    pc: view.fault_pc,
                    completed_bytes: view.completed_bytes,
                });
                let native_return = returned?;
                ensure!(
                    loan.context().has_supported_header()
                        && loan.context().memory == core::ptr::from_mut(view).cast(),
                    "checked context association changed after native call"
                );
                let status = MemoryStatus::from_code(view.fault_kind).ok_or_else(|| {
                    anyhow::anyhow!("unknown checked memory status {}", view.fault_kind)
                })?;
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
            })();
            if let Err(error) = &invoked {
                callback_failure = Some(error.to_string());
            }
            invoked
        })
    };
    Ok(match finalized {
        Ok(Ok(returned)) => returned,
        Ok(Err(error)) => CheckedReturn::InvocationFailed {
            detail: error.to_string(),
            native_invoked,
            native_executed,
            original_fault: observed_fault,
            raw_memory,
            completed_bytes,
            observed_exit,
            raw_returned_carrier,
        },
        // Only a refusal before the callback starts is an entry decline. After
        // that, finalizer errors keep every observation, and the consumer marks
        // the attempt failed.
        Err(status) if !callback_started => CheckedReturn::EntryDeclined(status),
        Err(status) => CheckedReturn::FinalizationFailed {
            status,
            native_executed,
            original_fault: observed_fault,
            completed_bytes,
            observed_exit,
            native_invoked,
            callback_failure,
            raw_memory,
            raw_returned_carrier,
        },
    })
}

#[cfg(test)]
mod tests;
