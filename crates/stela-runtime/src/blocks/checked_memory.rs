//! Entering blocks whose data accesses use the checked memory service.
use super::retirement::checked::{CallRecord, NativeObservation};
use crate::{
    execution::{context::ContextLoan, floating_environment::HostFloatingEnvironment, platform},
    system::execution::{Dispatcher, EntryBoundary},
};
#[cfg(not(feature = "std"))]
use alloc::format;
use anyhow::{Result, ensure};
use stela_compiler::{
    GuestAddress, GuestState,
    context::{ExecutionContext, memory::MemoryRequirements},
};

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
) -> Result<NativeObservation> {
    let _floating_environment = HostFloatingEnvironment::capture();
    ensure!(
        context.has_supported_header(),
        "unsupported checked execution context"
    );
    // Entry validation still applies; memory-policy eligibility does not bypass
    // the execution-state, debug-step or source checks.
    if let Err(failure) = dispatcher.validate_entry(boundary, source, registers) {
        return Ok(NativeObservation::CpuDeclined(format!("{failure:?}")));
    }
    // The backend validates the dynamic system state against its fixed controls
    // and refreshes this thread's policy. No GuestState reference escapes in
    // the returned borrow.
    let process_memory =
        match dispatcher.prepare_memory_entry(boundary, source, requirements, registers) {
            Ok(entry) => entry,
            Err(failure) => return Ok(NativeObservation::CpuDeclined(format!("{failure:?}"))),
        };
    ensure!(
        process_memory.profile_id() == cpu_profile_id,
        "checked CPU/artifact profile mismatch"
    );
    ensure!(
        process_memory.requirements() == requirements,
        "checked body/token requirements mismatch"
    );
    let mut record = CallRecord::default();
    // SAFETY: source, target, CPU, policy and storage are validated. Both
    // guards restore their views before the borrows end, including on error.
    let finalized = unsafe {
        process_memory.with_view(|view| {
            record.run(|record| {
                let mut loan = ContextLoan::memory(context, view);
                let returned = mapping.call_context_block(registers, loan.context());
                record.record(&returned, view);
                let exit = returned?;
                ensure!(
                    loan.context().has_supported_header()
                        && loan.context().memory == core::ptr::from_mut(view).cast(),
                    "checked context association changed after native call"
                );
                record.classify(exit, view, |fault| {
                    ensure!(
                        source_map.iter().any(|(address, _)| *address == fault.pc),
                        "checked fault PC is outside consumed source"
                    );
                    Ok(())
                })
            })
        })
    };
    Ok(match finalized {
        Ok(Ok(observation)) => observation,
        Ok(Err(error)) => record.invocation_failed(error),
        // Only a refusal before the callback starts is an entry decline. After
        // that, a finalizer error keeps every observation, and the consumer
        // marks the attempt failed.
        Err(status) if !record.started() => NativeObservation::EntryDeclined(status),
        Err(status) => record.finalization_failed(status),
    })
}
