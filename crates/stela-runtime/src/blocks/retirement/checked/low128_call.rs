//! Concrete typed low128 branch. The ordinary Dispatcher/base factory remains
//! unchanged and continues to refuse ASIMD. No supplied mapping or saved grant.
use super::{NativeObservation, OwnedMemoryFault, RawMemoryObservation, source::BoundSource};
use crate::{
    execution::{context::ContextLoan, floating_environment::HostFloatingEnvironment},
    memory::{domain::MemoryThread, policy::MemoryControls},
    system::{
        events::EventEndpoint,
        fp_access::{self, NoSme, StreamingState},
        process_memory::{FixedProcessMemoryControls, ProcessMemoryError},
        scalable_controls::fp::FpControlOwner,
        state::SystemState,
    },
};
use stela_compiler::{
    GuestAddress, GuestState,
    context::{ExecutionContext, memory::MemoryStatus},
};

/// Effect-free qualification consumes no native callback and changes no policy.
/// The typed access and unused prepared entry remain inside this actual-bank
/// callback; no context/permission can escape or apply to a replacement bank.
#[allow(clippy::too_many_arguments)]
pub(super) fn qualify(
    bound: &BoundSource<'_>,
    controls: &FixedProcessMemoryControls,
    fp: &FpControlOwner<'_>,
    system: &SystemState,
    registers: &mut GuestState,
    memory: &mut MemoryThread<MemoryControls>,
    endpoint: &EventEndpoint,
) -> anyhow::Result<()> {
    let ids = fp.identification_snapshot();
    let absent = NoSme::from_snapshot(ids)
        .map_err(|error| anyhow::anyhow!("actual SME subset: {error:?}"))?;
    fp_access::with_nonstreaming_low128(
        ids,
        fp,
        system,
        StreamingState::Absent(absent),
        registers,
        bound.entry.entry(),
        |mut access| {
            access.with_guest(|context, actual_guest| {
                bound.check_descriptor(&bound.entry)?;
                context
                    .check_system(system)
                    .map_err(|error| anyhow::anyhow!("actual FP System: {error:?}"))?;
                context
                    .check_guest(actual_guest)
                    .map_err(|error| anyhow::anyhow!("actual FP bank: {error:?}"))?;
                controls
                    .prepare_with_low128(
                        &bound.entry,
                        bound.requirements,
                        system,
                        context,
                        actual_guest,
                        memory,
                        Some(endpoint),
                    )
                    .map_err(|error| anyhow::anyhow!("actual low128 preparation: {error:?}"))?;
                Ok(())
            })
        },
    )
    .map_err(|error| anyhow::anyhow!("actual low128 access: {error:?}"))?
}

/// Canonical Active already owns NativeActive and outer SAME-domain exclusion.
/// It retains them until all returned observations and actual PC are settled.
#[allow(clippy::too_many_arguments)]
pub(super) fn call(
    bound: &BoundSource<'_>,
    controls: &FixedProcessMemoryControls,
    fp: &FpControlOwner<'_>,
    system: &SystemState,
    registers: &mut GuestState,
    memory: &mut MemoryThread<MemoryControls>,
    endpoint: &EventEndpoint,
    execution: &mut ExecutionContext,
) -> anyhow::Result<NativeObservation> {
    let _floating_environment = HostFloatingEnvironment::capture();
    anyhow::ensure!(
        execution.has_supported_header(),
        "unsupported actual checked context"
    );
    let ids = fp.identification_snapshot();
    let absent = match NoSme::from_snapshot(ids) {
        Ok(absent) => absent,
        Err(error) => {
            return Ok(NativeObservation::CpuDeclined(format!(
                "actual SME subset: {error:?}"
            )));
        }
    };
    // These actual observations outlive the consuming token's outer Result and
    // remain inside the whole typed FP callback. Finalization cannot erase them.
    let result = fp_access::with_nonstreaming_low128(
        ids,
        fp,
        system,
        StreamingState::Absent(absent),
        registers,
        bound.entry.entry(),
        |mut access| {
            access.with_guest(|context, actual_guest| {
                let prepared = match controls.prepare_with_low128(&bound.entry,
                    bound.requirements, system, context, actual_guest, memory, Some(endpoint)) {
                    Ok(prepared) => prepared,
                    Err(error) => return NativeObservation::CpuDeclined(format!("actual low128 preparation: {error:?}")),
                };
                if prepared.profile_id() != stela_compiler::block::ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID
                    || prepared.requirements() != bound.requirements {
                    return NativeObservation::UnqualifiedCallFailure("typed entry/body requirements differ".into());
                }
                let mut callback_started = false;
                let mut native_invoked = false;
                let mut native_executed = false;
                let mut observed_fault = None;
                let mut observed_exit = None;
                let mut raw_returned_carrier = None;
                let mut raw_memory = None;
                let mut completed_bytes = 0;
                let mut callback_failure = None;
                // SAFETY: actual source/RX/FP/context/domain owners are retained
                // here and canonical Active retains the outer PE/memory loan.
                let finalized = unsafe { prepared.with_view(actual_guest, |actual_boundary, checked_guest, view| {
                    callback_started = true;
                    let invoked = (|| -> anyhow::Result<NativeObservation> {
                        // The token passes its exact borrowed descriptor/bank.
                        // Recheck their association to the original admitted
                        // source/requirements/map/RX immediately before FFI.
                        bound.check_descriptor(actual_boundary)?;
                        context.check_system(system).map_err(|error| anyhow::anyhow!("actual FP System: {error:?}"))?;
                        context.check_guest(checked_guest).map_err(|error| anyhow::anyhow!("actual FP bank: {error:?}"))?;
                        let mut loan = ContextLoan::memory(execution, view);
                        native_invoked = true;
                        let carrier = bound.block.mapping.call_context_block(checked_guest, loan.context());
                        native_executed = carrier.is_ok();
                        // Preserve returned bits before any context/status/source
                        // check. Fault state may make them meaningless; they
                        // remain unqualified diagnostics and cannot settle PC.
                        raw_returned_carrier = carrier.as_ref().ok().map(|exit| (exit.next_pc, exit.kind));
                        completed_bytes = view.completed_bytes;
                        raw_memory = Some(RawMemoryObservation { status_code: view.fault_kind,
                            address: view.fault_address, pc: view.fault_pc, completed_bytes: view.completed_bytes });
                        let carrier = carrier?;
                        anyhow::ensure!(loan.context().has_supported_header()
                            && loan.context().memory == std::ptr::from_mut(view).cast(),
                            "actual checked context association changed after native call");
                        let status = MemoryStatus::from_code(view.fault_kind)
                            .ok_or_else(|| anyhow::anyhow!("unknown checked status {}", view.fault_kind))?;
                        if status == MemoryStatus::Success {
                            observed_exit = Some((carrier.next_pc, carrier.kind));
                            return Ok(NativeObservation::Returned { next_pc: carrier.next_pc, kind: carrier.kind });
                        }
                        let fault = OwnedMemoryFault { status, address: GuestAddress(view.fault_address),
                            pc: GuestAddress(view.fault_pc), completed_bytes: view.completed_bytes };
                        observed_fault = Some(fault);
                        // Source/fault validation precedes settlement by Active.
                        // The raw record is already retained if this check fails.
                        bound.validate_fault(&fault)?;
                        Ok(NativeObservation::Fault(fault))
                    })();
                    if let Err(error) = &invoked { callback_failure = Some(error.to_string()); }
                    invoked
                }) };
                match finalized {
                    Ok(Ok(observation)) => observation,
                    Ok(Err(error)) => NativeObservation::InvocationFailed {
                        detail: error.to_string(), native_invoked, native_executed,
                        original_fault: observed_fault, raw_memory, completed_bytes, observed_exit, raw_returned_carrier },
                    Err(ProcessMemoryError::Memory(status)) if callback_started => NativeObservation::FinalizationFailed {
                        status, native_executed, original_fault: observed_fault, completed_bytes, observed_exit,
                        native_invoked: Some(native_invoked), callback_failure, raw_memory, raw_returned_carrier,
                    },
                    // Before the callback no native/prefix effect happened.
                    Err(error) if !callback_started => NativeObservation::CpuDeclined(format!("actual typed entry refused: {error:?}")),
                    // A context/owner failure after invocation is never converted
                    // into NoEffect, even if no valid ordinary carrier exists.
                    Err(error) => NativeObservation::InvocationFailed {
                        detail: format!("typed finalization/owner failure: {error:?}; callback={callback_failure:?}"),
                        native_invoked, native_executed, original_fault: observed_fault,
                        raw_memory, completed_bytes, observed_exit, raw_returned_carrier },
                }
            })
        },
    );
    Ok(match result {
        Ok(observation) => observation,
        Err(error) => {
            NativeObservation::CpuDeclined(format!("actual low128 access refused: {error:?}"))
        }
    })
}
