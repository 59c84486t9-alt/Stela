//! Native calls of blocks that touch only the low 128 bits of vector registers.
use super::{CallRecord, NativeObservation, source::BoundSource};
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
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use stela_compiler::{GuestState, context::ExecutionContext};

/// Checking for effect-free execution uses no native callback and changes no
/// policy. The typed access and the unused prepared entry stay inside this
/// callback.
#[allow(clippy::too_many_arguments)]
pub(super) fn qualify(
    bound: &BoundSource<'_>,
    controls: &FixedProcessMemoryControls,
    fp: &FpControlOwner<'_>,
    debug: &crate::system::debug::DebugControls,
    system: &SystemState,
    registers: &mut GuestState,
    memory: &mut MemoryThread<MemoryControls>,
    endpoint: &EventEndpoint,
) -> anyhow::Result<()> {
    let requirements = bound.memory_requirements()?;
    let ids = fp.identification_snapshot();
    let absent =
        NoSme::from_snapshot(ids).map_err(|error| anyhow::anyhow!("SME subset: {error:?}"))?;
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
                    .map_err(|error| anyhow::anyhow!("FP System: {error:?}"))?;
                context
                    .check_guest(actual_guest)
                    .map_err(|error| anyhow::anyhow!("FP bank: {error:?}"))?;
                controls
                    .prepare_profile_with_low128(
                        &bound.entry,
                        bound.memory_profile()?,
                        requirements,
                        system,
                        debug,
                        context,
                        actual_guest,
                        memory,
                        Some(endpoint),
                    )
                    .map_err(|error| anyhow::anyhow!("low128 preparation: {error:?}"))?;
                Ok(())
            })
        },
    )
    .map_err(|error| anyhow::anyhow!("low128 access: {error:?}"))?
}

/// The consumer already holds the native session and the domain exclusion, and
/// keeps them until the observations and PC are settled.
#[allow(clippy::too_many_arguments)]
pub(super) fn call(
    bound: &BoundSource<'_>,
    controls: &FixedProcessMemoryControls,
    fp: &FpControlOwner<'_>,
    debug: &crate::system::debug::DebugControls,
    system: &SystemState,
    registers: &mut GuestState,
    memory: &mut MemoryThread<MemoryControls>,
    endpoint: &EventEndpoint,
    execution: &mut ExecutionContext,
) -> anyhow::Result<NativeObservation> {
    let _floating_environment = HostFloatingEnvironment::capture();
    let profile = bound.memory_profile()?;
    anyhow::ensure!(
        execution.has_supported_header(),
        "unsupported checked context"
    );
    let requirements = bound.memory_requirements()?;
    let ids = fp.identification_snapshot();
    let absent = match NoSme::from_snapshot(ids) {
        Ok(absent) => absent,
        Err(error) => {
            return Ok(NativeObservation::CpuDeclined(format!(
                "SME subset: {error:?}"
            )));
        }
    };
    // These observations outlive the token's result and stay inside the FP
    // callback, so finalization cannot erase them.
    let result = fp_access::with_nonstreaming_low128(
        ids,
        fp,
        system,
        StreamingState::Absent(absent),
        registers,
        bound.entry.entry(),
        |mut access| {
            access.with_guest(|context, actual_guest| {
                let prepared = match controls.prepare_profile_with_low128(
                    &bound.entry,
                    profile,
                    requirements,
                    system,
                    debug,
                    context,
                    actual_guest,
                    memory,
                    Some(endpoint),
                ) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        return NativeObservation::CpuDeclined(format!(
                            "low128 preparation: {error:?}"
                        ));
                    }
                };
                if prepared.profile_id() != profile.process_memory_profile_id()
                    || prepared.requirements() != requirements
                {
                    return NativeObservation::InvocationFailed(
                        "typed entry/body requirements differ".into(),
                    );
                }
                let mut record = CallRecord::default();
                // SAFETY: the source, native code, FP state, context and domain
                // are held here, and the consumer holds the PE and memory.
                let finalized = unsafe {
                    prepared.with_view(actual_guest, |actual_boundary, checked_guest, view| {
                        record.run(|record| {
                            // Re-check, immediately before the call, that the
                            // borrowed descriptor and bank still belong to the
                            // admitted source, requirements, map and native code.
                            bound.check_descriptor(actual_boundary)?;
                            context
                                .check_system(system)
                                .map_err(|error| anyhow::anyhow!("FP System: {error:?}"))?;
                            context
                                .check_guest(checked_guest)
                                .map_err(|error| anyhow::anyhow!("FP bank: {error:?}"))?;
                            let mut loan = ContextLoan::memory(execution, view);
                            let returned = bound
                                .block
                                .mapping
                                .call_context_block(checked_guest, loan.context());
                            record.record(&returned, view);
                            let exit = returned?;
                            anyhow::ensure!(
                                loan.context().has_supported_header()
                                    && loan.context().memory == core::ptr::from_mut(view).cast(),
                                "checked context association changed after native call"
                            );
                            // Source/fault validation precedes settlement by Active.
                            record.classify(exit, view, |fault| bound.validate_fault(fault))
                        })
                    })
                };
                match finalized {
                    Ok(Ok(observation)) => observation,
                    Ok(Err(error)) => record.invocation_failed(error),
                    Err(ProcessMemoryError::Memory(status)) if record.started() => {
                        record.finalization_failed(status)
                    }
                    // Before the callback no native/prefix effect happened.
                    Err(error) if !record.started() => {
                        NativeObservation::CpuDeclined(format!("typed entry refused: {error:?}"))
                    }
                    // A context/owner failure after invocation is never converted
                    // into NoEffect, even if no valid ordinary carrier exists.
                    Err(error) => record.invocation_failed(format_args!(
                        "typed finalization/owner failure: {error:?}"
                    )),
                }
            })
        },
    );
    Ok(match result {
        Ok(observation) => observation,
        Err(error) => NativeObservation::CpuDeclined(format!("low128 access refused: {error:?}")),
    })
}
