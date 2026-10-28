//! Protected Darwin process dispatch.
use super::checked::{CheckedProcessOwner, OwnedRunRequest, ProcessEntryControls};
use crate::{
    blocks::{BlockRuntime, ThreadState},
    darwin::{ExecutionServices, ServiceRunOutcome},
    memory::OwnedMemory,
    system::{debug::DebugControls, execution::owner::SystemExecutionOwner},
};
#[cfg(not(feature = "std"))]
use alloc::{string::ToString, vec::Vec};
use stela_compiler::GuestAddress;

pub(crate) unsafe fn run_protected_services(
    runtime: &mut BlockRuntime,
    state: &mut ThreadState,
    stop: Option<GuestAddress>,
    budget: usize,
    memory: &mut OwnedMemory,
    mut services: ExecutionServices<'_>,
) -> anyhow::Result<ServiceRunOutcome> {
    anyhow::ensure!(
        !services.data_vm
            && !services.mach_vm
            && !services.mach_vm_map
            && !services.crossarch
            && !services.entropy
            && services.csr.is_none()
            && services.mach_ports.is_none()
            && !services.absent_shared_region,
        "protected process OS service settlement is unsupported"
    );
    let system = services
        .protected_system
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing System owner"))?;
    let controls = services
        .protected_controls
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing memory controls"))?;
    let thread_memory = services
        .protected_memory
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing memory thread"))?;
    memory
        .check_execution_thread(thread_memory)
        .map_err(|e| anyhow::anyhow!("process memory owner: {e:?}"))?;
    let context = services
        .protected_context
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing execution context"))?;
    let endpoint = services
        .protected_event
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing event endpoint"))?;
    let fp = services
        .protected_fp
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing FP control owner"))?;
    let ids = controls
        .identification_snapshot()
        .ok_or_else(|| anyhow::anyhow!("missing identification owner"))?;
    anyhow::ensure!(
        ids.same_snapshot(fp.identification_snapshot()),
        "FP and memory identification owners differ"
    );
    let pauth = services
        .pauth
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing authentication owner"))?;
    let clock = services
        .clock
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing clock owner"))?;
    let thread = services
        .thread
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing thread service owner"))?;
    // This software machine has no asynchronous devices or injection; the
    // registry stays borrowed through construction, the call and settlement.
    let debug = DebugControls {
        halted: false,
        ignore_traps_in_debug: false,
        halting_allowed: false,
        edscr_tda: false,
        os_locked: true,
        breakpoint_count: 0,
        watchpoint_count: 0,
        raw_bank: 0,
        effective_bank: 0,
    };
    let execution = unsafe {
        if system.pacm_state_feature() == crate::system::state::PacmStateFeature::Full {
            ProcessEntryControls::fresh_software_link_register_pauth(
                controls
                    .identification_snapshot_owner()
                    .ok_or_else(|| anyhow::anyhow!("missing original LR Snapshot allocation"))?,
                ids.base_spe_absence()?,
                0,
                debug,
            )
        } else {
            ProcessEntryControls::fresh_software(
                ids.entry_profile()?,
                ids.base_spe_absence()?,
                0,
                debug,
            )
        }
    }?;
    let mut backend = unsafe {
        CheckedProcessOwner::fresh_software(
            runtime.address_space(),
            controls,
            &execution,
            thread_memory,
            endpoint,
            context,
            pauth,
            clock,
            thread,
            Some(fp),
        )
    }?;
    let mut pe = unsafe { SystemExecutionOwner::new_pe(state, system, &mut backend) };
    let identity = pe.identity();
    let result = runtime.run_owned(
        pe.loan(),
        OwnedRunRequest {
            stop_pc: stop,
            block_budget: budget,
        },
    );
    anyhow::ensure!(
        identity.same_pe(&pe.identity()) && pe.pc() == result.actual_pc,
        "retained PE diagnostic identity changed"
    );
    let prefixes = result.settled_prefixes.iter().map(|prefix| serde_json::json!({
        "entry":prefix.entry, "generation":prefix.generation,"source_sha256":prefix.source_sha256,
        "consumed_source_bytes":prefix.consumed_source_bytes,"source_prefix_bytes":prefix.source_prefix_bytes,
        "source_map":prefix.source_map,"stopped_before":prefix.stopped_before,
        "completed_memory_bytes":prefix.completed_memory_bytes,
    })).collect::<Vec<_>>();
    let observation = match pe.observe() {
        Ok(observation) => serde_json::json!({ "actual_pc":observation.actual_pc,
            "registers":format!("{:?}",observation.registers),"legacy_clock_bytes":observation.legacy_clock_bytes,
            "clock_events":observation.clock_events,"thread":observation.thread }),
        Err(error) => serde_json::json!({"declined":error.to_string()}),
    };
    let diagnostics = serde_json::json!({"stop":format!("{:?}",result.stop),"actual_pc":result.actual_pc,
        "last_native_observation":format!("{:?}",result.last_native_observation),
        "registers":format!("{:?}",pe.registers()), "settled_prefixes":prefixes,"retained":observation,"service_refusals":result.service_events.refusals,"mach_resource_effects":result.service_events.mach_effects});
    let mut report = ServiceRunOutcome::unserviced(result.accounting);
    report.protected_observation = Some(diagnostics);
    report.mach_services = result.service_events.mach;
    report.thread_services = result.service_events.thread;
    report.process_services = result.service_events.process;
    Ok(report)
}
