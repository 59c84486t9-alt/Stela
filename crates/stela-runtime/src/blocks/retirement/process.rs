//! Existing Darwin protected dispatch retains the sole actual PE until stop.
use super::{
    checked::{CheckedProcessOwner, OwnedRunRequest, ProcessEntryControls},
    software_async::SoftwareAsyncDomain,
};
use crate::{
    blocks::{BlockRuntime, ThreadState},
    darwin::{ExecutionServices, ServiceRunOutcome},
    memory::OwnedMemory,
    system::{debug::DebugControls, execution::owner::SystemExecutionOwner},
};
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
        .ok_or_else(|| anyhow::anyhow!("missing actual System owner"))?;
    let controls = services
        .protected_controls
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing actual memory controls"))?;
    let thread_memory = services
        .protected_memory
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing actual memory thread"))?;
    memory
        .check_execution_thread(thread_memory)
        .map_err(|e| anyhow::anyhow!("process memory owner: {e:?}"))?;
    let context = services
        .protected_context
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing actual execution context"))?;
    let endpoint = services
        .protected_event
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing actual event endpoint"))?;
    let fp = services
        .protected_fp
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing actual FP control owner"))?;
    let ids = controls
        .identification_snapshot()
        .ok_or_else(|| anyhow::anyhow!("missing actual identification owner"))?;
    anyhow::ensure!(
        ids.same_snapshot(fp.identification_snapshot()),
        "FP and memory identification owners differ"
    );
    let pauth = services
        .pauth
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing actual authentication owner"))?;
    let clock = services
        .clock
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing actual clock owner"))?;
    let thread = services
        .thread
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing actual thread service owner"))?;
    // This bounded software machine has no asynchronous devices or injection
    // APIs. The exclusive registry loan spans construction, FFI and settlement.
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
    let mut producers = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
    let pending = producers
        .lease_no_sources()
        .map_err(|e| anyhow::anyhow!("producer ownership: {e:?}"))?;
    let mut backend = unsafe {
        CheckedProcessOwner::fresh_software(
            runtime.address_space(),
            controls,
            &execution,
            thread_memory,
            endpoint,
            context,
            pending,
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
            #[cfg(all(
                test,
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            ))]
            pair_read_fixture: None,
            #[cfg(all(
                test,
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            ))]
            verify_pair_alias_monitor: false,
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
